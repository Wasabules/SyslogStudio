package notify

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"SyslogStudio/internal/models"
)

func msgAt(sev models.Severity, host, app, text string) models.SyslogMessage {
	now := time.Now()
	return models.SyslogMessage{
		ID: "m1", Timestamp: now, ReceivedAt: now,
		Severity: sev, SeverityLabel: models.SeverityToLabel(sev),
		Facility: models.FacLocal7, FacilityLabel: models.FacilityToLabel(models.FacLocal7),
		Hostname: host, AppName: app, Message: text,
		RawMessage: "<190>1 - " + host + " " + app + " - - - " + text,
		SourceIP:   "10.0.0.5", Protocol: "UDP",
	}
}

func intp(v int) *int { return &v }

// --- Routing ---------------------------------------------------------------

func TestRoute_Matching(t *testing.T) {
	base := msgAt(models.SevError, "web-01", "nginx", "connection refused")

	tests := []struct {
		name  string
		match RouteMatch
		msg   models.SyslogMessage
		want  bool
	}{
		{"empty match is a catch-all", RouteMatch{}, base, true},
		{"severity at least warning", RouteMatch{MaxSeverity: intp(4)}, base, true},
		{"severity too mild", RouteMatch{MaxSeverity: intp(2)}, base, false},
		{"severity range", RouteMatch{MinSeverity: intp(2), MaxSeverity: intp(4)}, base, true},
		{"hostname exact", RouteMatch{Hostnames: []string{"web-01"}}, base, true},
		{"hostname glob", RouteMatch{Hostnames: []string{"web-*"}}, base, true},
		{"hostname glob misses", RouteMatch{Hostnames: []string{"db-*"}}, base, false},
		{"hostname is case-insensitive", RouteMatch{Hostnames: []string{"WEB-01"}}, base, true},
		{"app name", RouteMatch{AppNames: []string{"nginx", "apache2"}}, base, true},
		{"facility", RouteMatch{Facilities: []int{int(models.FacLocal7)}}, base, true},
		{"facility misses", RouteMatch{Facilities: []int{int(models.FacKern)}}, base, false},
		{"source CIDR", RouteMatch{Sources: []string{"10.0.0.0/8"}}, base, true},
		{"source CIDR misses", RouteMatch{Sources: []string{"192.168.0.0/16"}}, base, false},
		// The two patterns that look most like "everything" are the two that
		// silently halve an estate if Contains is used across families.
		{"source 0.0.0.0/0 is everything", RouteMatch{Sources: []string{"0.0.0.0/0"}}, base, true},
		{"source glob", RouteMatch{Sources: []string{"10.0.0.*"}}, base, true},
		{"substring pattern", RouteMatch{Pattern: "refused"}, base, true},
		{"substring is case-insensitive", RouteMatch{Pattern: "REFUSED"}, base, true},
		{"substring misses", RouteMatch{Pattern: "timeout"}, base, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.match.Matches(tt.msg, nil, time.Now()); got != tt.want {
				t.Errorf("Matches = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRoute_RegexIsCompiledOnce(t *testing.T) {
	m := RouteMatch{Pattern: "refus(ed|al)", UseRegex: true}
	msg := msgAt(models.SevError, "web-01", "nginx", "connection refused")

	// Without a compiled expression the route must not match, rather than
	// falling through to "matches everything" — a route whose regex failed to
	// build must not start relaying the whole stream.
	if m.Matches(msg, nil, time.Now()) {
		t.Error("matched with no compiled regex")
	}

	re, err := models.SafeCompileRegex(m.Pattern)
	if err != nil {
		t.Fatal(err)
	}
	if !m.Matches(msg, re, time.Now()) {
		t.Error("did not match with its compiled regex")
	}
}

func TestCompileRoutes_DropsBrokenAndDisabled(t *testing.T) {
	routes := []Route{
		{ID: "ok", Name: "ok", Enabled: true, SinkIDs: []string{"s1"}},
		{ID: "off", Name: "off", Enabled: false, SinkIDs: []string{"s1"}},
		{ID: "nosink", Name: "no sink", Enabled: true},
		// An unclosed group. Treating this as a catch-all would start sending
		// every message to a third party because of a typo.
		{ID: "bad", Name: "bad regex", Enabled: true, SinkIDs: []string{"s1"},
			Match: RouteMatch{Pattern: "(unclosed", UseRegex: true}},
	}
	got := compileRoutes(routes)
	if len(got) != 1 || got[0].route.ID != "ok" {
		ids := []string{}
		for _, c := range got {
			ids = append(ids, c.route.ID)
		}
		t.Errorf("compiled %v, want just [ok]", ids)
	}
}

func TestSelectSinks_PriorityStopAndDedup(t *testing.T) {
	msg := msgAt(models.SevError, "web-01", "nginx", "boom")

	t.Run("priority orders evaluation", func(t *testing.T) {
		routes := compileRoutes([]Route{
			{ID: "b", Name: "second", Enabled: true, Priority: 20, SinkIDs: []string{"s2"}},
			{ID: "a", Name: "first", Enabled: true, Priority: 10, SinkIDs: []string{"s1"}},
		})
		got := selectSinks(routes, msg, time.Now())
		if len(got) != 2 || got[0] != "s1" {
			t.Errorf("got %v, want s1 first", got)
		}
	})

	t.Run("stop ends evaluation", func(t *testing.T) {
		routes := compileRoutes([]Route{
			{ID: "a", Name: "first", Enabled: true, Priority: 10, SinkIDs: []string{"s1"}, Stop: true},
			{ID: "b", Name: "catch-all", Enabled: true, Priority: 20, SinkIDs: []string{"s2"}},
		})
		got := selectSinks(routes, msg, time.Now())
		if len(got) != 1 || got[0] != "s1" {
			t.Errorf("got %v, want only s1", got)
		}
	})

	t.Run("a sink named twice is delivered once", func(t *testing.T) {
		routes := compileRoutes([]Route{
			{ID: "a", Name: "a", Enabled: true, Priority: 10, SinkIDs: []string{"s1"}},
			{ID: "b", Name: "b", Enabled: true, Priority: 20, SinkIDs: []string{"s1", "s2"}},
		})
		got := selectSinks(routes, msg, time.Now())
		if len(got) != 2 {
			t.Errorf("got %v, want s1 once and s2 once", got)
		}
	})
}

func TestWindow(t *testing.T) {
	at := func(h, m int, wd time.Weekday) time.Time {
		// 2026-09-21 is a Monday; add days to reach the requested weekday.
		base := time.Date(2026, 9, 21, h, m, 0, 0, time.Local)
		return base.AddDate(0, 0, (int(wd)-int(time.Monday)+7)%7)
	}
	tests := []struct {
		name string
		w    *Window
		t    time.Time
		want bool
	}{
		{"no window", nil, at(3, 0, time.Monday), true},
		{"inside", &Window{Start: "09:00", End: "17:00"}, at(12, 0, time.Monday), true},
		{"outside", &Window{Start: "09:00", End: "17:00"}, at(20, 0, time.Monday), false},
		// On-call hours are written end-before-start and must wrap midnight,
		// not become an empty window.
		{"wraps midnight, late", &Window{Start: "22:00", End: "06:00"}, at(23, 30, time.Monday), true},
		{"wraps midnight, early", &Window{Start: "22:00", End: "06:00"}, at(2, 0, time.Monday), true},
		{"wraps midnight, outside", &Window{Start: "22:00", End: "06:00"}, at(12, 0, time.Monday), false},
		{"weekday included", &Window{Start: "00:00", End: "23:59", Days: []int{1}}, at(12, 0, time.Monday), true},
		{"weekday excluded", &Window{Start: "00:00", End: "23:59", Days: []int{0}}, at(12, 0, time.Monday), false},
		// A typo must not silently stop every delivery on the route.
		{"malformed is treated as no window", &Window{Start: "nonsense", End: "17:00"}, at(3, 0, time.Monday), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := inWindow(tt.w, tt.t); got != tt.want {
				t.Errorf("inWindow = %v, want %v", got, tt.want)
			}
		})
	}
}

// --- Rendering -------------------------------------------------------------

func TestRender_DefaultsAndTemplate(t *testing.T) {
	msg := msgAt(models.SevError, "web-01", "nginx", "connection refused")

	r := Render(msg, MessageTemplate{}, false)
	if !strings.Contains(r.Subject, "web-01") || !strings.Contains(r.Body, "connection refused") {
		t.Errorf("defaults lost content: subject=%q body=%q", r.Subject, r.Body)
	}

	r = Render(msg, MessageTemplate{Subject: "{{.Hostname}} down", Body: "{{.Severity}}: {{.Message}}"}, false)
	if r.Subject != "web-01 down" {
		t.Errorf("subject = %q", r.Subject)
	}
	if r.Body != "Error: connection refused" {
		t.Errorf("body = %q", r.Body)
	}
}

// A broken template must not stop delivery: the operator still needs the alert,
// and seeing their unexpanded text tells them what they typed wrong.
func TestRender_BrokenTemplateFallsBackToItsText(t *testing.T) {
	msg := msgAt(models.SevError, "web-01", "nginx", "boom")
	r := Render(msg, MessageTemplate{Body: "{{.Nope"}, false)
	if r.Body != "{{.Nope" {
		t.Errorf("body = %q, want the raw template text", r.Body)
	}
	if err := ValidateTemplate(MessageTemplate{Body: "{{.Nope"}); err == nil {
		t.Error("ValidateTemplate accepted a broken template")
	}
}

func TestRender_Redaction(t *testing.T) {
	msg := msgAt(models.SevError, "web-01", "nginx", "peer 203.0.113.9 mailed ops@corp.example.com")
	r := Render(msg, MessageTemplate{Body: "{{.Hostname}} {{.SourceIP}} {{.Message}}"}, true)

	for _, leak := range []string{"web-01", "10.0.0.5", "203.0.113.9", "ops@corp.example.com"} {
		if strings.Contains(r.Body, leak) {
			t.Errorf("redacted body still contains %q: %s", leak, r.Body)
		}
	}
	// Without redaction the values must survive untouched.
	plain := Render(msg, MessageTemplate{Body: "{{.Hostname}} {{.SourceIP}}"}, false)
	if !strings.Contains(plain.Body, "web-01") || !strings.Contains(plain.Body, "10.0.0.5") {
		t.Errorf("unredacted body lost content: %s", plain.Body)
	}
}

// --- Syslog sink -----------------------------------------------------------

func TestSyslogSink_ForwardsAndPreservesSeverity(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	got := make(chan string, 4)
	go func() {
		buf := make([]byte, 65535)
		for {
			n, _, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			got <- string(buf[:n])
		}
	}()

	cfg := SinkConfig{
		ID: "s1", Name: "relay", Kind: SinkSyslog, Enabled: true,
		Syslog: SyslogSinkConfig{
			Address:  conn.LocalAddr().String(),
			Protocol: "udp", Facility: 16,
			PreserveOrigin: true,
		},
	}
	sink, err := Build(cfg, "")
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()

	msg := msgAt(models.SevCritical, "db-master", "postgres", "out of memory")
	if err := sink.Send(Render(msg, MessageTemplate{Body: "{{.Message}}"}, false)); err != nil {
		t.Fatalf("Send: %v", err)
	}

	select {
	case wire := <-got:
		// PRI = facility*8 + severity. Severity must come from the original
		// message: flattening it would destroy the far collector's filtering,
		// which is the main thing a relay is for.
		if !strings.HasPrefix(wire, "<130>1 ") {
			t.Errorf("wire = %q, want PRI <130> (local0 + critical)", wire)
		}
		if !strings.Contains(wire, "db-master") || !strings.Contains(wire, "postgres") {
			t.Errorf("PreserveOrigin lost the origin: %s", wire)
		}
		if !strings.Contains(wire, "out of memory") {
			t.Errorf("message body lost: %s", wire)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("nothing arrived")
	}
}

// A newline inside MSG ends the record under LF framing, so everything after it
// arrives as a SEPARATE syslog line with whatever PRI the sender chose. That is
// how a device forges an emergency from any host it likes on the far collector.
func TestSyslogSink_RefusesLogInjection(t *testing.T) {
	s := &syslogSink{
		cfg:      SyslogSinkConfig{Protocol: "tcp", Facility: 16},
		hostname: "collector", appName: "SyslogStudio",
	}

	hostile := msgAt(models.SevInformational, "evil", "app",
		"benign\n<0>1 2026-01-01T00:00:00Z trusted-host sshd - - - forged emergency")
	wire := s.frame(Render(hostile, MessageTemplate{Body: "{{.Message}}"}, false))

	// The newline is the vector, not the "<". Once the line cannot be split,
	// "<0>1 …" is inert text inside MSG: the receiver parses one record, and
	// the forged PRI is just characters in the message body.
	if strings.ContainsAny(wire, "\r\n") {
		t.Errorf("framed line can still be split into two records: %q", wire)
	}
	// The hostile text must survive as content. Neutralising it by deletion
	// would lose the evidence an operator needs to see what was attempted.
	if !strings.Contains(wire, "forged emergency") {
		t.Errorf("hostile text was dropped rather than neutralised: %q", wire)
	}
}

// A space in HOSTNAME or APP-NAME shifts every later field by one, letting a
// hostile device supply its own PROCID, MSGID and structured data.
func TestSyslogSink_SanitizesHeaderFields(t *testing.T) {
	s := &syslogSink{
		cfg:      SyslogSinkConfig{Protocol: "udp", Facility: 16, PreserveOrigin: true},
		hostname: "collector", appName: "SyslogStudio",
	}
	msg := msgAt(models.SevNotice, "host with spaces", "app - - - [inject@1 k=\"v\"]", "text")
	wire := s.frame(Render(msg, MessageTemplate{Body: "{{.Message}}"}, false))

	// PRI VERSION TIMESTAMP HOST APP PROCID MSGID SD MSG -> the MSG is the
	// eighth field onwards; anything before it must be a single token each.
	fields := strings.SplitN(wire, " ", 8)
	if len(fields) < 8 {
		t.Fatalf("framed line has too few fields: %q", wire)
	}
	if strings.Contains(fields[3], " ") || strings.Contains(fields[4], " ") {
		t.Errorf("header field carries a space: host=%q app=%q", fields[3], fields[4])
	}
	if fields[7] != "text" && !strings.HasPrefix(fields[7], "text") {
		t.Errorf("field shifting changed where MSG starts: %q", wire)
	}
}

// --- Webhook sink ----------------------------------------------------------

func TestWebhookSink_EnvelopeAndTemplate(t *testing.T) {
	var (
		mu   sync.Mutex
		body []byte
		ctyp string
		auth string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		body, ctyp, auth = b, r.Header.Get("Content-Type"), r.Header.Get("Authorization")
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	msg := msgAt(models.SevError, "web-01", "nginx", "connection refused")

	t.Run("envelope", func(t *testing.T) {
		cfg := SinkConfig{ID: "w", Name: "hook", Kind: SinkWebhook, Enabled: true,
			Webhook: WebhookSinkConfig{URL: srv.URL}}
		sink, err := Build(cfg, "tok-123")
		if err != nil {
			t.Fatal(err)
		}
		defer sink.Close()
		if err := sink.Send(Render(msg, MessageTemplate{}, false)); err != nil {
			t.Fatalf("Send: %v", err)
		}

		mu.Lock()
		defer mu.Unlock()
		var env webhookEnvelope
		if err := json.Unmarshal(body, &env); err != nil {
			t.Fatalf("payload is not the envelope: %v (%s)", err, body)
		}
		if env.Hostname != "web-01" || env.Message != "connection refused" {
			t.Errorf("envelope lost fields: %+v", env)
		}
		if auth != "Bearer tok-123" {
			t.Errorf("Authorization = %q", auth)
		}
		if ctyp != "application/json" {
			t.Errorf("Content-Type = %q", ctyp)
		}
	})

	t.Run("template mode sends the body verbatim", func(t *testing.T) {
		cfg := SinkConfig{ID: "w2", Name: "slack", Kind: SinkWebhook, Enabled: true,
			Webhook:  WebhookSinkConfig{URL: srv.URL, PayloadMode: "template"},
			Template: MessageTemplate{Body: `{"text":"{{.Hostname}} is down"}`}}
		sink, err := Build(cfg, "")
		if err != nil {
			t.Fatal(err)
		}
		defer sink.Close()
		if err := sink.Send(Render(msg, cfg.Template, false)); err != nil {
			t.Fatalf("Send: %v", err)
		}

		mu.Lock()
		defer mu.Unlock()
		if string(body) != `{"text":"web-01 is down"}` {
			t.Errorf("payload = %s", body)
		}
		// Receivers like Slack reject anything that is not declared as JSON.
		if ctyp != "application/json" {
			t.Errorf("Content-Type = %q, want application/json for a JSON body", ctyp)
		}
	})
}

func TestWebhookSink_ReportsFailureWithoutLeakingTheToken(t *testing.T) {
	const token = "super-secret-token"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A real endpoint echoing the credential back in its error is exactly
		// how it ends up in the delivery log.
		http.Error(w, "rejected auth "+token, http.StatusUnauthorized)
	}))
	defer srv.Close()

	cfg := SinkConfig{ID: "w", Name: "hook", Kind: SinkWebhook, Enabled: true,
		Webhook: WebhookSinkConfig{URL: srv.URL}}
	sink, err := Build(cfg, token)
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()

	err = sink.Send(Render(msgAt(models.SevError, "h", "a", "m"), MessageTemplate{}, false))
	if err == nil {
		t.Fatal("a 401 was reported as success")
	}
	if strings.Contains(err.Error(), token) {
		t.Errorf("error leaks the token: %v", err)
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("error does not say what happened: %v", err)
	}
}

// --- Credential binding ----------------------------------------------------

// A stored credential may be used only with the destination it was stored
// against. Without this, naming an existing sink's id while pointing the URL at
// your own server has the bearer token delivered to you.
func TestSameDestination(t *testing.T) {
	webhook := func(u string) SinkConfig {
		return SinkConfig{Kind: SinkWebhook, Webhook: WebhookSinkConfig{URL: u}}
	}
	email := func(host string, port int, enc string) SinkConfig {
		return SinkConfig{Kind: SinkEmail, Email: EmailSinkConfig{Host: host, Port: port, Encryption: enc}}
	}

	tests := []struct {
		name string
		a, b SinkConfig
		want bool
	}{
		{"same URL", webhook("https://h/x"), webhook("https://h/x"), true},
		{"different host", webhook("https://h/x"), webhook("https://evil/x"), false},
		{"different path", webhook("https://h/x"), webhook("https://h/y"), false},
		// https to http puts the token on the wire in the clear.
		{"scheme downgrade", webhook("https://h/x"), webhook("http://h/x"), false},
		{"same SMTP", email("smtp.example.com", 587, "starttls"), email("smtp.example.com", 587, "starttls"), true},
		// starttls to none on the same host sends the password unprotected.
		{"encryption downgrade", email("smtp.example.com", 587, "starttls"), email("smtp.example.com", 587, "none"), false},
		{"different port", email("smtp.example.com", 587, "starttls"), email("smtp.example.com", 25, "starttls"), false},
		// A kind that cannot be built must not compare equal by way of two
		// empty strings.
		{"unknown kind never binds", SinkConfig{Kind: "carrier-pigeon"}, SinkConfig{Kind: "carrier-pigeon"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SameDestination(tt.a, tt.b); got != tt.want {
				t.Errorf("SameDestination = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestScrubSecret_CoversEncodedForms(t *testing.T) {
	const secret = "p@ss word/+"
	for _, form := range secretForms(secret) {
		err := scrubSecret(errf("server said: %s", form), secret)
		if strings.Contains(err.Error(), form) {
			t.Errorf("form %q survived scrubbing: %v", form, err)
		}
	}
	// An unrelated error is returned unchanged rather than wrapped.
	orig := errf("connection refused")
	if got := scrubSecret(orig, secret); got != orig {
		t.Error("an error with no secret in it was rewritten")
	}
}

// --- E-mail framing --------------------------------------------------------

// "\r\n.\r\n" ends the DATA command, so a body line consisting of a single dot
// truncates the message and leaves the rest to be read as SMTP commands.
func TestEmail_DotStuffing(t *testing.T) {
	e := &emailSink{cfg: EmailSinkConfig{From: "a@b.c", To: []string{"d@e.f"}}}
	msg := msgAt(models.SevError, "h", "a", "line one\n.\nRCPT TO:<victim@example.com>")
	raw := string(e.message(Render(msg, MessageTemplate{Body: "{{.Message}}"}, false)))

	body := raw[strings.Index(raw, "\r\n\r\n")+4:]
	if strings.Contains(body, "\r\n.\r\n") {
		t.Errorf("body still contains a bare dot line, which ends DATA:\n%q", body)
	}
	if !strings.Contains(body, "\r\n..\r\n") {
		t.Errorf("the dot was not stuffed:\n%q", body)
	}
}

// A subject carrying a CRLF would otherwise define further headers.
func TestEmail_SubjectCannotInjectHeaders(t *testing.T) {
	e := &emailSink{cfg: EmailSinkConfig{From: "a@b.c", To: []string{"d@e.f"}}}
	msg := msgAt(models.SevError, "h", "a", "x")
	r := Render(msg, MessageTemplate{}, false)
	r.Subject = "ok\r\nBcc: victim@example.com"

	raw := string(e.message(r))
	headers := raw[:strings.Index(raw, "\r\n\r\n")]

	// What matters is whether a new header LINE was created, not whether the
	// text "Bcc:" appears anywhere: with the CRLF stripped it survives inside
	// the Subject value, where it is inert.
	for _, line := range strings.Split(headers, "\r\n") {
		if strings.HasPrefix(strings.ToLower(line), "bcc:") {
			t.Errorf("subject created a real header line:\n%s", headers)
		}
	}
	if strings.Count(headers, "Subject:") != 1 {
		t.Errorf("subject was split across lines:\n%s", headers)
	}
}

// --- Validation ------------------------------------------------------------

func TestValidateSink(t *testing.T) {
	tests := []struct {
		name    string
		cfg     SinkConfig
		wantErr bool
	}{
		{"valid syslog", SinkConfig{Name: "s", Kind: SinkSyslog,
			Syslog: SyslogSinkConfig{Address: "10.0.0.1:514", Protocol: "udp", Facility: 16}}, false},
		{"syslog without port", SinkConfig{Name: "s", Kind: SinkSyslog,
			Syslog: SyslogSinkConfig{Address: "10.0.0.1", Protocol: "udp"}}, true},
		{"syslog bad protocol", SinkConfig{Name: "s", Kind: SinkSyslog,
			Syslog: SyslogSinkConfig{Address: "10.0.0.1:514", Protocol: "sctp"}}, true},
		{"valid webhook", SinkConfig{Name: "w", Kind: SinkWebhook,
			Webhook: WebhookSinkConfig{URL: "https://example.com/hook"}}, false},
		// A file: URL is a local-file read dressed up as a delivery.
		{"webhook file scheme", SinkConfig{Name: "w", Kind: SinkWebhook,
			Webhook: WebhookSinkConfig{URL: "file:///etc/passwd"}}, true},
		{"webhook bad method", SinkConfig{Name: "w", Kind: SinkWebhook,
			Webhook: WebhookSinkConfig{URL: "https://e.com", Method: "DELETE"}}, true},
		{"valid email", SinkConfig{Name: "e", Kind: SinkEmail,
			Email: EmailSinkConfig{Host: "smtp.e.com", Port: 587, From: "a@b.c",
				To: []string{"d@e.f"}, Encryption: "starttls"}}, false},
		{"email without recipient", SinkConfig{Name: "e", Kind: SinkEmail,
			Email: EmailSinkConfig{Host: "smtp.e.com", Port: 587, From: "a@b.c", Encryption: "starttls"}}, true},
		{"unnamed", SinkConfig{Kind: SinkSyslog,
			Syslog: SyslogSinkConfig{Address: "10.0.0.1:514", Protocol: "udp"}}, true},
		{"unknown kind", SinkConfig{Name: "x", Kind: "pigeon"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateSink(tt.cfg); (err != nil) != tt.wantErr {
				t.Errorf("error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateRoute(t *testing.T) {
	ok := Route{Name: "r", SinkIDs: []string{"s1"}}
	tests := []struct {
		name    string
		mutate  func(*Route)
		wantErr bool
	}{
		{"valid", func(r *Route) {}, false},
		{"unnamed", func(r *Route) { r.Name = "" }, true},
		{"no destination", func(r *Route) { r.SinkIDs = nil }, true},
		{"severity out of range", func(r *Route) { r.Match.MinSeverity = intp(9) }, true},
		{"inverted severity range", func(r *Route) {
			r.Match.MinSeverity, r.Match.MaxSeverity = intp(5), intp(2)
		}, true},
		{"broken regex", func(r *Route) {
			r.Match.Pattern, r.Match.UseRegex = "(unclosed", true
		}, true},
		{"bad window", func(r *Route) { r.Match.Window = &Window{Start: "25:00", End: "09:00"} }, true},
		{"bad weekday", func(r *Route) {
			r.Match.Window = &Window{Start: "09:00", End: "17:00", Days: []int{9}}
		}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := ok
			tt.mutate(&r)
			if err := ValidateRoute(r); (err != nil) != tt.wantErr {
				t.Errorf("error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// --- Dispatcher ------------------------------------------------------------

func TestDispatcher_RoutesToSink(t *testing.T) {
	var hits int64
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	d := NewDispatcher(nil, nil)
	defer d.Close()

	d.Configure(
		[]Route{{ID: "r1", Name: "errors", Enabled: true, SinkIDs: []string{"s1"},
			Match: RouteMatch{MaxSeverity: intp(3)}}},
		[]SinkConfig{{ID: "s1", Name: "hook", Kind: SinkWebhook, Enabled: true,
			Webhook: WebhookSinkConfig{URL: srv.URL}}},
	)

	d.Dispatch(msgAt(models.SevError, "web-01", "nginx", "boom"))
	// Below the severity threshold: must not be delivered.
	d.Dispatch(msgAt(models.SevDebug, "web-01", "nginx", "noise"))

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := hits
		mu.Unlock()
		if n >= 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	mu.Lock()
	defer mu.Unlock()
	if hits != 1 {
		t.Errorf("endpoint received %d deliveries, want exactly 1", hits)
	}
	if st := d.Stats(); st.Matched != 1 {
		t.Errorf("Matched = %d, want 1", st.Matched)
	}
}

func TestDispatcher_NoRoutesIsInert(t *testing.T) {
	d := NewDispatcher(nil, nil)
	defer d.Close()
	// Must not panic and must not count anything.
	d.Dispatch(msgAt(models.SevEmergency, "h", "a", "m"))
	if st := d.Stats(); st.Matched != 0 || st.Delivered != 0 {
		t.Errorf("stats moved with no routes configured: %+v", st)
	}
}

func TestDispatcher_ReportsFailureInTheLog(t *testing.T) {
	d := NewDispatcher(nil, nil)
	defer d.Close()

	// Port 1 on loopback: reserved, nothing listening.
	d.Configure(
		[]Route{{ID: "r", Name: "all", Enabled: true, SinkIDs: []string{"s"}}},
		[]SinkConfig{{ID: "s", Name: "dead", Kind: SinkSyslog, Enabled: true,
			Syslog: SyslogSinkConfig{Address: "127.0.0.1:1", Protocol: "tcp", Facility: 16}}},
	)
	d.Dispatch(msgAt(models.SevError, "h", "a", "m"))

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		entries := d.Log()
		if len(entries) > 0 {
			last := entries[len(entries)-1]
			if !last.OK && last.Error != "" {
				return // reported, as it should be
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Errorf("an unreachable destination was never reported: %+v, stats %+v", d.Log(), d.Stats())
}

func TestDispatcher_CloseIsIdempotent(t *testing.T) {
	d := NewDispatcher(nil, nil)
	d.Close()
	d.Close() // must not panic on a second close
}

// A relayed syslog frame carries the timestamp, hostname, app name and PID in
// its header. Rendering the shared default body into MSG as well would put
// every one of those fields on the wire twice, which is what a collector
// downstream would then have to parse around.
func TestDefaultedTemplate_SyslogDoesNotRepeatTheHeader(t *testing.T) {
	msg := msgAt(models.SevInformational, "router-7", "sshd", "Accepted password for alice")
	msg.ProcID = "4242"

	relayed := Render(msg, DefaultedTemplate("syslog", MessageTemplate{}), false)
	if relayed.Body != "Accepted password for alice" {
		t.Fatalf("syslog body = %q, want the bare message", relayed.Body)
	}

	// The other transports have no header, so they keep the context.
	for _, kind := range []string{"email", "webhook"} {
		body := Render(msg, DefaultedTemplate(kind, MessageTemplate{}), false).Body
		for _, want := range []string{"router-7", "sshd", "4242"} {
			if !strings.Contains(body, want) {
				t.Errorf("%s body %q lost %q", kind, body, want)
			}
		}
	}

	// An explicit template always wins, including for syslog.
	custom := Render(msg, DefaultedTemplate("syslog", MessageTemplate{Body: "x {{.Hostname}}"}), false)
	if custom.Body != "x router-7" {
		t.Errorf("explicit template overridden: %q", custom.Body)
	}
}
