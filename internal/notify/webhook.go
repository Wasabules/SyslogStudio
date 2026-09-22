package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// WebhookSinkConfig posts messages to an HTTP endpoint.
type WebhookSinkConfig struct {
	URL     string            `json:"url"`
	Method  string            `json:"method"`  // defaults to POST
	Headers map[string]string `json:"headers"` // extra headers, e.g. a custom auth scheme
	Timeout int               `json:"timeout"` // seconds; 0 means 10

	// PayloadMode chooses what is actually sent:
	//
	//   "envelope" (default) — the fixed JSON object below, with the rendered
	//     text in its body field. Predictable, and what a receiver written for
	//     this app expects.
	//   "template" — the sink's body template IS the payload, sent as written.
	//     This is how you talk to Slack, Teams or Alertmanager, which each want
	//     their own shape rather than ours.
	PayloadMode string `json:"payloadMode,omitempty"`
}

const (
	defaultWebhookTimeout = 10 * time.Second
	// maxWebhookResponse bounds what is read back from the endpoint. The body
	// is only used to explain a failure, and an endpoint that streams forever
	// must not hold a dispatcher worker or grow the delivery log without end.
	maxWebhookResponse = 4 << 10
)

type webhookSink struct {
	cfg    WebhookSinkConfig
	token  string
	client *http.Client
}

// webhookEnvelope is the default payload.
type webhookEnvelope struct {
	Subject    string `json:"subject"`
	Body       string `json:"body"`
	Timestamp  string `json:"timestamp"`
	ReceivedAt string `json:"receivedAt"`
	Severity   string `json:"severity"`
	SeverityNo int    `json:"severityNo"`
	Facility   string `json:"facility"`
	Hostname   string `json:"hostname"`
	AppName    string `json:"appName"`
	Message    string `json:"message"`
	SourceIP   string `json:"sourceIP"`
	Protocol   string `json:"protocol"`
}

func newWebhookSink(cfg SinkConfig, secret string) (Sink, error) {
	c := cfg.Webhook
	if err := validateWebhookSink(c); err != nil {
		return nil, err
	}
	timeout := time.Duration(c.Timeout) * time.Second
	if timeout <= 0 {
		timeout = defaultWebhookTimeout
	}
	return &webhookSink{
		cfg:   c,
		token: secret,
		client: &http.Client{
			Timeout: timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return errf("stopped after 5 redirects")
				}
				// A redirect must not move the request to another scheme or
				// host: the Authorization header travels with it, so an
				// endpoint could bounce the bearer token to a third party, or
				// downgrade it to cleartext http.
				orig := via[0].URL
				if req.URL.Scheme != orig.Scheme || req.URL.Host != orig.Host {
					return errf("refusing cross-origin redirect to %s://%s", req.URL.Scheme, req.URL.Host)
				}
				return nil
			},
		},
	}, nil
}

func (w *webhookSink) Describe() string {
	if u, err := url.Parse(w.cfg.URL); err == nil {
		// The path can carry the credential — a Slack or Teams URL authorises
		// by its path alone — so the delivery log gets host only.
		return "webhook " + u.Scheme + "://" + u.Host
	}
	return "webhook"
}

func (w *webhookSink) Send(r Rendered) error {
	body, contentType, err := w.payload(r)
	if err != nil {
		return err
	}

	method := strings.ToUpper(strings.TrimSpace(w.cfg.Method))
	if method == "" {
		method = http.MethodPost
	}

	ctx, cancel := context.WithTimeout(context.Background(), w.client.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, method, w.cfg.URL, bytes.NewReader(body))
	if err != nil {
		return scrubSecret(err, w.token)
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", "SyslogStudio")
	for k, v := range w.cfg.Headers {
		if k == "" {
			continue
		}
		// Header values are operator-supplied; a newline would let one define
		// further headers, which is request splitting.
		req.Header.Set(k, sanitizeHeaderValue(v))
	}
	if w.token != "" {
		req.Header.Set("Authorization", "Bearer "+w.token)
	}

	resp, err := w.client.Do(req)
	if err != nil {
		return scrubSecret(err, w.token)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, maxWebhookResponse))
		return scrubSecret(
			errf("webhook returned %d: %s", resp.StatusCode, strings.TrimSpace(string(snippet))),
			w.token)
	}
	// Drain a little so the connection can be reused.
	_, _ = io.CopyN(io.Discard, resp.Body, 512)
	return nil
}

// payload builds the request body.
func (w *webhookSink) payload(r Rendered) ([]byte, string, error) {
	if w.cfg.PayloadMode == "template" {
		// The rendered body is sent verbatim. If it happens to be JSON, say so,
		// because a receiver like Slack rejects anything else — but do not
		// reformat it: the operator wrote the exact shape their endpoint wants.
		trimmed := strings.TrimSpace(r.Body)
		ct := "text/plain; charset=utf-8"
		if json.Valid([]byte(trimmed)) && (strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[")) {
			ct = "application/json"
		}
		return []byte(r.Body), ct, nil
	}

	env := webhookEnvelope{
		Subject:    r.Subject,
		Body:       r.Body,
		Timestamp:  r.Msg.Timestamp.Format(time.RFC3339),
		ReceivedAt: r.Msg.ReceivedAt.Format(time.RFC3339),
		Severity:   r.Msg.SeverityLabel,
		SeverityNo: int(r.Msg.Severity),
		Facility:   r.Msg.FacilityLabel,
		Hostname:   r.Msg.Hostname,
		AppName:    r.Msg.AppName,
		Message:    r.Msg.Message,
		SourceIP:   r.Msg.SourceIP,
		Protocol:   r.Msg.Protocol,
	}
	b, err := json.Marshal(env)
	if err != nil {
		return nil, "", err
	}
	return b, "application/json", nil
}

// sanitizeHeaderValue removes what would end the header line.
func sanitizeHeaderValue(v string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case '\r', '\n', 0:
			return -1
		}
		return r
	}, v)
}

func (w *webhookSink) Close() error {
	w.client.CloseIdleConnections()
	return nil
}
