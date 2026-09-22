package notify

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"SyslogStudio/internal/models"
)

// These tests speak real TLS to real listeners. The point is the part unit
// tests cannot reach: that a collector demanding a client certificate accepts
// this sink, that one signed by the wrong authority is turned away, and that
// STARTTLS to a relay with a private CA actually establishes.

// --- test PKI -------------------------------------------------------------

type testCA struct {
	cert   *x509.Certificate
	key    *ecdsa.PrivateKey
	pemDir string
	file   string // path to the CA certificate in PEM form
}

func newTestCA(t *testing.T, dir, name string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("self-sign CA: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}
	file := filepath.Join(dir, name+".crt")
	writePEMFile(t, file, "CERTIFICATE", der)
	return &testCA{cert: cert, key: key, pemDir: dir, file: file}
}

// issue returns the paths to a leaf certificate and its key.
func (ca *testCA) issue(t *testing.T, name string, server bool) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano() + 1),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	if server {
		tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tpl.DNSNames = []string{"localhost"}
		tpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	} else {
		tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("sign leaf: %v", err)
	}
	certPath = filepath.Join(ca.pemDir, name+".crt")
	keyPath = filepath.Join(ca.pemDir, name+".key")
	writePEMFile(t, certPath, "CERTIFICATE", der)
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal leaf key: %v", err)
	}
	writePEMFile(t, keyPath, "EC PRIVATE KEY", keyDER)
	return certPath, keyPath
}

func writePEMFile(t *testing.T, path, typ string, der []byte) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: typ, Bytes: der}); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func certPool(t *testing.T, path string) *x509.CertPool {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	p := x509.NewCertPool()
	if !p.AppendCertsFromPEM(raw) {
		t.Fatalf("%s holds no certificate", path)
	}
	return p
}

// --- a collector that demands a client certificate -------------------------

type collector struct {
	addr  string
	mu    sync.Mutex
	lines []string
	peers []string
	errs  []string
}

func (c *collector) snapshot() ([]string, []string, []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.lines...), append([]string(nil), c.peers...), append([]string(nil), c.errs...)
}

// startCollector listens with mutual TLS required and records what arrives.
func startCollector(t *testing.T, serverCert, serverKey string, clientCAs *x509.CertPool) *collector {
	t.Helper()
	pair, err := tls.LoadX509KeyPair(serverCert, serverKey)
	if err != nil {
		t.Fatalf("load collector pair: %v", err)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{pair},
		MinVersion:   tls.VersionTLS12,
	}
	if clientCAs != nil {
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
		cfg.ClientCAs = clientCAs
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	c := &collector{addr: ln.Addr().String()}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				tc := conn.(*tls.Conn)
				if err := tc.Handshake(); err != nil {
					c.mu.Lock()
					c.errs = append(c.errs, err.Error())
					c.mu.Unlock()
					return
				}
				st := tc.ConnectionState()
				peer := "(anonymous)"
				if len(st.PeerCertificates) > 0 {
					peer = st.PeerCertificates[0].Subject.CommonName
				}
				c.mu.Lock()
				c.peers = append(c.peers, peer)
				c.mu.Unlock()

				sc := bufio.NewScanner(tc)
				for sc.Scan() {
					c.mu.Lock()
					c.lines = append(c.lines, sc.Text())
					c.mu.Unlock()
				}
			}(conn)
		}
	}()
	return c
}

func sendOne(t *testing.T, cfg SyslogSinkConfig, text string) error {
	t.Helper()
	sink, err := newSyslogSink(SinkConfig{Kind: SinkSyslog, Syslog: cfg}, "")
	if err != nil {
		return err
	}
	defer sink.Close()
	msg := msgAt(models.SevWarning, "router-7", "sshd", text)
	return sink.Send(Render(msg, DefaultedTemplate("syslog", MessageTemplate{}), false))
}

func TestSyslogSink_MutualTLS(t *testing.T) {
	dir := t.TempDir()
	// Two unrelated authorities on purpose: the collector's certificate has
	// nothing to do with the one this app would serve its own listener with.
	collectorCA := newTestCA(t, dir, "collector-ca")
	clientCA := newTestCA(t, dir, "client-ca")

	srvCert, srvKey := collectorCA.issue(t, "collector", true)
	cliCert, cliKey := clientCA.issue(t, "syslogstudio-client", false)

	c := startCollector(t, srvCert, srvKey, certPool(t, clientCA.file))

	err := sendOne(t, SyslogSinkConfig{
		Address: c.addr, Protocol: "tls", Facility: 16, PreserveOrigin: true,
		CAFile:         collectorCA.file,
		ClientCertFile: cliCert,
		ClientKeyFile:  cliKey,
	}, "mutual tls works")
	if err != nil {
		t.Fatalf("send over mutual TLS: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		lines, peers, _ := c.snapshot()
		if len(lines) > 0 && len(peers) > 0 {
			if peers[0] != "syslogstudio-client" {
				t.Errorf("collector saw peer %q, want the client certificate's CN", peers[0])
			}
			if !strings.Contains(lines[0], "mutual tls works") {
				t.Errorf("collector got %q", lines[0])
			}
			if !strings.Contains(lines[0], "router-7") {
				t.Errorf("origin hostname lost: %q", lines[0])
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("collector received nothing")
}

func TestSyslogSink_MutualTLS_RejectsClientFromAnotherCA(t *testing.T) {
	dir := t.TempDir()
	collectorCA := newTestCA(t, dir, "collector-ca")
	clientCA := newTestCA(t, dir, "client-ca")
	rogueCA := newTestCA(t, dir, "rogue-ca")

	srvCert, srvKey := collectorCA.issue(t, "collector", true)
	rogueCert, rogueKey := rogueCA.issue(t, "rogue", false)

	// The collector trusts only clientCA.
	c := startCollector(t, srvCert, srvKey, certPool(t, clientCA.file))

	cfg := SyslogSinkConfig{
		Address: c.addr, Protocol: "tls", Facility: 16,
		CAFile:         collectorCA.file,
		ClientCertFile: rogueCert,
		ClientKeyFile:  rogueKey,
	}

	// Under TLS 1.3 the client finishes its handshake before the server has
	// validated the client certificate, so this first Send may return nil even
	// though the collector is already tearing the connection down. What must
	// hold is that the data never lands, and that the failure does surface
	// rather than being swallowed forever.
	sink, err := newSyslogSink(SinkConfig{Kind: SinkSyslog, Syslog: cfg}, "")
	if err != nil {
		t.Fatalf("build sink: %v", err)
	}
	defer sink.Close()
	rendered := Render(msgAt(models.SevWarning, "router-7", "sshd", "should not arrive"),
		DefaultedTemplate("syslog", MessageTemplate{}), false)

	firstErr := sink.Send(rendered)

	// The collector must have refused the handshake.
	deadline := time.Now().Add(3 * time.Second)
	var errs []string
	for time.Now().Before(deadline) {
		if _, _, errs = c.snapshot(); len(errs) > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(errs) == 0 {
		t.Fatal("collector did not reject the handshake")
	}

	if lines, peers, _ := c.snapshot(); len(lines) > 0 {
		t.Fatalf("collector recorded %q from a rejected client", lines[0])
	} else if len(peers) > 0 {
		t.Fatalf("collector completed a handshake with %q", peers[0])
	}

	// The failure must also become visible to the operator rather than the sink
	// reporting success forever into a socket nobody reads.
	//
	// This is an eventual property, not an immediate one: writes land in the
	// kernel buffer, so how many succeed before the peer's reset is noticed is
	// a matter of the platform's TCP stack — two is enough on Linux and
	// Windows, not always on macOS. So poll for it instead of assuming a count.
	if firstErr == nil {
		visible := false
		for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
			if sink.Send(rendered) != nil {
				visible = true
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		if !visible {
			t.Fatal("a rejected client kept reporting success, so the loss would go unnoticed")
		}
	}

	// Whatever happened client-side, the collector must still have stored none
	// of it.
	if lines, _, _ := c.snapshot(); len(lines) > 0 {
		t.Fatalf("collector recorded %q from a rejected client", lines[0])
	}
}

func TestSyslogSink_TLS_RejectsUntrustedCollector(t *testing.T) {
	dir := t.TempDir()
	collectorCA := newTestCA(t, dir, "collector-ca")
	srvCert, srvKey := collectorCA.issue(t, "collector", true)
	c := startCollector(t, srvCert, srvKey, nil) // no client auth; plain TLS

	// No CAFile: the collector's private authority is not in the system pool,
	// so this must fail rather than quietly trust it.
	err := sendOne(t, SyslogSinkConfig{
		Address: c.addr, Protocol: "tls", Facility: 16,
	}, "should not arrive")
	if err == nil {
		t.Fatal("a collector with an untrusted certificate was accepted")
	}

	// With the CA supplied, the very same collector is fine.
	if err := sendOne(t, SyslogSinkConfig{
		Address: c.addr, Protocol: "tls", Facility: 16,
		CAFile: collectorCA.file,
	}, "trusted now"); err != nil {
		t.Fatalf("send with the CA supplied: %v", err)
	}
}

func TestSyslogSink_TLS_ClientCertWithoutKeyIsRefused(t *testing.T) {
	dir := t.TempDir()
	ca := newTestCA(t, dir, "ca")
	cert, _ := ca.issue(t, "client", false)

	err := sendOne(t, SyslogSinkConfig{
		Address: "127.0.0.1:1", Protocol: "tls", Facility: 16,
		ClientCertFile: cert, // key deliberately missing
	}, "nope")
	if err == nil || !strings.Contains(err.Error(), "both a client certificate and a key") {
		t.Fatalf("expected a refusal naming the missing key, got %v", err)
	}
}

// --- an SMTP relay offering STARTTLS ---------------------------------------

type relay struct {
	addr string

	mu       sync.Mutex
	messages []string
	secured  []bool
	tlsState []string
}

func (r *relay) snapshot() ([]string, []bool, []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.messages...), append([]bool(nil), r.secured...), append([]string(nil), r.tlsState...)
}

// startRelay serves SMTP, advertising STARTTLS unless offerSTARTTLS is false.
func startRelay(t *testing.T, serverCert, serverKey string, offerSTARTTLS bool) *relay {
	t.Helper()
	pair, err := tls.LoadX509KeyPair(serverCert, serverKey)
	if err != nil {
		t.Fatalf("load relay pair: %v", err)
	}
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	r := &relay{addr: ln.Addr().String()}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go r.serve(conn, tlsCfg, offerSTARTTLS)
		}
	}()
	return r
}

func (r *relay) serve(conn net.Conn, tlsCfg *tls.Config, offerSTARTTLS bool) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))

	br := bufio.NewReader(conn)
	out := conn
	write := func(s string) { fmt.Fprintf(out, "%s\r\n", s) }
	secured := false

	write("220 relay.test ESMTP")
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		up := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(up, "EHLO"), strings.HasPrefix(up, "HELO"):
			write("250-relay.test")
			if offerSTARTTLS && !secured {
				write("250-STARTTLS")
			}
			write("250 SIZE 35882577")
		case up == "STARTTLS":
			write("220 Ready to start TLS")
			tc := tls.Server(out, tlsCfg)
			if err := tc.Handshake(); err != nil {
				return
			}
			st := tc.ConnectionState()
			r.mu.Lock()
			r.tlsState = append(r.tlsState, tls.VersionName(st.Version))
			r.mu.Unlock()
			secured = true
			out = tc
			br = bufio.NewReader(tc)
			write = func(s string) { fmt.Fprintf(tc, "%s\r\n", s) }
		case strings.HasPrefix(up, "MAIL FROM"), strings.HasPrefix(up, "RCPT TO"):
			write("250 OK")
		case up == "DATA":
			write("354 Send it")
			var b strings.Builder
			for {
				dl, err := br.ReadString('\n')
				if err != nil {
					return
				}
				if dl == ".\r\n" {
					break
				}
				b.WriteString(dl)
			}
			r.mu.Lock()
			r.messages = append(r.messages, b.String())
			r.secured = append(r.secured, secured)
			r.mu.Unlock()
			write("250 OK queued")
		case up == "QUIT":
			write("221 Bye")
			return
		default:
			write("250 OK")
		}
	}
}

func sendMail(t *testing.T, cfg EmailSinkConfig) error {
	t.Helper()
	sink, err := newEmailSink(SinkConfig{Kind: SinkEmail, Email: cfg}, "")
	if err != nil {
		return err
	}
	defer sink.Close()
	msg := msgAt(models.SevError, "db-1", "postgres", "connection pool exhausted")
	return sink.Send(Render(msg, DefaultedTemplate("email", MessageTemplate{}), false))
}

func hostPort(t *testing.T, addr string) (string, int) {
	t.Helper()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split %q: %v", addr, err)
	}
	var p int
	if _, err := fmt.Sscanf(port, "%d", &p); err != nil {
		t.Fatalf("port %q: %v", port, err)
	}
	return host, p
}

func TestEmailSink_STARTTLS(t *testing.T) {
	dir := t.TempDir()
	relayCA := newTestCA(t, dir, "relay-ca")
	srvCert, srvKey := relayCA.issue(t, "relay", true)
	r := startRelay(t, srvCert, srvKey, true)
	host, port := hostPort(t, r.addr)

	if err := sendMail(t, EmailSinkConfig{
		Host: host, Port: port, From: "syslogstudio@test.local",
		To: []string{"ops@test.local"}, Encryption: "starttls",
		TLS: TLSFiles{CAFile: relayCA.file},
	}); err != nil {
		t.Fatalf("send over STARTTLS: %v", err)
	}

	msgs, secured, states := r.snapshot()
	if len(msgs) != 1 {
		t.Fatalf("relay got %d messages, want 1", len(msgs))
	}
	if !secured[0] {
		t.Error("the message was accepted before STARTTLS completed")
	}
	if len(states) == 0 {
		t.Fatal("no TLS handshake was recorded")
	}
	if !strings.Contains(msgs[0], "connection pool exhausted") {
		t.Errorf("relay got %q", msgs[0])
	}
	if !strings.Contains(msgs[0], "Subject:") {
		t.Errorf("message has no Subject header: %q", msgs[0])
	}
}

func TestEmailSink_STARTTLS_RejectsUntrustedRelay(t *testing.T) {
	dir := t.TempDir()
	relayCA := newTestCA(t, dir, "relay-ca")
	srvCert, srvKey := relayCA.issue(t, "relay", true)
	r := startRelay(t, srvCert, srvKey, true)
	host, port := hostPort(t, r.addr)

	// No CA supplied: a private authority is not in the system pool.
	err := sendMail(t, EmailSinkConfig{
		Host: host, Port: port, From: "a@test.local",
		To: []string{"ops@test.local"}, Encryption: "starttls",
	})
	if err == nil {
		t.Fatal("a relay with an untrusted certificate was accepted")
	}
	if msgs, _, _ := r.snapshot(); len(msgs) > 0 {
		t.Fatalf("relay accepted a message over an unverified connection: %q", msgs[0])
	}
}

func TestEmailSink_STARTTLS_RefusedWhenNotOffered(t *testing.T) {
	dir := t.TempDir()
	relayCA := newTestCA(t, dir, "relay-ca")
	srvCert, srvKey := relayCA.issue(t, "relay", true)
	r := startRelay(t, srvCert, srvKey, false) // does not advertise STARTTLS
	host, port := hostPort(t, r.addr)

	err := sendMail(t, EmailSinkConfig{
		Host: host, Port: port, From: "a@test.local",
		To: []string{"ops@test.local"}, Encryption: "starttls",
		TLS: TLSFiles{CAFile: relayCA.file},
	})
	if err == nil || !strings.Contains(err.Error(), "does not offer STARTTLS") {
		t.Fatalf("expected a downgrade refusal, got %v", err)
	}
	// The whole point: nothing was sent in the clear instead.
	if msgs, _, _ := r.snapshot(); len(msgs) > 0 {
		t.Fatalf("message sent unprotected after the downgrade: %q", msgs[0])
	}
}

func TestEmailSink_MutualTLS(t *testing.T) {
	dir := t.TempDir()
	relayCA := newTestCA(t, dir, "relay-ca")
	clientCA := newTestCA(t, dir, "client-ca")
	srvCert, srvKey := relayCA.issue(t, "relay", true)
	cliCert, cliKey := clientCA.issue(t, "smtp-client", false)

	pair, err := tls.LoadX509KeyPair(srvCert, srvKey)
	if err != nil {
		t.Fatalf("load relay pair: %v", err)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{pair},
		MinVersion:   tls.VersionTLS12,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    certPool(t, clientCA.file),
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	r := &relay{addr: ln.Addr().String()}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go r.serve(conn, tlsCfg, true)
		}
	}()

	host, port := hostPort(t, r.addr)
	if err := sendMail(t, EmailSinkConfig{
		Host: host, Port: port, From: "syslogstudio@test.local",
		To: []string{"ops@test.local"}, Encryption: "starttls",
		TLS: TLSFiles{CAFile: relayCA.file, ClientCertFile: cliCert, ClientKeyFile: cliKey},
	}); err != nil {
		t.Fatalf("send over mutual TLS: %v", err)
	}
	if msgs, secured, _ := r.snapshot(); len(msgs) != 1 || !secured[0] {
		t.Fatalf("relay got %d messages (secured=%v)", len(msgs), secured)
	}
}
