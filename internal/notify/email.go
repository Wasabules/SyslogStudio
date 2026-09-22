package notify

import (
	"crypto/tls"
	"fmt"
	"mime"
	"net"
	"net/smtp"
	"strings"
	"time"
)

// EmailSinkConfig sends messages by SMTP.
type EmailSinkConfig struct {
	Host     string   `json:"host"`
	Port     int      `json:"port"`
	Username string   `json:"username"`
	From     string   `json:"from"`
	To       []string `json:"to"`
	// Encryption: "starttls" (587, the usual), "tls" (465, implicit) or "none".
	Encryption string `json:"encryption"`
	// Format is "text" (default) or "html". One part, not
	// multipart/alternative: a text alternative would have to be DERIVED from
	// the operator's markup, and every way of doing that guesses — strip the
	// tags and a table becomes a run-on sentence. The body is sent as what it
	// declares itself to be.
	Format  string `json:"format,omitempty"`
	Timeout int    `json:"timeout"` // seconds; 0 means 15

	// The password is NOT here. It travels in SinkConfig.Secret (write-only)
	// and lives in the secret store, because anything serialisable on this
	// struct lands in config.json in the clear.
}

const defaultEmailTimeout = 15 * time.Second

type emailSink struct {
	cfg      EmailSinkConfig
	password string
	timeout  time.Duration
}

func newEmailSink(cfg SinkConfig, secret string) (Sink, error) {
	c := cfg.Email
	if err := validateEmailSink(c); err != nil {
		return nil, err
	}
	timeout := time.Duration(c.Timeout) * time.Second
	if timeout <= 0 {
		timeout = defaultEmailTimeout
	}
	return &emailSink{cfg: c, password: secret, timeout: timeout}, nil
}

func (e *emailSink) Describe() string {
	return fmt.Sprintf("email %s:%d -> %s", e.cfg.Host, e.cfg.Port, strings.Join(e.cfg.To, ", "))
}

func (e *emailSink) addr() string {
	return net.JoinHostPort(e.cfg.Host, fmt.Sprint(e.cfg.Port))
}

func (e *emailSink) Send(r Rendered) error {
	return scrubSecret(e.send(r), e.password)
}

func (e *emailSink) send(r Rendered) error {
	conn, err := e.dial()
	if err != nil {
		return err
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, e.cfg.Host)
	if err != nil {
		return err
	}
	defer client.Close()

	if e.cfg.Encryption == "starttls" {
		ok, _ := client.Extension("STARTTLS")
		if !ok {
			// Refuse rather than continue in the clear. The operator asked for
			// STARTTLS; silently sending the password unprotected because the
			// server did not offer it is exactly the downgrade the setting
			// exists to prevent.
			return errf("server does not offer STARTTLS")
		}
		if err := client.StartTLS(&tls.Config{ServerName: e.cfg.Host, MinVersion: tls.VersionTLS12}); err != nil {
			return err
		}
	}

	if e.cfg.Username != "" && e.password != "" {
		if err := e.authenticate(client); err != nil {
			return err
		}
	}

	if err := client.Mail(e.cfg.From); err != nil {
		return err
	}
	for _, to := range e.cfg.To {
		if err := client.Rcpt(strings.TrimSpace(to)); err != nil {
			return err
		}
	}

	w, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(e.message(r)); err != nil {
		w.Close()
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return client.Quit()
}

func (e *emailSink) dial() (net.Conn, error) {
	d := &net.Dialer{Timeout: e.timeout}
	if e.cfg.Encryption == "tls" {
		return tls.DialWithDialer(d, "tcp", e.addr(), &tls.Config{
			ServerName: e.cfg.Host,
			MinVersion: tls.VersionTLS12,
		})
	}
	return d.Dial("tcp", e.addr())
}

// authenticate picks an auth mechanism.
//
// PLAIN is refused on an unencrypted connection by net/smtp itself, which is
// the right call — so on "none" the credential simply is not sent, and the
// server's rejection tells the operator why.
func (e *emailSink) authenticate(client *smtp.Client) error {
	auth := smtp.PlainAuth("", e.cfg.Username, e.password, e.cfg.Host)
	if err := client.Auth(auth); err != nil {
		// Some servers only offer LOGIN. net/smtp has no LOGIN implementation,
		// so say so plainly rather than leaving a bare "unencrypted connection"
		// or "unsupported mechanism" for the operator to decode.
		return errf("SMTP authentication failed (the server may require a mechanism this client does not implement): %w", err)
	}
	return nil
}

// message builds the RFC 5322 message.
func (e *emailSink) message(r Rendered) []byte {
	contentType := "text/plain; charset=UTF-8"
	if e.cfg.Format == "html" {
		contentType = "text/html; charset=UTF-8"
	}

	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", sanitizeHeaderValue(e.cfg.From))
	fmt.Fprintf(&b, "To: %s\r\n", sanitizeHeaderValue(strings.Join(e.cfg.To, ", ")))
	// Encoded-word, so a subject carrying a non-ASCII hostname or an accent
	// does not arrive as mojibake — and so that a subject cannot smuggle a
	// header break, since the encoded form has no CRLF.
	fmt.Fprintf(&b, "Subject: %s\r\n", mime.QEncoding.Encode("UTF-8", sanitizeHeaderValue(r.Subject)))
	fmt.Fprintf(&b, "Date: %s\r\n", time.Now().Format(time.RFC1123Z))
	b.WriteString("MIME-Version: 1.0\r\n")
	fmt.Fprintf(&b, "Content-Type: %s\r\n", contentType)
	b.WriteString("\r\n")
	b.WriteString(dotStuff(normalizeCRLF(r.Body)))
	b.WriteString("\r\n")
	return []byte(b.String())
}

// normalizeCRLF converts line endings to CRLF, which is what SMTP requires.
func normalizeCRLF(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	return strings.ReplaceAll(s, "\n", "\r\n")
}

// dotStuff escapes a line consisting of a single dot.
//
// In SMTP, "\r\n.\r\n" ends the DATA command. A message body containing a line
// with just a dot would therefore be truncated there, and everything after it
// interpreted as SMTP commands — which is how a log line becomes an injected
// RCPT TO. RFC 5321 §4.5.2 requires doubling a leading dot.
func dotStuff(s string) string {
	if strings.HasPrefix(s, ".") {
		s = "." + s
	}
	return strings.ReplaceAll(s, "\r\n.", "\r\n..")
}

func (e *emailSink) Close() error { return nil }
