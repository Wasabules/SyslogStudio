package notify

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Sink kinds.
const (
	SinkSyslog  = "syslog"
	SinkWebhook = "webhook"
	SinkEmail   = "email"
)

// Sink is one outbound destination.
type Sink interface {
	// Send delivers one already-rendered message. Rendering happens at enqueue
	// time so a sink never has to reach back into the message store, and so a
	// retry sends exactly what the first attempt did.
	Send(r Rendered) error
	// Describe names the destination for the delivery log.
	Describe() string
	// Close releases any held connection.
	Close() error
}

// SinkConfig is the stored, serialisable description of a sink.
//
// Secrets are NOT held here. They are stored separately, keyed by sink id, so
// the configuration can be exported, logged or sent to the frontend without
// carrying a password.
type SinkConfig struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Kind    string `json:"kind"`
	Enabled bool   `json:"enabled"`

	Syslog  SyslogSinkConfig  `json:"syslog,omitzero"`
	Webhook WebhookSinkConfig `json:"webhook,omitzero"`
	Email   EmailSinkConfig   `json:"email,omitzero"`

	// Template customises subject and body. It sits on SinkConfig rather than
	// on the e-mail config because the rendered body is also the syslog MSG and
	// the webhook payload: one concept, one slot.
	Template MessageTemplate `json:"template,omitzero"`

	// Redact masks identifying values in outbound messages. Anonymous mode is
	// display-only by design and cannot govern what a background dispatcher
	// sends, so this is its per-sink counterpart.
	Redact bool `json:"redact"`

	// Secret is WRITE-ONLY transport: the UI sends a new password or token
	// here, the app hands it to the secret store and clears the field before
	// persisting. It is never populated when reading a sink back, so a
	// credential cannot leak through an export, a log line or the JS bridge.
	Secret string `json:"secret,omitempty"`
	// HasSecret tells the UI a credential is on file, so the form can show
	// "configured" without ever receiving the value.
	HasSecret bool `json:"hasSecret"`
}

// Destination names WHERE a sink sends, and is the identity a stored
// credential is bound to.
//
// The credential is write-only from the UI, but that control has one hole: the
// methods that RESOLVE a credential by sink id while taking the destination
// from whatever the caller just sent. Name an existing sink's id, point the URL
// at your own server, and the bearer token or SMTP password is delivered to
// you. So a stored credential may be used only with the destination it was
// stored against; changing the destination clears it.
//
// What counts as the destination is per kind, and includes the parts that
// decide whether the credential travels protected:
//
//   - webhook: the URL exactly as configured. The scheme is part of it, so
//     https to http is a rebinding — that one downgrades the token to
//     cleartext.
//   - email: host, port and encryption. The password goes to the SMTP server,
//     so starttls to none on the same host puts it on the wire in the clear.
//   - syslog: protocol and address. Here the credential is a mutual-TLS client
//     key, which signs and is never transmitted, so it cannot be exfiltrated by
//     redirection. It is bound anyway, because a uniform rule is the one that
//     still holds when a fourth kind is added.
//
// ok is false for a kind that cannot be built. The caller must treat that as
// "cannot bind" rather than comparing two empty strings and finding them equal.
func Destination(cfg SinkConfig) (string, bool) {
	switch cfg.Kind {
	case SinkSyslog:
		return SinkSyslog + "|" + cfg.Syslog.Protocol + "|" + cfg.Syslog.Address, true
	case SinkWebhook:
		return SinkWebhook + "|" + cfg.Webhook.URL, true
	case SinkEmail:
		return fmt.Sprintf("%s|%s|%d|%s", SinkEmail, cfg.Email.Host, cfg.Email.Port, cfg.Email.Encryption), true
	default:
		return "", false
	}
}

// SameDestination reports whether two configurations address the same place,
// and so whether a stored credential may carry over from one to the other.
func SameDestination(a, b SinkConfig) bool {
	da, okA := Destination(a)
	db, okB := Destination(b)
	return okA && okB && da == db
}

// Build creates a live sink from its configuration and its secret.
func Build(cfg SinkConfig, secret string) (Sink, error) {
	switch cfg.Kind {
	case SinkSyslog:
		return newSyslogSink(cfg, secret)
	case SinkWebhook:
		return newWebhookSink(cfg, secret)
	case SinkEmail:
		return newEmailSink(cfg, secret)
	default:
		return nil, errf("unknown sink kind %q", cfg.Kind)
	}
}

// ValidateSink checks a sink before it is saved.
func ValidateSink(cfg SinkConfig) error {
	if strings.TrimSpace(cfg.Name) == "" {
		return errf("destination name is required")
	}
	switch cfg.Kind {
	case SinkSyslog:
		return validateSyslogSink(cfg.Syslog)
	case SinkWebhook:
		return validateWebhookSink(cfg.Webhook)
	case SinkEmail:
		return validateEmailSink(cfg.Email)
	default:
		return errf("unknown destination kind %q", cfg.Kind)
	}
}

func validateSyslogSink(c SyslogSinkConfig) error {
	if strings.TrimSpace(c.Address) == "" {
		return errf("syslog address is required")
	}
	host, port, err := net.SplitHostPort(c.Address)
	if err != nil {
		return errf("syslog address must be host:port")
	}
	if host == "" {
		return errf("syslog address has no host")
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return errf("syslog port %q is out of range (1-65535)", port)
	}
	switch c.Protocol {
	case "udp", "tcp", "tls":
	default:
		return errf("unknown syslog protocol %q", c.Protocol)
	}
	if c.Facility < 0 || c.Facility > 23 {
		return errf("syslog facility %d is out of range (0-23)", c.Facility)
	}
	if c.Protocol == "tls" {
		if err := validateTLSFiles(c.tlsFiles()); err != nil {
			return err
		}
	}
	return nil
}

func validateWebhookSink(c WebhookSinkConfig) error {
	if strings.TrimSpace(c.URL) == "" {
		return errf("webhook URL is required")
	}
	u, err := url.Parse(c.URL)
	if err != nil {
		return errf("webhook URL is not valid: %v", err)
	}
	// Only HTTP(S). Without this a sink could be pointed at file: or a custom
	// scheme, which is a local-file read dressed up as a delivery.
	if u.Scheme != "http" && u.Scheme != "https" {
		return errf("webhook URL must be http or https, got %q", u.Scheme)
	}
	if u.Host == "" {
		return errf("webhook URL has no host")
	}
	switch strings.ToUpper(strings.TrimSpace(c.Method)) {
	case "", "POST", "PUT", "PATCH":
	default:
		return errf("webhook method %q is not allowed", c.Method)
	}
	if c.PayloadMode != "" && c.PayloadMode != "envelope" && c.PayloadMode != "template" {
		return errf("unknown webhook payload mode %q", c.PayloadMode)
	}
	return nil
}

func validateEmailSink(c EmailSinkConfig) error {
	if strings.TrimSpace(c.Host) == "" {
		return errf("SMTP host is required")
	}
	if c.Port < 1 || c.Port > 65535 {
		return errf("SMTP port %d is out of range (1-65535)", c.Port)
	}
	if strings.TrimSpace(c.From) == "" {
		return errf("sender address is required")
	}
	if len(c.To) == 0 {
		return errf("at least one recipient is required")
	}
	for _, to := range c.To {
		if !strings.Contains(to, "@") {
			return errf("recipient %q is not an e-mail address", to)
		}
	}
	switch c.Encryption {
	case "starttls", "tls", "none":
	default:
		return errf("unknown encryption %q", c.Encryption)
	}
	if c.Format != "" && c.Format != "text" && c.Format != "html" {
		return errf("unknown e-mail format %q", c.Format)
	}
	if c.Encryption != "none" {
		if err := validateTLSFiles(c.TLS); err != nil {
			return err
		}
	}
	return nil
}

// scrubSecret removes a credential from an error before it reaches a log or the
// UI. Transport libraries put the value they were handed into their messages —
// an SMTP rejection quotes the auth line, a URL parse error quotes the URL — so
// the credential ends up in the delivery log unless it is taken out here.
func scrubSecret(err error, secret string) error {
	if err == nil || secret == "" {
		return err
	}
	msg := err.Error()
	for _, form := range secretForms(secret) {
		if form == "" {
			continue
		}
		msg = strings.ReplaceAll(msg, form, "[redacted]")
	}
	if msg == err.Error() {
		return err
	}
	return &scrubbedError{msg: msg, err: err}
}

// secretForms lists the shapes a credential takes on the wire, because the one
// that appears in an error is rarely the one that was typed: SMTP AUTH sends it
// base64-encoded, a URL carries it percent-encoded.
func secretForms(secret string) []string {
	return []string{
		secret,
		url.QueryEscape(secret),
		url.PathEscape(secret),
		b64(secret),
	}
}

type scrubbedError struct {
	msg string
	err error
}

func (e *scrubbedError) Error() string { return e.msg }
func (e *scrubbedError) Unwrap() error { return e.err }

func errf(format string, args ...any) error {
	return fmt.Errorf(format, args...)
}
