package notify

import (
	"encoding/base64"
	"regexp"
	"strings"
	"text/template"
	"time"

	"SyslogStudio/internal/models"
)

// MessageTemplate customises what a sink sends. Empty fields fall back to the
// defaults below, so a sink is usable before anyone opens the template editor.
type MessageTemplate struct {
	Subject string `json:"subject,omitempty"`
	Body    string `json:"body,omitempty"`
}

// Rendered is one message prepared for delivery. Rendering happens once, at
// enqueue time, so every retry sends byte-identical content and a sink never
// has to reach back into the message store.
type Rendered struct {
	Subject string
	Body    string
	// Msg is kept for the transports that build their own framing from the
	// fields rather than from the rendered text — the syslog sink needs the
	// severity and facility, not a sentence about them.
	Msg models.SyslogMessage
}

const (
	defaultSubject = "[{{.Severity}}] {{.Hostname}} {{.AppName}}"
	defaultBody    = "{{.Timestamp}} {{.Hostname}} {{.AppName}}[{{.ProcID}}]: {{.Message}}"
	// A syslog frame carries the timestamp, hostname, app name and PID in its
	// own header, so the shared default would put every one of them on the
	// wire twice.
	defaultSyslogBody = "{{.Message}}"
)

// DefaultedTemplate fills in the body a kind wants when the operator set none.
// An e-mail or webhook recipient sees only the body and needs the context; a
// relayed syslog message already has it in the header.
func DefaultedTemplate(kind string, tpl MessageTemplate) MessageTemplate {
	if kind == "syslog" && strings.TrimSpace(tpl.Body) == "" {
		tpl.Body = defaultSyslogBody
	}
	return tpl
}

// templateData is what a template sees. Deliberately a flat set of strings
// rather than the message struct: a template that can reach arbitrary fields
// is a template that breaks when the struct changes, and the flat names are
// what an operator can be told about in one line of help text.
type templateData struct {
	Timestamp  string
	ReceivedAt string
	Severity   string
	SeverityNo int
	Facility   string
	FacilityNo int
	Hostname   string
	AppName    string
	ProcID     string
	MsgID      string
	Message    string
	RawMessage string
	SourceIP   string
	Protocol   string
}

// templateCache avoids recompiling a sink's template for every message. Keyed
// by the template text itself, so editing a sink invalidates its entry without
// any explicit cache management.
var templateCache = newTTLCache()

// Render prepares a message for one sink.
//
// Redaction, when the sink asks for it, is applied to the FIELDS before the
// template runs, not to the rendered output. Doing it afterwards would mean
// scanning text the operator composed, where a stand-in could land inside a
// word the template added; doing it first keeps every substitution on a value
// that came off the wire.
func Render(msg models.SyslogMessage, tpl MessageTemplate, redact bool) Rendered {
	if redact {
		msg = redactMessage(msg)
	}

	data := templateData{
		Timestamp:  msg.Timestamp.Format(time.RFC3339),
		ReceivedAt: msg.ReceivedAt.Format(time.RFC3339),
		Severity:   msg.SeverityLabel,
		SeverityNo: int(msg.Severity),
		Facility:   msg.FacilityLabel,
		FacilityNo: int(msg.Facility),
		Hostname:   msg.Hostname,
		AppName:    msg.AppName,
		ProcID:     msg.ProcID,
		MsgID:      msg.MsgID,
		Message:    msg.Message,
		RawMessage: msg.RawMessage,
		SourceIP:   msg.SourceIP,
		Protocol:   msg.Protocol,
	}

	subject := tpl.Subject
	if strings.TrimSpace(subject) == "" {
		subject = defaultSubject
	}
	body := tpl.Body
	if strings.TrimSpace(body) == "" {
		body = defaultBody
	}

	return Rendered{
		Subject: execTemplate(subject, data),
		Body:    execTemplate(body, data),
		Msg:     msg,
	}
}

// execTemplate runs one template, falling back to the raw text when it does not
// compile. A broken template must not stop delivery: the operator still needs
// the alert, and the unexpanded text tells them what they typed wrong far
// better than silence does.
func execTemplate(text string, data templateData) string {
	t, err := templateCache.get(text)
	if err != nil {
		return text
	}
	var sb strings.Builder
	if err := t.Execute(&sb, data); err != nil {
		return text
	}
	return sb.String()
}

// ValidateTemplate reports whether a template compiles, so the UI can refuse a
// broken one at save time instead of at delivery time.
func ValidateTemplate(tpl MessageTemplate) error {
	for _, text := range []string{tpl.Subject, tpl.Body} {
		if strings.TrimSpace(text) == "" {
			continue
		}
		if _, err := template.New("t").Parse(text); err != nil {
			return errf("template error: %v", err)
		}
	}
	return nil
}

// --- Redaction -------------------------------------------------------------
//
// A deliberately smaller job than the UI's anonymous mode. That one is about
// making a screenshot shareable and can afford to be thorough because a human
// is looking at the result. This one runs unattended on the way out, where a
// false positive corrupts a log line that somebody will later try to correlate,
// so it sticks to values that are unambiguous.

var (
	reIPv4  = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	reEmail = regexp.MustCompile(`\b[\w.%+-]+@[\w.-]+\.[a-zA-Z]{2,}\b`)
	reMAC   = regexp.MustCompile(`\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b`)
)

// keepAddrs are the addresses that identify nobody. Rewriting them would tell
// the receiver the traffic came from somewhere it did not.
var keepAddrs = map[string]bool{"127.0.0.1": true, "0.0.0.0": true, "::1": true}

func redactValue(s string) string {
	if keepAddrs[s] {
		return s
	}
	return "[redacted]"
}

func redactText(s string) string {
	if s == "" {
		return s
	}
	s = reMAC.ReplaceAllString(s, "[redacted-mac]")
	s = reEmail.ReplaceAllString(s, "[redacted-email]")
	s = reIPv4.ReplaceAllStringFunc(s, redactValue)
	return s
}

func redactMessage(msg models.SyslogMessage) models.SyslogMessage {
	msg.Hostname = redactValue(msg.Hostname)
	msg.SourceIP = redactValue(msg.SourceIP)
	msg.Message = redactText(msg.Message)
	msg.RawMessage = redactText(msg.RawMessage)
	msg.StructuredData = redactText(msg.StructuredData)
	return msg
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
