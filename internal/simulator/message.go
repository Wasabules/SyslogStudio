package simulator

import (
	"fmt"
	"math/rand/v2"
	"strconv"
	"strings"
	"time"

	"SyslogStudio/internal/models"
)

const hexDigits = "0123456789abcdef"

func itoa(n int) string { return strconv.Itoa(n) }

func randHex(n int) string {
	var b strings.Builder
	b.Grow(n)
	for i := 0; i < n; i++ {
		b.WriteByte(hexDigits[rand.IntN(len(hexDigits))])
	}
	return b.String()
}

// structuredDataTemplates are the RFC 5424 SD-ELEMENTs the generator attaches
// to some messages, so the parser's structured-data path is exercised and not
// just the common case of "-".
var structuredDataTemplates = []string{
	`[origin ip="{ip}" software="SyslogStudio-Simulator" swVersion="1.0"]`,
	`[meta sequenceId="{seq}" sysUpTime="{uptime}"]`,
	`[event id="{event_id}" source="{source}" outcome="{outcome}"]`,
	`[origin ip="{ip}"][meta sequenceId="{seq}"]`,
}

// generated is one message ready to send, plus the fields that produced it so
// the UI can show what was sent without re-parsing the wire format.
type generated struct {
	Wire     string
	Severity models.Severity
	Facility models.Facility
	Hostname string
	AppName  string
	Message  string
}

// build assembles one message according to the config. A CustomMessage, when
// set, replaces the generated text but still travels through the same framing,
// which is what makes it useful for reproducing a specific parser input.
func build(cfg models.SimulatorConfig) generated {
	sev := weightedSeverity(cfg.Profile)
	fac := models.FacLocal7
	if cfg.Profile == models.SimProfileCritical || sev <= models.SevCritical {
		// Kernel and daemon facilities are where severe messages really come
		// from; keeping that association makes facility filters meaningful.
		fac = pick([]models.Facility{models.FacKern, models.FacDaemon, models.FacAuth})
	} else {
		fac = pick([]models.Facility{
			models.FacDaemon, models.FacUser, models.FacAuth, models.FacCron,
			models.FacLocal0, models.FacLocal7,
		})
	}

	host := cfg.Hostname
	if host == "" {
		host = pick(hostnames)
	}
	app := cfg.AppName
	if app == "" {
		app = pick(appNames)
	}

	text := cfg.CustomMessage
	if text == "" {
		candidates := messagesBySeverity[sev]
		if len(candidates) == 0 {
			candidates = messagesBySeverity[models.SevInformational]
		}
		text = fillTemplate(pick(candidates))
	}

	g := generated{Severity: sev, Facility: fac, Hostname: host, AppName: app, Message: text}
	g.Wire = frame(cfg.Format, g)
	return g
}

// buildFixed frames a caller-supplied message unchanged, for alert-test mode.
func buildFixed(format string, sev models.Severity, fac models.Facility, host, app, text string) generated {
	g := generated{Severity: sev, Facility: fac, Hostname: host, AppName: app, Message: text}
	g.Wire = frame(format, g)
	return g
}

func frame(format string, g generated) string {
	if format == "rfc3164" {
		return formatRFC3164(g)
	}
	return formatRFC5424(g)
}

// formatRFC5424 builds "<PRI>1 TIMESTAMP HOST APP PROCID MSGID SD MSG".
func formatRFC5424(g generated) string {
	pri := int(g.Facility)*8 + int(g.Severity)
	// RFC 5424 timestamps carry an explicit offset; local time with its real
	// offset is what a device actually sends, and it exercises the collector's
	// offset handling rather than always feeding it Z.
	ts := time.Now().Format("2006-01-02T15:04:05.000Z07:00")
	procID := itoa(rand.IntN(64536) + 1000)
	msgID := "ID" + itoa(rand.IntN(9000)+1000)

	sd := "-"
	if rand.IntN(100) < 30 {
		sd = fillTemplate(pick(structuredDataTemplates))
	}
	return fmt.Sprintf("<%d>1 %s %s %s %s %s %s %s",
		pri, ts, g.Hostname, g.AppName, procID, msgID, sd, g.Message)
}

// formatRFC3164 builds "<PRI>Mmm dd hh:mm:ss HOST TAG[PID]: MSG".
//
// The timestamp deliberately carries no zone, because the format has none —
// that is the whole point of exercising it, and it is what issue #24 was about.
func formatRFC3164(g generated) string {
	pri := int(g.Facility)*8 + int(g.Severity)
	// %e pads a single-digit day with a space, which is what the BSD format
	// wants ("Jan  1") and what Go's "Jan _2" reference layout produces.
	ts := time.Now().Format("Jan _2 15:04:05")
	pid := rand.IntN(64536) + 1000
	return fmt.Sprintf("<%d>%s %s %s[%d]: %s", pri, ts, g.Hostname, g.AppName, pid, g.Message)
}
