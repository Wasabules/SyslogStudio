package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"html"
	"os"
	"strings"
	"time"

	"SyslogStudio/internal/models"
)

// The formats an export can be written in, beyond the two it started with.
//
// Each one exists for something someone does with the file afterwards. CSV
// goes to a spreadsheet and text goes to a reader; these go to a machine, to
// another collector, and to somebody who does not have this application.
//
// What they share is that they carry the message AS RECEIVED. A relay may
// rewrite a message's origin on the way out — that is what forwarding is for —
// but an export that rewrote what was captured would be an export of something
// that never happened.

const (
	formatCSV      = "csv"
	formatText     = "txt"
	formatNDJSON   = "ndjson"
	formatRFC5424  = "rfc5424"
	formatRFC3164  = "rfc3164"
	formatHTML     = "html"
	maxHTMLPreview = 50000
)

// exportFile is the name and the dialog filter a format asks for.
func exportFile(format, base string) (string, []exportFilter) {
	switch format {
	case formatCSV:
		return base + ".csv", []exportFilter{{"CSV Files (*.csv)", "*.csv"}}
	case formatNDJSON:
		return base + ".ndjson", []exportFilter{{"JSON Lines (*.ndjson, *.jsonl)", "*.ndjson;*.jsonl"}}
	case formatRFC5424, formatRFC3164:
		return base + ".log", []exportFilter{{"Syslog (*.log)", "*.log"}}
	case formatHTML:
		return base + ".html", []exportFilter{{"HTML (*.html)", "*.html"}}
	default:
		return base + ".txt", []exportFilter{{"Text Files (*.txt)", "*.txt"}}
	}
}

type exportFilter struct {
	Display string
	Pattern string
}

// writeExport puts the messages on disk in the format asked for.
func writeExport(path, format string, messages []models.SyslogMessage, loc *time.Location) error {
	switch format {
	case formatCSV:
		return writeCSV(path, messages, loc)
	case formatNDJSON:
		return writeNDJSON(path, messages, loc)
	case formatRFC5424:
		return writeSyslog(path, messages, loc, true)
	case formatRFC3164:
		return writeSyslog(path, messages, loc, false)
	case formatHTML:
		return writeHTML(path, messages, loc)
	default:
		return writeText(path, messages, loc)
	}
}

// exportRecord is one message as a machine reads it.
//
// Named fields in a fixed order rather than the model itself: the model is
// free to change for the application's own reasons, and a file someone has
// written a script against is not.
type exportRecord struct {
	Timestamp      string `json:"timestamp"`
	ReceivedAt     string `json:"receivedAt"`
	Severity       int    `json:"severity"`
	SeverityLabel  string `json:"severityLabel"`
	Facility       int    `json:"facility"`
	FacilityLabel  string `json:"facilityLabel"`
	Version        int    `json:"version,omitempty"`
	Hostname       string `json:"hostname"`
	AppName        string `json:"appName"`
	ProcID         string `json:"procID,omitempty"`
	MsgID          string `json:"msgID,omitempty"`
	StructuredData string `json:"structuredData,omitempty"`
	Message        string `json:"message"`
	SourceIP       string `json:"sourceIP"`
	Protocol       string `json:"protocol"`
}

// writeNDJSON writes one JSON object per line.
//
// Not a JSON array: a file of lines can be read by `jq`, streamed into a bulk
// index, or tailed while it is still being written, and none of those work on
// a document that has to be closed before it parses.
func writeNDJSON(path string, messages []models.SyslogMessage, loc *time.Location) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	defer w.Flush()

	enc := json.NewEncoder(w)
	for _, msg := range messages {
		record := exportRecord{
			Timestamp:      msg.Timestamp.In(loc).Format(time.RFC3339Nano),
			ReceivedAt:     msg.ReceivedAt.In(loc).Format(time.RFC3339Nano),
			Severity:       int(msg.Severity),
			SeverityLabel:  msg.SeverityLabel,
			Facility:       int(msg.Facility),
			FacilityLabel:  msg.FacilityLabel,
			Version:        msg.Version,
			Hostname:       msg.Hostname,
			AppName:        msg.AppName,
			ProcID:         msg.ProcID,
			MsgID:          msg.MsgID,
			StructuredData: msg.StructuredData,
			Message:        msg.Message,
			SourceIP:       msg.SourceIP,
			Protocol:       msg.Protocol,
		}
		if err := enc.Encode(record); err != nil {
			return err
		}
	}
	return w.Flush()
}

// writeSyslog writes the messages back as protocol lines.
//
// The point is that the file can be replayed: into another collector, into
// this one, into anything that reads syslog. So the priority, the host and the
// application are the ones the message arrived with, and the framing is
// whichever RFC the receiving end understands.
func writeSyslog(path string, messages []models.SyslogMessage, loc *time.Location, rfc5424 bool) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	defer w.Flush()

	for _, msg := range messages {
		pri := int(msg.Facility)*8 + int(msg.Severity)
		ts := msg.Timestamp
		if ts.IsZero() {
			ts = msg.ReceivedAt
		}
		ts = ts.In(loc)

		var line string
		if rfc5424 {
			sd := strings.TrimSpace(msg.StructuredData)
			if sd == "" {
				sd = "-"
			}
			line = fmt.Sprintf("<%d>1 %s %s %s %s %s %s %s",
				pri,
				ts.Format("2006-01-02T15:04:05.000Z07:00"),
				orDash(msg.Hostname),
				orDash(msg.AppName),
				orDash(msg.ProcID),
				orDash(msg.MsgID),
				sd,
				oneLine(msg.Message),
			)
		} else {
			// RFC 3164 has no field for a message id, and its timestamp has no
			// year: this is the older wire, and writing it means accepting what
			// it cannot carry.
			tag := msg.AppName
			if tag != "" && msg.ProcID != "" {
				tag = fmt.Sprintf("%s[%s]", tag, msg.ProcID)
			}
			if tag != "" {
				tag += ": "
			}
			line = fmt.Sprintf("<%d>%s %s %s%s",
				pri,
				ts.Format("Jan _2 15:04:05"),
				orDash(msg.Hostname),
				tag,
				oneLine(msg.Message),
			)
		}
		if _, err := w.WriteString(line + "\n"); err != nil {
			return err
		}
	}
	return w.Flush()
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return sanitizeExportField(s)
}

// A syslog line ends at a newline, so a message containing one would become
// two lines — the second of which would parse as something else entirely.
func oneLine(s string) string {
	return strings.NewReplacer("\r\n", " ", "\n", " ", "\r", " ").Replace(s)
}

// A space inside a header field would shift every field after it.
func sanitizeExportField(s string) string {
	return strings.NewReplacer(" ", "_", "\r", "", "\n", "").Replace(s)
}

// The colours the application shows, so a report looks like the screen it came
// from rather than a different reading of the same data.
var htmlSeverityColours = [8]string{
	"#ff0040", "#ff4444", "#ff6644", "#ff8800",
	"#ffcc00", "#44aaff", "#66dd66", "#888888",
}

// writeHTML writes a report for someone who does not have this application.
//
// One file, no assets, no network: it opens from an e-mail attachment on a
// machine that has never heard of SyslogStudio, which is the whole point of
// attaching it.
func writeHTML(path string, messages []models.SyslogMessage, loc *time.Location) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	defer w.Flush()

	counts := map[string]int{}
	for _, msg := range messages {
		counts[msg.SeverityLabel]++
	}

	var summary strings.Builder
	for level := models.SevEmergency; level <= models.SevDebug; level++ {
		label := models.SeverityToLabel(level)
		if counts[label] == 0 {
			continue
		}
		summary.WriteString(fmt.Sprintf(
			`<span class="chip" style="border-color:%s">%s <b>%d</b></span>`,
			htmlSeverityColours[level], html.EscapeString(label), counts[label]))
	}

	fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Syslog export — %s</title>
<style>
:root { color-scheme: light dark; }
body { margin: 0; padding: 24px; background: #fff; color: #1a1d23;
       font: 13px/1.5 system-ui, -apple-system, Segoe UI, sans-serif; }
h1 { font-size: 16px; margin: 0 0 4px; }
.meta { color: #6b7280; font-size: 11px; margin-bottom: 14px; }
.chips { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 16px; }
.chip { font-size: 11px; padding: 2px 8px; border-radius: 10px; border: 1px solid #ccc; }
table { border-collapse: collapse; width: 100%%; }
th { text-align: left; font-size: 11px; text-transform: uppercase; letter-spacing: .04em;
     color: #6b7280; border-bottom: 1px solid #e5e7eb; padding: 6px 8px; }
td { padding: 4px 8px; border-bottom: 1px solid #f1f2f4; vertical-align: top; }
td.time, td.src { font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
                  font-size: 11px; color: #6b7280; white-space: nowrap; }
td.msg { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px;
         white-space: pre-wrap; word-break: break-word; }
.sev { display: inline-block; min-width: 64px; text-align: center; color: #fff;
       border-radius: 3px; padding: 1px 6px; font-size: 11px; font-weight: 600; }
.truncated { margin-top: 14px; color: #92400e; background: #fef3c7;
             border: 1px solid #fde68a; border-radius: 4px; padding: 8px 10px; font-size: 12px; }
@media (prefers-color-scheme: dark) {
  body { background: #14171d; color: #e5e7eb; }
  th { color: #9aa3af; border-bottom-color: #2a2f3a; }
  td { border-bottom-color: #21252e; }
  td.time, td.src { color: #9aa3af; }
  .truncated { color: #fde68a; background: #3a2f12; border-color: #5a4a1a; }
}
</style></head><body>
<h1>Syslog export</h1>
<div class="meta">%d messages · written %s</div>
<div class="chips">%s</div>
<table><thead><tr>
<th>Severity</th><th>Timestamp</th><th>Source</th><th>Host</th><th>App</th><th>Message</th>
</tr></thead><tbody>
`,
		html.EscapeString(time.Now().In(loc).Format("2006-01-02")),
		len(messages),
		html.EscapeString(time.Now().In(loc).Format(exportTimeLayout)),
		summary.String())

	shown := messages
	if len(shown) > maxHTMLPreview {
		shown = shown[:maxHTMLPreview]
	}
	for _, msg := range shown {
		colour := htmlSeverityColours[7]
		if int(msg.Severity) >= 0 && int(msg.Severity) < len(htmlSeverityColours) {
			colour = htmlSeverityColours[msg.Severity]
		}
		fmt.Fprintf(w,
			`<tr><td><span class="sev" style="background:%s">%s</span></td>`+
				`<td class="time">%s</td><td class="src">%s</td><td>%s</td><td>%s</td><td class="msg">%s</td></tr>`+"\n",
			colour,
			html.EscapeString(msg.SeverityLabel),
			html.EscapeString(msg.Timestamp.In(loc).Format(exportTimeLayout)),
			html.EscapeString(msg.SourceIP),
			html.EscapeString(msg.Hostname),
			html.EscapeString(msg.AppName),
			html.EscapeString(msg.Message))
	}

	fmt.Fprint(w, "</tbody></table>\n")
	if len(messages) > len(shown) {
		// Said in the file rather than only in a toast at export time: whoever
		// opens this may not be whoever wrote it.
		fmt.Fprintf(w,
			`<div class="truncated">Showing the first %d of %d messages. A browser stops being usable long before the rest would fit; export as CSV or NDJSON for the whole set.</div>`+"\n",
			len(shown), len(messages))
	}
	fmt.Fprint(w, "</body></html>\n")
	return w.Flush()
}
