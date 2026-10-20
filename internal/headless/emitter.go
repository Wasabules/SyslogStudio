package headless

import (
	"log/slog"

	"SyslogStudio/internal/models"
	"SyslogStudio/internal/notify"
)

// logEmitter is the event.EventEmitter of a host with no window: what a
// window would have shown, said in the log instead — or not at all.
//
// Message batches and statistics are dropped: they are the live view, and the
// database already has the messages. Alerts and failed deliveries are what an
// operator would have wanted to see, so they are logged. Message text is not:
// the log names the rule and the host, and the message itself stays in the
// database where access to it is controlled.
type logEmitter struct {
	log *slog.Logger
}

func newLogEmitter(log *slog.Logger) *logEmitter {
	return &logEmitter{log: log}
}

func (l *logEmitter) Emit(name string, data ...interface{}) {
	if len(data) == 0 {
		return
	}
	switch name {
	case "syslog:alerts":
		if events, ok := data[0].([]models.AlertEvent); ok {
			for _, ev := range events {
				l.log.Info("alert", "rule", ev.RuleName, "host", ev.Hostname, "severity", ev.Severity)
			}
		}
	case "syslog:delivery":
		if entry, ok := data[0].(notify.DeliveryEntry); ok && !entry.OK {
			l.log.Warn("delivery failed", "destination", entry.SinkName, "target", entry.Target,
				"attempts", entry.Attempts, "error", entry.Error)
		}
	case "syslog:status":
		if st, ok := data[0].(models.ServerStatus); ok && st.Error != "" {
			l.log.Warn("receiver", "error", st.Error)
		}
	}
}
