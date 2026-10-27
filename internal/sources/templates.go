package sources

import "SyslogStudio/internal/models"

// Templates are the rules offered to start from, each for a kind of device
// and doing only what its name says: the reading as received already copes
// with much (RFC 3164 and 5424, rsyslog's forward, key=value such as
// FortiGate's, JSON after the priority, Cisco), and a template is for what it
// cannot know — that this device sends no hostname, keeps its level in the
// text, logs JSON behind a standard header, garbles accents, or has a clock
// nobody set. templates_test.go reads a message of each kind with it, and
// none is offered that would read it as the reading as received does.
func Templates() []models.SourceTemplate {
	auto := models.ImportFormat{Mode: models.ImportAuto}
	return []models.SourceTemplate{
		{ID: "no-hostname", Rule: models.SourceRule{Format: auto, NoHostname: true}},
		{ID: "camera", Rule: models.SourceRule{Format: auto, NoHostname: true, LevelFrom: models.LevelFromMessage}},
		{ID: "level-in-text", Rule: models.SourceRule{Format: auto, LevelFrom: models.LevelFromMessage}},
		{ID: "json", Rule: models.SourceRule{Format: models.ImportFormat{Mode: models.ImportJSON}}},
		{ID: "windows-1252", Rule: models.SourceRule{Format: auto, Encoding: models.EncodingWindows1252}},
		{ID: "bad-clock", Rule: models.SourceRule{Format: auto, ArrivalTime: true}},
		{ID: "own-format", Rule: models.SourceRule{Format: models.ImportFormat{
			Mode:    models.ImportCustom,
			Pattern: `^(?P<time>\S+ \S+) (?P<level>\w+) (?P<msg>.*)$`,
		}}},
	}
}
