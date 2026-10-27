package sources

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/text/encoding/charmap"

	"SyslogStudio/internal/models"
)

// Every template does what its name says, on a message from the kind of
// device it is for — and what the reading as received does not.
func TestTemplates_DoWhatTheySay(t *testing.T) {
	latin, _ := charmap.Windows1252.NewEncoder().Bytes([]byte("<13>Oct 27 09:14:02 printsrv spooler: Impression terminée"))
	cases := map[string][]struct {
		raw   []byte
		check func(m models.SyslogMessage) bool
	}{
		"no-hostname": {
			{[]byte("<14>Oct 27 09:14:02 motion detected on channel 2"), func(m models.SyslogMessage) bool {
				return m.Hostname == "10.0.0.2" && m.Message == "motion detected on channel 2"
			}},
			{[]byte("<187>123: *Oct 27 09:14:02.123: %LINK-3-UPDOWN: Interface Gi0/1, changed state to down"), func(m models.SyslogMessage) bool {
				return m.Hostname == "10.0.0.2" && m.AppName == "%LINK-3-UPDOWN"
			}},
			{[]byte("<14>Oct 27 09:14:02 dhcp: lease 10.0.0.50 assigned"), func(m models.SyslogMessage) bool {
				return m.Hostname == "10.0.0.2" && m.AppName == "dhcp"
			}},
		},
		"camera": {
			{[]byte("<14>Oct 27 09:14:05 recorder: WARNING low light"), func(m models.SyslogMessage) bool {
				return m.Hostname == "10.0.0.2" && m.AppName == "recorder" && m.Severity == models.SevWarning
			}},
			{[]byte("2026-10-27 09:14:02 ERROR motion detection failed on channel 2"), func(m models.SyslogMessage) bool {
				return m.Hostname == "10.0.0.2" && m.Severity == models.SevError
			}},
		},
		"level-in-text": {
			{[]byte("<14>Oct 27 09:14:05 cam-lobby recorder: disk ERROR on volume 2"), func(m models.SyslogMessage) bool {
				return m.Hostname == "cam-lobby" && m.Severity == models.SevError
			}},
		},
		"json": {
			{[]byte(`<14>Oct 27 09:14:02 docker-host web[311]: {"level":"error","msg":"payment API returned 502","host":"web-7"}`),
				func(m models.SyslogMessage) bool {
					return m.Hostname == "web-7" && m.AppName == "web" && m.Severity == models.SevError && m.Message == "payment API returned 502"
				}},
		},
		"windows-1252": {
			{latin, func(m models.SyslogMessage) bool { return m.Message == "Impression terminée" }},
		},
		"bad-clock": {
			{[]byte("<14>Jan  1 00:00:00 plc-7 controller: cycle done"), func(m models.SyslogMessage) bool {
				return m.Timestamp.Equal(m.ReceivedAt)
			}},
		},
		"own-format": {
			{[]byte("<14>2026-10-27 09:14:02 ERROR something broke"), func(m models.SyslogMessage) bool {
				return m.Severity == models.SevError && m.Message == "something broke" &&
					m.Timestamp.Equal(time.Date(2026, 10, 27, 9, 14, 2, 0, time.Local))
			}},
		},
	}
	seen := map[string]bool{}
	for _, tpl := range Templates() {
		if tpl.ID == "" || tpl.Name != "" || seen[tpl.ID] {
			t.Errorf("template %+v: an ID of its own and no name", tpl)
		}
		seen[tpl.ID] = true
		rule := tpl.Rule
		rule.Name, rule.Enabled = tpl.ID, true
		rule.Match = models.SourceMatch{Sources: []string{"10.0.0.2"}}
		r := reader(t, rule)
		if len(cases[tpl.ID]) == 0 {
			t.Errorf("template %s is tried on no message", tpl.ID)
		}
		for _, c := range cases[tpl.ID] {
			if m := r.Read(c.raw, "10.0.0.2", "UDP"); !c.check(m) {
				t.Errorf("%s on %q: host %q app %q %s %q at %v", tpl.ID, c.raw, m.Hostname, m.AppName, m.SeverityLabel, m.Message, m.Timestamp)
			}
			// A template the reading as received already equals is no use.
			if c.check(New().Read(c.raw, "10.0.0.2", "UDP")) {
				t.Errorf("%s on %q: read so without it", tpl.ID, c.raw)
			}
		}
	}
	for id := range cases {
		if !seen[id] {
			t.Errorf("a case for %s, which is no template", id)
		}
	}
}

// The window names each template, in every language it speaks.
func TestTemplates_NamedInEveryLanguage(t *testing.T) {
	dir := filepath.Join("..", "..", "frontend", "src", "lib", "i18n")
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil || len(files) < 8 {
		t.Fatalf("locales: %v, %v", files, err)
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var locale struct {
			Sources struct {
				Templates map[string]struct{ Name, Hint string } `json:"templates"`
			} `json:"sources"`
		}
		if err := json.Unmarshal(data, &locale); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		for _, tpl := range Templates() {
			if n := locale.Sources.Templates[tpl.ID]; strings.TrimSpace(n.Name) == "" || strings.TrimSpace(n.Hint) == "" {
				t.Errorf("%s: sources.templates.%s has no name or hint", filepath.Base(f), tpl.ID)
			}
		}
	}
}

// A file of rules goes from one installation to another whole, or not at all.
func TestFile(t *testing.T) {
	rules := []models.SourceRule{
		{ID: "source-1", Name: "camera", Enabled: true, Match: bySource("10.0.7.0/24"), NoHostname: true},
		{ID: "source-2", Name: "firewall", Enabled: false, Match: bySource("10.0.0.1"), Format: models.ImportFormat{Mode: models.ImportLogfmt}},
	}
	templates := []models.SourceTemplate{{ID: "mine-1", Name: "Lobby cameras", Rule: models.SourceRule{NoHostname: true}}}
	data, err := EncodeFile(rules, templates)
	if err != nil {
		t.Fatal(err)
	}
	f, err := DecodeFile(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Rules) != 2 || f.Rules[0].ID != "" || f.Rules[0].Name != "camera" || !f.Rules[0].NoHostname || f.Rules[1].Enabled {
		t.Errorf("rules read back: %+v", f.Rules)
	}
	if len(f.Templates) != 1 || f.Templates[0].ID != "" || f.Templates[0].Name != "Lobby cameras" {
		t.Errorf("templates read back: %+v", f.Templates)
	}

	broken, _ := EncodeFile([]models.SourceRule{rules[0], {Name: "half", Match: bySource("10.0")}}, nil)
	newer := strings.Replace(string(data), `"version": 1`, `"version": 2`, 1)
	unnamed, _ := EncodeFile(nil, []models.SourceTemplate{{Rule: models.SourceRule{NoHostname: true}}})
	for name, bad := range map[string][]byte{
		"not json":           []byte("{"),
		"another file":       []byte(`{"format":"something-else","version":1,"rules":[]}`),
		"a newer version":    []byte(newer),
		"nothing in it":      []byte(`{"format":"syslogstudio-source-rules","version":1,"rules":[]}`),
		"one rule broken":    broken,
		"a template unnamed": unnamed,
	} {
		if _, err := DecodeFile(bad); err == nil {
			t.Errorf("%s: accepted", name)
		} else if name == "one rule broken" && !strings.Contains(err.Error(), `"half"`) {
			t.Errorf("the broken rule is not named: %v", err)
		}
	}
}
