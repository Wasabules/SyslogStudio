package sources

import (
	"os"
	"strings"
	"testing"
	"time"

	"SyslogStudio/internal/models"
	"SyslogStudio/internal/testenv"
)

// TestMain keeps the tests away from the user's own files (see testenv).
func TestMain(m *testing.M) { os.Exit(testenv.Run(m)) }

func reader(t *testing.T, rules ...models.SourceRule) *Reader {
	t.Helper()
	r := New()
	if err := r.SetRules(rules); err != nil {
		t.Fatal(err)
	}
	return r
}

func bySource(ip string) models.SourceMatch { return models.SourceMatch{Sources: []string{ip}} }

// A rule applies to the messages it matches, and to no others.
func TestRule_AppliesToWhatItMatches(t *testing.T) {
	r := reader(t, models.SourceRule{
		Name: "camera", Enabled: true, Match: bySource("10.0.0.0/24"),
		Hostname: "cam-lobby", AppName: "camera",
	})
	m := r.Read([]byte("<14>motion detected"), "10.0.0.7", "UDP")
	if m.Hostname != "cam-lobby" || m.AppName != "camera" || m.ReadBy != "camera" || m.Message != "motion detected" {
		t.Errorf("matched: %+v", m)
	}
	m = r.Read([]byte("<14>motion detected"), "10.0.1.7", "UDP")
	if m.Hostname != "" || m.AppName != "" || m.ReadBy != "" {
		t.Errorf("not matched, but read by a rule: %+v", m)
	}
}

// An address is that device, not the ones it is the start of (#98); a CIDR
// and a pattern take a range.
func TestRule_Addresses(t *testing.T) {
	for _, c := range []struct {
		entry string
		take  []string
		leave []string
	}{
		{"10.10.1.1", []string{"10.10.1.1"}, []string{"10.10.1.10", "10.10.1.100", "10.10.1.199"}},
		{"10.10.1.0/24", []string{"10.10.1.1", "10.10.1.254"}, []string{"10.10.2.1", "fe80::1"}},
		{"10.10.1.*", []string{"10.10.1.1", "10.10.1.199"}, []string{"10.10.10.1"}},
		{"fe80::/10", []string{"fe80::1"}, []string{"10.10.1.1"}},
	} {
		r := reader(t, models.SourceRule{Name: "device", Enabled: true, Match: bySource(c.entry), AppName: "x"})
		for _, ip := range c.take {
			if m := r.Read([]byte("<14>hello"), ip, "UDP"); m.ReadBy != "device" {
				t.Errorf("%s: %s not taken", c.entry, ip)
			}
		}
		for _, ip := range c.leave {
			if m := r.Read([]byte("<14>hello"), ip, "UDP"); m.ReadBy != "" {
				t.Errorf("%s: %s taken", c.entry, ip)
			}
		}
	}
}

// Behind a relay every device arrives from the same address: the raw message
// tells them apart, and the first rule that matches is the one applied.
func TestRules_InOrder_PatternTellsDevicesApart(t *testing.T) {
	r := reader(t,
		models.SourceRule{Name: "off", Enabled: false, Match: bySource("10.0.0.1"), AppName: "never"},
		models.SourceRule{Name: "forti", Enabled: true,
			Match: models.SourceMatch{Sources: []string{"10.0.0.1"}, Pattern: `devname="FGT`}, AppName: "fortigate"},
		models.SourceRule{Name: "relay", Enabled: true, Match: bySource("10.0.0.1"), AppName: "relayed"},
	)
	forti := r.Read([]byte(`<189>date=2026-10-27 time=09:14:02 devname="FGT60F" level="notice" msg="ok"`), "10.0.0.1", "UDP")
	other := r.Read([]byte(`<14>Oct 27 09:14:02 nas-01 smbd: hello`), "10.0.0.1", "UDP")
	if forti.AppName != "fortigate" || forti.ReadBy != "forti" {
		t.Errorf("FortiGate: %+v", forti)
	}
	if other.AppName != "relayed" || other.ReadBy != "relay" {
		t.Errorf("other device behind the relay: %+v", other)
	}
}

// Where the severity comes from.
func TestRule_LevelFrom(t *testing.T) {
	const words = "<13>Oct 27 09:14:02 cam-01 cam: channel 2 ERROR motion sensor"
	const declared = `<14>{"level":"error","msg":"db down"}`

	auto := reader(t, models.SourceRule{Name: "a", Enabled: true, Match: bySource("10.0.0.9")})
	if m := auto.Read([]byte(words), "10.0.0.9", "UDP"); m.Severity != models.SevNotice {
		t.Errorf("automatic: a word in the text took over the priority: %s", m.SeverityLabel)
	}
	if m := auto.Read([]byte(declared), "10.0.0.9", "UDP"); m.Severity != models.SevError {
		t.Errorf("automatic: a declared level did not: %s", m.SeverityLabel)
	}

	message := reader(t, models.SourceRule{Name: "m", Enabled: true, Match: bySource("10.0.0.9"),
		LevelFrom: models.LevelFromMessage})
	if m := message.Read([]byte(words), "10.0.0.9", "UDP"); m.Severity != models.SevError {
		t.Errorf("from the message: %s", m.SeverityLabel)
	}

	priority := reader(t, models.SourceRule{Name: "p", Enabled: true, Match: bySource("10.0.0.9"),
		LevelFrom: models.LevelFromPriority})
	if m := priority.Read([]byte(declared), "10.0.0.9", "UDP"); m.Severity != models.SevInformational {
		t.Errorf("from the priority: %s", m.SeverityLabel)
	}
}

// A declared format reads the message text when the header is the RFCs':
// a container logging JSON through syslog keeps its host and application,
// and gains its level and message.
func TestRule_FormatReadsTheMessageText(t *testing.T) {
	r := reader(t, models.SourceRule{Name: "docker", Enabled: true, Match: bySource("10.0.0.9"),
		Format: models.ImportFormat{Mode: models.ImportJSON}})
	m := r.Read([]byte(`<30>Oct 27 09:14:02 docker-01 web[1]: {"level":"error","msg":"db down"}`), "10.0.0.9", "UDP")
	if m.Hostname != "docker-01" || m.AppName != "web" || m.Severity != models.SevError || m.Message != "db down" {
		t.Errorf("%+v", m)
	}

	custom := reader(t, models.SourceRule{Name: "nas", Enabled: true, Match: bySource("10.0.0.9"),
		Format: models.ImportFormat{Mode: models.ImportCustom,
			Pattern: `^\[(?P<level>\w)\] (?P<time>\S+) (?P<msg>.*)$`}})
	m = custom.Read([]byte(`<14>Oct 27 09:14:02 nas-01 store: [W] 2026-10-27T09:15:00Z volume 1 at 91%`), "10.0.0.9", "UDP")
	if m.Severity != models.SevWarning || m.Message != "volume 1 at 91%" || m.Hostname != "nas-01" ||
		!m.Timestamp.Equal(time.Date(2026, 10, 27, 9, 15, 0, 0, time.UTC)) {
		t.Errorf("custom pattern: %+v", m)
	}

	// A message the format does not fit is left as it was read.
	m = custom.Read([]byte(`<14>Oct 27 09:14:02 nas-01 store: nothing like the pattern`), "10.0.0.9", "UDP")
	if m.Message != "nothing like the pattern" || m.Severity != models.SevInformational {
		t.Errorf("unmatched: %+v", m)
	}
}

// The clock: a device in another zone, and one whose clock is not trusted.
func TestRule_Clock(t *testing.T) {
	ny, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Skip("no zone database:", err)
	}
	zoned := reader(t, models.SourceRule{Name: "ny", Enabled: true, Match: bySource("10.0.0.9"),
		Format: models.ImportFormat{Timezone: "America/New_York"}})
	m := zoned.Read([]byte("<14>Oct 27 09:14:02 gw-ny app: up"), "10.0.0.9", "UDP")
	if got := m.Timestamp.In(ny); got.Hour() != 9 || got.Minute() != 14 || got.Day() != 27 {
		t.Errorf("read in New York: %v", got)
	}

	arrival := reader(t, models.SourceRule{Name: "now", Enabled: true, Match: bySource("10.0.0.9"), ArrivalTime: true})
	m = arrival.Read([]byte("<14>Jan  1 00:00:01 broken-clock app: up"), "10.0.0.9", "UDP")
	if !m.Timestamp.Equal(m.ReceivedAt) {
		t.Errorf("arrival time: %v, arrived %v", m.Timestamp, m.ReceivedAt)
	}

	host := reader(t, models.SourceRule{Name: "ip", Enabled: true, Match: bySource("10.0.0.9"), HostnameFromSource: true})
	if m := host.Read([]byte("<14>hello"), "10.0.0.9", "UDP"); m.Hostname != "10.0.0.9" {
		t.Errorf("hostname from the source: %q", m.Hostname)
	}
}

// A device that sends Windows-1252 has its accents back.
func TestRule_Encoding(t *testing.T) {
	raw := []byte("<14>Oct 27 09:14:02 old-pc app: d\xe9marrage termin\xe9")
	plain := reader(t)
	if m := plain.Read(raw, "10.0.0.9", "UDP"); strings.Contains(m.Message, "é") {
		t.Fatalf("decoded without a rule: %q", m.Message)
	}
	r := reader(t, models.SourceRule{Name: "w", Enabled: true, Match: bySource("10.0.0.9"),
		Encoding: models.EncodingWindows1252})
	m := r.Read(raw, "10.0.0.9", "UDP")
	if m.Message != "démarrage terminé" || m.Hostname != "old-pc" {
		t.Errorf("%+v", m)
	}
	// UTF-8 is left alone.
	if m := r.Read([]byte("<14>Oct 27 09:14:02 pc app: déjà"), "10.0.0.9", "UDP"); m.Message != "déjà" {
		t.Errorf("UTF-8 decoded again: %q", m.Message)
	}
}

// Trying a rule shows each sample without a rule and with it.
func TestTry(t *testing.T) {
	trials, err := Try(models.SourceRule{Name: "t", Match: bySource("10.0.0.9"), AppName: "camera"},
		[]models.SourceSample{
			{Raw: "<14>motion", SourceIP: "10.0.0.9", Protocol: "UDP"},
			{Raw: "<14>motion", SourceIP: "10.0.0.8", Protocol: "UDP"},
		})
	if err != nil {
		t.Fatal(err)
	}
	if len(trials) != 2 || !trials[0].Matched || trials[1].Matched {
		t.Fatalf("%+v", trials)
	}
	if trials[0].Before.AppName != "" || trials[0].After.AppName != "camera" || trials[1].After.AppName != "" {
		t.Errorf("before/after: %+v", trials)
	}
}

// What is wrong with a rule is said before it is saved.
func TestCompile_Refuses(t *testing.T) {
	for name, r := range map[string]models.SourceRule{
		"no condition":        {Name: "x"},
		"a bad pattern":       {Match: models.SourceMatch{Pattern: "("}},
		"a bad glob":          {Match: models.SourceMatch{Hostnames: []string{"["}}},
		"custom, no pattern":  {Match: bySource("10.0.0.1"), Format: models.ImportFormat{Mode: models.ImportCustom}},
		"custom, no groups":   {Match: bySource("10.0.0.1"), Format: models.ImportFormat{Mode: models.ImportCustom, Pattern: `^\w+$`}},
		"an unknown zone":     {Match: bySource("10.0.0.1"), Format: models.ImportFormat{Timezone: "Mars/Olympus"}},
		"an unknown level":    {Match: bySource("10.0.0.1"), LevelFrom: "guess"},
		"an unknown encoding": {Match: bySource("10.0.0.1"), Encoding: "ebcdic"},
		"half an address":     {Match: bySource("10.0.0")},
		"a name for address":  {Match: bySource("gateway")},
		"a CIDR too long":     {Match: bySource("10.0.0.0/33")},
	} {
		if err := Compile(r); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// One rule that does not compile does not keep the others from applying.
	r := New()
	err := r.SetRules([]models.SourceRule{
		{Name: "broken", Enabled: true},
		{Name: "fine", Enabled: true, Match: bySource("10.0.0.9"), AppName: "ok"},
	})
	if err == nil || !strings.Contains(err.Error(), "broken") {
		t.Errorf("the broken rule was not reported: %v", err)
	}
	if m := r.Read([]byte("<14>x"), "10.0.0.9", "UDP"); m.AppName != "ok" {
		t.Errorf("the fine rule did not apply: %+v", m)
	}
}
