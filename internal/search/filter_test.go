package search

import (
	"cmp"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"SyslogStudio/internal/models"
)

// testdata/filters.json is the specification of every other criterion: what
// each filter keeps, in what order each column sorts, how messages group. It
// is checked here against Filter, in internal/storage against the history's
// SQL, and in frontend/tests against the live view — so that the two views of
// the same messages cannot disagree.

func at(s string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		panic(err)
	}
	return t
}

type msgSpec struct {
	id, ts, host, app, proc, msgID, ip, proto, text string
	sev                                             models.Severity
	fac                                             models.Facility
	version                                         int
}

// The corpus, in order of arrival. Its traps: hostnames that differ by case,
// by an underscore LIKE would take for a wildcard, by an accent, by a
// character whose case folds oddly; an empty one; two messages in the same
// second; one in the previous day.
var filterCorpus = func() []models.SyslogMessage {
	specs := []msgSpec{
		{"a", "2026-10-23T08:00:00Z", "web-01", "nginx", "1234", "ID47", "10.0.0.5", "UDP", "upstream timed out", models.SevError, models.FacUser, 1},
		{"b", "2026-10-23T08:00:30Z", "Web-02", "sshd", "99", "", "10.0.0.10", "TCP", "Accepted publickey for root", models.SevInformational, models.FacAuth, 1},
		{"c", "2026-10-23T08:01:00Z", "web_01", "CRON", "", "-", "10.0.0.9", "UDP", "job started", models.SevWarning, models.FacUser, 0},
		{"d", "2026-10-23T08:01:59Z", "café-01", "nginx", "abc", "ID3", "192.168.1.20", "TLS", "Échec de connexion", models.SevError, models.FacDaemon, 1},
		{"e", "2026-10-23T08:02:00Z", "CAFE-02", "Nginx", "007", "ID10", "192.168.1.3", "udp", "cache warm", models.SevInformational, models.FacUser, 1},
		{"f", "2026-10-23T08:03:00.5Z", "", "", "12", "", "fe80::1", "UDP", "kernel panic", models.SevCritical, models.FacKern, 0},
		{"g", "2026-10-22T23:59:59Z", "db-01", "postgres", "1234", "id2", "10.0.0.5", "TCP", "checkpoint complete", models.SevDebug, models.FacLocal0, 1},
		{"h", "2026-10-23T08:00:00Z", "web-01", "nginx", "88", "ID47", "10.0.0.5", "UDP", "GET / 200", models.SevInformational, models.FacUser, 1},
		{"i", "2026-10-23T08:04:00Z", "50%-host", "app_x", "7", "", "10.1.0.1", "TCP", "disk 50% full", models.SevNotice, models.FacDaemon, 1},
		{"j", "2026-10-23T08:05:00Z", "Straße-1", "app-x", "", "98765432109876543210", "10.1.0.2", "UDP", "road closed", models.SevNotice, models.FacUser, 1},
		{"k", "2026-10-23T08:06:00Z", "İzmir-gw", "ΣΥΣ", "5", "98765432109876543211", "10.1.0.3", "UDP", "tunnel up", models.SevInformational, models.FacDaemon, 1},
	}
	var out []models.SyslogMessage
	for i, s := range specs {
		ts := at(s.ts)
		out = append(out, models.SyslogMessage{
			ID: s.id, Timestamp: ts, ReceivedAt: ts.Add(time.Duration(len(specs)-i) * time.Second),
			Severity: s.sev, SeverityLabel: models.SeverityToLabel(s.sev),
			Facility: s.fac, FacilityLabel: models.FacilityToLabel(s.fac),
			Hostname: s.host, AppName: s.app, ProcID: s.proc, MsgID: s.msgID,
			Message: s.text, RawMessage: "<14>1 " + s.ts + " " + s.host + " " + s.app + " - - - " + s.text,
			SourceIP: s.ip, Protocol: s.proto, Version: s.version,
		})
	}
	return out
}()

type filterCase struct {
	Name     string                `json:"name"`
	Criteria models.FilterCriteria `json:"criteria"`
	Want     []string              `json:"want"`
}

var filterCases = []filterCase{
	{"no criteria", models.FilterCriteria{}, []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k"}},
	// Field boxes: contains, without regard to case or Latin accents.
	{"host web", models.FilterCriteria{Hostname: "web"}, []string{"a", "b", "c", "h"}},
	{"host WEB-0", models.FilterCriteria{Hostname: "WEB-0"}, []string{"a", "b", "h"}},
	{"underscore is not a wildcard", models.FilterCriteria{Hostname: "web_01"}, []string{"c"}},
	{"percent is not a wildcard", models.FilterCriteria{Hostname: "50%"}, []string{"i"}},
	{"accent aside", models.FilterCriteria{Hostname: "cafe"}, []string{"d", "e"}},
	{"accent typed", models.FilterCriteria{Hostname: "CAFÉ"}, []string{"d", "e"}},
	{"sharp s is its own letter", models.FilterCriteria{Hostname: "strasse"}, []string{}},
	{"sharp s typed", models.FilterCriteria{Hostname: "straß"}, []string{"j"}},
	{"dotted capital I", models.FilterCriteria{Hostname: "izmir"}, []string{"k"}},
	{"greek case", models.FilterCriteria{AppName: "σύσ"}, []string{}},
	{"greek lowercase", models.FilterCriteria{AppName: "συσ"}, []string{"k"}},
	{"app nginx", models.FilterCriteria{AppName: "NGINX"}, []string{"a", "d", "e", "h"}},
	{"app underscore", models.FilterCriteria{AppName: "app_"}, []string{"i"}},
	{"ip prefix", models.FilterCriteria{SourceIP: "10.0.0.1"}, []string{"b"}},
	{"ip case", models.FilterCriteria{SourceIP: "FE80"}, []string{"f"}},
	{"host typed with a space", models.FilterCriteria{Hostname: "web "}, []string{}},
	// Levels.
	{"severity", models.FilterCriteria{Severities: []int{int(models.SevError)}}, []string{"a", "d"}},
	{"severities", models.FilterCriteria{Severities: []int{int(models.SevError), int(models.SevCritical)}}, []string{"a", "d", "f"}},
	{"facility", models.FilterCriteria{Facilities: []int{int(models.FacDaemon)}}, []string{"d", "i", "k"}},
	// Time: From included, To excluded, instants.
	{"from", models.FilterCriteria{DateFrom: "2026-10-23T08:01:00Z"}, []string{"c", "d", "e", "f", "i", "j", "k"}},
	{"to", models.FilterCriteria{DateTo: "2026-10-23T08:01:00Z"}, []string{"a", "b", "g", "h"}},
	{"a second with a fraction in it", models.FilterCriteria{DateFrom: "2026-10-23T08:03:00Z", DateTo: "2026-10-23T08:03:01Z"}, []string{"f"}},
	{"after the fraction", models.FilterCriteria{DateFrom: "2026-10-23T08:03:01Z"}, []string{"i", "j", "k"}},
	{"another zone", models.FilterCriteria{DateFrom: "2026-10-23T10:00:00+02:00", DateTo: "2026-10-23T10:01:00+02:00"}, []string{"a", "b", "h"}},
	{"the day before", models.FilterCriteria{DateTo: "2026-10-23T00:00:00Z"}, []string{"g"}},
	// One group, exactly as grouping made it.
	{"group host", models.FilterCriteria{GroupField: GroupHostname, GroupKey: "web-01"}, []string{"a", "h"}},
	{"group without host", models.FilterCriteria{GroupField: GroupHostname, GroupKey: ""}, []string{"f"}},
	{"group severity", models.FilterCriteria{GroupField: GroupSeverity, GroupKey: "Error"}, []string{"a", "d"}},
	{"group app is exact", models.FilterCriteria{GroupField: GroupAppName, GroupKey: "nginx"}, []string{"a", "d", "h"}},
	// Together, and with a search.
	{"host and level", models.FilterCriteria{Hostname: "web", Severities: []int{int(models.SevInformational)}}, []string{"b", "h"}},
	{"literal search", models.FilterCriteria{Search: "%", SearchMode: ModeText}, []string{"i"}},
	{"search and group", models.FilterCriteria{Search: "upstream OR get", SearchMode: ModeFTS, GroupField: GroupHostname, GroupKey: "web-01"}, []string{"a", "h"}},
}

// The columns both views sort by.
var sortFields = []string{"timestamp", "receivedAt", "severity", "facility", "version",
	"hostname", "appName", "sourceIP", "protocol", "message", "procID", "msgID"}

// compareText is SQLite's NOCASE: bytes, the ASCII letters folded.
func compareText(a, b string) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		x, y := a[i], b[i]
		if 'A' <= x && x <= 'Z' {
			x += 'a' - 'A'
		}
		if 'A' <= y && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return cmp.Compare(x, y)
		}
	}
	return cmp.Compare(len(a), len(b))
}

func isNumber(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// compareID puts numbers first, as numbers, then text.
func compareID(a, b string) int {
	na, nb := isNumber(a), isNumber(b)
	if na != nb {
		if na {
			return -1
		}
		return 1
	}
	if na {
		// As numbers, at any length: fewer digits is smaller.
		x, y := strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
		if c := cmp.Compare(len(x), len(y)); c != 0 {
			return c
		}
		if c := cmp.Compare(x, y); c != 0 {
			return c
		}
	}
	return compareText(a, b)
}

func compareBy(field string, a, b models.SyslogMessage) int {
	switch field {
	case "timestamp":
		return a.Timestamp.Compare(b.Timestamp)
	case "receivedAt":
		return a.ReceivedAt.Compare(b.ReceivedAt)
	case "severity":
		return cmp.Compare(a.Severity, b.Severity)
	case "facility":
		return cmp.Compare(a.Facility, b.Facility)
	case "version":
		return cmp.Compare(a.Version, b.Version)
	case "hostname":
		return compareText(a.Hostname, b.Hostname)
	case "appName":
		return compareText(a.AppName, b.AppName)
	case "sourceIP":
		return compareText(a.SourceIP, b.SourceIP)
	case "protocol":
		return compareText(a.Protocol, b.Protocol)
	case "message":
		return compareText(a.Message, b.Message)
	case "procID":
		return compareID(a.ProcID, b.ProcID)
	case "msgID":
		return compareID(a.MsgID, b.MsgID)
	}
	return 0
}

type sortCase struct {
	Field string   `json:"field"`
	Dir   string   `json:"dir"`
	Want  []string `json:"want"`
}

// sortedIDs orders the corpus by a column; ties keep their order of arrival,
// in the same direction.
func sortedIDs(field, dir string) []string {
	idx := make([]int, len(filterCorpus))
	for i := range idx {
		idx[i] = i
	}
	slices.SortStableFunc(idx, func(x, y int) int {
		c := compareBy(field, filterCorpus[x], filterCorpus[y])
		if c == 0 {
			c = cmp.Compare(x, y)
		}
		if dir == "desc" {
			c = -c
		}
		return c
	})
	ids := make([]string, len(idx))
	for i, k := range idx {
		ids[i] = filterCorpus[k].ID
	}
	return ids
}

type groupCase struct {
	Field  string                `json:"field"`
	Groups []models.GroupSummary `json:"groups"`
}

// groupsOf counts the corpus by a field: biggest first, then by name.
func groupsOf(field string) []models.GroupSummary {
	counts := map[string]int{}
	for _, m := range filterCorpus {
		counts[GroupKey(m, field)]++
	}
	var groups []models.GroupSummary
	for k, n := range counts {
		groups = append(groups, models.GroupSummary{Key: k, Count: n})
	}
	slices.SortFunc(groups, func(a, b models.GroupSummary) int {
		if c := cmp.Compare(b.Count, a.Count); c != 0 {
			return c
		}
		if c := compareText(a.Key, b.Key); c != 0 {
			return c
		}
		return cmp.Compare(a.Key, b.Key)
	})
	return groups
}

// goldenFilter is a filter case with its search compiled, which is how the
// window receives a search.
type goldenFilter struct {
	filterCase
	Plan Plan `json:"plan"`
}

type goldenFilters struct {
	Corpus  []models.SyslogMessage `json:"corpus"`
	Filters []goldenFilter         `json:"filters"`
	Sorts   []sortCase             `json:"sorts"`
	Groups  []groupCase            `json:"groups"`
}

func TestFilters(t *testing.T) {
	for _, c := range filterCases {
		f := CompileFilter(c.Criteria)
		got := []string{}
		for _, m := range filterCorpus {
			if f.Match(m) {
				got = append(got, m.ID)
			}
		}
		if !reflect.DeepEqual(got, c.Want) {
			t.Errorf("%s: kept %v, want %v", c.Name, got, c.Want)
		}
	}
	golden := goldenFilters{Corpus: filterCorpus}
	for _, c := range filterCases {
		golden.Filters = append(golden.Filters, goldenFilter{c, Compile(c.Criteria.Search, c.Criteria.SearchMode)})
	}
	for _, field := range sortFields {
		for _, dir := range []string{"asc", "desc"} {
			golden.Sorts = append(golden.Sorts, sortCase{field, dir, sortedIDs(field, dir)})
		}
	}
	for _, field := range []string{GroupSeverity, GroupHostname, GroupAppName, GroupSourceIP} {
		golden.Groups = append(golden.Groups, groupCase{field, groupsOf(field)})
	}
	checkGolden(t, "filters.json", golden)
}

// A filter saved before the window sent instants holds the wall clock of the
// machine, which still means what it meant: that day, that minute.
func TestFilters_OlderTimeForms(t *testing.T) {
	day := CompileFilter(models.FilterCriteria{DateFrom: "2026-09-17", DateTo: "2026-09-17"})
	if want := time.Date(2026, 9, 17, 0, 0, 0, 0, time.Local); !day.From.Equal(want) || !day.To.Equal(want.AddDate(0, 0, 1)) {
		t.Errorf("a day: %v – %v", day.From, day.To)
	}
	minute := CompileFilter(models.FilterCriteria{DateTo: "2026-09-17T14:30"})
	if want := time.Date(2026, 9, 17, 14, 31, 0, 0, time.Local); !minute.To.Equal(want) {
		t.Errorf("a minute ends at %v, want %v", minute.To, want)
	}
	for _, s := range []string{"not-a-date", "17/09/2026", "2026-13-45"} {
		if f := CompileFilter(models.FilterCriteria{DateFrom: s}); !f.From.IsZero() {
			t.Errorf("%q was read as %v", s, f.From)
		}
	}
}
