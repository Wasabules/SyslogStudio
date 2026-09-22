// Package notify routes incoming syslog messages to outbound destinations:
// another syslog collector, a webhook, or e-mail.
//
// The design is a rule/destination pair, ported from SnmpLens's pkg/notify and
// adapted to syslog messages. A Route decides WHICH messages are interesting;
// a Sink decides WHERE they go. Keeping them separate is what lets one rule
// feed several destinations, and one destination serve several rules, without
// duplicating either.
//
// Routing sees every received message, not only the ones that trip an alert.
// That is what makes relaying a whole stream to a second collector possible —
// the case an alert-shaped design cannot express.
package notify

import (
	"net"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"SyslogStudio/internal/models"
)

// Route is one rule: what to match, and where matches go.
type Route struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	// Priority orders evaluation, lowest first. It exists so Stop is
	// predictable: without an order, "first match wins" depends on map
	// iteration or insertion accident.
	Priority int        `json:"priority"`
	Match    RouteMatch `json:"match"`
	SinkIDs  []string   `json:"sinkIds"`
	// Stop ends evaluation when this route matches, so a broad catch-all can
	// sit at the bottom without doubling every delivery above it.
	Stop bool `json:"stop"`
}

// RouteMatch is the set of conditions a message must satisfy. Every field is
// optional and an empty field is "no constraint", so a route with an empty
// match is a deliberate catch-all rather than a rule that never fires.
type RouteMatch struct {
	// MinSeverity and MaxSeverity bound the severity range, inclusive.
	// Syslog severity counts DOWN with urgency (0 emergency, 7 debug), so
	// "at least warning" is MaxSeverity=4 — named after the value, not the
	// urgency, because the numbers are what the protocol carries.
	MinSeverity *int `json:"minSeverity,omitempty"`
	MaxSeverity *int `json:"maxSeverity,omitempty"`

	Facilities []int `json:"facilities,omitempty"`

	// Hostnames and AppNames accept shell-style globs, so "web-*" works.
	Hostnames []string `json:"hostnames,omitempty"`
	AppNames  []string `json:"appNames,omitempty"`

	// Sources accept a CIDR or a glob. Anything that parses as a prefix is
	// treated as CIDR; the rest falls back to path.Match, whose syntax has no
	// backtracking and therefore cannot hang on a hostile pattern.
	Sources []string `json:"sources,omitempty"`

	// Pattern matches the message text. UseRegex switches from a
	// case-insensitive substring to a regular expression.
	Pattern  string `json:"pattern,omitempty"`
	UseRegex bool   `json:"useRegex,omitempty"`

	// Window restricts the route to a time of day, for "page me only outside
	// office hours" rules.
	Window *Window `json:"window,omitempty"`
}

// Window is a daily time range in the collector's local zone. End before Start
// means the window wraps midnight, which is the common case for on-call.
type Window struct {
	Start string `json:"start"` // "HH:MM"
	End   string `json:"end"`   // "HH:MM"
	// Days restricts to weekdays, 0 = Sunday. Empty means every day.
	Days []int `json:"days,omitempty"`
}

// matchesGlob reports whether value matches one of the patterns. An empty list
// is "no constraint". Matching is case-insensitive, because hostnames are.
func matchesGlob(patterns []string, value string) bool {
	if len(patterns) == 0 {
		return true
	}
	v := strings.ToLower(value)
	for _, p := range patterns {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" {
			continue
		}
		if p == v {
			return true
		}
		if ok, err := path.Match(p, v); err == nil && ok {
			return true
		}
	}
	return false
}

func matchesInt(list []int, value int) bool {
	if len(list) == 0 {
		return true
	}
	for _, v := range list {
		if v == value {
			return true
		}
	}
	return false
}

// matchesSource accepts a CIDR or a glob against the sending address.
func matchesSource(patterns []string, source string) bool {
	if len(patterns) == 0 {
		return true
	}
	ip := net.ParseIP(source)
	for _, p := range patterns {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if _, cidr, err := net.ParseCIDR(p); err == nil {
			// A zero-length prefix is how an operator writes "everything".
			// Contains across families is false, so 0.0.0.0/0 would otherwise
			// silently drop every IPv6 sender — the pattern that looks most
			// like "all" being the one that halves the estate.
			if ones, _ := cidr.Mask.Size(); ones == 0 {
				return true
			}
			if ip != nil && cidr.Contains(ip) {
				return true
			}
			continue
		}
		if ok, err := path.Match(strings.ToLower(p), strings.ToLower(source)); err == nil && ok {
			return true
		}
	}
	return false
}

func parseHHMM(s string) (int, bool) {
	parts := strings.SplitN(strings.TrimSpace(s), ":", 2)
	if len(parts) != 2 {
		return 0, false
	}
	h, err1 := strconv.Atoi(parts[0])
	m, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil || h < 0 || h > 23 || m < 0 || m > 59 {
		return 0, false
	}
	return h*60 + m, true
}

// inWindow reports whether t falls inside the daily window.
func inWindow(w *Window, t time.Time) bool {
	if w == nil {
		return true
	}
	if len(w.Days) > 0 && !matchesInt(w.Days, int(t.Weekday())) {
		return false
	}
	start, okStart := parseHHMM(w.Start)
	end, okEnd := parseHHMM(w.End)
	if !okStart || !okEnd {
		// A malformed window is treated as no window rather than as "never":
		// a typo should not silently stop every delivery on the route.
		return true
	}
	now := t.Hour()*60 + t.Minute()
	if start <= end {
		return now >= start && now <= end
	}
	// Wraps midnight, e.g. 22:00-06:00.
	return now >= start || now <= end
}

// Matches reports whether the message satisfies every condition.
//
// compiled carries the route's regex when it has one; compiling per message
// would put the regex compiler on a path that runs at the full message rate.
func (m RouteMatch) Matches(msg models.SyslogMessage, compiled *regexp.Regexp, now time.Time) bool {
	sev := int(msg.Severity)
	if m.MinSeverity != nil && sev < *m.MinSeverity {
		return false
	}
	if m.MaxSeverity != nil && sev > *m.MaxSeverity {
		return false
	}
	if !matchesInt(m.Facilities, int(msg.Facility)) {
		return false
	}
	if !matchesGlob(m.Hostnames, msg.Hostname) {
		return false
	}
	if !matchesGlob(m.AppNames, msg.AppName) {
		return false
	}
	if !matchesSource(m.Sources, msg.SourceIP) {
		return false
	}
	if m.Pattern != "" {
		if m.UseRegex {
			if compiled == nil || (!compiled.MatchString(msg.Message) && !compiled.MatchString(msg.RawMessage)) {
				return false
			}
		} else {
			p := strings.ToLower(m.Pattern)
			if !strings.Contains(strings.ToLower(msg.Message), p) &&
				!strings.Contains(strings.ToLower(msg.RawMessage), p) {
				return false
			}
		}
	}
	return inWindow(m.Window, now)
}

// compiledRoute pairs a route with its prepared regex.
type compiledRoute struct {
	route Route
	re    *regexp.Regexp
}

// compileRoutes prepares routes for matching: sorted by priority, regexes
// compiled once, disabled ones dropped.
//
// A route whose regex does not compile is dropped rather than treated as
// matching everything — a typo must not start relaying the whole stream to a
// third party.
func compileRoutes(routes []Route) []compiledRoute {
	out := make([]compiledRoute, 0, len(routes))
	for _, r := range routes {
		if !r.Enabled || len(r.SinkIDs) == 0 {
			continue
		}
		var re *regexp.Regexp
		if r.Match.Pattern != "" && r.Match.UseRegex {
			compiled, err := models.SafeCompileRegex(r.Match.Pattern)
			if err != nil {
				continue
			}
			re = compiled
		}
		out = append(out, compiledRoute{route: r, re: re})
	}
	// Stable sort on priority, so routes sharing a priority keep the order the
	// operator put them in.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].route.Priority < out[j-1].route.Priority; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// selectSinks returns the sink ids a message should be delivered to, in route
// order and without duplicates: two routes naming the same sink must not send
// the message twice.
func selectSinks(routes []compiledRoute, msg models.SyslogMessage, now time.Time) []string {
	var out []string
	seen := make(map[string]struct{})
	for _, cr := range routes {
		if !cr.route.Match.Matches(msg, cr.re, now) {
			continue
		}
		for _, id := range cr.route.SinkIDs {
			if _, dup := seen[id]; dup {
				continue
			}
			seen[id] = struct{}{}
			out = append(out, id)
		}
		if cr.route.Stop {
			break
		}
	}
	return out
}

// ValidateRoute checks a route before it is saved.
func ValidateRoute(r Route) error {
	if strings.TrimSpace(r.Name) == "" {
		return errf("route name is required")
	}
	if len(r.SinkIDs) == 0 {
		return errf("route %q has no destination", r.Name)
	}
	if r.Match.MinSeverity != nil && (*r.Match.MinSeverity < 0 || *r.Match.MinSeverity > 7) {
		return errf("minimum severity must be between 0 and 7")
	}
	if r.Match.MaxSeverity != nil && (*r.Match.MaxSeverity < 0 || *r.Match.MaxSeverity > 7) {
		return errf("maximum severity must be between 0 and 7")
	}
	if r.Match.MinSeverity != nil && r.Match.MaxSeverity != nil && *r.Match.MinSeverity > *r.Match.MaxSeverity {
		return errf("minimum severity %d is above the maximum %d", *r.Match.MinSeverity, *r.Match.MaxSeverity)
	}
	if r.Match.Pattern != "" && r.Match.UseRegex {
		if _, err := models.SafeCompileRegex(r.Match.Pattern); err != nil {
			return errf("invalid regular expression: %v", err)
		}
	}
	for _, s := range r.Match.Sources {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, _, err := net.ParseCIDR(s); err == nil {
			continue
		}
		if _, err := path.Match(s, ""); err != nil {
			return errf("source pattern %q is not a valid CIDR or glob", s)
		}
	}
	if w := r.Match.Window; w != nil {
		if _, ok := parseHHMM(w.Start); !ok {
			return errf("window start %q is not HH:MM", w.Start)
		}
		if _, ok := parseHHMM(w.End); !ok {
			return errf("window end %q is not HH:MM", w.End)
		}
		for _, d := range w.Days {
			if d < 0 || d > 6 {
				return errf("window day %d is out of range (0-6, 0 = Sunday)", d)
			}
		}
	}
	return nil
}
