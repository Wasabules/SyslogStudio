package models

import (
	"fmt"
	"path"
	"strings"
)

// SourceRule says how the messages from a device, or a group of devices, are
// read — for a device that bends the syslog RFCs further than reading them
// automatically can follow.
//
// It answers three questions: which messages (Match), how their text is read
// (Format, the same formats a file import offers), and what to correct once it
// is (the hostname, the application, the clock, the level, the encoding).
// Rules are tried in order, and the first enabled one that matches applies.
type SourceRule struct {
	ID      string      `json:"id"`
	Name    string      `json:"name"`
	Enabled bool        `json:"enabled"`
	Match   SourceMatch `json:"match"`

	// Format reads the message: after its priority when the header is not
	// the RFCs', its message text when it is. Automatic detection — the
	// default — leaves the reading as it is and only the corrections below
	// apply, in the device's time zone when one is given.
	Format ImportFormat `json:"format"`

	// Hostname replaces the one sent, for a device that sends none or the
	// wrong one; HostnameFromSource uses the address it arrived from.
	Hostname           string `json:"hostname,omitempty"`
	HostnameFromSource bool   `json:"hostnameFromSource,omitempty"`
	// AppName replaces the application.
	AppName string `json:"appName,omitempty"`
	// ArrivalTime uses the moment the message arrived, for a device whose
	// clock cannot be trusted.
	ArrivalTime bool `json:"arrivalTime,omitempty"`
	// LevelFrom says where the severity comes from (LevelFrom* below).
	LevelFrom string `json:"levelFrom,omitempty"`
	// Encoding is what a device that does not send UTF-8 sends instead
	// (Encoding* below).
	Encoding string `json:"encoding,omitempty"`
}

// SourceMatch is which messages a rule applies to. Each list matches when any
// of its entries does, and a rule matches when every condition given does;
// at least one has to be.
type SourceMatch struct {
	// Sources are the addresses messages arrive from: an IP, a CIDR, or a
	// pattern with "*" ("10.0.7.*"), as the Source IP filter takes them
	// (search.Address; checked where rules are compiled, internal/sources).
	Sources []string `json:"sources,omitempty"`
	// Hostnames and AppNames are globs ("fw-*"), matched against the
	// message as read before the rule.
	Hostnames []string `json:"hostnames,omitempty"`
	AppNames  []string `json:"appNames,omitempty"`
	// Pattern is a regular expression the raw message must contain a match
	// for: what tells devices apart behind a relay, where they all arrive
	// from the same address.
	Pattern string `json:"pattern,omitempty"`
}

// Where a rule takes the severity from.
const (
	// LevelFromAuto keeps the priority's, unless the message declares its own
	// level in a field (JSON, key=value, a pattern's level group).
	LevelFromAuto = ""
	// LevelFromPriority always keeps the priority's: the device sets it
	// right, whatever its text says.
	LevelFromPriority = "priority"
	// LevelFromMessage takes a level the message carries, a word in its text
	// included: the device puts the same priority on everything.
	LevelFromMessage = "message"
)

// The encodings a device may send instead of UTF-8.
const (
	EncodingUTF8        = ""
	EncodingWindows1252 = "windows-1252"
	EncodingLatin1      = "iso-8859-1"
	EncodingLatin9      = "iso-8859-15"
)

// maxSourcePattern bounds a rule's pattern, as the import bounds its own.
const maxSourcePattern = 1000

// SourceSample is a received message to try a rule on: as it arrived.
type SourceSample struct {
	Raw      string `json:"raw"`
	SourceIP string `json:"sourceIP"`
	Protocol string `json:"protocol"`
}

// SourceTrial is what a rule makes of one sample: whether it matched, and the
// message read without any rule and with this one.
type SourceTrial struct {
	Matched bool          `json:"matched"`
	Before  SyslogMessage `json:"before"`
	After   SyslogMessage `json:"after"`
}

// ValidateSourceRule says what is wrong with a rule before it is saved.
// The format's own pattern is compiled where it is read (importer).
func ValidateSourceRule(r SourceRule) error {
	m := r.Match
	if len(nonEmpty(m.Sources)) == 0 && len(nonEmpty(m.Hostnames)) == 0 &&
		len(nonEmpty(m.AppNames)) == 0 && strings.TrimSpace(m.Pattern) == "" {
		return fmt.Errorf("say which messages the rule applies to: a source, a hostname, an application or a pattern")
	}
	for _, g := range append(nonEmpty(m.Hostnames), nonEmpty(m.AppNames)...) {
		if _, err := path.Match(g, ""); err != nil {
			return fmt.Errorf("%q is not a valid pattern", g)
		}
	}
	if p := strings.TrimSpace(m.Pattern); p != "" {
		if len(p) > maxSourcePattern {
			return fmt.Errorf("the pattern is longer than %d characters", maxSourcePattern)
		}
		if _, err := SafeCompileRegex(p); err != nil {
			return fmt.Errorf("the pattern does not compile: %w", err)
		}
	}
	if err := ValidateImportFormat(r.Format); err != nil {
		return err
	}
	switch r.LevelFrom {
	case LevelFromAuto, LevelFromPriority, LevelFromMessage:
	default:
		return fmt.Errorf("unknown level source %q", r.LevelFrom)
	}
	switch r.Encoding {
	case EncodingUTF8, EncodingWindows1252, EncodingLatin1, EncodingLatin9:
	default:
		return fmt.Errorf("unknown encoding %q", r.Encoding)
	}
	return nil
}

func nonEmpty(list []string) []string {
	var out []string
	for _, s := range list {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}
