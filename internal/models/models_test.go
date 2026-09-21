package models

import (
	"testing"
	"time"
)

func validBaseConfig() ServerConfig {
	c := DefaultServerConfig()
	return c
}

func TestValidateServerConfig_BindAddress(t *testing.T) {
	tests := []struct {
		name    string
		bind    string
		wantErr bool
	}{
		{"empty means all interfaces", "", false},
		{"valid IPv4", "192.168.1.10", false},
		{"valid IPv4 loopback", "127.0.0.1", false},
		{"valid IPv6", "::1", false},
		{"valid IPv6 full", "fe80::1", false},
		{"hostname rejected", "localhost", true},
		{"garbage rejected", "not-an-ip", true},
		{"ip with port rejected", "192.168.1.10:514", true},
		{"cidr rejected", "192.168.1.0/24", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := validBaseConfig()
			c.BindAddress = tt.bind
			err := ValidateServerConfig(c)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateServerConfig(bind=%q) error = %v, wantErr %v", tt.bind, err, tt.wantErr)
			}
		})
	}
}

func TestParseSourceEntry(t *testing.T) {
	tests := []struct {
		name    string
		entry   string
		wantErr bool
	}{
		{"IPv4 literal", "192.168.1.5", false},
		{"IPv4 CIDR", "10.0.0.0/8", false},
		{"IPv6 literal", "fe80::1", false},
		{"IPv6 CIDR", "2001:db8::/32", false},
		{"with surrounding spaces", "  192.168.1.5  ", false},
		{"empty", "", true},
		{"hostname", "syslog.example.com", true},
		{"bad CIDR", "10.0.0.0/40", true},
		{"garbage", "abc/def", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseSourceEntry(tt.entry)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseSourceEntry(%q) error = %v, wantErr %v", tt.entry, err, tt.wantErr)
			}
		})
	}
}

func TestParseSourceEntry_BareIPMask(t *testing.T) {
	n4, err := ParseSourceEntry("192.168.1.5")
	if err != nil {
		t.Fatal(err)
	}
	if ones, bits := n4.Mask.Size(); ones != 32 || bits != 32 {
		t.Errorf("IPv4 literal should compile to /32, got /%d of %d", ones, bits)
	}
	n6, err := ParseSourceEntry("fe80::1")
	if err != nil {
		t.Fatal(err)
	}
	if ones, bits := n6.Mask.Size(); ones != 128 || bits != 128 {
		t.Errorf("IPv6 literal should compile to /128, got /%d of %d", ones, bits)
	}
}

func TestValidateServerConfig_AllowedSources(t *testing.T) {
	c := validBaseConfig()
	c.AllowedSources = []string{"10.0.0.0/8", "192.168.1.5"}
	if err := ValidateServerConfig(c); err != nil {
		t.Errorf("valid allowlist rejected: %v", err)
	}

	c.AllowedSources = []string{"10.0.0.0/8", "not-an-ip"}
	if err := ValidateServerConfig(c); err == nil {
		t.Error("invalid allowlist entry accepted")
	}
}

func TestValidateServerConfig_MaxBuffer(t *testing.T) {
	tests := []struct {
		name    string
		buffer  int
		wantErr bool
	}{
		{"default", DefaultServerConfig().MaxBuffer, false},
		{"zero falls back to default at Start", 0, false},
		{"at the limit", MaxBufferLimit, false},
		{"negative rejected", -1, true},
		{"above the limit rejected", MaxBufferLimit + 1, true},
		// Start() allocates make([]SyslogMessage, MaxBuffer) up front, so an
		// absurd value from a hand-edited config.json must be a config error,
		// not an out-of-memory abort.
		{"absurd value rejected", 1 << 40, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := validBaseConfig()
			c.MaxBuffer = tt.buffer
			err := ValidateServerConfig(c)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateServerConfig(maxBuffer=%d) error = %v, wantErr %v", tt.buffer, err, tt.wantErr)
			}
		})
	}
}

func TestValidateCertOptions_ValidityDays(t *testing.T) {
	tests := []struct {
		name    string
		days    int
		wantErr bool
	}{
		{"default", DefaultCertOptions().ValidityDays, false},
		{"zero means caller default", 0, false},
		{"ten years", 3650, false},
		{"at the limit", MaxValidityDays, false},
		{"negative rejected", -1, true},
		{"above the limit rejected", MaxValidityDays + 1, true},
		// Past ~106751 days, ValidityDays * 24 * time.Hour overflows int64 and
		// NotAfter lands in the past — an already-expired certificate rather
		// than the very long-lived one the caller asked for.
		{"int64 overflow range rejected", 200000, true},
		{"max int rejected", int(^uint(0) >> 1), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := DefaultCertOptions()
			o.ValidityDays = tt.days
			err := ValidateCertOptions(o)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateCertOptions(validityDays=%d) error = %v, wantErr %v", tt.days, err, tt.wantErr)
			}
		})
	}
}

func TestValidateServerConfig_RejectsBadCertOptions(t *testing.T) {
	// Certificate options ride along in ServerConfig, so starting the server
	// must reject them too, not just the direct generation entry points.
	c := validBaseConfig()
	c.CertOptions = DefaultCertOptions()
	c.CertOptions.ValidityDays = MaxValidityDays + 1
	if err := ValidateServerConfig(c); err == nil {
		t.Error("out-of-range certificate validity accepted by ValidateServerConfig")
	}
}

func TestParseFilterDate_ZonelessInputsAreLocal(t *testing.T) {
	// These come from the UI's date and datetime-local inputs, which a user
	// fills in wall-clock time. Reading them as UTC moved every filter boundary
	// by the collector's UTC offset — same root cause as issue #24's timestamp
	// shift. Asserted against the wall clock so this holds in any zone.
	tests := []struct {
		name  string
		input string
		want  string // wall clock, as it must read back
	}{
		{"date only", "2026-09-17", "2026-09-17 00:00:00"},
		{"date and time", "2026-09-17T14:30", "2026-09-17 14:30:00"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := ParseFilterDate(tt.input)
			if !ok {
				t.Fatalf("ParseFilterDate(%q) did not parse", tt.input)
			}
			if got.Location() != time.Local {
				t.Errorf("parsed into %v, want the local zone", got.Location())
			}
			if s := got.Format("2006-01-02 15:04:05"); s != tt.want {
				t.Errorf("wall clock = %s, want %s", s, tt.want)
			}
		})
	}
}

func TestParseFilterDate_RFC3339KeepsItsOffset(t *testing.T) {
	// An explicit offset is authoritative and must not be reinterpreted.
	got, ok := ParseFilterDate("2026-09-17T14:30:00+02:00")
	if !ok {
		t.Fatal("RFC 3339 input did not parse")
	}
	want := time.Date(2026, 9, 17, 12, 30, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("parsed %v, want the same instant as %v", got, want)
	}
}

func TestParseFilterDate_Rejects(t *testing.T) {
	for _, s := range []string{"", "not-a-date", "17/09/2026", "2026-13-45"} {
		if _, ok := ParseFilterDate(s); ok {
			t.Errorf("ParseFilterDate(%q) accepted an invalid value", s)
		}
	}
}
