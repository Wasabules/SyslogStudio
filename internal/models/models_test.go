package models

import "testing"

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
