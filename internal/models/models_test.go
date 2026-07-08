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
