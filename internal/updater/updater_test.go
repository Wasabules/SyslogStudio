package updater

import "testing"

func TestIsNewer(t *testing.T) {
	tests := []struct {
		name    string
		latest  string
		current string
		want    bool
	}{
		{"patch newer", "v1.1.1", "v1.1.0", true},
		{"minor newer", "v1.2.0", "v1.1.9", true},
		{"major newer", "v2.0.0", "v1.9.9", true},
		{"equal", "v1.1.0", "v1.1.0", false},
		{"older", "v1.0.9", "v1.1.0", false},
		{"double-digit minor vs single", "v1.10.0", "v1.9.0", true},
		{"double-digit patch vs single", "v1.1.10", "v1.1.9", true},
		{"current double-digit not older", "v1.9.0", "v1.10.0", false},
		{"no v prefix", "1.2.0", "1.1.0", true},
		{"mixed prefix", "v1.2.0", "1.2.0", false},
		{"longer tag wins on tie", "v1.1.0.1", "v1.1.0", true},
		{"empty latest", "", "v1.0.0", false},
		{"empty current", "v1.0.0", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isNewer(tt.latest, tt.current); got != tt.want {
				t.Errorf("isNewer(%q, %q) = %v, want %v", tt.latest, tt.current, got, tt.want)
			}
		})
	}
}
