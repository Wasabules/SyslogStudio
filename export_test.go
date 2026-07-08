package main

import "testing"

func TestSanitizeCSVField(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"plain text", "connection refused", "connection refused"},
		{"empty", "", ""},
		{"equals formula", "=HYPERLINK(\"http://evil\")", "'=HYPERLINK(\"http://evil\")"},
		{"plus prefix", "+1+2", "'+1+2"},
		{"minus prefix", "-2+3", "'-2+3"},
		{"at prefix", "@SUM(A1)", "'@SUM(A1)"},
		{"tab smuggled formula", "\t=1+1", "'\t=1+1"},
		{"cr smuggled formula", "\r=1+1", "'\r=1+1"},
		{"only whitespace prefix chars", "\t\r", "\t\r"},
		{"equals mid-string untouched", "a=b", "a=b"},
		{"negative-looking log text", "-- MARK --", "'-- MARK --"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sanitizeCSVField(tt.input); got != tt.want {
				t.Errorf("sanitizeCSVField(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
