package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"SyslogStudio/internal/models"
)

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

func TestResolveLocation(t *testing.T) {
	// time/tzdata is embedded in main.go, so named zones must resolve even on a
	// host with no zone files — which is every stock Windows machine, and the
	// reason the import is there.
	for _, name := range []string{"UTC", "Europe/Paris", "Asia/Tokyo", "America/New_York"} {
		loc := resolveLocation(name)
		if loc.String() != name {
			t.Errorf("resolveLocation(%q) = %q, want %q", name, loc, name)
		}
	}

	// An empty or unknown name falls back rather than failing the export: the
	// user has already picked a file, and local time beats no file at all.
	for _, name := range []string{"", "Not/AZone", "garbage"} {
		if got := resolveLocation(name); got != time.Local {
			t.Errorf("resolveLocation(%q) = %v, want the local zone", name, got)
		}
	}
}

func TestExport_RendersInTheChosenZone(t *testing.T) {
	// One instant, three zones: the wall clock differs, the offset says which
	// clock it is, and the instant itself never moves.
	instant := time.Date(2026, 9, 17, 18, 26, 32, 0, time.UTC)
	msg := models.SyslogMessage{
		ID: "m1", Timestamp: instant, ReceivedAt: instant,
		SeverityLabel: "Notice", FacilityLabel: "local7",
		Hostname: "firewall", AppName: "app", Message: "hello",
		SourceIP: "10.0.0.1", Protocol: "TLS",
	}

	tests := []struct {
		zone string
		want string
	}{
		{"UTC", "2026-09-17 18:26:32 +00:00"},
		{"Europe/Paris", "2026-09-17 20:26:32 +02:00"},
		{"Asia/Tokyo", "2026-09-18 03:26:32 +09:00"},
	}

	for _, tt := range tests {
		t.Run(tt.zone, func(t *testing.T) {
			loc := resolveLocation(tt.zone)

			csvPath := filepath.Join(t.TempDir(), "export.csv")
			if err := writeCSV(csvPath, []models.SyslogMessage{msg}, loc); err != nil {
				t.Fatalf("writeCSV: %v", err)
			}
			csvData, err := os.ReadFile(csvPath)
			if err != nil {
				t.Fatalf("read csv: %v", err)
			}
			if !strings.Contains(string(csvData), tt.want) {
				t.Errorf("CSV does not contain %q:\n%s", tt.want, csvData)
			}

			txtPath := filepath.Join(t.TempDir(), "export.txt")
			if err := writeText(txtPath, []models.SyslogMessage{msg}, loc); err != nil {
				t.Fatalf("writeText: %v", err)
			}
			txtData, err := os.ReadFile(txtPath)
			if err != nil {
				t.Fatalf("read txt: %v", err)
			}
			if !strings.Contains(string(txtData), tt.want) {
				t.Errorf("text export does not contain %q:\n%s", tt.want, txtData)
			}
		})
	}
}
