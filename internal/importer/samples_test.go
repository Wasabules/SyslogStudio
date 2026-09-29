package importer

import (
	"os"
	"path/filepath"
	"testing"

	"SyslogStudio/internal/models"
)

// Every sample file in tools/sample-logs, read the way the application reads
// it, checked against what it is supposed to produce.
//
// Line-level tests say the parser can read a shape. This says a FILE comes out
// right: the right number of messages, the right name for what the file is,
// and the right fields on the first line of it. Those are three different ways
// to be wrong and only the last one is visible in a unit test of a parser.
//
// The directory is walked rather than listed, and a file with no expectation
// fails the test. Adding a sample is therefore adding a claim about it, which
// is the only way a corpus stays honest as it grows.

type sampleExpectation struct {
	imported int
	detected string
	mode     models.ImportMode
	// The first message, which is where a wrong field shows up first.
	severity string
	host     string
	app      string
	procID   string
	message  string
}

func TestSampleFiles(t *testing.T) {
	expected := map[string]sampleExpectation{
		"access.txt": {
			imported: 7, detected: ShapeAccess, mode: models.ImportAccess,
			severity: "Info", host: "198.51.100.7",
			message: `GET /health HTTP/1.1 200 12 ua="kube-probe/1.29"`,
		},
		"apache-error.txt": {
			imported: 5, detected: ShapeApache, mode: models.ImportApache,
			severity: "Error", procID: "1234",
			message: "AH00037: Symbolic link not allowed: /var/www/html/data",
		},
		"archive-2019.txt": {
			imported: 6, detected: ShapeBSD, mode: models.ImportBSD,
			severity: "Notice", host: "mail-1", app: "postfix/smtpd", procID: "3121",
			message: "connect from unknown[192.0.2.91]",
		},
		"auto-formats.txt": {
			imported: 23, detected: "mixed",
			severity: "Info", host: "web-1", app: "sshd", procID: "4242",
			message: "Accepted publickey for deploy from 203.0.113.9",
		},
		"json-lines.txt": {
			imported: 8, detected: ShapeJSON, mode: models.ImportJSON,
			severity: "Info", host: "web-1", app: "api",
			message: "listening on :8080",
		},
		"klog.txt": {
			imported: 6, detected: ShapeKlog, mode: models.ImportKlog,
			severity: "Info", app: "controller.go", procID: "1",
			message: "Starting workers for queue depth 812",
		},
		"logcat.txt": {
			imported: 9, detected: ShapeLogcat, mode: models.ImportLogcat,
			severity: "Info", app: "ActivityManager", procID: "1234",
			message: "Start proc com.example.app for activity MainActivity",
		},
		"logfmt.txt": {
			imported: 7, detected: ShapeLogfmt, mode: models.ImportLogfmt,
			severity: "Info",
			message:  "server started addr=:8080 version=1.4.0",
		},
		"messy.txt": {
			imported: 8, detected: "mixed",
			severity: "Notice",
		},
		"nginx-error.txt": {
			imported: 5, detected: ShapePlain,
			severity: "Error",
		},
		"plain-app.txt": {
			imported: 9, detected: ShapePlain,
			severity: "Info",
			message:  "INFO   worker pool started with 16 threads",
		},
		"rsyslog-traditional.txt": {
			imported: 6, detected: ShapeBSD, mode: models.ImportBSD,
			severity: "Notice", host: "nbb-ad-01.vms.example.invalid",
			app: "Microsoft-Windows-Security-Auditing", procID: "756",
			message: "An account was successfully logged on",
		},
		"syslog-capture.txt": {
			imported: 8, detected: ShapeSyslog, mode: models.ImportSyslog,
			severity: "Error", host: "vpn-gw-01", app: "ipsec", procID: "4242",
			message: "IKE_SA rekey failed with 198.51.100.7",
		},
	}

	dir := filepath.Join("..", "..", "tools", "sample-logs")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("the samples are part of the repository: %v", err)
	}

	seen := map[string]bool{}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || filepath.Ext(name) != ".txt" {
			continue
		}
		seen[name] = true

		want, ok := expected[name]
		if !ok {
			t.Errorf("%s has no expectation; a sample nobody has checked proves nothing", name)
			continue
		}

		t.Run(name, func(t *testing.T) {
			var msgs []models.SyslogMessage
			res, err := Read(
				Options{Path: filepath.Join(dir, name), Year: 2026, Format: models.DefaultImportFormat()},
				func(m models.SyslogMessage) bool { msgs = append(msgs, m); return true })
			if err != nil {
				t.Fatalf("Read: %v", err)
			}

			if res.Imported != want.imported {
				t.Errorf("Imported = %d, want %d (shapes: %v)", res.Imported, want.imported, res.ByShape)
			}
			if res.Detected != want.detected {
				t.Errorf("Detected = %q, want %q (shapes: %v)", res.Detected, want.detected, res.ByShape)
			}
			if res.DetectedMode != want.mode {
				t.Errorf("DetectedMode = %q, want %q", res.DetectedMode, want.mode)
			}
			if len(msgs) == 0 {
				t.Fatal("no messages")
			}

			first := msgs[0]
			if first.SeverityLabel != want.severity {
				t.Errorf("severity = %q, want %q", first.SeverityLabel, want.severity)
			}
			if first.Hostname != want.host {
				t.Errorf("hostname = %q, want %q", first.Hostname, want.host)
			}
			if first.AppName != want.app {
				t.Errorf("app = %q, want %q", first.AppName, want.app)
			}
			if first.ProcID != want.procID {
				t.Errorf("procID = %q, want %q", first.ProcID, want.procID)
			}
			if want.message != "" && first.Message != want.message {
				t.Errorf("message = %q, want %q", first.Message, want.message)
			}

			// Whatever else is true, the source must say the line came from a
			// file and not off the wire.
			for _, m := range msgs {
				if m.Protocol != "file" || m.SourceIP != name {
					t.Fatalf("a message claims to be %s traffic from %q", m.Protocol, m.SourceIP)
					break
				}
			}
		})
	}

	for name := range expected {
		if !seen[name] {
			t.Errorf("%s is expected but is not in the directory", name)
		}
	}
}

// A declared mode reads its own file at least as well as detection does.
// Whatever the detector names a file, switching to that mode must not lose
// anything — the interface offers exactly that switch, and an operator who
// takes it would otherwise get a worse result for agreeing with us.
func TestSampleFiles_DeclaringTheDetectedModeLosesNothing(t *testing.T) {
	dir := filepath.Join("..", "..", "tools", "sample-logs")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || filepath.Ext(name) != ".txt" {
			continue
		}
		path := filepath.Join(dir, name)

		auto, err := Read(Options{Path: path, Year: 2026, Format: models.DefaultImportFormat()},
			func(models.SyslogMessage) bool { return true })
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if auto.DetectedMode == "" {
			continue
		}

		declared, err := Read(Options{Path: path, Year: 2026, Format: models.ImportFormat{
			Mode: auto.DetectedMode, JoinContinuations: true,
		}}, func(models.SyslogMessage) bool { return true })
		if err != nil {
			t.Fatalf("%s as %s: %v", name, auto.DetectedMode, err)
		}

		t.Run(name, func(t *testing.T) {
			if declared.Imported != auto.Imported {
				t.Errorf("as %s: %d messages, detection gave %d",
					auto.DetectedMode, declared.Imported, auto.Imported)
			}
			if declared.LevelDetected < auto.LevelDetected {
				t.Errorf("as %s: %d levels, detection found %d",
					auto.DetectedMode, declared.LevelDetected, auto.LevelDetected)
			}
			if declared.TimeDetected < auto.TimeDetected {
				t.Errorf("as %s: %d timestamps, detection found %d",
					auto.DetectedMode, declared.TimeDetected, auto.TimeDetected)
			}
			if declared.Unmatched > auto.Unmatched {
				t.Errorf("as %s: %d unmatched, detection had %d",
					auto.DetectedMode, declared.Unmatched, auto.Unmatched)
			}
		})
	}
}

// Declaring a format the file is not must say so, not quietly do something
// else. That is the whole reason these shapes are selectable: a reader who
// picks "Kubernetes klog" for an Apache log has made a mistake, and the
// preview is where it should become obvious.
func TestSampleFiles_TheWrongModeSaysSo(t *testing.T) {
	dir := filepath.Join("..", "..", "tools", "sample-logs")
	cases := []struct {
		file string
		mode models.ImportMode
	}{
		{"apache-error.txt", models.ImportKlog},
		{"klog.txt", models.ImportAccess},
		{"json-lines.txt", models.ImportLogcat},
		{"access.txt", models.ImportEpoch},
		{"plain-app.txt", models.ImportBSD},
	}

	for _, c := range cases {
		t.Run(c.file+" as "+string(c.mode), func(t *testing.T) {
			res, err := Read(Options{
				Path:   filepath.Join(dir, c.file),
				Year:   2026,
				Format: models.ImportFormat{Mode: c.mode},
			}, func(models.SyslogMessage) bool { return true })
			if err != nil {
				t.Fatalf("Read: %v", err)
			}
			if res.Unmatched != res.LinesRead-res.Blank {
				t.Errorf("Unmatched = %d of %d lines; a format the file is not must not match any of it",
					res.Unmatched, res.LinesRead-res.Blank)
			}
			if res.Detected != "" && res.Detected != "mixed" {
				t.Errorf("Detected = %q on a file read with the wrong format", res.Detected)
			}
		})
	}
}
