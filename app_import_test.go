package main

import (
	"os"
	"path/filepath"
	"testing"

	"SyslogStudio/internal/alert"
	"SyslogStudio/internal/event"
	"SyslogStudio/internal/models"
	"SyslogStudio/internal/syslog"
)

// The facade is where the feature either works or does not: the importer can be
// perfect and the import still be useless if the messages never reach the buffer
// the viewer reads, or if they arrive as traffic and wake the alert rules.

func importApp(t *testing.T) (*App, *event.MockEventEmitter) {
	t.Helper()
	em := event.NewMockEventEmitter()
	return &App{server: syslog.NewSyslogServer(em, nil)}, em
}

// A file with both shapes in it, which is what an archive directory looks like
// in practice.
func mixedFile(t *testing.T) string {
	t.Helper()
	const content = `<131>1 2026-03-17T21:42:10Z vpn-gw-01 ipsec 4242 - - tunnel torn down
<134>1 2026-03-17T21:42:11Z web-1 sshd 22 - - Accepted publickey for bob
2026-03-17 21:42:12 ERROR connection refused
2026-03-17 21:42:13 INFO  retrying in 5s
2026-03-17 21:42:14 WARN  disk almost full
`
	p := filepath.Join(t.TempDir(), "archive.log")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// What the reporter of #46 actually asked for: open a file that is already on
// disk and have its lines sort by severity.
func TestImportLogFile_MessagesReachTheBufferAndFilterBySeverity(t *testing.T) {
	app, _ := importApp(t)
	path := mixedFile(t)

	res, err := app.ImportLogFile(path, false)
	if err != nil {
		t.Fatalf("ImportLogFile: %v", err)
	}
	if res.Imported != 5 || res.Syslog != 2 {
		t.Fatalf("Imported = %d, Syslog = %d, want 5 and 2", res.Imported, res.Syslog)
	}

	all := app.GetMessages(models.FilterCriteria{})
	if len(all) != 5 {
		t.Fatalf("buffer holds %d messages after importing 5", len(all))
	}

	// Two errors: the <131> line (PRI, read) and the ERROR line (inferred).
	errs := app.GetMessages(models.FilterCriteria{Severities: []int{int(models.SevError)}})
	if len(errs) != 2 {
		t.Fatalf("filtering on Error gives %d messages, want 2 — which is the whole point of the feature", len(errs))
	}
	// Without level detection every plain line would be a Notice, and this
	// filter would return only the one line that carried a priority.
	var inferred bool
	for _, m := range errs {
		if m.Message == "ERROR connection refused" {
			inferred = true
		}
	}
	if !inferred {
		t.Error("the plain ERROR line did not come back as an Error")
	}
}

// An import is history. Relaying last week's logs into a live alert pipeline is
// the worst surprise this feature could spring on someone opening an archive.
func TestImportLogFile_DoesNotFireAlertRules(t *testing.T) {
	app, em := importApp(t)
	app.server.AlertManager = alert.NewAlertManager(em)
	app.server.AlertManager.SetRules([]models.AlertRule{{
		ID: "r1", Name: "anything refused", Enabled: true,
		Pattern: "refused", MinSeverity: int(models.SevDebug),
	}})

	if _, err := app.ImportLogFile(mixedFile(t), false); err != nil {
		t.Fatal(err)
	}

	for _, ev := range em.GetEvents() {
		if ev.Name == "syslog:alerts" {
			t.Fatal("an import fired an alert rule: last week's logs would page someone")
		}
	}
	if n := len(app.server.AlertManager.GetHistory()); n != 0 {
		t.Errorf("alert history has %d entries after an import, want 0", n)
	}
}

// The preview is what makes the inference a decision rather than a surprise, so
// it must report what was read and what was guessed without importing anything.
func TestPreviewLogFile_ReportsWithoutImporting(t *testing.T) {
	app, _ := importApp(t)

	pv, err := app.PreviewLogFile(mixedFile(t))
	if err != nil {
		t.Fatalf("PreviewLogFile: %v", err)
	}
	if len(pv.Messages) != 5 {
		t.Fatalf("preview shows %d messages, want 5", len(pv.Messages))
	}
	if pv.Result.Syslog != 2 || pv.Result.LevelDetected != 3 || pv.Result.TimeDetected != 3 {
		t.Errorf("preview counts: syslog=%d level=%d time=%d, want 2/3/3",
			pv.Result.Syslog, pv.Result.LevelDetected, pv.Result.TimeDetected)
	}
	if n := len(app.GetMessages(models.FilterCriteria{})); n != 0 {
		t.Errorf("a preview put %d messages in the buffer; it must not import", n)
	}
}

func TestImportLogFile_RefusesAnEmptyPath(t *testing.T) {
	app, _ := importApp(t)
	if _, err := app.ImportLogFile("", false); err == nil {
		t.Error("an empty path was accepted")
	}
	if _, err := app.PreviewLogFile(""); err == nil {
		t.Error("an empty path was previewed")
	}
}

// The import is capped at what the ring can hold, so the beginning of a long
// file is not silently dropped and reported as a full import.
func TestImportLogFile_StopsAtTheBufferSize(t *testing.T) {
	app, _ := importApp(t)
	size := app.server.BufferSize()
	if size <= 0 {
		t.Fatalf("BufferSize() = %d; the ring is allocated by the constructor", size)
	}

	var lines []byte
	for i := 0; i < size+5; i++ {
		lines = append(lines, "2026-03-17 21:42:10 INFO line\n"...)
	}
	p := filepath.Join(t.TempDir(), "long.log")
	if err := os.WriteFile(p, lines, 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := app.ImportLogFile(p, false)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Stopped {
		t.Error("a file longer than the ring did not report that the import stopped early")
	}
	if res.Imported != size {
		t.Errorf("Imported = %d, want the ring size %d", res.Imported, size)
	}
}
