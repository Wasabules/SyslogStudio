package engine

import (
	"testing"
	"time"

	"golang.org/x/text/encoding/charmap"

	"SyslogStudio/internal/models"
)

// waitReread waits for the reading again that runs to finish.
func waitReread(t *testing.T, e *Engine) models.HistoryReread {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		p := e.GetHistoryReread()
		if !p.Running {
			return p
		}
		if time.Now().After(deadline) {
			t.Fatal("the reading again did not finish")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func reread(t *testing.T, e *Engine, opts models.RereadOptions) models.HistoryReread {
	t.Helper()
	if err := e.RereadHistory(opts); err != nil {
		t.Fatal(err)
	}
	p := waitReread(t, e)
	if p.Error != "" {
		t.Fatal(p.Error)
	}
	return p
}

// stored is a message as an older reading stored it: received from a device
// an hour ago, read as given.
func stored(id, ip, protocol string, raw []byte, host string, sev models.Severity, text string) models.SyslogMessage {
	at := time.Now().Add(-time.Hour).UTC()
	return models.SyslogMessage{
		ID: id, Timestamp: at, ReceivedAt: at, Severity: sev, SeverityLabel: models.SeverityToLabel(sev),
		Facility: models.FacUser, FacilityLabel: models.FacilityToLabel(models.FacUser),
		Hostname: host, Message: text, RawMessage: string(raw), SourceIP: ip, Protocol: protocol,
	}
}

// A rule written today reads what its device sent before it: the stored
// messages it names are read again, the others and the imported ones left as
// they are, and the raw text kept so that it can be done again.
func TestRereadHistory(t *testing.T) {
	camRaw := []byte("2026-10-27 09:14:02 ERROR motion detection failed on channel 2")
	printRaw, _ := charmap.Windows1252.NewEncoder().Bytes([]byte("<13>Oct 27 09:14:02 printsrv spooler: Impression terminée"))
	e, _ := openEngine(t, []models.SyslogMessage{
		stored("cam", "10.0.0.17", "UDP", camRaw, "", models.SevNotice, string(camRaw)),
		stored("print", "10.0.0.19", "UDP", printRaw, "printsrv", models.SevNotice, "Impression termin�e"),
		stored("imported", "10.0.0.17", "file", camRaw, "", models.SevNotice, string(camRaw)),
	})
	for _, r := range []models.SourceRule{
		{Name: "camera", Enabled: true, Match: models.SourceMatch{Sources: []string{"10.0.0.17"}},
			HostnameFromSource: true, LevelFrom: models.LevelFromMessage},
		{Name: "printer", Enabled: true, Match: models.SourceMatch{Sources: []string{"10.0.0.19"}},
			Encoding: models.EncodingWindows1252},
	} {
		if _, err := e.SaveSourceRule(r); err != nil {
			t.Fatal(err)
		}
	}
	get := func() map[string]models.SyslogMessage {
		out := map[string]models.SyslogMessage{}
		for _, m := range e.QueryMessages(models.QueryOptions{PageSize: 100}).Messages {
			out[m.ID] = m
		}
		return out
	}

	// Received before the period asked for: left alone.
	if p := reread(t, e, models.RereadOptions{Since: time.Now().Format(time.RFC3339)}); p.Changed != 0 || p.Total != 3 || p.Read != 3 {
		t.Fatalf("since now: %+v", p)
	}
	// One address: that device only.
	if p := reread(t, e, models.RereadOptions{Sources: []string{"10.0.0.19"}}); p.Changed != 1 {
		t.Fatalf("one address: %+v", p)
	}
	m := get()
	if m["print"].Message != "Impression terminée" || m["cam"].Hostname != "" {
		t.Fatalf("one address: print %q, cam %q", m["print"].Message, m["cam"].Hostname)
	}
	// Everything: the camera too, the imported line still not.
	if p := reread(t, e, models.RereadOptions{}); p.Changed != 1 {
		t.Fatalf("everything: %+v", p)
	}
	m = get()
	if cam := m["cam"]; cam.Hostname != "10.0.0.17" || cam.Severity != models.SevError || cam.RawMessage != string(camRaw) {
		t.Errorf("camera: %+v", cam)
	}
	if imp := m["imported"]; imp.Hostname != "" || imp.Severity != models.SevNotice {
		t.Errorf("an imported line was read again: %+v", imp)
	}
	// The search finds the text as now read.
	if r := e.QueryMessages(models.QueryOptions{PageSize: 10, Filter: models.FilterCriteria{Search: "terminée"}}); len(r.Messages) != 1 {
		t.Errorf("search for the decoded text: %d found", len(r.Messages))
	}

	// The rule gone, reading again undoes what it did.
	for _, r := range e.GetSourceRules() {
		e.DeleteSourceRule(r.ID)
	}
	reread(t, e, models.RereadOptions{})
	if cam := get()["cam"]; cam.Hostname == "10.0.0.17" {
		t.Errorf("the camera kept what the deleted rule read: %+v", cam)
	}

	// Rules passed in — a sealing service's — are read with instead.
	reread(t, e, models.RereadOptions{Rules: []models.SourceRule{{Name: "camera", Enabled: true,
		Match: models.SourceMatch{Sources: []string{"10.0.0.17"}}, HostnameFromSource: true}}})
	if cam := get()["cam"]; cam.Hostname != "10.0.0.17" {
		t.Errorf("the rules passed in were not used: %+v", cam)
	}

	if err := e.RereadHistory(models.RereadOptions{Sources: []string{"gateway"}}); err == nil {
		t.Error("an address that is none was accepted")
	}
}
