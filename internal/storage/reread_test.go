package storage

import (
	"testing"

	"SyslogStudio/internal/models"
)

// A reading rewritten in place: the fields it reads change, the raw message,
// source and arrival stay, and the search index finds the new text and no
// longer the old.
func TestRewriteReadings_KeepsTheIndexInStep(t *testing.T) {
	ls := newTestStore(t, models.StorageConfig{})
	a := testMessage(1, "", "2026-10-27T09", "stale reading", models.SevInformational)
	a.RawMessage = "<134>Oct 27 09:14:02 dhcp: lease assigned"
	a.SourceIP, a.Protocol = "10.0.0.5", "UDP"
	b := testMessage(2, "web-01", "nginx", "upstream timed out", models.SevError)
	if err := ls.InsertMessages([]models.SyslogMessage{a, b}); err != nil {
		t.Fatal(err)
	}

	count, last, err := ls.Extent()
	if err != nil || count != 2 || last < 2 {
		t.Fatalf("extent: %d, %d, %v", count, last, err)
	}
	msgs, next, err := ls.MessagesUpTo(0, last, 1)
	if err != nil || len(msgs) != 1 || next >= last {
		t.Fatalf("first batch: %d messages, next %d, %v", len(msgs), next, err)
	}
	if more, _, _ := ls.MessagesUpTo(last, last, 10); len(more) != 0 {
		t.Fatal("read past the last rowid")
	}

	fixed := a
	fixed.Hostname, fixed.AppName, fixed.Message = "10.0.0.5", "dhcp", "renewed lease"
	fixed.Severity, fixed.SeverityLabel = models.SevWarning, models.SeverityToLabel(models.SevWarning)
	gone := testMessage(99, "", "", "", models.SevInformational)
	n, err := ls.RewriteReadings([]models.SyslogMessage{fixed, gone})
	if err != nil || n != 1 {
		t.Fatalf("rewrote %d, %v", n, err)
	}

	got, _, err := ls.MessagesUpTo(0, last, 10)
	if err != nil || len(got) != 2 {
		t.Fatalf("read back: %d, %v", len(got), err)
	}
	r := got[0]
	if r.Hostname != "10.0.0.5" || r.AppName != "dhcp" || r.Message != "renewed lease" || r.Severity != models.SevWarning {
		t.Errorf("not rewritten: %+v", r)
	}
	if r.RawMessage != a.RawMessage || r.SourceIP != a.SourceIP || r.Protocol != "UDP" || !r.ReceivedAt.Equal(a.ReceivedAt) {
		t.Errorf("what was received changed: %+v", r)
	}
	if got[1].Message != b.Message {
		t.Errorf("another message changed: %+v", got[1])
	}

	db := ls.handle()
	find := func(word string) int {
		var n int
		if err := db.QueryRow("SELECT count(*) FROM messages_fts WHERE messages_fts MATCH ?", word).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	// "assigned" is in the raw message, which stays indexed.
	if find("renewed") != 1 || find("stale") != 0 || find("assigned") != 1 {
		t.Errorf("the index has renewed %d, stale %d, assigned %d", find("renewed"), find("stale"), find("assigned"))
	}
	if _, err := db.Exec("INSERT INTO messages_fts(messages_fts) VALUES('integrity-check')"); err != nil {
		t.Errorf("the index no longer matches the table: %v", err)
	}
}
