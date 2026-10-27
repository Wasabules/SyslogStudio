package engine

import (
	"testing"

	"SyslogStudio/internal/event"
	"SyslogStudio/internal/models"
	"SyslogStudio/internal/storage"
)

// Source rules are saved in the order they are tried, apply as soon as they
// are saved, and reach the service with the rest of the configuration.
func TestSourceRules_SavedOrderedAppliedAndBundled(t *testing.T) {
	e, _ := openEngine(t, nil)

	if _, err := e.SaveSourceRule(models.SourceRule{Name: "broken", Enabled: true}); err == nil {
		t.Fatal("a rule matching nothing was saved")
	}
	cam, err := e.SaveSourceRule(models.SourceRule{Enabled: true,
		Match: models.SourceMatch{Sources: []string{"10.0.0.9"}}, AppName: "camera"})
	if err != nil {
		t.Fatal(err)
	}
	if cam.ID == "" || cam.Name != "10.0.0.9" {
		t.Fatalf("saved as %+v", cam)
	}
	all, err := e.SaveSourceRule(models.SourceRule{Name: "everything", Enabled: true,
		Match: models.SourceMatch{Sources: []string{"0.0.0.0/0"}}, AppName: "any"})
	if err != nil {
		t.Fatal(err)
	}

	read := func() string { return e.reader.Read([]byte("<14>motion"), "10.0.0.9", "UDP").AppName }
	if got := read(); got != "camera" {
		t.Fatalf("the first rule did not apply: %q", got)
	}
	if err := e.ReorderSourceRules([]string{all.ID, cam.ID}); err != nil {
		t.Fatal(err)
	}
	if got := read(); got != "any" {
		t.Fatalf("after reordering: %q", got)
	}
	if err := e.ReorderSourceRules([]string{all.ID}); err == nil {
		t.Fatal("an order missing a rule was accepted")
	}

	b, err := e.ExportBundle()
	if err != nil {
		t.Fatal(err)
	}
	if len(b.SourceRules) != 2 {
		t.Fatalf("the bundle carries %d rules", len(b.SourceRules))
	}
	svc := New(storage.NewConfigStoreAt(t.TempDir()))
	if err := svc.ImportBundle(b); err != nil {
		t.Fatal(err)
	}
	if err := svc.Open(event.NewMockEventEmitter()); err != nil {
		t.Fatal(err)
	}
	defer svc.Close()
	if got := svc.reader.Read([]byte("<14>motion"), "10.0.0.9", "UDP").AppName; got != "any" {
		t.Fatalf("the service reads it as %q", got)
	}

	e.DeleteSourceRule(all.ID)
	if rules := e.GetSourceRules(); len(rules) != 1 || rules[0].ID != cam.ID {
		t.Fatalf("after deleting: %+v", rules)
	}
	if got := read(); got != "camera" {
		t.Fatalf("after deleting: %q", got)
	}
}
