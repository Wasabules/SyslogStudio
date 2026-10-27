package main

import (
	"testing"

	"SyslogStudio/internal/models"
	"SyslogStudio/internal/sources"
	"SyslogStudio/internal/storage"
)

// A person's templates: saved without the devices a rule names, offered after
// those that come with SyslogStudio, replaced by ID, deleted.
func TestSourceTemplates_Mine(t *testing.T) {
	a := newAppIn(storage.NewConfigStoreAt(t.TempDir()))
	builtIn := len(sources.Templates())

	rule := models.SourceRule{ID: "source-1", Name: "Lobby cameras", Enabled: true,
		Match:      models.SourceMatch{Sources: []string{"10.10.7.0/24"}},
		Format:     models.ImportFormat{Mode: models.ImportCustom, Pattern: `^(?P<time>\S+ \S+) \[(?P<level>\w+)\] (?P<msg>.*)$`},
		NoHostname: true}
	if _, err := a.SaveSourceTemplate(models.SourceTemplate{Name: "  ", Rule: rule}); err == nil {
		t.Error("a template with no name was saved")
	}
	bad := rule
	bad.Format.Pattern = "^(no groups)$"
	if _, err := a.SaveSourceTemplate(models.SourceTemplate{Name: "broken", Rule: bad}); err == nil {
		t.Error("a template whose pattern names no field was saved")
	}

	saved, err := a.SaveSourceTemplate(models.SourceTemplate{Name: " NVR export ", Rule: rule})
	if err != nil {
		t.Fatal(err)
	}
	if saved.ID == "" || saved.Name != "NVR export" || saved.Rule.Match.Sources != nil || saved.Rule.ID != "" ||
		saved.Rule.Name != "" || saved.Rule.Format.Pattern != rule.Format.Pattern || !saved.Rule.NoHostname {
		t.Fatalf("saved as %+v", saved)
	}
	all := a.GetSourceTemplates()
	if len(all) != builtIn+1 || all[builtIn].ID != saved.ID {
		t.Fatalf("offered: %d templates, the last %+v", len(all), all[len(all)-1])
	}

	saved.Name = "NVR export, v2"
	if _, err := a.SaveSourceTemplate(saved); err != nil {
		t.Fatal(err)
	}
	if all := a.GetSourceTemplates(); len(all) != builtIn+1 || all[builtIn].Name != "NVR export, v2" {
		t.Fatalf("replaced: %+v", all[builtIn:])
	}

	a.DeleteSourceTemplate(saved.ID)
	if len(a.GetSourceTemplates()) != builtIn {
		t.Fatal("not deleted")
	}
}
