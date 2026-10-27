package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/google/uuid"

	"SyslogStudio/internal/models"
	"SyslogStudio/internal/sources"

	wailsRuntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// --- Source rules: templates, and files to share them ------------------------
//
// Window-only: the templates are the same everywhere, and a file is read or
// written where the person sits. Rules read from a file are saved through the
// Backend like any other, so they reach the service the window drives.

// GetSourceTemplates returns the rules offered to start from: those that
// come with SyslogStudio, then those this person saved.
func (a *App) GetSourceTemplates() []models.SourceTemplate {
	return append(sources.Templates(), a.prefs.LoadSourceTemplates()...)
}

// SaveSourceTemplate saves a rule's way of reading as one of this person's
// templates — a new one, or in place of the one with its ID — and returns it.
// The devices the rule names are not part of it.
func (a *App) SaveSourceTemplate(t models.SourceTemplate) (models.SourceTemplate, error) {
	t.Name = strings.TrimSpace(t.Name)
	t.Rule = t.Rule.AsTemplate()
	if err := sources.CheckTemplate(t); err != nil {
		return models.SourceTemplate{}, err
	}
	mine := a.prefs.LoadSourceTemplates()
	replaced := false
	for i := range mine {
		if t.ID != "" && mine[i].ID == t.ID {
			mine[i], replaced = t, true
		}
	}
	if !replaced {
		t.ID = "mine-" + uuid.NewString()
		mine = append(mine, t)
	}
	a.prefs.SaveSourceTemplates(mine)
	return t, nil
}

// DeleteSourceTemplate removes one of this person's templates. The rules
// started from it keep what they took.
func (a *App) DeleteSourceTemplate(id string) {
	mine := a.prefs.LoadSourceTemplates()
	kept := mine[:0]
	for _, t := range mine {
		if t.ID != id {
			kept = append(kept, t)
		}
	}
	a.prefs.SaveSourceTemplates(kept)
}

// ExportSourceRules asks where, then writes the rules there, with this
// person's templates. "" when the person cancelled.
func (a *App) ExportSourceRules(rules []models.SourceRule) (string, error) {
	data, err := sources.EncodeFile(rules, a.prefs.LoadSourceTemplates())
	if err != nil {
		return "", err
	}
	path, err := wailsRuntime.SaveFileDialog(a.ctx, wailsRuntime.SaveDialogOptions{
		Title:           "Export source rules",
		DefaultFilename: "syslogstudio-source-rules.json",
		Filters:         []wailsRuntime.FileFilter{{DisplayName: "Source rules (*.json)", Pattern: "*.json"}},
	})
	if err != nil || path == "" {
		return "", err
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return "", fmt.Errorf("failed to write the rules: %w", err)
	}
	return path, nil
}

// ReadSourceRulesFile asks for a file of exported rules and reads it, every
// rule and template checked as it would be saved. The templates are added to
// this person's; the rules are returned, for the window to save — through the
// Backend, so that they reach the engine it drives. Nothing when the person
// cancelled.
func (a *App) ReadSourceRulesFile() (sources.RuleFile, error) {
	path, err := wailsRuntime.OpenFileDialog(a.ctx, wailsRuntime.OpenDialogOptions{
		Title:   "Import source rules",
		Filters: []wailsRuntime.FileFilter{{DisplayName: "Source rules (*.json)", Pattern: "*.json"}},
	})
	if err != nil || path == "" {
		return sources.RuleFile{}, err
	}
	f, err := os.Open(path)
	if err != nil {
		return sources.RuleFile{}, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, sources.MaxFileSize+1))
	if err != nil {
		return sources.RuleFile{}, err
	}
	file, err := sources.DecodeFile(data)
	if err != nil {
		return sources.RuleFile{}, err
	}
	for i, t := range file.Templates {
		saved, err := a.SaveSourceTemplate(t)
		if err != nil {
			return sources.RuleFile{}, err
		}
		file.Templates[i] = saved
	}
	return file, nil
}
