package sources

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"SyslogStudio/internal/models"
)

// A file of source rules: what one installation exports for another to
// import, with the templates the person saved. Both travel without their ids
// — the one importing gives them its own — and are checked as they would be
// when saved.

const (
	fileFormat  = "syslogstudio-source-rules"
	fileVersion = 1
	// maxFileRules bounds what one file brings.
	maxFileRules = 500
	// MaxFileSize bounds what is read of one.
	MaxFileSize = 4 << 20
)

// RuleFile is what a file of source rules holds.
type RuleFile struct {
	Format    string                  `json:"format"`
	Version   int                     `json:"version"`
	Rules     []models.SourceRule     `json:"rules"`
	Templates []models.SourceTemplate `json:"templates,omitempty"`
}

// EncodeFile writes rules and templates as a file to share.
func EncodeFile(rules []models.SourceRule, templates []models.SourceTemplate) ([]byte, error) {
	f := RuleFile{Format: fileFormat, Version: fileVersion, Rules: []models.SourceRule{}}
	for _, r := range rules {
		r.ID = ""
		f.Rules = append(f.Rules, r)
	}
	for _, t := range templates {
		t.ID = ""
		f.Templates = append(f.Templates, t)
	}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// DecodeFile reads a file of rules, refusing it whole when one of them would
// not be saved: half a set of rules that work together reads devices in ways
// nobody chose.
func DecodeFile(data []byte) (RuleFile, error) {
	if len(data) > MaxFileSize {
		return RuleFile{}, errors.New("this file is too large to be a file of source rules")
	}
	var f RuleFile
	if err := json.Unmarshal(data, &f); err != nil || f.Format != fileFormat {
		return RuleFile{}, errors.New("this is not a file of source rules exported by SyslogStudio")
	}
	if f.Version > fileVersion {
		return RuleFile{}, errors.New("these rules were exported by a newer SyslogStudio: update it to import them")
	}
	if len(f.Rules)+len(f.Templates) == 0 {
		return RuleFile{}, errors.New("this file holds no rule and no template")
	}
	if n := len(f.Rules) + len(f.Templates); n > maxFileRules {
		return RuleFile{}, fmt.Errorf("this file holds %d rules and templates, more than the %d one file may bring", n, maxFileRules)
	}
	for i := range f.Rules {
		f.Rules[i].ID = ""
		if err := Compile(f.Rules[i]); err != nil {
			return RuleFile{}, fmt.Errorf("rule %q: %w", nameOr(f.Rules[i].Name, i), err)
		}
	}
	for i := range f.Templates {
		f.Templates[i].ID = ""
		if err := CheckTemplate(f.Templates[i]); err != nil {
			return RuleFile{}, fmt.Errorf("template %q: %w", nameOr(f.Templates[i].Name, i), err)
		}
	}
	return f, nil
}

func nameOr(name string, i int) string {
	if name == "" {
		return fmt.Sprintf("#%d", i+1)
	}
	return name
}

// CheckTemplate says what is wrong with a template a person saved: a name,
// and a way of reading that would compile once a device is named.
func CheckTemplate(t models.SourceTemplate) error {
	if strings.TrimSpace(t.Name) == "" {
		return errors.New("give the template a name")
	}
	if len(t.Name) > 200 {
		return errors.New("the template's name is longer than 200 characters")
	}
	r := t.Rule.AsTemplate()
	r.Match = models.SourceMatch{Sources: []string{"0.0.0.0/0"}}
	return Compile(r)
}
