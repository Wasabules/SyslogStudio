package engine

// Source rules: how the messages of particular devices are read (package
// sources). Kept in config.json in the order they are tried, and applied as
// messages arrive.

import (
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"SyslogStudio/internal/models"
	"SyslogStudio/internal/neighbors"
	"SyslogStudio/internal/sources"
)

// maxTrySamples bounds what one try reads: the editor shows the latest few.
const maxTrySamples = 100

// applySourceRules gives the reader the rules as saved.
func (e *Engine) applySourceRules() {
	if e.reader == nil {
		return
	}
	if err := e.reader.SetRules(e.configStore.LoadSourceRules()); err != nil {
		slog.Warn("source rules", "error", err)
	}
}

// GetSourceDevices returns the devices messages have arrived from since the
// engine started, the last heard from first, with what the neighbor table
// says of each.
func (e *Engine) GetSourceDevices() []models.SourceDevice {
	if e.inventory == nil {
		return []models.SourceDevice{}
	}
	devices := e.inventory.Devices(time.Now())
	if e.neighbors == nil {
		return devices
	}
	for i := range devices {
		d := &devices[i]
		remembered := d.MAC
		d.AddressInfo = e.neighbors.Lookup(d.Address)
		// Gone from the table since, the MAC last seen still says who it was.
		if d.MAC == "" && d.OnLink && !d.ThisMachine && remembered != "" {
			if mac, ok := neighbors.ParseMAC(remembered); ok {
				hw, _ := net.ParseMAC(mac)
				d.MAC, d.Vendor, d.Randomized = mac, neighbors.Vendor(hw), neighbors.Randomized(hw)
			}
		}
	}
	return devices
}

// LookupAddress says what is known of an address: whether it is this
// machine or on one of its networks, and then its MAC and maker.
func (e *Engine) LookupAddress(address string) models.AddressInfo {
	if e.neighbors == nil {
		return models.AddressInfo{}
	}
	return e.neighbors.Lookup(address)
}

// watchNeighbors reads the neighbor table every neighbors.Every, and has the
// inventory remember the MAC of each address it has heard from.
func (e *Engine) watchNeighbors(stop <-chan struct{}) {
	tick := time.NewTicker(neighbors.Every)
	defer tick.Stop()
	for {
		e.neighbors.Refresh()
		e.inventory.ObserveMACs(e.neighbors.MAC)
		select {
		case <-stop:
			return
		case <-tick.C:
		}
	}
}

// ClearSourceDevices forgets them: counting starts again from now.
func (e *Engine) ClearSourceDevices() {
	if e.inventory != nil {
		e.inventory.Clear()
	}
}

// GetSourceRules returns the rules, in the order they are tried.
func (e *Engine) GetSourceRules() []models.SourceRule {
	rules := e.configStore.LoadSourceRules()
	if rules == nil {
		return []models.SourceRule{}
	}
	return rules
}

// SaveSourceRule adds a rule — last, so it is tried after those already
// there — or replaces one, and returns it as saved.
func (e *Engine) SaveSourceRule(r models.SourceRule) (models.SourceRule, error) {
	r.Name = strings.TrimSpace(r.Name)
	if r.Name == "" {
		r.Name = defaultRuleName(r.Match)
	}
	if err := sources.Compile(r); err != nil {
		return models.SourceRule{}, err
	}
	if r.ID == "" {
		r.ID = newID("source")
	}
	rules := e.configStore.LoadSourceRules()
	replaced := false
	for i := range rules {
		if rules[i].ID == r.ID {
			rules[i], replaced = r, true
		}
	}
	if !replaced {
		rules = append(rules, r)
	}
	e.configStore.SaveSourceRules(rules)
	e.applySourceRules()
	return r, nil
}

// defaultRuleName names a rule after what it matches.
func defaultRuleName(m models.SourceMatch) string {
	for _, list := range [][]string{m.Sources, m.Hostnames, m.AppNames} {
		for _, s := range list {
			if s = strings.TrimSpace(s); s != "" {
				return s
			}
		}
	}
	return "Source rule"
}

// DeleteSourceRule removes a rule.
func (e *Engine) DeleteSourceRule(id string) {
	rules := e.configStore.LoadSourceRules()
	out := rules[:0]
	for _, r := range rules {
		if r.ID != id {
			out = append(out, r)
		}
	}
	e.configStore.SaveSourceRules(out)
	e.applySourceRules()
}

// ReorderSourceRules puts the rules in the order given by their ids: the
// order they are tried in. Every rule has to be named once.
func (e *Engine) ReorderSourceRules(ids []string) error {
	rules := e.configStore.LoadSourceRules()
	if len(ids) != len(rules) {
		return fmt.Errorf("the order names %d rules, there are %d", len(ids), len(rules))
	}
	byID := make(map[string]models.SourceRule, len(rules))
	for _, r := range rules {
		byID[r.ID] = r
	}
	out := make([]models.SourceRule, 0, len(rules))
	for _, id := range ids {
		r, ok := byID[id]
		if !ok {
			return fmt.Errorf("no rule %q, or named twice", id)
		}
		delete(byID, id)
		out = append(out, r)
	}
	e.configStore.SaveSourceRules(out)
	e.applySourceRules()
	return nil
}

// TrySourceRule reads samples without any rule and with r, saved or not: what
// the rule editor shows while a rule is written.
func (e *Engine) TrySourceRule(r models.SourceRule, samples []models.SourceSample) ([]models.SourceTrial, error) {
	if len(samples) > maxTrySamples {
		samples = samples[:maxTrySamples]
	}
	if strings.TrimSpace(r.Name) == "" {
		r.Name = defaultRuleName(r.Match)
	}
	return sources.Try(r, samples)
}
