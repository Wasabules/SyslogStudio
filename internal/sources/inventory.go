package sources

import (
	"slices"
	"sync"
	"time"
	"unicode/utf8"

	"SyslogStudio/internal/models"
	"SyslogStudio/internal/syslog"
)

// Inventory is the devices messages arrive from since the engine started
// (models.SourceDevice). Bounded: past maxDevices addresses, a new one is not
// kept — a scan from a whole network would otherwise be remembered forever.
type Inventory struct {
	mu      sync.Mutex
	devices map[string]*device
}

const (
	maxDevices   = 5000
	maxHostnames = 8
	maxRaw       = 400
	// rateSlot is the width of the slots the last minute is counted in.
	rateSlot  = 10 * time.Second
	rateSlots = 6
)

type device struct {
	models.SourceDevice
	// counts[i] is how many arrived in the slot slots[i], a count of
	// rateSlot since the epoch.
	counts [rateSlots]int64
	slots  [rateSlots]int64
}

// NewInventory makes an empty inventory.
func NewInventory() *Inventory {
	return &Inventory{devices: map[string]*device{}}
}

// note counts a message as it was read: rd is how its header was.
func (inv *Inventory) note(msg models.SyslogMessage, rd syslog.Reading) {
	at := msg.ReceivedAt
	inv.mu.Lock()
	defer inv.mu.Unlock()
	d := inv.devices[msg.SourceIP]
	if d == nil {
		if len(inv.devices) >= maxDevices {
			return
		}
		d = &device{SourceDevice: models.SourceDevice{Address: msg.SourceIP, FirstSeen: at}}
		inv.devices[msg.SourceIP] = d
	}
	d.Messages++
	d.LastSeen = at
	d.Protocol = msg.Protocol
	d.Hostname = msg.Hostname
	d.AppName = msg.AppName
	if msg.Hostname == "" {
		d.NoHostname++
	} else {
		// The last first, each once.
		d.Hostnames = slices.DeleteFunc(d.Hostnames, func(h string) bool { return h == msg.Hostname })
		d.Hostnames = append([]string{msg.Hostname}, d.Hostnames...)
		if len(d.Hostnames) > maxHostnames {
			d.Hostnames = d.Hostnames[:maxHostnames]
		}
	}
	if !rd.HasPRI {
		d.NoPriority++
	}
	if !rd.Standard {
		d.NonStandard++
	}
	d.ReadBy = msg.ReadBy
	if msg.ReadBy != "" {
		d.Ruled++
	}
	d.LastRaw = cut(msg.RawMessage, maxRaw)

	slot := at.UnixNano() / int64(rateSlot)
	i := int(slot % rateSlots)
	if d.slots[i] != slot {
		d.slots[i], d.counts[i] = slot, 0
	}
	d.counts[i]++
}

// Devices returns them, the last heard from first.
func (inv *Inventory) Devices(now time.Time) []models.SourceDevice {
	current := now.UnixNano() / int64(rateSlot)
	inv.mu.Lock()
	out := make([]models.SourceDevice, 0, len(inv.devices))
	for _, d := range inv.devices {
		dev := d.SourceDevice
		dev.Hostnames = slices.Clone(d.Hostnames)
		for i := range d.slots {
			if d.slots[i] > current-rateSlots && d.slots[i] <= current {
				dev.PerMinute += d.counts[i]
			}
		}
		out = append(out, dev)
	}
	inv.mu.Unlock()
	slices.SortFunc(out, func(a, b models.SourceDevice) int {
		if c := b.LastSeen.Compare(a.LastSeen); c != 0 {
			return c
		}
		return compareText(a.Address, b.Address)
	})
	return out
}

// Clear forgets every device: counting starts again from now.
func (inv *Inventory) Clear() {
	inv.mu.Lock()
	defer inv.mu.Unlock()
	inv.devices = map[string]*device{}
}

func compareText(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// cut shortens s to at most n bytes, on a character boundary.
func cut(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "…"
}
