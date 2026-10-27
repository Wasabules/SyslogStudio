// Package neighbors says which link-layer (MAC) address answers for an IP:
// what the system's neighbor table — ARP for IPv4, NDP for IPv6 — has learnt
// of the networks this machine is on.
//
// A message carries no MAC. The table only knows the devices on this
// machine's own networks: one behind a router reaches us with the router's
// MAC, so an address that is not on one of them is said to be routed, and
// given none.
package neighbors

import (
	"errors"
	"net"
	"strings"
)

// ErrUnsupported is a system whose table is not read.
var ErrUnsupported = errors.New("the neighbor table is not read on this system")

// Entry is one line of the table.
type Entry struct {
	IP  net.IP
	MAC net.HardwareAddr
}

// Read returns the table: the entries with a unicast MAC for a unicast IP,
// whatever their age — a stale entry still says who answered.
func Read() ([]Entry, error) {
	entries, err := read()
	if err != nil {
		return nil, err
	}
	out := entries[:0]
	for _, e := range entries {
		if usable(e) {
			out = append(out, e)
		}
	}
	return out, nil
}

func usable(e Entry) bool {
	if e.IP == nil || e.IP.IsUnspecified() || e.IP.IsMulticast() || e.IP.Equal(net.IPv4bcast) || e.IP.IsLoopback() {
		return false
	}
	if len(e.MAC) != 6 || e.MAC[0]&1 == 1 {
		return false // multicast or broadcast
	}
	for _, b := range e.MAC {
		if b != 0 {
			return true
		}
	}
	return false
}

// FormatMAC writes a MAC the way the application shows and compares it:
// lowercase, colon-separated.
func FormatMAC(mac net.HardwareAddr) string {
	return strings.ToLower(mac.String())
}

// ParseMAC reads a MAC however it is written — aa:bb:cc:dd:ee:ff,
// AA-BB-CC-DD-EE-FF, aabb.ccdd.eeff, aabbccddeeff — as FormatMAC writes it.
func ParseMAC(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if len(s) == 12 && !strings.ContainsAny(s, ":-.") {
		s = s[0:2] + ":" + s[2:4] + ":" + s[4:6] + ":" + s[6:8] + ":" + s[8:10] + ":" + s[10:12]
	}
	mac, err := net.ParseMAC(s)
	if err != nil || len(mac) != 6 {
		return "", false
	}
	return FormatMAC(mac), true
}

// Randomized says the MAC is locally administered: chosen by the device
// rather than its maker — a phone's private address, a virtual machine's.
// It has no maker to name.
func Randomized(mac net.HardwareAddr) bool {
	return len(mac) > 0 && mac[0]&2 == 2
}
