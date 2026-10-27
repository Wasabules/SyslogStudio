package neighbors

import (
	"log/slog"
	"net"
	"sync"
	"time"

	"SyslogStudio/internal/models"
)

// Every is how often the cache reads the table again: entries live minutes,
// and a device that has just appeared waits half a minute at most.
const Every = 30 * time.Second

// Cache keeps the table and this machine's networks, read every so often:
// looking an address up costs a map read, whatever the rate of messages.
type Cache struct {
	mu    sync.RWMutex
	macs  map[string]net.HardwareAddr // by IP, as net.IP.String writes it
	nets  []*net.IPNet
	self  map[string]bool
	read  func() ([]Entry, error)
	addrs func() ([]net.Addr, error)
	// warned keeps an unreadable table from being logged every Every.
	warned bool
}

// NewCache makes an empty cache; Refresh fills it.
func NewCache() *Cache {
	return &Cache{read: Read, addrs: net.InterfaceAddrs}
}

// Refresh reads the table and this machine's addresses again.
func (c *Cache) Refresh() {
	entries, err := c.read()
	macs := make(map[string]net.HardwareAddr, len(entries))
	for _, e := range entries {
		macs[e.IP.String()] = e.MAC
	}
	var nets []*net.IPNet
	self := map[string]bool{}
	if addrs, aerr := c.addrs(); aerr == nil {
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				self[n.IP.String()] = true
				if !n.IP.IsLoopback() {
					nets = append(nets, n)
				}
			}
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err != nil {
		if !c.warned {
			slog.Warn("neighbor table not read: no MAC addresses", "error", err)
			c.warned = true
		}
		// What was known stays known until the table reads again.
		macs = c.macs
	}
	c.macs, c.nets, c.self = macs, nets, self
}

// Lookup says what is known of an address: whether it is this machine, on
// one of its networks, and if so the MAC the table has for it and its maker.
func (c *Cache) Lookup(address string) models.AddressInfo {
	ip := net.ParseIP(address)
	if ip == nil {
		return models.AddressInfo{}
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	info := models.AddressInfo{}
	if ip.IsLoopback() || c.self[ip.String()] {
		info.ThisMachine, info.OnLink = true, true
		return info
	}
	for _, n := range c.nets {
		if n.Contains(ip) {
			info.OnLink = true
			break
		}
	}
	// Off this machine's networks, the table has the router's MAC, if any:
	// not the device's.
	if !info.OnLink {
		return info
	}
	if mac, ok := c.macs[ip.String()]; ok {
		info.MAC = FormatMAC(mac)
		info.Randomized = Randomized(mac)
		info.Vendor = Vendor(mac)
	}
	return info
}

// MAC is the MAC Lookup gives, "" when there is none.
func (c *Cache) MAC(address string) string {
	return c.Lookup(address).MAC
}
