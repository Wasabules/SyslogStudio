package neighbors

import (
	"net"
	"testing"

	"SyslogStudio/internal/models"
)

func TestParseMAC(t *testing.T) {
	for in, want := range map[string]string{
		"AA:BB:CC:DD:EE:FF":   "aa:bb:cc:dd:ee:ff",
		"aa-bb-cc-dd-ee-ff":   "aa:bb:cc:dd:ee:ff",
		"aabb.ccdd.eeff":      "aa:bb:cc:dd:ee:ff",
		"AABBCCDDEEFF":        "aa:bb:cc:dd:ee:ff",
		" aa:bb:cc:dd:ee:ff ": "aa:bb:cc:dd:ee:ff",
	} {
		if got, ok := ParseMAC(in); !ok || got != want {
			t.Errorf("ParseMAC(%q) = %q, %v", in, got, ok)
		}
	}
	for _, bad := range []string{"", "aa:bb:cc", "10.0.0.1", "aa:bb:cc:dd:ee:ff:00:11", "gg:bb:cc:dd:ee:ff"} {
		if _, ok := ParseMAC(bad); ok {
			t.Errorf("ParseMAC(%q) accepted", bad)
		}
	}
}

func TestVendor(t *testing.T) {
	mac := func(s string) net.HardwareAddr { m, _ := net.ParseMAC(s); return m }
	if v := Vendor(mac("38:07:16:1d:30:4c")); v != "FREEBOX SAS" {
		t.Errorf("a Freebox: %q", v)
	}
	if v := Vendor(mac("00:00:0c:12:34:56")); v != "Cisco Systems, Inc" {
		t.Errorf("Cisco's first: %q", v)
	}
	// Chosen by the device: no maker to name, though its bytes may match one.
	if r := mac("d2:00:ef:ff:89:56"); !Randomized(r) || Vendor(r) != "" {
		t.Errorf("a private address: randomized %v, vendor %q", Randomized(r), Vendor(r))
	}
	if Vendor(nil) != "" {
		t.Error("no MAC, a vendor")
	}
}

func TestUsable(t *testing.T) {
	mac := func(s string) net.HardwareAddr { m, _ := net.ParseMAC(s); return m }
	for _, c := range []struct {
		ip, mac string
		want    bool
	}{
		{"192.168.1.20", "e8:aa:cb:16:c4:12", true},
		{"fe80::1", "e8:aa:cb:16:c4:12", true},
		{"224.0.0.22", "01:00:5e:00:00:16", false},
		{"255.255.255.255", "ff:ff:ff:ff:ff:ff", false},
		{"192.168.1.30", "00:00:00:00:00:00", false},
		{"127.0.0.1", "e8:aa:cb:16:c4:12", false},
	} {
		if got := usable(Entry{IP: net.ParseIP(c.ip), MAC: mac(c.mac)}); got != c.want {
			t.Errorf("%s %s: %v", c.ip, c.mac, got)
		}
	}
}

// Only an address on one of this machine's networks gets a MAC: one behind a
// router would get the router's.
func TestCache_Lookup(t *testing.T) {
	_, lan, _ := net.ParseCIDR("192.168.1.10/24")
	lan.IP = net.ParseIP("192.168.1.10")
	router, _ := net.ParseMAC("38:07:16:1d:30:4c")
	camera, _ := net.ParseMAC("e8:aa:cb:16:c4:12")
	c := &Cache{
		read: func() ([]Entry, error) {
			return []Entry{
				{IP: net.ParseIP("192.168.1.254"), MAC: router},
				{IP: net.ParseIP("192.168.1.20"), MAC: camera},
				// What a table holds of an address it reached through the router.
				{IP: net.ParseIP("10.20.0.5"), MAC: router},
			}, nil
		},
		addrs: func() ([]net.Addr, error) {
			return []net.Addr{lan, &net.IPNet{IP: net.IPv4(127, 0, 0, 1), Mask: net.CIDRMask(8, 32)}}, nil
		},
	}
	c.Refresh()

	if i := c.Lookup("192.168.1.20"); !i.OnLink || i.MAC != "e8:aa:cb:16:c4:12" || i.Vendor == "" || i.ThisMachine {
		t.Errorf("a device on the network: %+v", i)
	}
	if i := c.Lookup("10.20.0.5"); i.OnLink || i.MAC != "" {
		t.Errorf("a device behind the router got its MAC: %+v", i)
	}
	if i := c.Lookup("192.168.1.99"); !i.OnLink || i.MAC != "" {
		t.Errorf("on the network, not in the table: %+v", i)
	}
	for _, self := range []string{"192.168.1.10", "127.0.0.1", "::1"} {
		if i := c.Lookup(self); !i.ThisMachine || i.MAC != "" {
			t.Errorf("%s, this machine: %+v", self, i)
		}
	}
	if i := c.Lookup("not an address"); i != (models.AddressInfo{}) {
		t.Errorf("not an address: %+v", i)
	}
	if c.MAC("192.168.1.20") != "e8:aa:cb:16:c4:12" {
		t.Error("MAC")
	}
}

// The table read on this machine, whatever it holds: well formed.
func TestRead(t *testing.T) {
	entries, err := Read()
	if err == ErrUnsupported {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !usable(e) {
			t.Errorf("an entry not usable: %v %v", e.IP, e.MAC)
		}
	}
}
