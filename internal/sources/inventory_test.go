package sources

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"SyslogStudio/internal/models"
	"SyslogStudio/internal/syslog"
)

// What each device sends is counted as it is read: how many, how lately,
// with which header, which hostnames, which rule.
func TestInventory(t *testing.T) {
	r := reader(t, models.SourceRule{Name: "camera", Enabled: true, Match: bySource("10.0.0.17"), NoHostname: true})
	inv := NewInventory()
	r.SetInventory(inv)

	r.Read([]byte("<14>1 2026-10-27T09:14:02Z web-01 nginx - - - hello"), "10.0.0.5", "UDP")
	r.Read([]byte("<14>Oct 27 09:14:03 relay-a sshd: hi"), "10.0.0.9", "UDP")
	r.Read([]byte("<14>Oct 27 09:14:04 relay-b sshd: hi"), "10.0.0.9", "UDP")
	r.Read([]byte("<14>Oct 27 09:14:05 relay-a sshd: again"), "10.0.0.9", "UDP")
	r.Read([]byte("2026-10-27 09:14:02 ERROR motion detection failed"), "10.0.0.17", "UDP")
	r.Read([]byte(`<189>date=2026-10-27 time=09:14:02 devname="FGT60F" level="warning" msg="x"`), "10.0.0.1", "UDP")
	// Read again and tried: not received, not counted.
	r.ReadAt([]byte("<14>Oct 27 09:14:03 relay-c sshd: hi"), "10.0.0.9", "UDP", time.Now())
	Try(models.SourceRule{Name: "t", Enabled: true, Match: bySource("10.0.0.9")}, []models.SourceSample{{Raw: "x", SourceIP: "10.0.0.9", Protocol: "UDP"}})

	devs := inv.Devices(time.Now())
	by := map[string]models.SourceDevice{}
	for _, d := range devs {
		by[d.Address] = d
	}
	if len(devs) != 4 || devs[0].Address != "10.0.0.1" {
		t.Fatalf("devices, the last heard from first: %+v", devs)
	}
	if d := by["10.0.0.5"]; d.Messages != 1 || d.NonStandard != 0 || d.NoPriority != 0 || d.Hostname != "web-01" || d.AppName != "nginx" {
		t.Errorf("a standard sender: %+v", d)
	}
	if d := by["10.0.0.9"]; d.Messages != 3 || d.PerMinute != 3 || strings.Join(d.Hostnames, ",") != "relay-a,relay-b" || d.LastRaw != "<14>Oct 27 09:14:05 relay-a sshd: again" {
		t.Errorf("behind a relay: %+v", d)
	}
	if d := by["10.0.0.17"]; d.NoPriority != 1 || d.NonStandard != 1 || d.Ruled != 1 || d.ReadBy != "camera" || d.Hostname != "10.0.0.17" {
		t.Errorf("a camera its rule reads: %+v", d)
	}
	if d := by["10.0.0.1"]; d.NonStandard != 1 || d.NoPriority != 0 || d.NoHostname != 0 {
		t.Errorf("key=value after a priority: %+v", d)
	}

	// A minute later, nothing arrived in the last one.
	if d := inv.Devices(time.Now().Add(2 * time.Minute)); d[0].PerMinute != 0 {
		t.Errorf("per minute, two minutes on: %d", d[0].PerMinute)
	}

	inv.Clear()
	if len(inv.Devices(time.Now())) != 0 {
		t.Error("not cleared")
	}
}

// Past maxDevices addresses, a new one is not kept; those kept still count.
func TestInventory_Bounded(t *testing.T) {
	inv := NewInventory()
	at := time.Now()
	for i := 0; i < maxDevices+10; i++ {
		inv.note(models.SyslogMessage{SourceIP: fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255), ReceivedAt: at}, syslog.Reading{HasPRI: true, Standard: true})
	}
	inv.note(models.SyslogMessage{SourceIP: "10.0.0.0", ReceivedAt: at}, syslog.Reading{})
	devs := inv.Devices(at)
	if len(devs) != maxDevices {
		t.Fatalf("%d devices kept", len(devs))
	}
	for _, d := range devs {
		if d.Address == "10.0.0.0" && (d.Messages != 2 || d.NoPriority != 1) {
			t.Errorf("a device kept stopped counting: %+v", d)
		}
	}
}

func TestCut(t *testing.T) {
	if got := cut("abcdé", 5); got != "abcd…" {
		t.Errorf("cut in the middle of é: %q", got)
	}
	if got := cut("abc", 5); got != "abc" {
		t.Errorf("short: %q", got)
	}
}

// A MAC seen at a second address is a device that moved (DHCP); an address
// whose MAC changes changed hands. Both are remembered.
func TestInventory_MACs(t *testing.T) {
	inv := NewInventory()
	at := time.Now()
	for _, ip := range []string{"192.168.1.20", "192.168.1.31", "192.168.1.50"} {
		inv.note(models.SyslogMessage{SourceIP: ip, ReceivedAt: at}, syslog.Reading{HasPRI: true, Standard: true})
	}
	table := map[string]string{"192.168.1.20": "aa:aa:aa:00:00:01", "192.168.1.50": "aa:aa:aa:00:00:05"}
	inv.ObserveMACs(func(ip string) string { return table[ip] })
	// The camera's lease moved it to .31; .50 was replaced by another box.
	table = map[string]string{"192.168.1.31": "aa:aa:aa:00:00:01", "192.168.1.50": "bb:bb:bb:00:00:09"}
	inv.ObserveMACs(func(ip string) string { return table[ip] })

	by := map[string]models.SourceDevice{}
	for _, d := range inv.Devices(at) {
		by[d.Address] = d
	}
	if d := by["192.168.1.31"]; d.MAC != "aa:aa:aa:00:00:01" || strings.Join(d.AlsoAt, ",") != "192.168.1.20" {
		t.Errorf("moved to .31: %+v", d)
	}
	if d := by["192.168.1.20"]; d.MAC != "aa:aa:aa:00:00:01" || strings.Join(d.AlsoAt, ",") != "192.168.1.31" {
		t.Errorf("its old address: %+v", d)
	}
	if d := by["192.168.1.50"]; d.MAC != "bb:bb:bb:00:00:09" || strings.Join(d.PreviousMACs, ",") != "aa:aa:aa:00:00:05" || len(d.AlsoAt) != 0 {
		t.Errorf("changed hands: %+v", d)
	}
}
