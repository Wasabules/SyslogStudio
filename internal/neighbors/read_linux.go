package neighbors

import (
	"encoding/binary"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// read asks the kernel for its neighbors over netlink (RTM_GETNEIGH): IPv4
// and IPv6 alike, which /proc/net/arp does not.
func read() ([]Entry, error) {
	rib, err := syscall.NetlinkRIB(unix.RTM_GETNEIGH, unix.AF_UNSPEC)
	if err != nil {
		return nil, err
	}
	msgs, err := syscall.ParseNetlinkMessage(rib)
	if err != nil {
		return nil, err
	}
	var out []Entry
	for _, m := range msgs {
		if m.Header.Type != unix.RTM_NEWNEIGH {
			continue
		}
		if e, ok := parseNeigh(m.Data); ok {
			out = append(out, e)
		}
	}
	return out, nil
}

// parseNeigh reads one neighbor: an ndmsg, then its attributes.
func parseNeigh(data []byte) (Entry, bool) {
	if len(data) < unix.SizeofNdMsg {
		return Entry{}, false
	}
	// struct ndmsg: family, two pads, ifindex, then the state.
	state := binary.NativeEndian.Uint16(data[8:10])
	if state&(unix.NUD_INCOMPLETE|unix.NUD_FAILED|unix.NUD_NOARP) != 0 || state == unix.NUD_NONE {
		return Entry{}, false
	}
	var e Entry
	attrs := data[unix.SizeofNdMsg:]
	for len(attrs) >= 4 {
		l := int(binary.NativeEndian.Uint16(attrs[0:2]))
		if l < 4 || l > len(attrs) {
			break
		}
		v := attrs[4:l]
		switch binary.NativeEndian.Uint16(attrs[2:4]) {
		case unix.NDA_DST:
			e.IP = net.IP(append([]byte(nil), v...))
		case unix.NDA_LLADDR:
			e.MAC = net.HardwareAddr(append([]byte(nil), v...))
		}
		next := (l + 3) &^ 3
		if next > len(attrs) {
			break
		}
		attrs = attrs[next:]
	}
	return e, e.IP != nil && e.MAC != nil
}
