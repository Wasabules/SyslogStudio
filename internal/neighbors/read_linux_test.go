package neighbors

import (
	"encoding/binary"
	"net"
	"testing"

	"golang.org/x/sys/unix"
)

// One RTM_NEWNEIGH as the kernel sends it: an ndmsg, then NDA_DST and
// NDA_LLADDR, each padded to four bytes.
func TestParseNeigh(t *testing.T) {
	attr := func(typ uint16, v []byte) []byte {
		b := make([]byte, 4, 4+len(v)+3)
		binary.NativeEndian.PutUint16(b[0:2], uint16(4+len(v)))
		binary.NativeEndian.PutUint16(b[2:4], typ)
		b = append(b, v...)
		for len(b)%4 != 0 {
			b = append(b, 0)
		}
		return b
	}
	msg := func(state uint16) []byte {
		nd := make([]byte, unix.SizeofNdMsg)
		nd[0] = unix.AF_INET
		binary.NativeEndian.PutUint16(nd[8:10], state)
		nd = append(nd, attr(unix.NDA_DST, []byte{192, 168, 1, 20})...)
		return append(nd, attr(unix.NDA_LLADDR, []byte{0xe8, 0xaa, 0xcb, 0x16, 0xc4, 0x12})...)
	}
	e, ok := parseNeigh(msg(unix.NUD_STALE))
	if !ok || !e.IP.Equal(net.IPv4(192, 168, 1, 20)) || FormatMAC(e.MAC) != "e8:aa:cb:16:c4:12" {
		t.Fatalf("a stale neighbor: %v %v %v", ok, e.IP, e.MAC)
	}
	if _, ok := parseNeigh(msg(unix.NUD_FAILED)); ok {
		t.Error("a failed neighbor was read")
	}
	if _, ok := parseNeigh([]byte{1, 2, 3}); ok {
		t.Error("a short message was read")
	}
}
