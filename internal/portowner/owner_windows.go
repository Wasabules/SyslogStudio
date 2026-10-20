//go:build windows

package portowner

import (
	"encoding/binary"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	iphlpapi                = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTcpTable = iphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUdpTable = iphlpapi.NewProc("GetExtendedUdpTable")
)

// Table classes: the listening TCP sockets, and every UDP socket, each with
// its owning process.
const (
	tcpTableOwnerPIDListener = 3
	udpTableOwnerPID         = 1
)

// rowLayout is where a table's rows keep the local port and the owning PID.
type rowLayout struct {
	size, port, pid int
}

// The MIB_*ROW_OWNER_PID structures, by address family.
var (
	tcp4Row = rowLayout{size: 24, port: 8, pid: 20}
	tcp6Row = rowLayout{size: 56, port: 20, pid: 52}
	udp4Row = rowLayout{size: 12, port: 4, pid: 8}
	udp6Row = rowLayout{size: 28, port: 20, pid: 24}
)

// Find returns the process holding port for proto, "tcp" (listening) or
// "udp", on IPv4 or IPv6.
func Find(proto string, port int) (Owner, bool) {
	var proc *windows.LazyProc
	var class uint32
	var rows [2]rowLayout
	switch proto {
	case "tcp":
		proc, class, rows = procGetExtendedTcpTable, tcpTableOwnerPIDListener, [2]rowLayout{tcp4Row, tcp6Row}
	case "udp":
		proc, class, rows = procGetExtendedUdpTable, udpTableOwnerPID, [2]rowLayout{udp4Row, udp6Row}
	default:
		return Owner{}, false
	}
	for i, family := range []uint32{windows.AF_INET, windows.AF_INET6} {
		buf, err := table(proc, family, class)
		if err != nil {
			continue
		}
		if pid, ok := ownerIn(buf, rows[i], port); ok {
			return Owner{PID: pid, Name: processName(pid)}, true
		}
	}
	return Owner{}, false
}

// table reads one of the extended tables, growing the buffer while sockets
// open between the call that sizes it and the one that fills it.
func table(proc *windows.LazyProc, family, class uint32) ([]byte, error) {
	size := uint32(16 << 10)
	for {
		buf := make([]byte, size)
		r, _, _ := proc.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)),
			0, uintptr(family), uintptr(class), 0)
		switch err := windows.Errno(r); err {
		case 0:
			return buf, nil
		case windows.ERROR_INSUFFICIENT_BUFFER:
			continue
		default:
			return nil, err
		}
	}
}

// ownerIn looks for port in a table: a count, then the rows. The port is in
// network byte order in the low half of its field.
func ownerIn(buf []byte, row rowLayout, port int) (uint32, bool) {
	if len(buf) < 4 {
		return 0, false
	}
	n := int(binary.LittleEndian.Uint32(buf))
	for i := range n {
		r := buf[4+i*row.size:]
		if len(r) < row.size {
			break
		}
		if int(binary.BigEndian.Uint16(r[row.port:])) == port {
			return binary.LittleEndian.Uint32(r[row.pid:]), true
		}
	}
	return 0, false
}

// processName is the executable's file name. A snapshot lists every process
// with its name, without opening any: a system process another account may
// not open is named all the same.
func processName(pid uint32) string {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(snap)
	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	for err = windows.Process32First(snap, &e); err == nil; err = windows.Process32Next(snap, &e) {
		if e.ProcessID == pid {
			return windows.UTF16ToString(e.ExeFile[:])
		}
	}
	return ""
}
