package neighbors

import (
	"encoding/binary"
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// GetIpNetTable2 (iphlpapi), which x/sys/windows does not wrap: every
// neighbor of every interface, IPv4 and IPv6, in MIB_IPNET_ROW2s.
var (
	iphlpapi           = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetIpNetTable2 = iphlpapi.NewProc("GetIpNetTable2")
	procFreeMibTable   = iphlpapi.NewProc("FreeMibTable")
)

// The layout of MIB_IPNET_TABLE2 and MIB_IPNET_ROW2 (netioapi.h).
const (
	tableRows    = 8  // NumEntries, then the rows 8-aligned
	rowSize      = 88 // sizeof(MIB_IPNET_ROW2)
	rowPhys      = 40 // PhysicalAddress[32]
	rowPhysLen   = 72 // PhysicalAddressLength
	rowState     = 76 // NL_NEIGHBOR_STATE
	afInet       = 2
	afInet6      = 23
	stateProbe   = 2 // NlnsProbe: from here on, the MAC was heard
	statePermant = 6 // NlnsPermanent
)

func read() ([]Entry, error) {
	var table unsafe.Pointer
	if r, _, _ := procGetIpNetTable2.Call(0, uintptr(unsafe.Pointer(&table))); r != 0 {
		return nil, syscall.Errno(r)
	}
	defer procFreeMibTable.Call(uintptr(table))

	n := int(*(*uint32)(table))
	out := make([]Entry, 0, n)
	for i := 0; i < n; i++ {
		row := unsafe.Slice((*byte)(unsafe.Add(table, tableRows+i*rowSize)), rowSize)
		state := binary.LittleEndian.Uint32(row[rowState:])
		if state < stateProbe || state > statePermant {
			continue
		}
		var ip net.IP
		switch binary.LittleEndian.Uint16(row[0:2]) {
		case afInet:
			ip = net.IP(append([]byte(nil), row[4:8]...))
		case afInet6:
			ip = net.IP(append([]byte(nil), row[8:24]...))
		default:
			continue
		}
		length := int(binary.LittleEndian.Uint32(row[rowPhysLen:]))
		if length <= 0 || length > 32 {
			continue
		}
		out = append(out, Entry{IP: ip, MAC: net.HardwareAddr(append([]byte(nil), row[rowPhys:rowPhys+length]...))})
	}
	return out, nil
}
