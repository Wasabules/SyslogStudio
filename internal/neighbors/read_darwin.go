package neighbors

import (
	"net"
	"syscall"

	"golang.org/x/net/route"
)

// read lists the routes that carry a link-layer address (RTF_LLINFO): the
// ARP and NDP entries.
func read() ([]Entry, error) {
	rib, err := route.FetchRIB(syscall.AF_UNSPEC, route.RIBTypeRoute, syscall.RTF_LLINFO)
	if err != nil {
		return nil, err
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return nil, err
	}
	var out []Entry
	for _, m := range msgs {
		rm, ok := m.(*route.RouteMessage)
		if !ok || len(rm.Addrs) <= syscall.RTAX_GATEWAY {
			continue
		}
		var ip net.IP
		switch a := rm.Addrs[syscall.RTAX_DST].(type) {
		case *route.Inet4Addr:
			ip = net.IP(append([]byte(nil), a.IP[:]...))
		case *route.Inet6Addr:
			ip = net.IP(append([]byte(nil), a.IP[:]...))
		default:
			continue
		}
		la, ok := rm.Addrs[syscall.RTAX_GATEWAY].(*route.LinkAddr)
		if !ok || len(la.Addr) == 0 {
			continue
		}
		out = append(out, Entry{IP: ip, MAC: net.HardwareAddr(append([]byte(nil), la.Addr...))})
	}
	return out, nil
}
