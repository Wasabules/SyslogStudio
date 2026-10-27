package neighbors

import (
	"bufio"
	"bytes"
	"compress/gzip"
	_ "embed"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// oui.txt.gz is the IEEE's MA-L registry, as tools/oui reduces it: who
// makes the devices whose MAC starts with each 24-bit prefix.
//
//go:embed oui.txt.gz
var ouiData []byte

var vendors struct {
	once     sync.Once
	prefixes []uint32
	names    []string
}

// Vendor names the maker of a MAC from its first three bytes, "" when the
// registry does not know it or the MAC was not given by a maker.
func Vendor(mac net.HardwareAddr) string {
	if len(mac) < 3 || Randomized(mac) {
		return ""
	}
	vendors.once.Do(loadVendors)
	p := uint32(mac[0])<<16 | uint32(mac[1])<<8 | uint32(mac[2])
	i := sort.Search(len(vendors.prefixes), func(i int) bool { return vendors.prefixes[i] >= p })
	if i < len(vendors.prefixes) && vendors.prefixes[i] == p {
		return vendors.names[i]
	}
	return ""
}

func loadVendors() {
	zr, err := gzip.NewReader(bytes.NewReader(ouiData))
	if err != nil {
		return
	}
	defer zr.Close()
	sc := bufio.NewScanner(zr)
	for sc.Scan() {
		prefix, name, ok := strings.Cut(sc.Text(), "\t")
		if !ok {
			continue
		}
		p, err := strconv.ParseUint(prefix, 16, 32)
		if err != nil {
			continue
		}
		vendors.prefixes = append(vendors.prefixes, uint32(p))
		vendors.names = append(vendors.names, name)
	}
}
