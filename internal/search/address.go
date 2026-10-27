package search

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"unicode/utf8"
)

// AddressKind is how an address box or an address list entry is read.
type AddressKind int

const (
	// AddressAny is an empty box: every address passes.
	AddressAny AddressKind = iota
	// AddressExact is one address, written whole: "10.10.1.1" is that
	// device and not 10.10.1.10 to 10.10.1.199.
	AddressExact
	// AddressNet is a CIDR: "10.10.1.0/24".
	AddressNet
	// AddressGlob holds a "*" (any run of characters) or a "?" (one):
	// "10.10.1.*".
	AddressGlob
	// AddressText is anything else. The Source IP filter box reads it as
	// text the address contains — "10.10." while it is being typed; a list
	// entry (source rules, routing) as the address itself.
	AddressText
)

// Address is what an address is matched against, in the Source IP filter,
// the source rules and the routing — one meaning for all three, and for the
// history's SQL (storage/query.go) and the window (lib/search.ts), held to it
// by testdata/filters.json.
//
// Addresses are compared as the receiver writes them (net.IP.String: dotted
// IPv4, RFC 5952 IPv6, lowercase): an exact address is written that way
// before it is compared, and a CIDR contains only the addresses written that
// way, which is every address a message arrives from.
//
// A CIDR is a number of leading bits of the 16-byte form, where an IPv4
// address is ::ffff:a.b.c.d — so 10.0.0.0/8 is the first 104 bits of
// ::ffff:10.0.0.0. Plain arithmetic, which the window repeats exactly.
type Address struct {
	Kind AddressKind
	// Text is the exact address as the receiver writes it, the glob, or the
	// text contained, folded.
	Text string
	// Base and Bits are a CIDR's network in the 16-byte form, and how many of
	// its leading bits an address has to share. Bits is 0 for a /0, which is
	// everything, both families included.
	Base [16]byte
	Bits int
	// Prefix is what every IPv4 address of the CIDR starts with as text: its
	// whole octets and a dot ("10.10.1." for a /24). The history narrows on
	// it through the index before checking each address.
	Prefix string
}

// CompileAddress reads an address as typed. partial says what text that is
// not an address means: contained, for the filter box; the address itself,
// for a list entry.
func CompileAddress(typed string, partial bool) Address {
	t := strings.TrimSpace(typed)
	if t == "" {
		return Address{Kind: AddressAny}
	}
	if ip, ones, v4, ok := parseCIDR(t); ok {
		a := Address{Kind: AddressNet}
		if ones == 0 {
			return a
		}
		a.Bits = ones
		if v4 {
			a.Bits += 96
		}
		copy(a.Base[:], ip.To16())
		maskBits(&a.Base, a.Bits)
		// An IPv4 network, however it was written, with a whole octet or
		// more: three at most, since a /32's fourth is followed by no dot.
		if base := net.IP(a.Base[:]); base.To4() != nil && a.Bits >= 104 {
			octets := strings.Split(base.String(), ".")
			a.Prefix = strings.Join(octets[:min((a.Bits-96)/8, 3)], ".") + "."
		}
		return a
	}
	if ip := net.ParseIP(t); ip != nil {
		return Address{Kind: AddressExact, Text: ip.String()}
	}
	if strings.ContainsAny(t, "*?") {
		return Address{Kind: AddressGlob, Text: Fold(t)}
	}
	if partial {
		return Address{Kind: AddressText, Text: Fold(t)}
	}
	return Address{Kind: AddressExact, Text: Fold(t)}
}

// parseCIDR reads address/length: the address as ParseIP takes it, and a
// length of one to three digits that fits it — an IPv4 address written
// dotted has 32 bits (v4), any other 128.
func parseCIDR(s string) (ip net.IP, ones int, v4, ok bool) {
	addr, length, found := strings.Cut(s, "/")
	if !found || len(length) == 0 || len(length) > 3 || strings.Trim(length, "0123456789") != "" {
		return nil, 0, false, false
	}
	if ip = net.ParseIP(addr); ip == nil {
		return nil, 0, false, false
	}
	ones, _ = strconv.Atoi(length)
	v4 = !strings.Contains(addr, ":")
	if (v4 && ones > 32) || ones > 128 {
		return nil, 0, false, false
	}
	return ip, ones, v4, true
}

// maskBits zeroes every bit of b after the first n.
func maskBits(b *[16]byte, n int) {
	for i := range b {
		switch {
		case n >= 8*(i+1):
		case n <= 8*i:
			b[i] = 0
		default:
			b[i] &= byte(0xff << (8 - (n - 8*i)))
		}
	}
}

// Match reports whether an address passes.
func (a Address) Match(value string) bool {
	switch a.Kind {
	case AddressAny:
		return true
	case AddressExact:
		return Fold(value) == a.Text
	case AddressNet:
		if a.Bits == 0 {
			return true
		}
		ip := net.ParseIP(value)
		if ip == nil || ip.String() != Fold(value) {
			return false
		}
		var b [16]byte
		copy(b[:], ip.To16())
		maskBits(&b, a.Bits)
		return b == a.Base
	case AddressGlob:
		return Glob(a.Text, Fold(value))
	case AddressText:
		return strings.Contains(Fold(value), a.Text)
	}
	return false
}

// CIDR writes a CIDR back as one CompileAddress reads the same, in the
// 16-byte form: an IPv4 network as ::ffff:a.b.c.d, since 0.0.0.0/0 would
// read as everything and ::ffff:0:0/96 is every IPv4 address only.
func (a Address) CIDR() string {
	ip := net.IP(a.Base[:])
	if ip.To4() != nil {
		return "::ffff:" + ip.String() + "/" + strconv.Itoa(a.Bits)
	}
	return ip.String() + "/" + strconv.Itoa(a.Bits)
}

// Glob reports whether text matches pattern whole, "*" standing for any run
// of characters and "?" for one. Linear in practice: on a mismatch it only
// ever goes back to just after the last "*".
func Glob(pattern, text string) bool {
	p, t := 0, 0
	star, mark := -1, 0
	for t < len(text) {
		if p < len(pattern) {
			switch pattern[p] {
			case '*':
				star, mark = p, t
				p++
				continue
			case '?':
				_, n := utf8.DecodeRuneInString(text[t:])
				p, t = p+1, t+n
				continue
			default:
				pr, pn := utf8.DecodeRuneInString(pattern[p:])
				tr, tn := utf8.DecodeRuneInString(text[t:])
				if pr == tr {
					p, t = p+pn, t+tn
					continue
				}
			}
		}
		if star < 0 {
			return false
		}
		_, n := utf8.DecodeRuneInString(text[mark:])
		mark += n
		p, t = star+1, mark
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}

// CheckAddressEntry says what is wrong with an entry of an address list (a
// source rule's): anything that is not an address, a CIDR or a pattern can
// match nothing a message arrives from.
func CheckAddressEntry(entry string) error {
	a := CompileAddress(entry, false)
	if a.Kind != AddressExact || net.ParseIP(strings.TrimSpace(entry)) != nil {
		return nil
	}
	return fmt.Errorf("%q is not an address: write one whole (10.0.7.12), a CIDR (10.0.7.0/24) or a pattern (10.0.7.*)", strings.TrimSpace(entry))
}

// MatchAddresses reports whether value matches one of the entries of an
// address list; an empty list matches everything.
func MatchAddresses(entries []Address, value string) bool {
	if len(entries) == 0 {
		return true
	}
	for _, a := range entries {
		if a.Match(value) {
			return true
		}
	}
	return false
}

// CompileAddresses compiles an address list, leaving out blank entries.
func CompileAddresses(list []string) []Address {
	var out []Address
	for _, s := range list {
		if strings.TrimSpace(s) != "" {
			out = append(out, CompileAddress(s, false))
		}
	}
	return out
}
