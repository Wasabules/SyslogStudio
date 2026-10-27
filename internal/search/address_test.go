package search

import (
	"net"
	"testing"
)

// addressTexts are read as addresses: testdata/addresses.json records how
// Go reads and writes each, which the window's parseIP and ipString repeat.
var addressTexts = []string{
	"", "10.0.0.1", "0.0.0.0", "255.255.255.255", "256.0.0.1", "010.0.0.1", "10.0.0", "10.0.0.1.2",
	"10..0.1", ".10.0.0.1", "10.0.0.1.", "1.2.3.4 ", " 1.2.3.4", "1.2.3.a", "1.2.3.4:514",
	"::", "::1", "1::", "fe80::1", "FE80::0001", "fe80:0:0:0:0:0:0:1", "1:2:3:4:5:6:7:8",
	"1:2:3:4:5:6:7::", "::2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8::", "1:2:3:4:5:6:7:8:9", "1:2:3:4:5:6:7",
	"1::2::3", ":1::2", "1:::2", "1:2:", "12345::", "fe80::1%eth0", "%eth0", "::ffff:10.0.0.5",
	"::ffff:a00:5", "::10.0.0.5", "1:2:3:4:5:6:10.0.0.5", "1:2:3:4:5:10.0.0.5", "1:2:3:4:5:6:7:10.0.0.5",
	"::01.2.3.4", "::1.2.3.4.5", "2001:db8:0:0:1:0:0:1", "2001:db8::1:0:0:1", "2001:0:0:1:0:0:0:1",
	"0:0:1:0:0:1:0:0", "2001:db8:0:1:1:1:1:1", "1:0:0:0:0:0:0:0", "0:0:0:0:0:0:0:1", "ABCD:EF01::",
	"g::1", "::ffff:255.255.255.255",
}

// addressCases are an address typed against an address received.
var addressCases = []struct {
	Typed   string `json:"typed"`
	Partial bool   `json:"partial"`
	Value   string `json:"value"`
}{
	{"10.10.1.1", true, "10.10.1.1"},
	{"10.10.1.1", true, "10.10.1.10"},
	{"10.10.1.1", true, "10.10.1.199"},
	{"10.10.1.1", false, "10.10.1.1"},
	{" 10.10.1.1 ", false, "10.10.1.1"},
	{"10.10.1.", true, "10.10.1.199"},
	{"10.10.1.", false, "10.10.1.199"},
	{"10.10.1.0/24", false, "10.10.1.199"},
	{"10.10.1.0/24", false, "10.10.2.1"},
	{"10.10.1.0/24", false, "::ffff:10.10.1.5"},
	{"10.10.1.128/25", false, "10.10.1.127"},
	{"10.10.1.128/25", false, "10.10.1.128"},
	{"10.10.1.7/32", false, "10.10.1.7"},
	{"10.10.1.7/32", false, "10.10.1.8"},
	{"0.0.0.0/0", false, "fe80::1"},
	{"::/0", false, "10.0.0.1"},
	{"0.0.0.0/1", false, "fe80::1"},
	{"::/1", false, "10.0.0.1"},
	{"::ffff:0:0/96", false, "10.0.0.1"},
	{"::ffff:0:0/96", false, "fe80::1"},
	{"::/80", false, "10.0.0.1"},
	{"::/80", false, "::1"},
	{"fe80::/10", false, "FE80::1"},
	{"fe80::/10", false, "fec0::1"},
	{"2001:db8::/32", false, "2001:db8:0:0:0:0:0:1"},
	{"2001:db8::/32", false, "2001:db8::1"},
	{"10.0.0.0/8", false, "not an address"},
	{"10.0.0.0/033", false, "10.0.0.1"},
	{"10.0.0.0/0x8", true, "10.0.0.0/0x8"},
	{"10.10.1.*", false, "10.10.1.1"},
	{"10.10.1.*", false, "10.10.10.1"},
	{"10.10.*.1", false, "10.10.200.1"},
	{"10.10.1.?", false, "10.10.1.12"},
	{"10.10.1.??", false, "10.10.1.12"},
	{"*", false, ""},
	{"FE80::*", false, "fe80::1"},
	{"fe80:0::1", false, "fe80::1"},
	{"gateway", false, "GATEWAY"},
	{"gateway", false, "gateway-2"},
	{"gate", true, "gateway-2"},
	{"10.0.0.1%", false, "10.0.0.1%"},
	{"", false, "10.0.0.1"},
}

type goldenIP struct {
	Text string  `json:"text"`
	Want *string `json:"want"`
}

type goldenAddress struct {
	Typed   string `json:"typed"`
	Partial bool   `json:"partial"`
	Value   string `json:"value"`
	Match   bool   `json:"match"`
}

func TestAddresses(t *testing.T) {
	var golden struct {
		IPs     []goldenIP      `json:"ips"`
		Matches []goldenAddress `json:"matches"`
	}
	for _, s := range addressTexts {
		g := goldenIP{Text: s}
		if ip := net.ParseIP(s); ip != nil {
			w := ip.String()
			g.Want = &w
		}
		golden.IPs = append(golden.IPs, g)
	}
	for _, c := range addressCases {
		golden.Matches = append(golden.Matches, goldenAddress{c.Typed, c.Partial, c.Value, CompileAddress(c.Typed, c.Partial).Match(c.Value)})
	}
	checkGolden(t, "addresses.json", golden)

	// The cases #98 is about, said plainly.
	for _, c := range []struct {
		typed, value string
		want         bool
	}{
		{"10.10.1.1", "10.10.1.1", true},
		{"10.10.1.1", "10.10.1.10", false},
		{"10.10.1.1", "10.10.1.100", false},
		{"10.10.1.0/24", "10.10.1.100", true},
		{"10.10.1.*", "10.10.1.100", true},
		{"10.10.1.*", "10.10.10.1", false},
	} {
		if got := CompileAddress(c.typed, true).Match(c.value); got != c.want {
			t.Errorf("%q against %q: %v, want %v", c.typed, c.value, got, c.want)
		}
	}
}

// A CIDR written back reads the same, which is how ss_addr gets it.
func TestAddress_CIDRRoundTrip(t *testing.T) {
	for _, s := range []string{"10.10.1.0/24", "10.10.1.9/31", "0.0.0.0/1", "::ffff:10.1.0.0/112", "fe80::/10", "::/80", "::ffff:0:0/96", "2001:db8::/127"} {
		a := CompileAddress(s, false)
		if b := CompileAddress(a.CIDR(), false); b != a {
			t.Errorf("%s: written back as %s, read as %+v, want %+v", s, a.CIDR(), b, a)
		}
	}
}

func TestAddress_Prefix(t *testing.T) {
	for typed, want := range map[string]string{
		"10.10.1.0/24": "10.10.1.", "10.10.0.0/20": "10.10.", "10.0.0.0/8": "10.", "10.0.0.0/7": "",
		"10.10.1.7/32": "10.10.1.", "::ffff:10.1.0.0/112": "10.1.", "fe80::/10": "",
	} {
		if got := CompileAddress(typed, false).Prefix; got != want {
			t.Errorf("%s: prefix %q, want %q", typed, got, want)
		}
	}
}

func TestGlob(t *testing.T) {
	for _, c := range []struct {
		pattern, text string
		want          bool
	}{
		{"*", "", true},
		{"", "", true},
		{"", "a", false},
		{"a*b", "ab", true},
		{"a*b", "axxb", true},
		{"a*b", "axxbx", false},
		{"*b*b", "abxb", true},
		{"?", "é", true},
		{"??", "é", false},
		{"a?c", "abc", true},
		{"a?c", "ac", false},
		{"**", "x", true},
		{"*a*a*a*a*a*b", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", false},
	} {
		if got := Glob(c.pattern, c.text); got != c.want {
			t.Errorf("Glob(%q, %q) = %v, want %v", c.pattern, c.text, got, c.want)
		}
	}
}

func TestCheckAddressEntry(t *testing.T) {
	for _, ok := range []string{"10.0.0.1", "fe80::1", "10.0.0.0/24", "10.0.0.*", "*", "fe80::/10"} {
		if err := CheckAddressEntry(ok); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"10.0.0", "gateway", "10.0.0.0/33", "fe80::1%eth0"} {
		if CheckAddressEntry(bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
