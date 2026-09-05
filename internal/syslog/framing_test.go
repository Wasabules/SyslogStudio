package syslog

import (
	"bufio"
	"strings"
	"testing"
)

// scanAll runs the split function over input and returns all tokens.
func scanAll(t *testing.T, input string) []string {
	t.Helper()
	sc := bufio.NewScanner(strings.NewReader(input))
	sc.Buffer(make([]byte, 0, tcpScanBufSize), tcpScanBufSize)
	sc.Split(syslogFrameSplit)
	var out []string
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scanner error: %v", err)
	}
	return out
}

func eq(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d tokens %q, want %d %q", len(got), got, len(want), want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("token %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestFraming_OctetCounting_Single(t *testing.T) {
	msg := "<34>1 2003-10-11T22:14:15.003Z host app - - - hello"
	// The octet count must be the byte length of msg, so compute it rather
	// than hardcoding a number that silently rots when msg is edited.
	input := itoa(len(msg)) + " " + msg
	eq(t, scanAll(t, input), []string{msg})
}

func TestFraming_OctetCounting_Multiple(t *testing.T) {
	a := "<13>1 - - - - - first"
	b := "<13>1 - - - - - second"
	input := itoa(len(a)) + " " + a + itoa(len(b)) + " " + b
	eq(t, scanAll(t, input), []string{a, b})
}

func TestFraming_OctetCounting_EmbeddedNewline(t *testing.T) {
	// A newline inside an octet-counted frame must NOT split it.
	msg := "<13>1 - - - - - line1\nline2"
	input := itoa(len(msg)) + " " + msg
	eq(t, scanAll(t, input), []string{msg})
}

func TestFraming_NonTransparent_LF(t *testing.T) {
	input := "<13>1 - - - - - alpha\n<13>1 - - - - - beta\n"
	eq(t, scanAll(t, input), []string{
		"<13>1 - - - - - alpha",
		"<13>1 - - - - - beta",
	})
}

func TestFraming_NonTransparent_CRLF(t *testing.T) {
	input := "<13>one\r\n<13>two\r\n"
	eq(t, scanAll(t, input), []string{"<13>one", "<13>two"})
}

func TestFraming_Mixed(t *testing.T) {
	// Octet-counted frame followed by an LF-delimited frame.
	octet := "<13>1 - - - - - counted"
	input := itoa(len(octet)) + " " + octet + "<13>1 - - - - - delimited\n"
	eq(t, scanAll(t, input), []string{octet, "<13>1 - - - - - delimited"})
}

func TestFraming_DigitLedMessageNoSpace(t *testing.T) {
	// A message that starts with digits but has no space-delimited count
	// must be treated as LF-framed, not misparsed as octet counting.
	input := "12345\n"
	eq(t, scanAll(t, input), []string{"12345"})
}

func TestFraming_IncompleteOctetFrameAtEOF(t *testing.T) {
	// Declared length longer than provided data at EOF: emit what we have.
	msg := "<13>partial"
	input := "100 " + msg
	got := scanAll(t, input)
	if len(got) != 1 || got[0] != msg {
		t.Fatalf("got %q, want [%q]", got, msg)
	}
}

func TestFraming_ZeroLength(t *testing.T) {
	// "0 " frame is a valid empty message; the scanner drops empty tokens
	// only at the server level, so here we just confirm no crash and that
	// a following frame is still parsed.
	next := "<13>next"
	input := "0 " + next + "\n"
	got := scanAll(t, input)
	// The empty token may or may not be emitted depending on Scanner's
	// empty-token handling; the important guarantee is that "next" arrives.
	found := false
	for _, tok := range got {
		if tok == next {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected %q among tokens, got %q", next, got)
	}
}

// itoa is a tiny local helper to avoid importing strconv in the test's
// table setup expressions.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
