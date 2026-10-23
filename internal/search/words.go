package search

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// Words splits text into the words a search compares, the way the history's
// index does — SQLite FTS5 with its default tokenizer, unicode61 — so that the
// live view and an export find what the history finds:
//
//   - a word is a run of letters, digits and private-use characters, and
//     anything else separates words: "192.168.1.10:514" is five words;
//   - case is folded, and a Latin letter carrying a single accent loses it
//     (É → e, ş → s), as do the combining accents U+0300–U+036F; a letter with
//     two accents keeps them, as FTS5 has it;
//   - CJK text has no spaces to split on, so a run of it is one word.
//
// FTS5 sorts characters by its own tables, from Unicode 6.1, and this by the
// Unicode of the Go release: they part only over characters assigned since,
// emoji among them, which FTS5 takes for words and this does not. The window's
// copy of this, in frontend/src/lib/search.ts, follows the same rules, and both
// are held to testdata/words.json.
func Words(text string) []string {
	return strings.Fields(index(text))
}

// index is text's words, each between single spaces: " connection refused by
// peer ". Words in a row are then a substring of it — " connection refused " —
// which is how a message is matched: one string per field to build, where a
// slice of words cost an allocation per word.
func index(text string) string {
	var b strings.Builder
	b.Grow(len(text) + 2)
	b.WriteByte(' ')
	inWord := false
	for i := 0; i < len(text); {
		var r rune
		if c := text[i]; c < utf8.RuneSelf {
			i++
			switch {
			case 'a' <= c && c <= 'z', '0' <= c && c <= '9':
				r = rune(c)
			case 'A' <= c && c <= 'Z':
				r = rune(c + 'a' - 'A')
			}
		} else {
			var size int
			r, size = utf8.DecodeRuneInString(text[i:])
			i += size
			switch {
			case isAccent(r):
				// Dropped where it stands, without splitting the word it marks.
				continue
			case unicode.IsLetter(r), unicode.IsNumber(r), unicode.In(r, unicode.Co):
				r = fold(r)
			default:
				r = 0
			}
		}
		if r != 0 {
			b.WriteRune(r)
			inWord = true
		} else if inWord {
			b.WriteByte(' ')
			inWord = false
		}
	}
	if inWord {
		b.WriteByte(' ')
	}
	return b.String()
}

// isAccent reports the combining accents FTS5 removes. The other combining
// marks separate words there, and so here.
func isAccent(r rune) bool {
	switch {
	case 0x300 <= r && r <= 0x304, 0x306 <= r && r <= 0x30C, r == 0x30F, r == 0x311, r == 0x31B,
		0x323 <= r && r <= 0x328, 0x32D <= r && r <= 0x32E, 0x330 <= r && r <= 0x331:
		return true
	}
	return false
}

// variants are the lowercase letters that case folding takes further than
// lowercasing does: the micro sign is mu, a final sigma is a sigma.
var variants = map[rune]rune{
	'µ': 'μ', 'ſ': 's', 'ς': 'σ', 'ϐ': 'β', 'ϑ': 'θ', 'ϕ': 'φ', 'ϖ': 'π',
	'ϰ': 'κ', 'ϱ': 'ρ', 'ϵ': 'ε', 'ẛ': 'ṡ', '\u1fbe': 'ι',
}

// fold lowercases a letter, and takes the accent off a Latin letter that has
// just one.
func fold(r rune) rune {
	r = unicode.ToLower(r)
	if v, ok := variants[r]; ok {
		r = v
	}
	if base, ok := unaccented[r]; ok {
		return base
	}
	return r
}

// unaccented maps each lowercase Latin letter made of an ASCII letter and one
// accent to that letter. Only Latin-1 to Latin Extended-B and Latin Extended
// Additional hold such letters; worked out once rather than for every letter
// of every message.
var unaccented = func() map[rune]rune {
	m := map[rune]rune{}
	for _, block := range [][2]rune{{0xC0, 0x24F}, {0x1E00, 0x1EFF}} {
		for r := block[0]; r <= block[1]; r++ {
			d := norm.NFD.String(string(r))
			if len(d) != 3 || d[0] >= utf8.RuneSelf {
				continue
			}
			if mark, _ := utf8.DecodeRuneInString(d[1:]); isAccent(mark) {
				m[r] = rune(d[0])
			}
		}
	}
	return m
}()
