package search

import (
	"regexp/syntax"
	"strconv"
	"strings"
	"unicode"
)

// jsPattern re-spells a regular expression, as Go compiles it, for the
// window's JavaScript, to be compiled there with the "u" flag and no other.
//
// The two syntaxes overlap, but not their meanings: (?i) and [[:alpha:]] and
// \z are Go's alone — JavaScript rejects some and reads [[:alpha:]] as a
// different class without a word — and case-insensitive matching folds
// differently. So rather than pass the pattern along, the live view gets Go's
// own parse of it written out in full: every character class as its ranges,
// every case-insensitive letter as the set Go matches, every anchor as the
// look-around that means exactly it. JavaScript then has nothing left to
// interpret.
func jsPattern(pattern string) (string, error) {
	re, err := syntax.Parse("(?i)"+pattern, syntax.Perl)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	writeJS(&b, re)
	return b.String(), nil
}

func writeJS(b *strings.Builder, re *syntax.Regexp) {
	switch re.Op {
	case syntax.OpNoMatch:
		b.WriteString(`[^\s\S]`)
	case syntax.OpEmptyMatch:
		b.WriteString(`(?:)`)
	case syntax.OpLiteral:
		for _, r := range re.Rune {
			if re.Flags&syntax.FoldCase != 0 {
				writeFolded(b, r)
			} else {
				writeRune(b, r)
			}
		}
	case syntax.OpCharClass:
		writeClass(b, re.Rune)
	case syntax.OpAnyCharNotNL:
		b.WriteString(`[^\n]`)
	case syntax.OpAnyChar:
		b.WriteString(`[\s\S]`)
	// JavaScript's ^ and $ change meaning with its "m" flag, and \A and \z do
	// not exist there: each anchor becomes the look-around it amounts to.
	case syntax.OpBeginLine:
		b.WriteString(`(?<![^\n])`)
	case syntax.OpEndLine:
		b.WriteString(`(?![^\n])`)
	case syntax.OpBeginText:
		b.WriteString(`(?<![\s\S])`)
	case syntax.OpEndText:
		b.WriteString(`(?![\s\S])`)
	// Both are ASCII word boundaries, in Go and in JavaScript without "i".
	case syntax.OpWordBoundary:
		b.WriteString(`\b`)
	case syntax.OpNoWordBoundary:
		b.WriteString(`\B`)
	case syntax.OpCapture:
		b.WriteByte('(')
		writeJS(b, re.Sub[0])
		b.WriteByte(')')
	case syntax.OpStar, syntax.OpPlus, syntax.OpQuest, syntax.OpRepeat:
		b.WriteString("(?:")
		writeJS(b, re.Sub[0])
		b.WriteByte(')')
		switch re.Op {
		case syntax.OpStar:
			b.WriteByte('*')
		case syntax.OpPlus:
			b.WriteByte('+')
		case syntax.OpQuest:
			b.WriteByte('?')
		default:
			b.WriteString("{" + strconv.Itoa(re.Min))
			if re.Max != re.Min {
				b.WriteByte(',')
				if re.Max >= 0 {
					b.WriteString(strconv.Itoa(re.Max))
				}
			}
			b.WriteByte('}')
		}
		if re.Flags&syntax.NonGreedy != 0 {
			b.WriteByte('?')
		}
	case syntax.OpConcat:
		for _, sub := range re.Sub {
			writeJS(b, sub)
		}
	case syntax.OpAlternate:
		b.WriteString("(?:")
		for i, sub := range re.Sub {
			if i > 0 {
				b.WriteByte('|')
			}
			writeJS(b, sub)
		}
		b.WriteByte(')')
	}
}

func writeRune(b *strings.Builder, r rune) {
	b.WriteString(`\u{` + strconv.FormatInt(int64(r), 16) + `}`)
}

// writeFolded writes a letter matched without regard to case as the set of
// letters Go matches it with: its whole case-folding orbit, k and K and the
// Kelvin sign alike.
func writeFolded(b *strings.Builder, r rune) {
	if unicode.SimpleFold(r) == r {
		writeRune(b, r)
		return
	}
	b.WriteByte('[')
	for f := r; ; {
		writeRune(b, f)
		if f = unicode.SimpleFold(f); f == r {
			break
		}
	}
	b.WriteByte(']')
}

// writeClass writes a class as its ranges, which is all Go keeps of it.
func writeClass(b *strings.Builder, ranges []rune) {
	if len(ranges) == 0 {
		b.WriteString(`[^\s\S]`)
		return
	}
	b.WriteByte('[')
	for i := 0; i+1 < len(ranges); i += 2 {
		writeRune(b, ranges[i])
		if ranges[i+1] != ranges[i] {
			b.WriteByte('-')
			writeRune(b, ranges[i+1])
		}
	}
	b.WriteByte(']')
}
