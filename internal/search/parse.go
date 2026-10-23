package search

import (
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// The fts mode's grammar, with FTS5's precedence — NOT binds tightest, then
// AND, then OR:
//
//	or      = and { OR and }
//	and     = not { [AND] not }          a space is an AND
//	not     = primary { NOT primary }
//	primary = "(" or ")" | near | "words"[*] | word[*]
//	near    = NEAR( words { words } [, distance] )
//
// Unlike FTS5, operators are recognised in any case: "error or timeout" is
// what people type. To look for the word "or" itself, quote it.

type tokenKind int

const (
	tokWords tokenKind = iota
	tokAnd
	tokOr
	tokNot
	tokNear
	tokOpen
	tokClose
	tokComma
)

type token struct {
	kind   tokenKind
	text   string
	prefix bool
}

// nearDistance is how far apart NEAR lets its words be when the query does
// not say, as in FTS5.
const nearDistance = 10

func lex(q string) ([]token, *Error) {
	var toks []token
	// Inside NEAR( ), a comma introduces the distance; elsewhere it is part of
	// a word, which splits there anyway.
	inNear := false
	for i := 0; i < len(q); {
		r, size := utf8.DecodeRuneInString(q[i:])
		switch {
		case unicode.IsSpace(r):
			i += size
		case r == '(':
			toks = append(toks, token{kind: tokOpen, text: "("})
			i++
		case r == ')':
			toks = append(toks, token{kind: tokClose, text: ")"})
			inNear = false
			i++
		case r == ',' && inNear:
			toks = append(toks, token{kind: tokComma, text: ","})
			i++
		case r == '"':
			// A quote inside quotes is written twice, as in FTS5.
			var b strings.Builder
			j := i + 1
			for {
				k := strings.IndexByte(q[j:], '"')
				if k < 0 {
					return nil, &Error{Code: ErrUnclosedQuote, Term: q[i:]}
				}
				b.WriteString(q[j : j+k])
				j += k + 1
				if j < len(q) && q[j] == '"' {
					b.WriteByte('"')
					j++
					continue
				}
				break
			}
			t := token{kind: tokWords, text: b.String()}
			if j < len(q) && q[j] == '*' {
				t.prefix = true
				j++
			}
			toks = append(toks, t)
			i = j
		default:
			j := i
			for j < len(q) {
				r, size := utf8.DecodeRuneInString(q[j:])
				if unicode.IsSpace(r) || r == '(' || r == ')' || r == '"' || r == ',' && inNear {
					break
				}
				j += size
			}
			word := q[i:j]
			i = j
			t := token{kind: tokWords, text: strings.TrimRight(word, "*")}
			t.prefix = len(t.text) < len(word)
			if t.text == "" {
				// A lone "*" has nothing to be the start of.
				t.text, t.prefix = word, false
			}
			if !t.prefix {
				switch strings.ToUpper(word) {
				case "AND":
					t.kind = tokAnd
				case "OR":
					t.kind = tokOr
				case "NOT":
					t.kind = tokNot
				case "NEAR":
					if rest := strings.TrimLeftFunc(q[i:], unicode.IsSpace); strings.HasPrefix(rest, "(") {
						t.kind = tokNear
						inNear = true
					}
				}
			}
			toks = append(toks, t)
		}
	}
	return toks, nil
}

type parser struct {
	toks []token
	pos  int
	err  *Error
}

func parse(q string) (*Node, *Error) {
	toks, err := lex(q)
	if err != nil {
		return nil, err
	}
	p := &parser{toks: toks}
	n := p.or()
	if p.err == nil && p.pos < len(p.toks) {
		// Only a closing parenthesis can stop the grammar early.
		p.err = &Error{Code: ErrUnexpectedParen, Term: ")"}
	}
	if p.err != nil {
		return nil, p.err
	}
	return n, nil
}

func (p *parser) peek() (token, bool) {
	if p.pos < len(p.toks) {
		return p.toks[p.pos], true
	}
	return token{}, false
}

func (p *parser) or() *Node {
	left := p.and()
	for p.err == nil {
		t, ok := p.peek()
		if !ok || t.kind != tokOr {
			break
		}
		p.pos++
		left = join(OpOr, left, p.and())
	}
	return left
}

func (p *parser) and() *Node {
	left := p.not()
	for p.err == nil {
		t, ok := p.peek()
		if !ok {
			break
		}
		switch t.kind {
		case tokAnd:
			p.pos++
		case tokWords, tokNear, tokOpen:
			// Side by side: an AND.
		default:
			return left
		}
		left = join(OpAnd, left, p.not())
	}
	return left
}

func (p *parser) not() *Node {
	left := p.primary()
	for p.err == nil {
		t, ok := p.peek()
		if !ok || t.kind != tokNot {
			break
		}
		p.pos++
		right := p.primary()
		left = &Node{Op: OpNot, Kids: []*Node{left, right}}
	}
	return left
}

func (p *parser) primary() *Node {
	if p.err != nil {
		return nil
	}
	t, ok := p.peek()
	if !ok {
		p.err = &Error{Code: ErrMissingTerm, Term: p.before()}
		return nil
	}
	switch t.kind {
	case tokWords:
		p.pos++
		return p.words(t)
	case tokNear:
		return p.near()
	case tokOpen:
		p.pos++
		if t, ok := p.peek(); ok && t.kind == tokClose {
			p.err = &Error{Code: ErrMissingTerm, Term: "()"}
			return nil
		}
		n := p.or()
		if p.err != nil {
			return nil
		}
		if t, ok := p.peek(); !ok || t.kind != tokClose {
			p.err = &Error{Code: ErrUnclosedParen, Term: "("}
			return nil
		}
		p.pos++
		return n
	case tokNot:
		p.err = &Error{Code: ErrNotNeedsLeft, Term: t.text}
	case tokClose:
		p.err = &Error{Code: ErrUnexpectedParen, Term: ")"}
	default:
		// AND or OR with nothing before it.
		p.err = &Error{Code: ErrMissingTerm, Term: t.text}
	}
	return nil
}

func (p *parser) words(t token) *Node {
	words := Words(t.text)
	if len(words) == 0 {
		p.err = &Error{Code: ErrNoWords, Term: t.text}
		return nil
	}
	return wordsNode(words, t.prefix, t.text)
}

// near reads NEAR(words words…[, distance]); the lexer has seen to it that a
// parenthesis follows the keyword.
func (p *parser) near() *Node {
	p.pos += 2
	n := &Node{Op: OpNear, Distance: nearDistance}
	for p.err == nil {
		t, ok := p.peek()
		if !ok {
			p.err = &Error{Code: ErrUnclosedParen, Term: "NEAR("}
			return nil
		}
		p.pos++
		switch t.kind {
		case tokWords:
			if w := p.words(t); w != nil {
				n.Kids = append(n.Kids, w)
			}
		case tokComma:
			d, ok := p.peek()
			dist, err := strconv.Atoi(d.text)
			if !ok || d.kind != tokWords || d.prefix || err != nil || dist < 0 {
				p.err = &Error{Code: ErrNearDistance, Term: d.text}
				return nil
			}
			p.pos++
			if c, ok := p.peek(); !ok || c.kind != tokClose {
				p.err = &Error{Code: ErrUnclosedParen, Term: "NEAR("}
				return nil
			}
			n.Distance = dist
		case tokClose:
			if len(n.Kids) == 0 {
				p.err = &Error{Code: ErrMissingTerm, Term: "NEAR()"}
				return nil
			}
			return n
		default:
			p.err = &Error{Code: ErrNearWordsOnly, Term: t.text}
		}
	}
	return nil
}

// before is the operator the query ended on, for the error that says what
// it lacks.
func (p *parser) before() string {
	if p.pos > 0 {
		return p.toks[p.pos-1].text
	}
	return ""
}

// join adds right to an operation of kind op, flattening a chain of the same
// operation into one node.
func join(op string, left, right *Node) *Node {
	if left == nil || right == nil {
		return nil
	}
	if left.Op == op {
		left.Kids = append(left.Kids, right)
		return left
	}
	return &Node{Op: op, Kids: []*Node{left, right}}
}
