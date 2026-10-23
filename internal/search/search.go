// Package search is the one definition of what a search finds. The history
// asks SQLite's full-text index, the live view filters the messages the window
// holds, an export filters the receiver's buffer: each used to read the query
// its own way, so the same words found different messages depending on where
// they were typed. Now a query is compiled here once, into a Plan, and every
// place applies that plan — the window included, which receives it compiled
// rather than parsing anything itself.
//
// Three modes:
//
//   - text: the words as typed, in that order, the last one possibly
//     unfinished — "connection ref" finds "Connection refused". Case, accents
//     and punctuation between words do not matter. A query with no letter or
//     digit in it ("->") is looked for as is.
//   - fts: words combined with AND (or just a space), OR and NOT, in any case,
//     with parentheses, "exact phrases", prefix* searches and NEAR(a b, 5).
//     NOT excludes from what comes before it: "error NOT timeout".
//   - regex: a regular expression, case-insensitive, in Go's syntax.
//
// A query that does not compile is not applied, and the error says why.
package search

import (
	"errors"
	"regexp"
	"regexp/syntax"
	"strconv"
	"strings"

	"SyslogStudio/internal/models"
)

// The modes, as FilterCriteria.SearchMode carries them.
const (
	ModeText  = "text"
	ModeFTS   = "fts"
	ModeRegex = "regex"
)

// Plan is a query compiled once and applied to many messages.
type Plan struct {
	Mode string `json:"mode"`
	// Root is the query's tree in the text and fts modes.
	Root *Node `json:"root,omitempty"`
	// Literal is a text query with no word in it, looked for as is.
	Literal string `json:"literal,omitempty"`
	// Pattern is a regex query that compiled.
	Pattern string `json:"pattern,omitempty"`
	// Error says why the query is not applied.
	Error *Error `json:"error,omitempty"`

	re *regexp.Regexp
}

// Node is a step of a query: words that must follow each other, or AND, OR,
// NOT, NEAR over other nodes. NOT has two: what to keep, and what to take out
// of it. NEAR's are word runs, all within Distance words of each other.
type Node struct {
	Op       string   `json:"op"`
	Words    []string `json:"words,omitempty"`
	Prefix   bool     `json:"prefix,omitempty"`
	Kids     []*Node  `json:"kids,omitempty"`
	Distance int      `json:"distance,omitempty"`

	// text is the query's own spelling of the words, for the index to split.
	text string
	// needle is the words as they appear in a field's index: whole, or the
	// last one only begun.
	needle string
}

// wordsNode is a run of words, spelt text in the query.
func wordsNode(words []string, prefix bool, text string) *Node {
	needle := " " + strings.Join(words, " ")
	if !prefix {
		needle += " "
	}
	return &Node{Op: OpWords, Words: words, Prefix: prefix, text: text, needle: needle}
}

// The operations a Node can be.
const (
	OpWords = "words"
	OpAnd   = "and"
	OpOr    = "or"
	OpNot   = "not"
	OpNear  = "near"
)

// Error is why a query cannot be applied, as a code the window translates and
// the part of the query it is about.
type Error struct {
	Code string `json:"code"`
	Term string `json:"term,omitempty"`
}

// The error codes.
const (
	ErrUnclosedQuote   = "unclosedQuote"
	ErrUnclosedParen   = "unclosedParen"
	ErrUnexpectedParen = "unexpectedParen"
	ErrMissingTerm     = "missingTerm"
	ErrNotNeedsLeft    = "notNeedsLeft"
	ErrNoWords         = "noWords"
	ErrNearDistance    = "nearDistance"
	ErrNearWordsOnly   = "nearWordsOnly"
	ErrBadRegex        = "badRegex"
	ErrRegexTooLong    = "regexTooLong"
)

func (e *Error) Error() string {
	if e.Term == "" {
		return e.Code
	}
	return e.Code + ": " + e.Term
}

// Compile compiles a query in a mode; an unknown mode is text. An empty query
// compiles to a plan that leaves every message in.
func Compile(query, mode string) Plan {
	if mode != ModeFTS && mode != ModeRegex {
		mode = ModeText
	}
	p := Plan{Mode: mode}
	trimmed := strings.TrimSpace(query)
	if trimmed == "" {
		return p
	}
	switch mode {
	case ModeRegex:
		// Spaces are part of a pattern: it is compiled as typed.
		re, err := models.SafeCompileRegex(query)
		switch {
		case len(query) > models.MaxRegexLen:
			p.Error = &Error{Code: ErrRegexTooLong}
		case err != nil:
			p.Error = &Error{Code: ErrBadRegex, Term: regexMessage(err)}
		default:
			p.Pattern, p.re = query, re
		}
	case ModeFTS:
		p.Root, p.Error = parse(trimmed)
	default:
		if words := Words(trimmed); len(words) > 0 {
			p.Root = wordsNode(words, true, trimmed)
		} else {
			p.Literal = strings.ToLower(trimmed)
		}
	}
	return p
}

// regexMessage keeps what Go says is wrong with a pattern, without the
// pattern itself, which the user has in front of them.
func regexMessage(err error) string {
	var bad *syntax.Error
	if errors.As(err, &bad) {
		return string(bad.Code)
	}
	return err.Error()
}

// Active reports whether the plan filters anything.
func (p *Plan) Active() bool {
	return p.Error == nil && (p.Root != nil || p.Literal != "" || p.re != nil)
}

// Match reports whether a message, given as its fields (its text and its raw
// line), matches. An inactive plan matches everything.
func (p *Plan) Match(fields ...string) bool {
	if !p.Active() {
		return true
	}
	switch {
	case p.re != nil:
		for _, f := range fields {
			if p.re.MatchString(f) {
				return true
			}
		}
		return false
	case p.Literal != "":
		for _, f := range fields {
			if strings.Contains(strings.ToLower(f), p.Literal) {
				return true
			}
		}
		return false
	}
	d := doc{fields: fields}
	return p.Root.match(&d)
}

// NeedsScan reports whether the plan can only be applied by reading each
// message: SQLite has no regular expressions.
func (p *Plan) NeedsScan() bool { return p.Active() && p.re != nil }

// FTS5 is the plan as an FTS5 MATCH expression, or "" when the index cannot
// answer it — no plan, a literal, a regex. Every word group is quoted with the
// query's own spelling inside, so FTS5 splits it the way it split the messages
// and nothing in a query is ever FTS5 syntax by accident.
func (p *Plan) FTS5() string {
	if !p.Active() || p.Root == nil {
		return ""
	}
	return p.Root.fts5()
}

func (n *Node) fts5() string {
	switch n.Op {
	case OpWords:
		s := `"` + strings.ReplaceAll(n.text, `"`, `""`) + `"`
		if n.Prefix {
			s += "*"
		}
		return s
	case OpNot:
		return "(" + n.Kids[0].fts5() + " NOT " + n.Kids[1].fts5() + ")"
	case OpNear:
		parts := make([]string, len(n.Kids))
		for i, k := range n.Kids {
			parts[i] = k.fts5()
		}
		return "NEAR(" + strings.Join(parts, " ") + ", " + strconv.Itoa(n.Distance) + ")"
	}
	op := " AND "
	if n.Op == OpOr {
		op = " OR "
	}
	parts := make([]string, len(n.Kids))
	for i, k := range n.Kids {
		parts[i] = k.fts5()
	}
	return "(" + strings.Join(parts, op) + ")"
}

// doc is a message being matched: its fields, indexed on first use.
type doc struct {
	fields  []string
	indexes []string
}

func (d *doc) index() []string {
	if d.indexes == nil {
		d.indexes = make([]string, len(d.fields))
		for i, f := range d.fields {
			d.indexes[i] = index(f)
		}
	}
	return d.indexes
}

func (n *Node) match(d *doc) bool {
	switch n.Op {
	case OpWords:
		// The words must follow each other within one field, as FTS5 has a
		// phrase within one column.
		for _, idx := range d.index() {
			if strings.Contains(idx, n.needle) {
				return true
			}
		}
		return false
	case OpAnd:
		for _, k := range n.Kids {
			if !k.match(d) {
				return false
			}
		}
		return true
	case OpOr:
		for _, k := range n.Kids {
			if k.match(d) {
				return true
			}
		}
		return false
	case OpNot:
		return n.Kids[0].match(d) && !n.Kids[1].match(d)
	case OpNear:
		// Every run must be there before positions are worth working out.
		for _, k := range n.Kids {
			if !k.match(d) {
				return false
			}
		}
		for _, idx := range d.index() {
			if n.near(strings.Fields(idx)) {
				return true
			}
		}
		return false
	}
	return false
}

// near reports whether each of the node's word runs appears in words so that
// none ends more than Distance words before the last one starts. It walks the
// runs' occurrences the way FTS5 does: whatever ends too early for the latest
// start so far can be dropped for good.
func (n *Node) near(words []string) bool {
	starts := make([][]int, len(n.Kids))
	for i, k := range n.Kids {
		if starts[i] = runStarts(words, k.Words, k.Prefix); len(starts[i]) == 0 {
			return false
		}
	}
	at := make([]int, len(n.Kids))
	for {
		latest := 0
		for i := range n.Kids {
			latest = max(latest, starts[i][at[i]])
		}
		moved := false
		for i, k := range n.Kids {
			for starts[i][at[i]]+len(k.Words) < latest-n.Distance {
				if at[i]++; at[i] == len(starts[i]) {
					return false
				}
				moved = true
			}
		}
		if !moved {
			return true
		}
	}
}

// runStarts is where run appears in words.
func runStarts(words, run []string, prefix bool) []int {
	var at []int
	for i := 0; i+len(run) <= len(words); i++ {
		if runAt(words, i, run, prefix) {
			at = append(at, i)
		}
	}
	return at
}

func runAt(words []string, i int, run []string, prefix bool) bool {
	last := len(run) - 1
	for j := 0; j < last; j++ {
		if words[i+j] != run[j] {
			return false
		}
	}
	w := words[i+last]
	return w == run[last] || prefix && strings.HasPrefix(w, run[last])
}
