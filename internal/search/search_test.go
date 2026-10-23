package search

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"unicode"

	_ "modernc.org/sqlite"
)

// The window filters its live view with its own copy of Words and Match, in
// frontend/src/lib/search.ts. It is held to the same answers through the two
// files in testdata, which these tests check against SQLite's FTS5 — the
// history's own index — and rewrite with -update.
var update = flag.Bool("update", false, "rewrite testdata from what FTS5 and the plans give")

type corpusMessage struct {
	ID         string `json:"id"`
	Message    string `json:"message"`
	RawMessage string `json:"rawMessage"`
}

func message(id, text string) corpusMessage {
	return corpusMessage{ID: id, Message: text, RawMessage: "<14>1 2026-10-23T10:00:00Z web-01 svc - - - " + text}
}

var corpus = []corpusMessage{
	message("disk", "Disk error on /dev/sda"),
	message("slow", "Request timeout after 30s"),
	message("both", "error: timeout while connecting to 10.0.0.5"),
	message("later", "timeout, then an error"),
	message("refused", "Connection refused by peer"),
	message("french", "Échec de connexion : délai dépassé"),
	message("ssh", "Accepted publickey for root from 192.168.1.10 port 51234"),
	message("choice", "Choose this or that"),
	message("cjk", "数据库连接失败 error"),
	message("arrow", "value -> next"),
	message("quote", `He said "hello world" loudly`),
}

type queryCase struct {
	mode, query string
	want        []string // nil: every message, the query not being applied
	code        string   // the error expected, if any
}

var cases = []queryCase{
	// Text: the words in their order, the last one possibly unfinished.
	{ModeText, "", nil, ""},
	{ModeText, "error", []string{"disk", "both", "later", "cjk"}, ""},
	{ModeText, "ERROR", []string{"disk", "both", "later", "cjk"}, ""},
	{ModeText, "error timeout", []string{"both"}, ""},
	{ModeText, "connection ref", []string{"refused"}, ""},
	{ModeText, "onnection", []string{}, ""},
	{ModeText, "echec", []string{"french"}, ""},
	{ModeText, "délai", []string{"french"}, ""},
	{ModeText, "192.168.1", []string{"ssh"}, ""},
	{ModeText, "->", []string{"arrow"}, ""},
	{ModeText, "web-01 svc", allIDs(), ""},

	// FTS: the cases of issue #77, which the live view and the history
	// answered differently.
	{ModeFTS, "error timeout", []string{"both", "later"}, ""},
	{ModeFTS, `"error" "timeout"`, []string{"both", "later"}, ""},
	{ModeFTS, "error AND timeout", []string{"both", "later"}, ""},
	{ModeFTS, "error or timeout", []string{"disk", "slow", "both", "later", "cjk"}, ""},
	{ModeFTS, "error OR timeout", []string{"disk", "slow", "both", "later", "cjk"}, ""},
	{ModeFTS, `"error" or "timeout"`, []string{"disk", "slow", "both", "later", "cjk"}, ""},
	{ModeFTS, "error NOT timeout", []string{"disk", "cjk"}, ""},
	{ModeFTS, "error not timeout", []string{"disk", "cjk"}, ""},
	{ModeFTS, "(error OR refused) NOT disk", []string{"both", "later", "refused", "cjk"}, ""},
	{ModeFTS, "error timeout OR refused", []string{"both", "later", "refused"}, ""},
	{ModeFTS, `"error timeout"`, []string{"both"}, ""},
	{ModeFTS, "time*", []string{"slow", "both", "later"}, ""},
	{ModeFTS, `"connection ref"*`, []string{"refused"}, ""},
	{ModeFTS, "error*", []string{"disk", "both", "later", "cjk"}, ""},
	{ModeFTS, `"or"`, []string{"choice"}, ""},
	{ModeFTS, `"hello ""world"""`, []string{"quote"}, ""},
	{ModeFTS, "192.168.1.10", []string{"ssh"}, ""},
	{ModeFTS, "délai", []string{"french"}, ""},
	{ModeFTS, "DELAI", []string{"french"}, ""},
	{ModeFTS, "数据库连接失败", []string{"cjk"}, ""},
	{ModeFTS, "NEAR(error timeout, 0)", []string{"both"}, ""},
	{ModeFTS, "NEAR(error timeout, 2)", []string{"both", "later"}, ""},
	{ModeFTS, "near(error timeout, 2)", []string{"both", "later"}, ""},
	{ModeFTS, "NEAR(error connecting)", []string{"both"}, ""},
	{ModeFTS, "NEAR(error connecting, 1)", []string{}, ""},
	{ModeFTS, `NEAR("connection refused" peer, 1)`, []string{"refused"}, ""},
	{ModeFTS, "NEAR(time* error, 5) NOT connecting", []string{"later"}, ""},
	{ModeFTS, "near error", []string{}, ""},
	{ModeFTS, "NEAR(error OR timeout)", nil, ErrNearWordsOnly},
	{ModeFTS, "NEAR(error, x)", nil, ErrNearDistance},
	{ModeFTS, "NEAR(error timeout", nil, ErrUnclosedParen},
	{ModeFTS, "NEAR()", nil, ErrMissingTerm},
	{ModeFTS, "error)", nil, ErrUnexpectedParen},
	{ModeFTS, `"error`, nil, ErrUnclosedQuote},
	{ModeFTS, "(error", nil, ErrUnclosedParen},
	{ModeFTS, "error OR", nil, ErrMissingTerm},
	{ModeFTS, "AND error", nil, ErrMissingTerm},
	{ModeFTS, "()", nil, ErrMissingTerm},
	{ModeFTS, "NOT error", nil, ErrNotNeedsLeft},
	{ModeFTS, "error OR NOT timeout", nil, ErrNotNeedsLeft},
	{ModeFTS, "->", nil, ErrNoWords},
	{ModeFTS, "*", nil, ErrNoWords},

	// Regex: Go's syntax, without regard to case.
	{ModeRegex, `err(or)?\s+on`, []string{"disk"}, ""},
	{ModeRegex, "TIMEOUT", []string{"slow", "both", "later"}, ""},
	{ModeRegex, "(", nil, ErrBadRegex},
	{ModeRegex, strings.Repeat("a", 1001), nil, ErrRegexTooLong},
}

func allIDs() []string {
	ids := make([]string, len(corpus))
	for i, m := range corpus {
		ids[i] = m.ID
	}
	return ids
}

// ftsIndex is the history's index over the corpus: the same two columns.
func ftsIndex(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec("CREATE VIRTUAL TABLE f USING fts5(message, raw_message)"); err != nil {
		t.Fatal(err)
	}
	for i, m := range corpus {
		if _, err := db.Exec("INSERT INTO f(rowid, message, raw_message) VALUES(?, ?, ?)", i, m.Message, m.RawMessage); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

// fromIndex is what the history finds for a plan, asked the way the log store
// asks.
func fromIndex(t *testing.T, db *sql.DB, p *Plan) []string {
	t.Helper()
	var rows *sql.Rows
	var err error
	switch {
	case p.FTS5() != "":
		rows, err = db.Query("SELECT rowid FROM f WHERE f MATCH ? ORDER BY rowid", p.FTS5())
	case p.Literal != "":
		rows, err = db.Query("SELECT rowid FROM f WHERE instr(lower(message), ?) > 0 OR instr(lower(raw_message), ?) > 0 ORDER BY rowid", p.Literal, p.Literal)
	default:
		rows, err = db.Query("SELECT rowid FROM f ORDER BY rowid")
	}
	if err != nil {
		t.Fatalf("FTS5 refused %q: %v", p.FTS5(), err)
	}
	defer rows.Close()
	ids := []string{}
	for rows.Next() {
		var i int
		rows.Scan(&i)
		ids = append(ids, corpus[i].ID)
	}
	return ids
}

type goldenCase struct {
	Mode  string   `json:"mode"`
	Query string   `json:"query"`
	Plan  Plan     `json:"plan"`
	Want  []string `json:"want"`
}

type goldenCases struct {
	Corpus []corpusMessage `json:"corpus"`
	Cases  []goldenCase    `json:"cases"`
}

func TestPlans(t *testing.T) {
	db := ftsIndex(t)
	golden := goldenCases{Corpus: corpus}
	for _, c := range cases {
		p := Compile(c.query, c.mode)
		want := c.want
		if want == nil {
			want = allIDs()
		}
		name := c.mode + " " + c.query
		if len(name) > 40 {
			name = name[:40]
		}
		t.Run(name, func(t *testing.T) {
			switch {
			case c.code != "" && (p.Error == nil || p.Error.Code != c.code):
				t.Fatalf("error = %v, want %s", p.Error, c.code)
			case c.code == "" && p.Error != nil:
				t.Fatalf("unexpected error %v", p.Error)
			}
			got := []string{}
			for _, m := range corpus {
				if p.Match(m.Message, m.RawMessage) {
					got = append(got, m.ID)
				}
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("live and export find %v, want %v", got, want)
			}
			if !p.NeedsScan() {
				if hist := fromIndex(t, db, &p); !reflect.DeepEqual(hist, want) {
					t.Errorf("history finds %v (MATCH %s), want %v", hist, p.FTS5(), want)
				}
			}
		})
		golden.Cases = append(golden.Cases, goldenCase{Mode: c.mode, Query: c.query, Plan: p, Want: want})
	}
	checkGolden(t, "cases.json", golden)
}

// The texts whose words the window must split as FTS5 does: what logs are
// made of, then whole Unicode blocks.
var wordTexts = []string{
	"Oct 11 22:14:15 web-01 sshd[4242]: Failed password for root from 10.0.0.5 port 22 ssh2",
	"GET /api/v1/users?id=42&sort=desc HTTP/1.1 200 1534 \"-\" \"curl/8.4.0\"",
	"user_name=alice key=value;other=thing [ERROR] {json:true} <tag/> 50% €100 C:\\Windows\\System32",
	"2001:db8::ff00:42:8329 fe80::1%eth0 aa:bb:cc:dd:ee:ff eth0.100",
	"Café Ünïcödé ÉLÈVE naïve façade Ångström Øresund Łódź straße İstanbul ǅemal",
	"cafe\u0301 a\u0308b e\u0305f",
	"Ωμέγα ΣΊΣΥΦΟΣ σίσυφος µs ſtraße ϐ ϑ",
	"ПРИВЕТ мир Ёжик",
	"日本語テキスト 中文 한국어 ＡＢＣ１２３",
	"ằ ṍ Ǿ ǿ ḣ Ḣ",
	"tab\tsep nbsp\u00a0x zero\u200bwidth line\u2028sep",
	"don't it's O'Brien naïve—em-dash…ellipsis",
	"½ ² ① Ⅻ ° ™ ©2026",
}

// wordBlocks are the Unicode blocks swept character by character. FTS5 sorts
// characters by Unicode 6.1: the few letters assigned since in these blocks
// are left out, as are code points still unassigned.
var wordBlocks = [][2]rune{
	{0x21, 0x7E}, {0xA1, 0x24F}, {0x250, 0x36F}, {0x370, 0x37E}, {0x384, 0x3FF},
	{0x400, 0x527}, {0x1E00, 0x1FFF}, {0x2000, 0x2064}, {0x3041, 0x30FF},
	{0x4E00, 0x4FFF}, {0xAC00, 0xADFF}, {0xFF01, 0xFFEF},
}

func blockText(lo, hi rune) string {
	var b strings.Builder
	for r := lo; r <= hi; r++ {
		if !unicode.In(r, unicode.L, unicode.M, unicode.N, unicode.P, unicode.S, unicode.Z, unicode.Cc, unicode.Cf, unicode.Co) {
			continue // unassigned
		}
		b.WriteString("q" + string(r) + "q ")
	}
	return b.String()
}

type goldenWords struct {
	Text  string   `json:"text"`
	Words []string `json:"words"`
}

func TestWordsAreFTS5Words(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	db.Exec("CREATE VIRTUAL TABLE f USING fts5(x)")
	db.Exec("CREATE VIRTUAL TABLE v USING fts5vocab(f, 'instance')")

	texts := append([]string{}, wordTexts...)
	for _, b := range wordBlocks {
		texts = append(texts, blockText(b[0], b[1]))
	}
	var golden []goldenWords
	for i, text := range texts {
		if _, err := db.Exec("INSERT INTO f(rowid, x) VALUES(?, ?)", i, text); err != nil {
			t.Fatal(err)
		}
		rows, err := db.Query("SELECT term FROM v WHERE doc = ? ORDER BY offset", i)
		if err != nil {
			t.Fatal(err)
		}
		fts := []string{}
		for rows.Next() {
			var w string
			rows.Scan(&w)
			fts = append(fts, w)
		}
		rows.Close()
		got := Words(text)
		if got == nil {
			got = []string{}
		}
		if !reflect.DeepEqual(got, fts) {
			k := 0
			for k < len(got) && k < len(fts) && got[k] == fts[k] {
				k++
			}
			t.Errorf("text %d: Words parts from FTS5 at word %d: %+q vs %+q", i, k, tail(got, k), tail(fts, k))
		}
		golden = append(golden, goldenWords{Text: text, Words: fts})
	}
	checkGolden(t, "words.json", golden)
}

func tail(ws []string, k int) []string {
	if k+3 < len(ws) {
		return ws[k : k+3]
	}
	return ws[k:]
}

// checkGolden compares what testdata holds with what the tests computed, or
// writes it with -update.
func checkGolden(t *testing.T, name string, v any) {
	t.Helper()
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	have, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v: run go test ./internal/search -update", err)
	}
	if !bytes.Equal(bytes.ReplaceAll(have, []byte("\r\n"), []byte("\n")), data) {
		t.Fatalf("testdata/%s is stale: run go test ./internal/search -update, and the frontend's tests", name)
	}
}
