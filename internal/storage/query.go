package storage

import (
	"database/sql"
	"database/sql/driver"
	"log/slog"
	"strings"
	"sync"
	"time"

	"SyslogStudio/internal/search"

	"modernc.org/sqlite"
)

// The history's half of the filters, sorting and grouping that the live view
// applies in the window. Each criterion has one meaning, defined in
// internal/search; this turns it into SQL that means the same, as cheaply as
// SQLite allows.

func init() {
	// ss_fold is search.Fold in SQL: what a field box compares, for the rare
	// rows that LIKE cannot judge alone (see containsCondition).
	sqlite.MustRegisterDeterministicScalarFunction("ss_fold", 1,
		func(_ *sqlite.FunctionContext, args []driver.Value) (driver.Value, error) {
			switch v := args[0].(type) {
			case string:
				return search.Fold(v), nil
			case []byte:
				return search.Fold(string(v)), nil
			}
			return args[0], nil
		})
	// ss_addr is search.Address.Match in SQL, for what plain SQL cannot say:
	// whether an address is inside a CIDR.
	sqlite.MustRegisterDeterministicScalarFunction("ss_addr", 2,
		func(_ *sqlite.FunctionContext, args []driver.Value) (driver.Value, error) {
			value, _ := args[0].(string)
			typed, _ := args[1].(string)
			if a, ok := compiledAddresses.Load(typed); ok {
				return a.(search.Address).Match(value), nil
			}
			a := search.CompileAddress(typed, false)
			compiledAddresses.Store(typed, a)
			return a.Match(value), nil
		})
}

// compiledAddresses keeps ss_addr from compiling its CIDR once per row. One
// entry per CIDR filtered on in this run, which a person types.
var compiledAddresses sync.Map

// buildWhereClause turns a compiled filter into SQL. A search plan that needs
// a scan — a regex — is left for the caller to apply to the rows.
func buildWhereClause(f *search.Filter) (string, []any) {
	var conditions []string
	var args []any

	if len(f.Severities) > 0 {
		conditions = append(conditions, "severity IN ("+placeholders(len(f.Severities))+")")
		for s := range f.Severities {
			args = append(args, s)
		}
	}
	if len(f.Facilities) > 0 {
		conditions = append(conditions, "facility IN ("+placeholders(len(f.Facilities))+")")
		for x := range f.Facilities {
			args = append(args, x)
		}
	}
	for _, field := range []struct {
		col    string
		needle string
	}{
		{"hostname", f.Hostname.Needle},
		{"app_name", f.AppName.Needle},
	} {
		if field.needle != "" {
			cond, a := containsCondition(field.col, field.needle)
			conditions = append(conditions, cond)
			args = append(args, a...)
		}
	}
	if cond, a := addressCondition("source_ip", f.SourceIP); cond != "" {
		conditions = append(conditions, cond)
		args = append(args, a...)
	}

	if match := f.Plan.FTS5(); match != "" {
		conditions = append(conditions, "rowid IN (SELECT rowid FROM messages_fts WHERE messages_fts MATCH ?)")
		args = append(args, match)
	} else if f.Plan.Active() && f.Plan.Literal != "" {
		// No word to look up in the index: read the text itself.
		m, ma := containsCondition("message", f.Plan.Literal)
		r, ra := containsCondition("raw_message", f.Plan.Literal)
		conditions = append(conditions, "("+m+" OR "+r+")")
		args = append(append(args, ma...), ra...)
	}

	if !f.From.IsZero() {
		conditions = append(conditions, "timestamp >= ?")
		args = append(args, sqlTime(f.From))
	}
	if !f.To.IsZero() {
		conditions = append(conditions, "timestamp < ?")
		args = append(args, sqlTime(f.To))
	}

	if col, ok := groupColumns[f.GroupField]; ok {
		if _, indexed := nocaseIndexed[col]; indexed {
			// Equal without regard to case first, which the column's index
			// answers; then exactly, which is what grouping meant.
			conditions = append(conditions, "("+col+" = ? COLLATE NOCASE AND "+col+" = ?)")
			args = append(args, f.GroupKey, f.GroupKey)
		} else {
			conditions = append(conditions, col+" = ?")
			args = append(args, f.GroupKey)
		}
	}

	if len(conditions) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(conditions, " AND "), args
}

func placeholders(n int) string {
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}

// containsCondition is search.Field's test in SQL: col, folded, contains the
// folded needle. LIKE answers it exactly for a row of plain ASCII — it ignores
// ASCII case and nothing else, and folding such a row only lowercases it — and
// when LIKE finds the needle in any row, folding would have found it too. So
// only the rows LIKE turns down and that hold something beyond ASCII, rare in
// the fields and cheap to tell apart (a character there takes more than one
// byte), go through ss_fold.
func containsCondition(col, needle string) (string, []any) {
	cond := "(" + col + ` LIKE ? ESCAPE '\'` +
		" OR (length(" + col + ") <> length(CAST(" + col + " AS BLOB)) AND instr(ss_fold(" + col + "), ?) > 0))"
	return cond, []any{"%" + escapeLike(needle) + "%", needle}
}

// addressCondition is search.Address's test in SQL. An exact address and a
// pattern are answered as containsCondition answers text: by the column's
// own comparison for a row of plain ASCII, through ss_fold for the others. A
// CIDR goes through ss_addr, after the index has narrowed the rows to those
// starting with its whole octets when it has some.
func addressCondition(col string, a search.Address) (string, []any) {
	ascii := "length(" + col + ") = length(CAST(" + col + " AS BLOB))"
	switch a.Kind {
	case search.AddressExact:
		return "(" + col + " = ? COLLATE NOCASE OR (NOT " + ascii + " AND ss_fold(" + col + ") = ?))",
			[]any{a.Text, a.Text}
	case search.AddressNet:
		if a.Bits == 0 {
			return "", nil
		}
		if a.Prefix != "" {
			return "(" + col + ` LIKE ? ESCAPE '\' AND ss_addr(` + col + ", ?))",
				[]any{escapeLike(a.Prefix) + "%", a.CIDR()}
		}
		return "ss_addr(" + col + ", ?)", []any{a.CIDR()}
	case search.AddressGlob:
		like := globEscaper.Replace(escapeLike(a.Text))
		return "((" + ascii + " AND " + col + ` LIKE ? ESCAPE '\') OR (NOT ` + ascii +
			" AND ss_fold(" + col + `) LIKE ? ESCAPE '\'))`, []any{like, like}
	case search.AddressText:
		return containsCondition(col, a.Text)
	}
	return "", nil
}

// globEscaper turns a glob, its LIKE wildcards already escaped, into LIKE.
var globEscaper = strings.NewReplacer("*", "%", "?", "_")

var likeEscaper = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)

// escapeLike makes LIKE's wildcards literal: "web_01" is not "web?01".
func escapeLike(s string) string { return likeEscaper.Replace(s) }

// sqlTime is a bound of the time range as the stored timestamps compare with
// it. They are RFC 3339 in UTC, with as many decimals as they have and a Z at
// the end — so "…:00Z" sorts after "…:00.5Z" as text. Written without the Z,
// and to the second, a bound sorts before every timestamp of its second and
// after every one before it, which is what >= and < need.
func sqlTime(t time.Time) string {
	return t.UTC().Truncate(time.Second).Format("2006-01-02T15:04:05")
}

// sortColumns are the columns the history sorts by, as the live view names
// them, each with the expression that orders it the way the live view does:
// numbers as numbers, text without regard to ASCII case.
var sortColumns = map[string][]string{
	"timestamp":  {"timestamp"},
	"receivedAt": {"received_at"},
	"severity":   {"severity"},
	"facility":   {"facility"},
	"version":    {"version"},
	"hostname":   {"hostname COLLATE NOCASE"},
	"appName":    {"app_name COLLATE NOCASE"},
	"sourceIP":   {"source_ip COLLATE NOCASE"},
	"protocol":   {"protocol COLLATE NOCASE"},
	"message":    {"message COLLATE NOCASE"},
	// Process and message ids: those that are numbers first, as numbers,
	// then the rest as text.
	"procID": idOrder("proc_id"),
	"msgID":  idOrder("msg_id"),
}

// idOrder sorts the ids that are numbers as numbers of any length — by their
// digits without leading zeros, shorter first — where a cast to an integer
// would saturate at 19 digits and the window could not follow past 16.
func idOrder(col string) []string {
	number := "(" + col + " <> '' AND " + col + " NOT GLOB '*[^0-9]*')"
	return []string{
		"(CASE WHEN " + number + " THEN 0 ELSE 1 END)",
		"(CASE WHEN " + number + " THEN length(ltrim(" + col + ", '0')) END)",
		"(CASE WHEN " + number + " THEN ltrim(" + col + ", '0') END)",
		col + " COLLATE NOCASE",
	}
}

// buildOrderClause orders by a column, ties by arrival — rowid, in the same
// direction — as the live view leaves them. The column's index holds rowid
// already, so the tie-break costs nothing; any other would cost a sort of
// every row.
func buildOrderClause(sortField, sortDir string) string {
	terms, ok := sortColumns[sortField]
	dir := " DESC"
	if !ok {
		// Unsorted, the history shows the newest first.
		terms = sortColumns["timestamp"]
	} else if sortDir == "asc" {
		dir = " ASC"
	}
	var b strings.Builder
	b.WriteString(" ORDER BY ")
	for _, t := range terms {
		b.WriteString(t + dir + ", ")
	}
	b.WriteString("rowid" + dir)
	return b.String()
}

// groupColumns are the fields the history groups by.
var groupColumns = map[string]string{
	search.GroupSeverity: "severity_label",
	search.GroupHostname: "hostname",
	search.GroupAppName:  "app_name",
	search.GroupSourceIP: "source_ip",
}

// nocaseIndexed are the columns indexed without regard to case: the text ones
// people sort by and group by.
var nocaseIndexed = map[string]string{
	"hostname":  "idx_hostname_nocase",
	"app_name":  "idx_app_name_nocase",
	"source_ip": "idx_source_ip_nocase",
}

// migrateSortIndexes gives a database from before its case-blind indexes, in
// place of the byte-order ones, so that sorting by hostname stays a walk down
// an index. Run once, in the background, after opening.
func migrateSortIndexes(db *sql.DB) {
	for col, name := range nocaseIndexed {
		if _, err := db.Exec("CREATE INDEX IF NOT EXISTS " + name + " ON messages(" + col + " COLLATE NOCASE)"); err != nil {
			slog.Warn("log store: index not built", "index", name, "error", err)
			continue
		}
		_, _ = db.Exec("DROP INDEX IF EXISTS idx_" + col)
	}
}
