package storage

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"SyslogStudio/internal/models"
)

// The history must keep, sort and group the messages exactly as the live view
// does. internal/search/testdata/filters.json says how, and is checked there
// against the Go side and in frontend/tests against the window's; this holds
// the SQL to it.
func TestLogStore_FiltersAsSpecified(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "search", "testdata", "filters.json"))
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		Corpus  []models.SyslogMessage `json:"corpus"`
		Filters []struct {
			Name     string                `json:"name"`
			Criteria models.FilterCriteria `json:"criteria"`
			Want     []string              `json:"want"`
		} `json:"filters"`
		Sorts []struct {
			Field string   `json:"field"`
			Dir   string   `json:"dir"`
			Want  []string `json:"want"`
		} `json:"sorts"`
		Groups []struct {
			Field  string                `json:"field"`
			Groups []models.GroupSummary `json:"groups"`
		} `json:"groups"`
	}
	if err := json.Unmarshal(data, &spec); err != nil {
		t.Fatal(err)
	}

	ls := newTestStore(t, models.StorageConfig{})
	<-ls.ftsReadyCh
	// One transaction, in order: rowids follow the order of arrival.
	if err := ls.InsertMessages(spec.Corpus); err != nil {
		t.Fatal(err)
	}
	query := func(f models.FilterCriteria, field, dir string) []string {
		res := ls.QueryMessages(models.QueryOptions{Filter: f, Page: 1, PageSize: 100, SortField: field, SortDir: dir})
		ids := []string{}
		for _, m := range res.Messages {
			ids = append(ids, m.ID)
		}
		return ids
	}

	for _, c := range spec.Filters {
		got := query(c.Criteria, "", "")
		slices.Sort(got)
		want := slices.Clone(c.Want)
		slices.Sort(want)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("filter %q: the history keeps %v, want %v", c.Name, got, want)
		}
	}
	for _, c := range spec.Sorts {
		if got := query(models.FilterCriteria{}, c.Field, c.Dir); !reflect.DeepEqual(got, c.Want) {
			t.Errorf("sort by %s %s: the history gives %v, want %v", c.Field, c.Dir, got, c.Want)
		}
	}
	for _, c := range spec.Groups {
		got := ls.QueryGroups(models.FilterCriteria{}, c.Field)
		if !reflect.DeepEqual(got, c.Groups) {
			t.Errorf("groups by %s: the history gives %+v, want %+v", c.Field, got, c.Groups)
		}
	}
}

// A database from before had byte-order indexes on the text columns; opening
// it replaces them with the case-blind ones its sorting now walks.
func TestLogStore_SortIndexesAreMigrated(t *testing.T) {
	ls := newTestStore(t, models.StorageConfig{})
	<-ls.ftsReadyCh
	db := ls.handle()
	for _, stmt := range []string{
		"DROP INDEX idx_hostname_nocase",
		"CREATE INDEX idx_hostname ON messages(hostname)",
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	migrateSortIndexes(db)
	var names []string
	rows, err := db.Query("SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'messages' AND name LIKE 'idx_%' ORDER BY name")
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var n string
		rows.Scan(&n)
		names = append(names, n)
	}
	rows.Close()
	want := []string{"idx_app_name_nocase", "idx_hostname_nocase", "idx_severity", "idx_source_ip_nocase", "idx_timestamp"}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("indexes %v, want %v", names, want)
	}
	var plan string
	db.QueryRow("EXPLAIN QUERY PLAN SELECT id FROM messages"+buildOrderClause("hostname", "asc")+" LIMIT 10").Scan(new(int), new(int), new(int), &plan)
	if want := "SCAN messages USING INDEX idx_hostname_nocase"; plan != want {
		t.Errorf("sorting by hostname: %q, want %q", plan, want)
	}
}
