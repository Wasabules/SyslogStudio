// Command oui turns the IEEE's MA-L registry into the list of manufacturers
// SyslogStudio embeds (internal/neighbors/oui.txt.gz): one "AABBCC<TAB>Name"
// line per assignment, sorted.
//
//	curl -o oui.csv https://standards-oui.ieee.org/oui/oui.csv
//	go run ./tools/oui oui.csv internal/neighbors/oui.txt.gz
package main

import (
	"compress/gzip"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: oui <oui.csv> <out.txt.gz>")
		os.Exit(2)
	}
	if err := run(os.Args[1], os.Args[2]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(in, out string) error {
	f, err := os.Open(in)
	if err != nil {
		return err
	}
	defer f.Close()
	r := csv.NewReader(f)
	r.FieldsPerRecord = -1
	header, err := r.Read()
	if err != nil || len(header) < 3 || header[1] != "Assignment" {
		return fmt.Errorf("%s is not the IEEE's oui.csv", in)
	}
	names := map[string]string{}
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if len(rec) < 3 || rec[0] != "MA-L" || len(rec[1]) != 6 {
			continue
		}
		name := strings.Join(strings.Fields(rec[2]), " ")
		if name != "" {
			names[strings.ToUpper(rec[1])] = name
		}
	}
	prefixes := make([]string, 0, len(names))
	for p := range names {
		prefixes = append(prefixes, p)
	}
	sort.Strings(prefixes)

	o, err := os.Create(out)
	if err != nil {
		return err
	}
	zw, err := gzip.NewWriterLevel(o, gzip.BestCompression)
	if err != nil {
		o.Close()
		return err
	}
	for _, p := range prefixes {
		fmt.Fprintf(zw, "%s\t%s\n", p, names[p])
	}
	if err := zw.Close(); err != nil {
		o.Close()
		return err
	}
	fmt.Printf("%d manufacturers\n", len(prefixes))
	return o.Close()
}
