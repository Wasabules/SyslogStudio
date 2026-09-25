package importer

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"SyslogStudio/internal/models"
	"SyslogStudio/internal/syslog"
)

const (
	// maxLineBytes bounds one line. A log file can contain a single enormous
	// line — a stack trace, a base64 payload, or a truncated write — and
	// bufio.Scanner's default 64 KiB would abort the whole import on it.
	// Longer lines are truncated and counted rather than ending the read.
	maxLineBytes = 1 << 20 // 1 MiB
	// previewLines is how much is read to show the operator what will happen.
	// Enough to be representative, small enough to be instant on a file of any
	// size.
	previewLines = 200
)

// Options describe how a file should be read.
type Options struct {
	// Path is the file. A .gz suffix is decompressed, because rotated logs are
	// almost always gzipped and asking the user to gunzip first would be a
	// chore the application can simply not impose.
	Path string
	// Year supplies the one a BSD-shaped timestamp omits.
	Year int
	// Location is the zone a timestamp without one is read in. Nil means local.
	Location *time.Location
	// Limit caps how many messages are produced. 0 means the caller's buffer
	// size is the only limit, which the caller passes explicitly.
	Limit int
}

// Result reports what an import did, in the terms someone would check it by.
type Result struct {
	// File is the base name, used as the source so imported lines are visibly
	// not received traffic.
	File string `json:"file"`
	// LinesRead is every line the file had, including the ones skipped.
	LinesRead int `json:"linesRead"`
	// Imported is how many messages were produced.
	Imported int `json:"imported"`
	// Blank counts empty lines, which are skipped silently: a file ending in a
	// newline is not a file with a mystery message at the end.
	Blank int `json:"blank"`
	// Truncated counts lines longer than one mebibyte, kept but cut.
	Truncated int `json:"truncated"`
	// Syslog counts lines that carried a <PRI> and went through the wire
	// parser, guessing nothing.
	Syslog int `json:"syslog"`
	// TimeDetected and LevelDetected count what was INFERRED from plain lines.
	// Reported so the operator can see how much of the result is inference
	// rather than being told a number and left to trust it.
	TimeDetected  int `json:"timeDetected"`
	LevelDetected int `json:"levelDetected"`
	// Stopped is set when Limit cut the read short, so a partial import is
	// never mistaken for a complete one.
	Stopped bool `json:"stopped"`
	// BySeverity counts the result per severity label, which is the question
	// the feature exists to answer.
	BySeverity map[string]int `json:"bySeverity"`
}

// Preview is a sample of what an import would produce, for confirming before
// committing to it.
type Preview struct {
	Result   Result                 `json:"result"`
	Messages []models.SyslogMessage `json:"messages"`
}

func open(path string) (io.ReadCloser, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(filepath.Ext(path), ".gz") {
		return f, nil
	}
	gz, err := gzip.NewReader(f)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("%s does not look like a gzip file: %w", filepath.Base(path), err)
	}
	// Closing the gzip reader does not close the file underneath it.
	return struct {
		io.Reader
		io.Closer
	}{Reader: gz, Closer: multiCloser{gz, f}}, nil
}

type multiCloser []io.Closer

func (m multiCloser) Close() error {
	var first error
	for _, c := range m {
		if err := c.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// Read turns a file into messages.
//
// `emit` is called for each one. Returning false from it stops the read, which
// is how the caller enforces its own ceiling without this package knowing about
// ring buffers.
func Read(opts Options, emit func(models.SyslogMessage) bool) (Result, error) {
	res := Result{File: filepath.Base(opts.Path), BySeverity: map[string]int{}}

	loc := opts.Location
	if loc == nil {
		loc = time.Local
	}
	year := opts.Year
	if year == 0 {
		year = time.Now().In(loc).Year()
	}

	rc, err := open(opts.Path)
	if err != nil {
		return res, err
	}
	defer rc.Close()

	sc := bufio.NewScanner(rc)
	sc.Buffer(make([]byte, 0, 64*1024), maxLineBytes)

	for sc.Scan() {
		res.LinesRead++
		line := strings.TrimRight(sc.Text(), "\r")

		if strings.TrimSpace(line) == "" {
			res.Blank++
			continue
		}
		if len(line) >= maxLineBytes {
			res.Truncated++
		}

		msg := convert(line, res.File, year, loc, &res)
		res.Imported++
		res.BySeverity[msg.SeverityLabel]++

		if !emit(msg) {
			res.Stopped = true
			break
		}
		if opts.Limit > 0 && res.Imported >= opts.Limit {
			res.Stopped = true
			break
		}
	}

	if err := sc.Err(); err != nil {
		// A line past the ceiling is the one error worth naming, because the
		// remedy is different from "the file is unreadable".
		if err == bufio.ErrTooLong {
			return res, fmt.Errorf("a line exceeds %d bytes, which is past what this reads", maxLineBytes)
		}
		return res, err
	}
	return res, nil
}

// convert turns one line into a message.
//
// A line with a <PRI> is the thing this application already parses off the
// wire, so it goes through the same parser and nothing is guessed. Anything
// else is a plain line, where the timestamp and the level are inference.
func convert(line, file string, year int, loc *time.Location, res *Result) models.SyslogMessage {
	if strings.HasPrefix(strings.TrimLeft(line, " \t"), "<") {
		msg := syslog.Parse([]byte(line), file, "file")
		res.Syslog++
		return msg
	}

	d := Detect(line, year, loc)

	// Parse gives the shape — an id, the labels, a sane fallback — and what was
	// detected is laid over it. Building the message here instead would mean a
	// second place that has to know how a SyslogMessage is filled in.
	msg := syslog.Parse([]byte(d.Rest), file, "file")
	msg.RawMessage = line

	if d.HasTime {
		msg.Timestamp = d.Timestamp
		res.TimeDetected++
	}
	if d.HasLevel {
		msg.Severity = d.Severity
		msg.SeverityLabel = models.SeverityToLabel(d.Severity)
		res.LevelDetected++
	}
	return msg
}

// PreviewFile reads the first few lines so the operator can see what the file
// will turn into — how much was recognised and how much was assumed — before
// any of it reaches the viewer.
func PreviewFile(opts Options) (Preview, error) {
	opts.Limit = previewLines
	var out []models.SyslogMessage
	res, err := Read(opts, func(m models.SyslogMessage) bool {
		out = append(out, m)
		return true
	})
	return Preview{Result: res, Messages: out}, err
}
