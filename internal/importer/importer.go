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
)

const (
	// maxLineBytes bounds one line. A log file can contain a single enormous
	// line — a stack trace, a base64 payload, or a truncated write — and
	// bufio.Scanner's default 64 KiB would abort the whole import on it.
	// Longer lines are truncated and counted rather than ending the read.
	maxLineBytes = 1 << 20 // 1 MiB
	// maxJoinLines and maxJoinBytes bound one record's continuation lines. A
	// format that matches nothing would otherwise fold an entire file into a
	// single message, which is a worse failure than a wrong severity because
	// nothing about it looks wrong until the message is opened.
	maxJoinLines = 500
	maxJoinBytes = 64 * 1024
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
	// Format describes the file. Its zero value means automatic detection, so
	// a caller that says nothing gets the behaviour it had before formats
	// existed. Year and Location above are what a format leaves unsaid; the
	// format wins when it says them itself.
	Format models.ImportFormat
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
	// Unmatched counts lines that did not fit the declared format. Reported
	// rather than hidden: a format that matches nothing is a format chosen
	// wrongly, and the number says so before the import is confirmed.
	Unmatched int `json:"unmatched"`
	// Joined counts continuation lines folded into the record above them —
	// the stack-trace lines that would otherwise each become a message.
	Joined int `json:"joined"`
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

	// A format answers the two questions a file cannot, when it was told them;
	// the caller's Year and Location are the fallback, which is what keeps a
	// caller that predates formats working unchanged.
	format := opts.Format
	if format.Year == 0 {
		format.Year = opts.Year
	}
	if format.Timezone == "" && opts.Location != nil {
		format.Timezone = opts.Location.String()
	}
	p, err := newParser(format)
	if err != nil {
		return res, err
	}

	rc, err := open(opts.Path)
	if err != nil {
		return res, err
	}
	defer rc.Close()

	sc := bufio.NewScanner(rc)
	sc.Buffer(make([]byte, 0, 64*1024), maxLineBytes)

	// The record being built. A line that does not start a record is attached
	// to this one, so a stack trace is one message at the right severity rather
	// than twenty stray Notices — which is only exact because the format says
	// what starting a record looks like.
	var (
		held      record
		holding   bool
		joined    int
		joinBytes int
	)

	// release lets the held record go. The counting happens here rather than
	// at parse time, because a line that is still being added to has not become
	// a message yet.
	release := func() bool {
		if !holding {
			return true
		}
		holding = false
		res.Imported++
		res.BySeverity[held.msg.SeverityLabel]++
		if held.syslog {
			res.Syslog++
		}
		if held.hasTime {
			res.TimeDetected++
		}
		if held.hasLevel {
			res.LevelDetected++
		}
		return emit(held.msg)
	}

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

		r := p.parse(line, res.File)

		if !r.start {
			// A continuation belongs to the record above it, and only to one
			// that actually started a record: without that condition a file of
			// plain sentences would collapse into a single message.
			//
			// Counted as joined and NOT as unmatched: a stack-trace line found
			// its place. Counting it both ways would report six unrecognised
			// lines on a file that was read perfectly, which reads as a warning
			// about nothing.
			if p.format.JoinContinuations && holding && held.start &&
				joined < maxJoinLines && joinBytes < maxJoinBytes {
				held.msg.Message += "\n" + line
				held.msg.RawMessage += "\n" + line
				res.Joined++
				joined++
				joinBytes += len(line)
				continue
			}
			res.Unmatched++
			if p.format.SkipUnmatched {
				continue
			}
		}

		if !release() {
			res.Stopped = true
			return finish(res, sc)
		}
		if opts.Limit > 0 && res.Imported >= opts.Limit {
			res.Stopped = true
			return finish(res, sc)
		}

		held, holding, joined, joinBytes = r, true, 0, 0
	}

	if !release() {
		res.Stopped = true
	}
	return finish(res, sc)
}

// finish reports a read error in the terms its remedy differs by.
func finish(res Result, sc *bufio.Scanner) (Result, error) {
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
