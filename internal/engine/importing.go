package engine

import (
	"fmt"
	"time"

	"SyslogStudio/internal/importer"
	"SyslogStudio/internal/models"
)

// --- Importing a log file ---------------------------------------------------
//
// Asked for in #46: read logs that are already on disk and sort them by
// severity, for a site where running a receiver around the clock is not worth
// it.
//
// Two things make this more than "read the file and call Parse".
//
// A captured syslog file goes through the wire parser and nothing is guessed.
// A plain application log has no PRI, and Parse deliberately makes such a line
// a Notice stamped with the moment it was read — correct for a stray line off
// the network, useless for a file, because ten thousand identical Notices do
// not sort by severity. So a plain line's timestamp and level are INFERRED, and
// the preview exists so that inference can be seen and rejected before anything
// is imported.
//
// And an import is history, not traffic. It never fires alert rules and never
// reaches the router: relaying last week's logs to a live SIEM is the worst
// surprise this feature could spring on someone opening an archive to look at
// it.

// importBatch is how many messages are sent to the renderer at once. The same
// shape the receiver uses, so the viewer's existing path handles them.
const importBatch = 500

// PreviewLogFile reads the first lines of a file and reports what they would
// become, without importing anything.
//
// This is what turns a guess into a decision: the counts say how much was read
// from the file and how much was inferred from it, and the sample shows the
// result, so the operator can judge before committing.
//
// It is also the test bench for a declared format. The dialog calls this again
// on every change, so a pattern is written against the file's own lines and
// judged by what comes back — not written blind and discovered to be wrong
// after ten thousand messages have been imported.
func (e *Engine) PreviewLogFile(path string, format models.ImportFormat) (importer.Preview, error) {
	if path == "" {
		return importer.Preview{}, fmt.Errorf("no file chosen")
	}
	return importer.PreviewFile(e.importOptions(path, format))
}

// ImportLogFile reads a file into the live view.
//
// persist writes the messages to the database as well. It defaults to off in
// the interface on purpose: mixing an imported archive into the history of a
// running receiver is a decision, not something to discover afterwards.
func (e *Engine) ImportLogFile(path string, persist bool, format models.ImportFormat) (importer.Result, error) {
	if path == "" {
		return importer.Result{}, fmt.Errorf("no file chosen")
	}

	opts := e.importOptions(path, format)
	// Sized to the ring the viewer reads from: importing more than it can hold
	// would silently drop the beginning of the file, which reads as a broken
	// import rather than a full buffer.
	if e.server != nil {
		opts.Limit = e.server.BufferSize()
	}

	batch := make([]models.SyslogMessage, 0, importBatch)
	flush := func() {
		if len(batch) == 0 || e.emitter == nil {
			return
		}
		e.emitter.Emit("syslog:messages", batch)
		batch = make([]models.SyslogMessage, 0, importBatch)
	}

	ls := e.logStore
	res, err := importer.Read(opts, func(msg models.SyslogMessage) bool {
		if e.server != nil {
			e.server.AddImported(msg)
		}
		if persist && ls != nil {
			ls.BufferMessage(msg)
		}
		batch = append(batch, msg)
		if len(batch) >= importBatch {
			flush()
		}
		return true
	})
	flush()

	// Remembered only when it worked. Storing a format that just failed would
	// mean the next import opens pre-loaded with the thing that went wrong.
	if err == nil && e.configStore != nil {
		e.configStore.SaveImportFormat(format)
	}

	return res, err
}

// GetImportFormat is what the dialog opens with: whatever the last import
// used, or automatic detection the first time.
func (e *Engine) GetImportFormat() models.ImportFormat {
	if e.configStore == nil {
		return models.DefaultImportFormat()
	}
	return e.configStore.LoadImportFormat()
}

// importOptions answers the two questions a file cannot: which year a
// BSD-shaped timestamp belongs to, and which zone a timestamp without one is
// read in.
//
// The local zone, because that is exactly what the wire parser does with an
// RFC 3164 message (#24) — so a line read from a file and the same line
// received over the network land on the same instant. The timezone setting in
// the interface changes how a timestamp is DISPLAYED, not how a zoneless one is
// interpreted, and importing must not be the one place that differs.
func (e *Engine) importOptions(path string, format models.ImportFormat) importer.Options {
	return importer.Options{
		Path:     path,
		Year:     time.Now().Year(),
		Location: time.Local,
		Format:   format,
	}
}
