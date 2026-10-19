package main

import (
	wailsRuntime "github.com/wailsapp/wails/v2/pkg/runtime"
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
//
// The reading itself lives in the engine; the window only asks which file.

// SelectLogFile asks for a file to import.
func (a *App) SelectLogFile() (string, error) {
	return wailsRuntime.OpenFileDialog(a.ctx, wailsRuntime.OpenDialogOptions{
		Title: "Select a log file",
		Filters: []wailsRuntime.FileFilter{
			{DisplayName: "Log files (*.log, *.txt, *.gz)", Pattern: "*.log;*.txt;*.gz"},
			{DisplayName: "All Files", Pattern: "*.*"},
		},
	})
}
