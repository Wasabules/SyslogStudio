package main

import (
	"context"
	"encoding/csv"
	"fmt"
	"log/slog"
	neturl "net/url"
	"os"
	"strings"
	"time"

	"SyslogStudio/internal/engine"
	"SyslogStudio/internal/models"
	"SyslogStudio/internal/remote"
	"SyslogStudio/internal/search"
	"SyslogStudio/internal/storage"
	"SyslogStudio/internal/updater"

	wailsRuntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// App is the Wails binding facade: the window's side of the application.
//
// What the receiver does lives in the engine, and reaches the frontend through
// the embedded Backend: the window's own engine, or the system service's when
// it runs (app_service.go). What stays here needs the window: file dialogs,
// the updater, the close button, the tray, and the user's own preferences.
type App struct {
	Backend

	ctx context.Context
	// sw is the embedded Backend: it forwards to the engine driven now.
	sw *remote.Switch
	// link is which engine that is, and why.
	link serviceLink
	// engine is the window's own engine, nil while it drives the service.
	// Read it through local(), under link's lock.
	engine *engine.Engine
	// prefs holds this window's preferences — the close action, update
	// checks. In-process it is the engine's own store, shared rather than
	// opened twice on the same file.
	prefs   *storage.ConfigStore
	updater *updater.Service

	// bg is how this run started and what that still owes: listeners to
	// start, a window to hide again.
	bg backgroundState
}

// NewApp creates a new App application struct.
func NewApp() *App {
	return newAppIn(storage.NewConfigStore())
}

// newAppIn builds the application around a configuration store, so tests can
// root one in a temporary directory.
func newAppIn(cs *storage.ConfigStore) *App {
	eng := engine.New(cs)
	sw := remote.NewSwitch(eng)
	a := &App{
		Backend: sw,
		sw:      sw,
		engine:  eng,
		prefs:   eng.ConfigStore(),
		updater: updater.NewService("Wasabules", "SyslogStudio"),
	}
	// An update quits for real: closing to the tray, or asking, would leave
	// the executable running and locked against the installer.
	a.updater.SetQuit(a.QuitApplication)
	return a
}

// startup is called when the app starts. It drives the system service when it
// runs, and its own engine otherwise.
//
// An engine that cannot claim its data directory — another SyslogStudio has
// it — still opens far enough to answer questions; the window asks
// GetDataDirConflict and explains instead of receiving.
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	a.updater.SetContext(ctx)
	a.startLink()
}

// shutdown is called when the app is closing.
func (a *App) shutdown(ctx context.Context) {
	a.stopLink()
}

// --- Certificate export ---
//
// The engine hands over the material; the window writes it where its user
// chose. Writing is the window's job because the file is the user's: an engine
// running as a service would otherwise create it under the service's account.

func (a *App) ExportCACertificate() (string, error) {
	certPEM, err := a.keyMaterial().CACertificatePEM()
	if err != nil {
		return "", err
	}

	path, err := wailsRuntime.SaveFileDialog(a.ctx, wailsRuntime.SaveDialogOptions{
		Title:           "Export CA Certificate (for device)",
		DefaultFilename: "ca-cert.pem",
		Filters: []wailsRuntime.FileFilter{
			{DisplayName: "PEM Files (*.pem, *.crt)", Pattern: "*.pem;*.crt"},
		},
	})
	if err != nil {
		return "", err
	}
	if path == "" {
		return "", nil
	}

	if err := os.WriteFile(path, certPEM, 0644); err != nil {
		return "", err
	}
	return path, nil
}

func (a *App) ExportServerCertificate() (string, error) {
	certPEM, keyPEM, err := a.keyMaterial().ServerCertificatePEM()
	if err != nil {
		return "", err
	}

	certPath, err := wailsRuntime.SaveFileDialog(a.ctx, wailsRuntime.SaveDialogOptions{
		Title:           "Export Server Certificate",
		DefaultFilename: "server-cert.pem",
		Filters: []wailsRuntime.FileFilter{
			{DisplayName: "PEM Files (*.pem)", Pattern: "*.pem"},
		},
	})
	if err != nil {
		return "", err
	}
	if certPath == "" {
		return "", nil
	}

	keyPath, err := wailsRuntime.SaveFileDialog(a.ctx, wailsRuntime.SaveDialogOptions{
		Title:           "Export Server Private Key",
		DefaultFilename: "server-key.pem",
		Filters: []wailsRuntime.FileFilter{
			{DisplayName: "PEM Files (*.pem)", Pattern: "*.pem"},
		},
	})
	if err != nil {
		return "", err
	}
	if keyPath == "" {
		return "", nil
	}

	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return "", fmt.Errorf("failed to write certificate: %w", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return "", fmt.Errorf("failed to write key: %w", err)
	}
	return fmt.Sprintf("Exported:\n  %s\n  %s", certPath, keyPath), nil
}

func (a *App) ExportCertificate() (string, error) {
	return a.ExportServerCertificate()
}

// CheckForUpdate queries GitHub for the latest release. Errors are logged and
// returned so the frontend can surface them (e.g. on a manual check).
func (a *App) CheckForUpdate() (models.UpdateInfo, error) {
	info, err := a.updater.CheckForUpdate()
	if err != nil {
		slog.Warn("update check failed", "error", err)
		return info, err
	}
	// Record the successful check time (used to throttle auto-checks).
	cfg := a.prefs.LoadUpdateConfig()
	cfg.LastCheckUnix = time.Now().Unix()
	a.prefs.SaveUpdateConfig(cfg)
	return info, nil
}

// DownloadAndApplyUpdate downloads the pending update, verifies it, and applies
// it (self-replace + relaunch, run the installer, or open the browser).
func (a *App) DownloadAndApplyUpdate() error {
	return a.updater.DownloadAndApply()
}

// GetAppVersion returns the current application version string.
func (a *App) GetAppVersion() string {
	return updater.GetAppVersion()
}

// OpenURL opens a URL in the user's default browser.
func (a *App) OpenURL(url string) {
	// Only open web URLs — never file:, javascript:, or custom-protocol
	// handlers, which BrowserOpenURL would otherwise dispatch.
	if u, err := neturl.Parse(url); err == nil && (u.Scheme == "http" || u.Scheme == "https") {
		wailsRuntime.BrowserOpenURL(a.ctx, url)
	}
}

// GetUpdateConfig returns the persisted update-check preferences.
func (a *App) GetUpdateConfig() models.UpdateConfig {
	return a.prefs.LoadUpdateConfig()
}

// SetUpdateConfig persists update-check preferences.
func (a *App) SetUpdateConfig(cfg models.UpdateConfig) {
	a.prefs.SaveUpdateConfig(cfg)
}

// SkipUpdateVersion records a release version the user chose to skip.
func (a *App) SkipUpdateVersion(version string) {
	cfg := a.prefs.LoadUpdateConfig()
	cfg.SkipVersion = version
	a.prefs.SaveUpdateConfig(cfg)
}

func (a *App) SelectCertFile() (string, error) {
	return wailsRuntime.OpenFileDialog(a.ctx, wailsRuntime.OpenDialogOptions{
		Title: "Select TLS Certificate",
		Filters: []wailsRuntime.FileFilter{
			{DisplayName: "PEM Files (*.pem, *.crt)", Pattern: "*.pem;*.crt"},
			{DisplayName: "All Files", Pattern: "*.*"},
		},
	})
}

func (a *App) SelectKeyFile() (string, error) {
	return wailsRuntime.OpenFileDialog(a.ctx, wailsRuntime.OpenDialogOptions{
		Title: "Select TLS Private Key",
		Filters: []wailsRuntime.FileFilter{
			{DisplayName: "PEM Files (*.pem, *.key)", Pattern: "*.pem;*.key"},
			{DisplayName: "All Files", Pattern: "*.*"},
		},
	})
}

func (a *App) SelectCAFile() (string, error) {
	return wailsRuntime.OpenFileDialog(a.ctx, wailsRuntime.OpenDialogOptions{
		Title: "Select CA Certificate",
		Filters: []wailsRuntime.FileFilter{
			{DisplayName: "PEM Files (*.pem, *.crt)", Pattern: "*.pem;*.crt"},
			{DisplayName: "All Files", Pattern: "*.*"},
		},
	})
}

// CompileSearch compiles a search for the live view, which applies the plan to
// the messages the window holds. The window never reads a query itself: the
// plan is the one the history and an export apply, so all three find the same
// messages.
func (a *App) CompileSearch(query, mode string) search.Plan {
	return search.Compile(query, mode)
}

// ExportLogs writes the filtered messages to a file the user picks. timezone is
// an IANA zone name from the display setting, so an export reads the same way as
// the screen it was taken from; an empty or unknown name falls back to the
// machine's zone rather than failing the export.
func (a *App) ExportLogs(filter models.FilterCriteria, format string, timezone string) (string, error) {
	return a.writeMessagesTo(a.GetMessages(filter), "syslog_export", format, timezone)
}

// ExportSelection writes only the messages whose ids are given.
//
// The same writers and the same dialog as a full export; what differs is
// which messages. Picking a handful of lines out of a stream and handing
// exactly those to someone is a different act from exporting everything a
// filter matched, and doing it by narrowing the filter until only those
// remain is not a thing anyone should have to do.
func (a *App) ExportSelection(ids []string, format string, timezone string) (string, error) {
	if len(ids) == 0 {
		return "", fmt.Errorf("nothing selected")
	}

	wanted := make(map[string]bool, len(ids))
	for _, id := range ids {
		wanted[id] = true
	}
	// Taken from the buffer in buffer order, not in the order they were
	// clicked: an export that reordered a log would be a strange thing to hand
	// to anyone.
	var messages []models.SyslogMessage
	for _, msg := range a.GetMessages(models.FilterCriteria{}) {
		if wanted[msg.ID] {
			messages = append(messages, msg)
		}
	}
	if len(messages) == 0 {
		return "", fmt.Errorf("the selected messages are no longer in the buffer")
	}
	return a.writeMessagesTo(messages, "syslog_selection", format, timezone)
}

// ExportMessages writes messages the interface hands over, as it has them.
//
// This is how an export can match the screen. Anonymous mode substitutes
// hostnames and addresses for DISPLAY, and that substitution lives in the
// interface — so an export written from the server's own copy contains the
// real values, whatever the screen says. Someone attaching that file to a
// ticket would be publishing exactly what they thought they had masked.
//
// Rather than teaching the backend to redact (a second implementation, whose
// stand-ins would not even match the ones on screen), the interface sends what
// it is showing.
func (a *App) ExportMessages(messages []models.SyslogMessage, format string, timezone string) (string, error) {
	if len(messages) == 0 {
		return "", fmt.Errorf("nothing to export")
	}
	return a.writeMessagesTo(messages, "syslog_export", format, timezone)
}

// writeMessagesTo asks where, then writes there. One place that knows how an
// export is named, filtered and written, for all three ways in.
func (a *App) writeMessagesTo(messages []models.SyslogMessage, base, format, timezone string) (string, error) {
	defaultFilename, wanted := exportFile(format, base)
	filters := make([]wailsRuntime.FileFilter, 0, len(wanted))
	for _, f := range wanted {
		filters = append(filters, wailsRuntime.FileFilter{DisplayName: f.Display, Pattern: f.Pattern})
	}

	path, err := wailsRuntime.SaveFileDialog(a.ctx, wailsRuntime.SaveDialogOptions{
		Title:           "Export Logs",
		DefaultFilename: defaultFilename,
		Filters:         filters,
	})
	if err != nil {
		return "", err
	}
	if path == "" {
		return "", nil
	}

	if err := writeExport(path, format, messages, resolveLocation(timezone)); err != nil {
		return "", fmt.Errorf("failed to write export: %w", err)
	}
	return path, nil
}

// sanitizeCSVField neutralizes spreadsheet formula injection (CWE-1236).
// Syslog message content is attacker-controlled; a message starting with
// '=', '+', '-' or '@' would be interpreted as a formula when the exported
// CSV is opened in Excel or LibreOffice. Prefixing a single quote forces
// the cell to be treated as text. Leading tab/CR are stripped as they can
// be used to smuggle a formula prefix past naive checks.
func sanitizeCSVField(s string) string {
	trimmed := strings.TrimLeft(s, "\t\r")
	if trimmed == "" {
		return s
	}
	switch trimmed[0] {
	case '=', '+', '-', '@':
		return "'" + s
	}
	return s
}

// resolveLocation turns an IANA zone name into a *time.Location, falling back to
// the machine's zone. Export is a user action with a file dialog already behind
// it; refusing to write because a zone name did not resolve would be a poor
// trade against writing it in local time.
func resolveLocation(name string) *time.Location {
	if name == "" {
		return time.Local
	}
	loc, err := time.LoadLocation(name)
	if err != nil {
		slog.Warn("unknown time zone for export, falling back to local", "zone", name, "error", err)
		return time.Local
	}
	return loc
}

// exportTimeLayout carries the UTC offset. The previous layout printed a bare
// wall clock, so an exported file could not be read without knowing which
// machine and which setting produced it — the same ambiguity issue #24 was
// about, one step further down the pipeline.
const exportTimeLayout = "2006-01-02 15:04:05 -07:00"

func writeCSV(path string, messages []models.SyslogMessage, loc *time.Location) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	f.Write([]byte{0xEF, 0xBB, 0xBF})

	w := csv.NewWriter(f)
	defer w.Flush()

	w.Write([]string{
		"Timestamp", "Severity", "Facility", "Hostname",
		"AppName", "ProcID", "Message", "SourceIP", "Protocol",
	})

	for _, msg := range messages {
		w.Write([]string{
			msg.Timestamp.In(loc).Format(exportTimeLayout),
			msg.SeverityLabel,
			msg.FacilityLabel,
			sanitizeCSVField(msg.Hostname),
			sanitizeCSVField(msg.AppName),
			sanitizeCSVField(msg.ProcID),
			sanitizeCSVField(msg.Message),
			msg.SourceIP,
			msg.Protocol,
		})
	}

	return w.Error()
}

func writeText(path string, messages []models.SyslogMessage, loc *time.Location) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	var sb strings.Builder
	for _, msg := range messages {
		sb.WriteString(fmt.Sprintf("%s [%s] %s %s %s: %s\n",
			msg.Timestamp.In(loc).Format(exportTimeLayout),
			msg.SeverityLabel,
			msg.FacilityLabel,
			msg.Hostname,
			msg.AppName,
			msg.Message,
		))
	}
	_, err = f.WriteString(sb.String())
	return err
}
