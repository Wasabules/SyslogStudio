package main

import (
	"context"
	"encoding/csv"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"

	wailsRuntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// App struct is the main Wails binding facade.
type App struct {
	ctx         context.Context
	server      *SyslogServer
	tlsManager  *TLSManager
	configStore *ConfigStore
	logStore    *LogStore
}

// NewApp creates a new App application struct.
func NewApp() *App {
	return &App{
		tlsManager:  NewTLSManager(),
		configStore: NewConfigStore(),
	}
}

// startup is called when the app starts.
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	emitter := NewWailsEventEmitter(ctx)
	a.server = NewSyslogServer(emitter, a.tlsManager)

	// Initialize log store
	storageCfg := a.configStore.LoadStorage()
	ls, err := NewLogStore(storageCfg, emitter)
	if err != nil {
		slog.Warn("failed to initialize log store, persistence disabled", "error", err)
	} else {
		a.logStore = ls
		a.server.logStore = ls
	}

	// Restore alert rules
	rules := a.configStore.LoadAlertRules()
	if len(rules) > 0 {
		a.server.alertManager.SetRules(rules)
		slog.Info("restored alert rules", "count", len(rules))
	}
}

// shutdown is called when the app is closing.
func (a *App) shutdown(ctx context.Context) {
	if a.server != nil {
		a.server.Stop()
	}
	// Persist alert rules
	a.configStore.SaveAlertRules(a.server.alertManager.GetRules())
	// Close log store (flush + vacuum + close)
	if a.logStore != nil {
		a.logStore.Close()
	}
}

// --- Server Control Methods ---

// StartServer starts the syslog server with the given configuration.
func (a *App) StartServer(config ServerConfig) error {
	err := a.server.Start(config)
	if err == nil {
		a.configStore.Save(config)
	}
	return err
}

// StopServer stops all listeners.
func (a *App) StopServer() error {
	return a.server.Stop()
}

// GetServerStatus returns the current running state.
func (a *App) GetServerStatus() ServerStatus {
	return a.server.GetStatus()
}

// GetDefaultConfig returns the saved or default server configuration.
func (a *App) GetDefaultConfig() ServerConfig {
	return a.configStore.Load()
}

// --- Log Methods ---

// GetMessages returns the buffered messages, optionally filtered.
func (a *App) GetMessages(filter FilterCriteria) []SyslogMessage {
	return a.server.GetMessages(filter)
}

// ClearMessages empties the log buffer.
func (a *App) ClearMessages() {
	a.server.ClearMessages()
}

// GetStats returns the current server statistics.
func (a *App) GetStats() ServerStats {
	return a.server.GetStats()
}

// --- Storage Methods ---

// GetStorageConfig returns the current storage configuration with resolved path.
func (a *App) GetStorageConfig() StorageConfig {
	cfg := a.configStore.LoadStorage()
	// Resolve the actual DB path so the frontend can display it
	if cfg.Path == "" {
		resolved, err := resolveDBPath("")
		if err == nil {
			cfg.Path = resolved
		}
	}
	return cfg
}

// SetStorageConfig updates the storage configuration.
func (a *App) SetStorageConfig(cfg StorageConfig) {
	a.configStore.SaveStorage(cfg)
	if a.logStore != nil {
		a.logStore.UpdateConfig(cfg)
	}
}

// GetStorageStats returns database statistics.
func (a *App) GetStorageStats() StorageStats {
	if a.logStore != nil {
		return a.logStore.GetStats()
	}
	return StorageStats{}
}

// QueryMessages returns paginated, filtered, sorted messages from the database.
func (a *App) QueryMessages(opts QueryOptions) PagedResult {
	if a.logStore != nil {
		return a.logStore.QueryMessages(opts)
	}
	return PagedResult{Page: opts.Page, PageSize: opts.PageSize}
}

// QueryMessageGroups returns message counts grouped by a field.
func (a *App) QueryMessageGroups(filter FilterCriteria, groupField string) []GroupSummary {
	if a.logStore != nil {
		return a.logStore.QueryGroups(filter, groupField)
	}
	return nil
}

// CompactDatabase runs VACUUM to reclaim disk space.
func (a *App) CompactDatabase() error {
	if a.logStore != nil {
		return a.logStore.Compact()
	}
	return nil
}

// ClearDatabase deletes all stored messages.
func (a *App) ClearDatabase() error {
	if a.logStore != nil {
		return a.logStore.ClearAll()
	}
	return nil
}

// --- PKI / Certificate Methods ---

// GenerateCA generates a self-signed CA certificate.
func (a *App) GenerateCA(opts CertOptions) (CertInfo, error) {
	return a.tlsManager.GenerateCA(opts)
}

// GenerateServerCert generates a server certificate signed by the stored CA.
func (a *App) GenerateServerCert(opts CertOptions) (CertInfo, error) {
	return a.tlsManager.GenerateServerCertSignedByCA(opts)
}

// GenerateCertificate generates a self-signed certificate with the given options (legacy/quick).
func (a *App) GenerateCertificate(opts CertOptions) (CertInfo, error) {
	_, info, err := a.tlsManager.GenerateSelfSignedWithOptions(opts)
	if err != nil {
		return CertInfo{}, err
	}
	return info, nil
}

// GetCACertInfo returns details about the stored CA certificate.
func (a *App) GetCACertInfo() (CertInfo, error) {
	return a.tlsManager.GetCACertificateInfo()
}

// GetServerCertInfo returns details about the stored server certificate.
func (a *App) GetServerCertInfo() (CertInfo, error) {
	return a.tlsManager.GetServerCertificateInfo()
}

// GetCertificateInfo returns details about the currently loaded/generated certificate.
func (a *App) GetCertificateInfo(config ServerConfig) (CertInfo, error) {
	return a.tlsManager.GetCertificateInfo(config)
}

// GetDefaultCertOptions returns sensible defaults for certificate generation.
func (a *App) GetDefaultCertOptions() CertOptions {
	return DefaultCertOptions()
}

// ExportCACertificate exports the CA certificate (for uploading to devices) via a save dialog.
func (a *App) ExportCACertificate() (string, error) {
	if !a.tlsManager.HasCA() {
		return "", fmt.Errorf("no CA certificate available to export; generate a CA first")
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

	if err := a.tlsManager.SaveCACertificateToFile(path); err != nil {
		return "", err
	}
	return path, nil
}

// ExportServerCertificate exports the server cert + key via save dialogs.
func (a *App) ExportServerCertificate() (string, error) {
	if !a.tlsManager.HasServerCert() {
		return "", fmt.Errorf("no server certificate available to export")
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

	if err := a.tlsManager.SaveServerCertificateToFile(certPath, keyPath); err != nil {
		return "", err
	}
	return fmt.Sprintf("Exported:\n  %s\n  %s", certPath, keyPath), nil
}

// ExportCertificate exports the last generated/loaded certificate (legacy).
func (a *App) ExportCertificate() (string, error) {
	return a.ExportServerCertificate()
}

// GetLocalIPs returns the machine's non-loopback IPv4 addresses.
func (a *App) GetLocalIPs() []string {
	var ips []string
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ips
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				ips = append(ips, ipnet.IP.String())
			}
		}
	}
	return ips
}

// --- Alert Methods ---

// GetAlertRules returns all configured alert rules.
func (a *App) GetAlertRules() []AlertRule {
	return a.server.alertManager.GetRules()
}

// AddAlertRule adds a new alert rule and returns it with its generated ID.
func (a *App) AddAlertRule(rule AlertRule) AlertRule {
	r := a.server.alertManager.AddRule(rule)
	a.configStore.SaveAlertRules(a.server.alertManager.GetRules())
	return r
}

// UpdateAlertRule updates an existing alert rule.
func (a *App) UpdateAlertRule(rule AlertRule) bool {
	ok := a.server.alertManager.UpdateRule(rule)
	if ok {
		a.configStore.SaveAlertRules(a.server.alertManager.GetRules())
	}
	return ok
}

// DeleteAlertRule removes an alert rule by ID.
func (a *App) DeleteAlertRule(id string) bool {
	ok := a.server.alertManager.DeleteRule(id)
	if ok {
		a.configStore.SaveAlertRules(a.server.alertManager.GetRules())
	}
	return ok
}

// GetAlertHistory returns recent alert events.
func (a *App) GetAlertHistory() []AlertEvent {
	return a.server.alertManager.GetHistory()
}

// ClearAlertHistory removes all alert history.
func (a *App) ClearAlertHistory() {
	a.server.alertManager.ClearHistory()
}

// --- Update Check ---

// CheckForUpdate queries GitHub for a newer release.
func (a *App) CheckForUpdate() UpdateInfo {
	return CheckForUpdate()
}

// GetAppVersion returns the current version string.
func (a *App) GetAppVersion() string {
	return AppVersion
}

// --- File Selection Dialogs ---

// SelectCertFile opens a file dialog for selecting a TLS certificate.
func (a *App) SelectCertFile() (string, error) {
	return wailsRuntime.OpenFileDialog(a.ctx, wailsRuntime.OpenDialogOptions{
		Title: "Select TLS Certificate",
		Filters: []wailsRuntime.FileFilter{
			{DisplayName: "PEM Files (*.pem, *.crt)", Pattern: "*.pem;*.crt"},
			{DisplayName: "All Files", Pattern: "*.*"},
		},
	})
}

// SelectKeyFile opens a file dialog for selecting a TLS private key.
func (a *App) SelectKeyFile() (string, error) {
	return wailsRuntime.OpenFileDialog(a.ctx, wailsRuntime.OpenDialogOptions{
		Title: "Select TLS Private Key",
		Filters: []wailsRuntime.FileFilter{
			{DisplayName: "PEM Files (*.pem, *.key)", Pattern: "*.pem;*.key"},
			{DisplayName: "All Files", Pattern: "*.*"},
		},
	})
}

// SelectCAFile opens a file dialog for selecting a CA certificate.
func (a *App) SelectCAFile() (string, error) {
	return wailsRuntime.OpenFileDialog(a.ctx, wailsRuntime.OpenDialogOptions{
		Title: "Select CA Certificate",
		Filters: []wailsRuntime.FileFilter{
			{DisplayName: "PEM Files (*.pem, *.crt)", Pattern: "*.pem;*.crt"},
			{DisplayName: "All Files", Pattern: "*.*"},
		},
	})
}

// --- Export Logs ---

// ExportLogs exports filtered logs to a file chosen by the user.
func (a *App) ExportLogs(filter FilterCriteria, format string) (string, error) {
	var defaultFilename string
	var filters []wailsRuntime.FileFilter

	if format == "csv" {
		defaultFilename = "syslog_export.csv"
		filters = []wailsRuntime.FileFilter{
			{DisplayName: "CSV Files (*.csv)", Pattern: "*.csv"},
		}
	} else {
		defaultFilename = "syslog_export.txt"
		filters = []wailsRuntime.FileFilter{
			{DisplayName: "Text Files (*.txt)", Pattern: "*.txt"},
		}
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

	messages := a.server.GetMessages(filter)
	if format == "csv" {
		err = writeCSV(path, messages)
	} else {
		err = writeText(path, messages)
	}

	if err != nil {
		return "", fmt.Errorf("failed to write export: %w", err)
	}
	return path, nil
}

func writeCSV(path string, messages []SyslogMessage) error {
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
			msg.Timestamp.Format("2006-01-02 15:04:05"),
			msg.SeverityLabel,
			msg.FacilityLabel,
			msg.Hostname,
			msg.AppName,
			msg.ProcID,
			msg.Message,
			msg.SourceIP,
			msg.Protocol,
		})
	}

	return w.Error()
}

func writeText(path string, messages []SyslogMessage) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	var sb strings.Builder
	for _, msg := range messages {
		sb.WriteString(fmt.Sprintf("%s [%s] %s %s %s: %s\n",
			msg.Timestamp.Format("2006-01-02 15:04:05"),
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
