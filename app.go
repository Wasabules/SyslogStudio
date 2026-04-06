package main

import (
	"context"
	"encoding/csv"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"

	"SyslogStudio/internal/event"
	"SyslogStudio/internal/models"
	"SyslogStudio/internal/pki"
	"SyslogStudio/internal/storage"
	"SyslogStudio/internal/syslog"
	"SyslogStudio/internal/updater"

	wailsRuntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// App struct is the main Wails binding facade.
type App struct {
	ctx         context.Context
	server      *syslog.SyslogServer
	tlsManager  *pki.TLSManager
	configStore *storage.ConfigStore
	logStore    *storage.LogStore

	encryptionPassword string // in-memory only for session
	unlockAttempts     int
}

const maxUnlockAttempts = 5

// NewApp creates a new App application struct.
func NewApp() *App {
	return &App{
		tlsManager:  pki.NewTLSManager(),
		configStore: storage.NewConfigStore(),
	}
}

// startup is called when the app starts.
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	emitter := event.NewWailsEventEmitter(ctx)
	a.server = syslog.NewSyslogServer(emitter, a.tlsManager)

	// Initialize log store
	storageCfg := a.configStore.LoadStorage()
	ls, err := storage.NewLogStore(storageCfg, emitter)
	if err != nil {
		slog.Warn("failed to initialize log store, persistence disabled", "error", err)
	} else {
		a.logStore = ls
		a.server.LogStore = ls
	}

	// Restore alert rules
	rules := a.configStore.LoadAlertRules()
	if len(rules) > 0 {
		a.server.AlertManager.SetRules(rules)
		slog.Info("restored alert rules", "count", len(rules))
	}
}

// shutdown is called when the app is closing.
func (a *App) shutdown(ctx context.Context) {
	if a.server != nil {
		a.server.Stop()
	}
	a.configStore.SaveAlertRules(a.server.AlertManager.GetRules())
	if a.logStore != nil {
		a.logStore.Close()
	}
}

// --- Server Control Methods ---

func (a *App) StartServer(config models.ServerConfig) error {
	err := a.server.Start(config)
	if err == nil {
		a.configStore.Save(config)
	}
	return err
}

func (a *App) StopServer() error {
	return a.server.Stop()
}

func (a *App) GetServerStatus() models.ServerStatus {
	return a.server.GetStatus()
}

func (a *App) GetDefaultConfig() models.ServerConfig {
	return a.configStore.Load()
}

// --- Log Methods ---

func (a *App) GetMessages(filter models.FilterCriteria) []models.SyslogMessage {
	return a.server.GetMessages(filter)
}

func (a *App) ClearMessages() {
	a.server.ClearMessages()
}

func (a *App) GetStats() models.ServerStats {
	return a.server.GetStats()
}

// IsStorageReady returns true if the database is fully initialized (FTS index built).
func (a *App) IsStorageReady() bool {
	if a.logStore == nil {
		return false
	}
	return a.logStore.IsReady()
}

// --- Storage Methods ---

func (a *App) GetStorageConfig() models.StorageConfig {
	cfg := a.configStore.LoadStorage()
	if cfg.Path == "" {
		resolved, err := storage.ResolveDBPath("")
		if err == nil {
			cfg.Path = resolved
		}
	}
	return cfg
}

func (a *App) SetStorageConfig(cfg models.StorageConfig) {
	a.configStore.SaveStorage(cfg)
	if a.logStore != nil {
		a.logStore.UpdateConfig(cfg)
	}
}

func (a *App) GetStorageStats() models.StorageStats {
	if a.logStore != nil {
		return a.logStore.GetStats()
	}
	return models.StorageStats{}
}

func (a *App) QueryMessages(opts models.QueryOptions) models.PagedResult {
	if a.logStore != nil {
		return a.logStore.QueryMessages(opts)
	}
	return models.PagedResult{Page: opts.Page, PageSize: opts.PageSize}
}

func (a *App) QueryMessageGroups(filter models.FilterCriteria, groupField string) []models.GroupSummary {
	if a.logStore != nil {
		return a.logStore.QueryGroups(filter, groupField)
	}
	return nil
}

func (a *App) CompactDatabase() error {
	if a.logStore != nil {
		return a.logStore.Compact()
	}
	return nil
}

func (a *App) ClearDatabase() error {
	if a.logStore != nil {
		return a.logStore.ClearAll()
	}
	return nil
}

// --- PKI / Certificate Methods ---

func (a *App) GenerateCA(opts models.CertOptions) (models.CertInfo, error) {
	return a.tlsManager.GenerateCA(opts)
}

func (a *App) GenerateServerCert(opts models.CertOptions) (models.CertInfo, error) {
	return a.tlsManager.GenerateServerCertSignedByCA(opts)
}

func (a *App) GenerateCertificate(opts models.CertOptions) (models.CertInfo, error) {
	_, info, err := a.tlsManager.GenerateSelfSignedWithOptions(opts)
	if err != nil {
		return models.CertInfo{}, err
	}
	return info, nil
}

func (a *App) GetCACertInfo() (models.CertInfo, error) {
	return a.tlsManager.GetCACertificateInfo()
}

func (a *App) GetServerCertInfo() (models.CertInfo, error) {
	return a.tlsManager.GetServerCertificateInfo()
}

func (a *App) GetCertificateInfo(config models.ServerConfig) (models.CertInfo, error) {
	return a.tlsManager.GetCertificateInfo(config)
}

func (a *App) GetDefaultCertOptions() models.CertOptions {
	return models.DefaultCertOptions()
}

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

func (a *App) ExportCertificate() (string, error) {
	return a.ExportServerCertificate()
}

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

func (a *App) GetAlertRules() []models.AlertRule {
	return a.server.AlertManager.GetRules()
}

func (a *App) AddAlertRule(rule models.AlertRule) models.AlertRule {
	r := a.server.AlertManager.AddRule(rule)
	a.configStore.SaveAlertRules(a.server.AlertManager.GetRules())
	return r
}

func (a *App) UpdateAlertRule(rule models.AlertRule) bool {
	ok := a.server.AlertManager.UpdateRule(rule)
	if ok {
		a.configStore.SaveAlertRules(a.server.AlertManager.GetRules())
	}
	return ok
}

func (a *App) DeleteAlertRule(id string) bool {
	ok := a.server.AlertManager.DeleteRule(id)
	if ok {
		a.configStore.SaveAlertRules(a.server.AlertManager.GetRules())
	}
	return ok
}

func (a *App) GetAlertHistory() []models.AlertEvent {
	return a.server.AlertManager.GetHistory()
}

func (a *App) ClearAlertHistory() {
	a.server.AlertManager.ClearHistory()
}

// --- Encryption Methods ---

// GetUnlockAttemptsRemaining returns how many unlock attempts are left.
func (a *App) GetUnlockAttemptsRemaining() int {
	return maxUnlockAttempts - a.unlockAttempts
}

// IsEncryptionEnabled returns whether encryption is configured.
func (a *App) IsEncryptionEnabled() bool {
	return a.configStore.LoadStorage().EncryptionEnabled
}

// IsEncryptionLocked returns true if the database is encrypted and not yet unlocked.
func (a *App) IsEncryptionLocked() bool {
	return a.logStore != nil && a.logStore.IsLocked()
}

// UnlockDatabase decrypts the database with the given password and opens it.
// After maxUnlockAttempts failed attempts, the application is closed.
func (a *App) UnlockDatabase(password string) error {
	if a.logStore == nil {
		return fmt.Errorf("log store not initialized")
	}
	if a.unlockAttempts >= maxUnlockAttempts {
		go func() {
			wailsRuntime.Quit(a.ctx)
		}()
		return fmt.Errorf("too many failed attempts")
	}
	if err := a.logStore.UnlockAndOpen(password); err != nil {
		a.unlockAttempts++
		remaining := maxUnlockAttempts - a.unlockAttempts
		slog.Warn("unlock failed", "attempt", a.unlockAttempts, "remaining", remaining)
		if a.unlockAttempts >= maxUnlockAttempts {
			slog.Error("max unlock attempts reached, shutting down")
			go func() {
				wailsRuntime.Quit(a.ctx)
			}()
			return fmt.Errorf("too many failed attempts — application will close")
		}
		return fmt.Errorf("wrong password (%d attempts remaining)", remaining)
	}
	a.unlockAttempts = 0
	a.encryptionPassword = password
	a.server.LogStore = a.logStore

	// Restore alert rules now that the store is available
	rules := a.configStore.LoadAlertRules()
	if len(rules) > 0 {
		a.server.AlertManager.SetRules(rules)
	}
	return nil
}

// EnableEncryption enables at-rest encryption with the given password.
func (a *App) EnableEncryption(password string) error {
	if password == "" {
		return fmt.Errorf("password cannot be empty")
	}
	cfg := a.configStore.LoadStorage()
	cfg.EncryptionEnabled = true
	a.configStore.SaveStorage(cfg)
	a.encryptionPassword = password
	if a.logStore != nil {
		a.logStore.SetEncryptionPassword(password)
		a.logStore.UpdateConfig(cfg)
	}
	return nil
}

// DisableEncryption disables at-rest encryption after verifying the password.
func (a *App) DisableEncryption(password string) error {
	if a.encryptionPassword != "" && password != a.encryptionPassword {
		return fmt.Errorf("incorrect password")
	}
	cfg := a.configStore.LoadStorage()
	cfg.EncryptionEnabled = false
	a.configStore.SaveStorage(cfg)
	a.encryptionPassword = ""
	if a.logStore != nil {
		a.logStore.SetEncryptionPassword("")
		a.logStore.UpdateConfig(cfg)
	}
	return nil
}

// ChangeEncryptionPassword changes the encryption password.
func (a *App) ChangeEncryptionPassword(oldPassword, newPassword string) error {
	if oldPassword != a.encryptionPassword {
		return fmt.Errorf("incorrect current password")
	}
	if newPassword == "" {
		return fmt.Errorf("new password cannot be empty")
	}
	a.encryptionPassword = newPassword
	if a.logStore != nil {
		a.logStore.SetEncryptionPassword(newPassword)
	}
	return nil
}

// --- Update Check ---

func (a *App) CheckForUpdate() models.UpdateInfo {
	return updater.CheckForUpdate()
}

func (a *App) GetAppVersion() string {
	return updater.AppVersion
}

// --- File Selection Dialogs ---

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

// --- Export Logs ---

func (a *App) ExportLogs(filter models.FilterCriteria, format string) (string, error) {
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

func writeCSV(path string, messages []models.SyslogMessage) error {
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

func writeText(path string, messages []models.SyslogMessage) error {
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
