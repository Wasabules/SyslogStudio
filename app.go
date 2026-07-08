package main

import (
	"context"
	"crypto/subtle"
	"encoding/csv"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"time"

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
}

const (
	// unlockAttemptsBeforeBackoff is how many failed unlock attempts are
	// allowed before a backoff delay begins.
	unlockAttemptsBeforeBackoff = 5
	// baseLockoutBackoff is the delay imposed at the first backoff step;
	// it doubles with each subsequent failed attempt.
	baseLockoutBackoff = 30 * time.Second
	// maxLockoutBackoff caps the backoff delay.
	maxLockoutBackoff = 15 * time.Minute
)

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

// GetUnlockAttemptsRemaining returns how many unlock attempts remain
// before the next backoff delay is applied.
func (a *App) GetUnlockAttemptsRemaining() int {
	state := a.configStore.LoadLockout()
	remaining := unlockAttemptsBeforeBackoff - (state.FailedAttempts % unlockAttemptsBeforeBackoff)
	if remaining < 0 {
		remaining = 0
	}
	return remaining
}

// GetUnlockLockoutSeconds returns the number of seconds remaining in the
// current lockout window, or 0 if unlock attempts are currently allowed.
func (a *App) GetUnlockLockoutSeconds() int {
	state := a.configStore.LoadLockout()
	if state.LockedUntilUnix == 0 {
		return 0
	}
	remaining := state.LockedUntilUnix - time.Now().Unix()
	if remaining < 0 {
		return 0
	}
	return int(remaining)
}

// IsEncryptionEnabled returns whether encryption is configured.
func (a *App) IsEncryptionEnabled() bool {
	return a.configStore.LoadStorage().EncryptionEnabled
}

// IsEncryptionLocked returns true if the database is encrypted and not yet unlocked.
func (a *App) IsEncryptionLocked() bool {
	return a.logStore != nil && a.logStore.IsLocked()
}

// lockoutBackoff returns the delay to impose after failedAttempts
// consecutive failures. No delay until the threshold is reached, then an
// exponentially growing delay capped at maxLockoutBackoff.
func lockoutBackoff(failedAttempts int) time.Duration {
	if failedAttempts < unlockAttemptsBeforeBackoff {
		return 0
	}
	steps := failedAttempts - unlockAttemptsBeforeBackoff // 0, 1, 2, ...
	delay := baseLockoutBackoff << steps
	if delay > maxLockoutBackoff || delay <= 0 {
		delay = maxLockoutBackoff
	}
	return delay
}

// UnlockDatabase decrypts the database with the given password and opens it.
// Failed attempts accumulate in persisted state; after a threshold, an
// exponentially growing backoff delay is enforced that survives restarts,
// so relaunching the app cannot be used to reset the counter or bypass
// the delay.
func (a *App) UnlockDatabase(password string) error {
	if a.logStore == nil {
		return fmt.Errorf("log store not initialized")
	}

	state := a.configStore.LoadLockout()
	if wait := state.LockedUntilUnix - time.Now().Unix(); state.LockedUntilUnix != 0 && wait > 0 {
		return fmt.Errorf("too many failed attempts — locked for %d more seconds", wait)
	}

	if err := a.logStore.UnlockAndOpen(password); err != nil {
		state.FailedAttempts++
		if backoff := lockoutBackoff(state.FailedAttempts); backoff > 0 {
			state.LockedUntilUnix = time.Now().Add(backoff).Unix()
			a.configStore.SaveLockout(state)
			slog.Warn("unlock failed, backoff enforced", "attempts", state.FailedAttempts, "backoffSeconds", int(backoff.Seconds()))
			return fmt.Errorf("wrong password — locked for %d seconds after %d failed attempts", int(backoff.Seconds()), state.FailedAttempts)
		}
		a.configStore.SaveLockout(state)
		remaining := unlockAttemptsBeforeBackoff - state.FailedAttempts
		slog.Warn("unlock failed", "attempts", state.FailedAttempts, "remaining", remaining)
		return fmt.Errorf("wrong password (%d attempts remaining before lockout)", remaining)
	}

	// Success: clear persisted lockout state.
	a.configStore.SaveLockout(models.LockoutState{})
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
	cfg := a.configStore.LoadStorage()
	if cfg.EncryptionEnabled {
		// If the session password is not present (e.g. fresh start with a
		// still-locked database), require an unlock first. Previously an
		// empty session password caused the verification to be skipped
		// entirely, allowing encryption to be disabled without knowing
		// the password.
		if a.encryptionPassword == "" {
			return fmt.Errorf("database must be unlocked before disabling encryption")
		}
		if subtle.ConstantTimeCompare([]byte(password), []byte(a.encryptionPassword)) != 1 {
			return fmt.Errorf("incorrect password")
		}
	}
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
	if a.encryptionPassword == "" {
		return fmt.Errorf("database must be unlocked before changing the password")
	}
	if subtle.ConstantTimeCompare([]byte(oldPassword), []byte(a.encryptionPassword)) != 1 {
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
