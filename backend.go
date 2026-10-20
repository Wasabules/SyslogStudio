package main

import (
	"SyslogStudio/internal/engine"
	"SyslogStudio/internal/importer"
	"SyslogStudio/internal/models"
	"SyslogStudio/internal/notify"
)

// Backend is what the window drives: the receiver, its storage, its rules and
// its certificates — every engine method the frontend calls, by the name and
// signature it calls it with.
//
// App embeds it, so each of these is a method of App, which is what Wails
// binds, without a forwarding stub apiece. The window hosts the engine
// in-process today; a window that drives an engine running elsewhere — a
// background service — will satisfy the same interface, and the frontend will
// not be able to tell the difference.
type Backend interface {
	// Receiving
	StartServer(config models.ServerConfig) error
	StopServer() error
	GetServerStatus() models.ServerStatus
	SaveServerConfig(config models.ServerConfig)
	GetDefaultConfig() models.ServerConfig
	GetMessages(filter models.FilterCriteria) []models.SyslogMessage
	ClearMessages()
	GetStats() models.ServerStats
	GetLocalIPs() []string
	GetNetworkInterfaces() []models.NetworkInterface

	// Storage
	IsStorageReady() bool
	GetStorageConfig() models.StorageConfig
	SetStorageConfig(cfg models.StorageConfig)
	GetStorageStats() models.StorageStats
	QueryMessages(opts models.QueryOptions) models.PagedResult
	QueryMessageGroups(filter models.FilterCriteria, groupField string) []models.GroupSummary
	CompactDatabase() error
	ClearDatabase() error

	// Certificates
	GenerateCA(opts models.CertOptions) (models.CertInfo, error)
	LoadPersistedCA() error
	IsCAKeyUnencrypted() bool
	GenerateServerCert(opts models.CertOptions) (models.CertInfo, error)
	GenerateCertificate(opts models.CertOptions) (models.CertInfo, error)
	GetCACertInfo() (models.CertInfo, error)
	GetServerCertInfo() (models.CertInfo, error)
	GetCertificateInfo(config models.ServerConfig) (models.CertInfo, error)
	GetDefaultCertOptions() models.CertOptions

	// Alerts
	GetAlertRules() []models.AlertRule
	AddAlertRule(rule models.AlertRule) models.AlertRule
	UpdateAlertRule(rule models.AlertRule) bool
	DeleteAlertRule(id string) bool
	GetAlertHistory() []models.AlertEvent
	ClearAlertHistory()

	// Encryption
	GetUnlockAttemptsRemaining() int
	GetUnlockLockoutSeconds() int
	IsEncryptionEnabled() bool
	IsEncryptionLocked() bool
	UnlockDatabase(password string) error
	EnableEncryption(password string) error
	DisableEncryption(password string) error
	ChangeEncryptionPassword(oldPassword, newPassword string) error

	// Simulator
	StartSimulator(cfg models.SimulatorConfig) error
	StopSimulator() error
	GetSimulatorStatus() models.SimulatorStatus
	GetSimulatorConfig() models.SimulatorConfig
	SaveSimulatorConfig(cfg models.SimulatorConfig)
	GetScenarioDurationSeconds() int

	// Routing
	GetNotifyRoutes() []notify.Route
	GetNotifySinks() []notify.SinkConfig
	SaveNotifyRoute(route notify.Route) error
	DeleteNotifyRoute(id string)
	SaveNotifySink(sink notify.SinkConfig) error
	DeleteNotifySink(id string)
	TestNotifySink(sink notify.SinkConfig) error
	GetNotifyLog() []notify.DeliveryEntry
	ClearNotifyLog()
	GetNotifyStats() notify.Stats
	AreSinkCredentialsUnencrypted() bool

	// Import
	PreviewLogFile(path string, format models.ImportFormat) (importer.Preview, error)
	ImportLogFile(path string, persist bool, format models.ImportFormat) (importer.Result, error)
	GetImportFormat() models.ImportFormat
}

// keyMaterial is what the window needs from the engine and must never hand to
// the frontend. Wails binds every exported method of App, promoted ones
// included, so private keys and credentials stay off the embedded interface:
// the window writes them to the files its user picks, or to the service it
// installs, and no script can read them.
type keyMaterial interface {
	CACertificatePEM() ([]byte, error)
	ServerCertificatePEM() (certPEM, keyPEM []byte, err error)
	ExportBundle() (engine.Bundle, error)
}

// The in-process engine is a complete backend.
var (
	_ Backend     = (*engine.Engine)(nil)
	_ keyMaterial = (*engine.Engine)(nil)
)
