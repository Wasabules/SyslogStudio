// Package remote lets a window drive an engine that runs in another process —
// the system service — as if it ran in its own.
//
// The service owns the engine: the listeners, the database, the rules. A
// window that connects to it gets a Client, which satisfies the same Backend
// interface the in-process engine does, so the frontend cannot tell the two
// apart. Calls travel as JSON over a stream the host provides (a named pipe
// on Windows), and what the engine emits — messages, statistics, alerts — is
// broadcast to every connected window.
//
// The transport, and who may use it, are the host's business: this package
// only speaks over a net.Conn it is given.
package remote

import (
	"SyslogStudio/internal/importer"
	"SyslogStudio/internal/models"
	"SyslogStudio/internal/notify"
)

//go:generate go run ./gen

// Backend is what the window drives: the receiver, its storage, its rules and
// its certificates — every engine method the frontend calls, by the name and
// signature it calls it with.
//
// The desktop application embeds it, so each of these is a method Wails binds,
// without a forwarding stub apiece. The in-process engine satisfies it, and so
// does a Client driving the service.
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
	GetListenOnStart() bool
	SetListenOnStart(enabled bool)

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
	// The recovery key: the window makes the pair and hands the public half
	// over, so the private half never leaves it — except to unlock, or to
	// open a backup, the way a password does.
	GetRecoveryKey() models.RecoveryKeyInfo
	SetRecoveryKey(pub []byte) (models.RecoveryKeyInfo, error)
	RemoveRecoveryKey() error
	UnlockWithRecoveryKey(keyFile []byte) error
	IsUnlockedByRecoveryKey() bool
	ResetEncryptionPassword(newPassword string) error

	// Backups
	GetBackupConfig() models.BackupConfig
	SetBackupConfig(cfg models.BackupConfig) error
	SaveBackupDestination(d models.BackupDestination) (models.BackupDestination, error)
	DeleteBackupDestination(id string) error
	TestBackupDestination(d models.BackupDestination) models.BackupDestinationCheck
	GetBackupStatus() models.BackupStatus
	ListBackups() models.BackupListing
	BackupNow() error
	RestoreBackup(ref models.BackupRef, password string, keyFile []byte) error

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

// Host is everything a service answers over the wire: the Backend, plus what
// the window needs from it but must not bind to its frontend, and the half of
// an import the service does.
//
// A file to import is the window user's, and the service's account cannot
// read it: the window reads and parses it, and hands over the messages.
type Host interface {
	Backend

	// CACertificatePEM and ServerCertificatePEM are what the window writes to
	// the files its user picks when exporting certificates. The second holds
	// the private key, which is why neither is on Backend.
	CACertificatePEM() ([]byte, error)
	ServerCertificatePEM() (certPEM, keyPEM []byte, err error)

	// ImportCapacity is how many messages an import may bring into the live
	// view, ImportMessages adds a batch of them, and RememberImportFormat
	// keeps the format of an import that worked for the next one.
	ImportCapacity() int
	ImportMessages(msgs []models.SyslogMessage, persist bool) error
	RememberImportFormat(format models.ImportFormat)

	// GetInboxStatus, InboxBatches, InboxBatch and InboxAck are the
	// service's end of the sealed inbox: what waits, and handing it over to
	// the window holding the key, which acknowledges each batch once stored.
	GetInboxStatus() models.InboxStatus
	InboxBatches() ([]models.InboxBatch, error)
	InboxBatch(id string) ([]byte, error)
	InboxAck(id string) error

	// BackupDestinationAccess is a backup destination and what signs in to
	// it, for the window to read a backup itself: with its user's rights,
	// and without sending the copy through the service.
	BackupDestinationAccess(id string) (models.BackupDestination, models.BackupAccess, error)

	// MessagesAfter and MergeMessages read and write the database a batch at
	// a time, for a window that copies a history between it and its own
	// (package history): a backup it merges, its history brought to the
	// service, or the service's taken back.
	MessagesAfter(after int64, limit int) ([]models.SyslogMessage, int64, error)
	MergeMessages(msgs []models.SyslogMessage) (int, error)
}
