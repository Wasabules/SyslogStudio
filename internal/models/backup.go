package models

// RecoveryKeyInfo says whether a recovery key is set up, and which: never the
// key itself, which only the user holds.
type RecoveryKeyInfo struct {
	Set     bool   `json:"set"`
	ID      string `json:"id,omitempty"`
	Created string `json:"created,omitempty"`
}

// BackupConfig is where copies of the database go, and when.
type BackupConfig struct {
	// Enabled runs the schedule; "Back up now" works either way.
	Enabled bool `json:"enabled"`
	// Dir is the folder the copies go to: another disk, a network share.
	Dir string `json:"dir"`
	// Schedule is when: daily, weekly or monthly at a time of day. A
	// continuous schedule means daily here.
	Schedule CleanupSchedule `json:"schedule"`
	// Keep is how many of the copies made here are kept, the oldest deleted
	// first; 0 is DefaultBackupKeep. Files that are not this installation's
	// copies are never touched.
	Keep int `json:"keep,omitempty"`
}

// DefaultBackupKeep is how many copies are kept when nothing says otherwise.
const DefaultBackupKeep = 7

// The values of BackupFile.Lock: what opens a copy.
const (
	// BackupLockPassword opens with the password the database had when the
	// copy was made, BackupLockKey with the recovery key, and
	// BackupLockBoth with either.
	BackupLockPassword = "password"
	BackupLockKey      = "key"
	BackupLockBoth     = "both"
	// BackupLockNone is a copy in the clear, made while the database was not
	// encrypted and no recovery key was set up.
	BackupLockNone = "none"
)

// BackupFile is one copy.
type BackupFile struct {
	Name    string  `json:"name"`
	Path    string  `json:"path"`
	SizeMB  float64 `json:"sizeMB"`
	Created string  `json:"created"`
	Lock    string  `json:"lock"`
	// KeyID names the recovery key that opens it, if one does.
	KeyID string `json:"keyId,omitempty"`
	// App is the version that wrote it.
	App string `json:"app,omitempty"`
	// SafetyCopy marks the copy made just before a restore replaced the
	// database.
	SafetyCopy bool `json:"safetyCopy,omitempty"`
}

// BackupStatus is what the copies are doing.
type BackupStatus struct {
	Running bool `json:"running"`
	// Phase is what the running copy is doing (BackupPhase*), and Percent
	// how far it is, all phases together.
	Phase   string  `json:"phase,omitempty"`
	Percent float64 `json:"percent"`
	// LastAt and LastFile are the last copy that worked; LastError, why the
	// last attempt did not, cleared by the next one that works.
	LastAt     string  `json:"lastAt,omitempty"`
	LastFile   string  `json:"lastFile,omitempty"`
	LastSizeMB float64 `json:"lastSizeMB,omitempty"`
	LastTookMs int64   `json:"lastTookMs,omitempty"`
	LastError  string  `json:"lastError,omitempty"`
	LastFailAt string  `json:"lastFailAt,omitempty"`
	// Next is when the schedule runs next, "" when it is off.
	Next string `json:"next,omitempty"`
	// Lock is what will open the next copy (BackupLock*).
	Lock string `json:"lock"`
}

// The values of BackupStatus.Phase.
const (
	// BackupPhaseSnapshot copies the database as it stands, BackupPhaseEncrypt
	// encrypts that copy into the folder, BackupPhaseVerify reads it back.
	BackupPhaseSnapshot = "snapshot"
	BackupPhaseEncrypt  = "encrypt"
	BackupPhaseVerify   = "verify"
	// BackupPhaseOpen decrypts a copy to restore it, BackupPhaseRestore puts
	// it in place of the database.
	BackupPhaseOpen    = "open"
	BackupPhaseRestore = "restore"
)

// BackupView is a copy opened to be read: the History shows it instead of
// the database until it is closed.
type BackupView struct {
	Open     bool   `json:"open"`
	Name     string `json:"name,omitempty"`
	Path     string `json:"path,omitempty"`
	Created  string `json:"created,omitempty"`
	Messages int64  `json:"messages"`
	Oldest   string `json:"oldest,omitempty"`
	Newest   string `json:"newest,omitempty"`
}
