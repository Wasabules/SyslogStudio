package models

// RecoveryKeyInfo says whether a recovery key is set up, and which: never the
// key itself, which only the user holds.
type RecoveryKeyInfo struct {
	Set     bool   `json:"set"`
	ID      string `json:"id,omitempty"`
	Created string `json:"created,omitempty"`
}

// BackupConfig is when copies of the database are made, and where they go.
type BackupConfig struct {
	// Enabled runs the schedule; "Back up now" works either way.
	Enabled bool `json:"enabled"`
	// Schedule is when: daily, weekly or monthly at a time of day. A
	// continuous schedule means daily here.
	Schedule CleanupSchedule `json:"schedule"`
	// Destinations are where each copy goes, every one of them.
	Destinations []BackupDestination `json:"destinations,omitempty"`

	// Dir and Keep are the single folder of the first version of backups,
	// read once and turned into a destination.
	Dir  string `json:"dir,omitempty"`
	Keep int    `json:"keep,omitempty"`
}

// DefaultBackupKeep is how many copies are kept when nothing says otherwise.
const DefaultBackupKeep = 7

// The values of BackupDestination.Kind.
const (
	// BackupToFolder is a folder of this machine: another disk, a USB drive,
	// a network share or an NFS export mounted here.
	BackupToFolder = "folder"
	// BackupToSFTP is a server reached over SSH.
	BackupToSFTP = "sftp"
	// BackupToFTPS is an FTP server reached over TLS; BackupToFTP, one reached
	// in the clear, which sends its password in the clear.
	BackupToFTPS = "ftps"
	BackupToFTP  = "ftp"
)

// The values of BackupDestination.TLS, for FTPS.
const (
	// FTPSExplicit starts in the clear and upgrades (AUTH TLS), usually on
	// port 21; FTPSImplicit is TLS from the first byte, usually on port 990.
	FTPSExplicit = "explicit"
	FTPSImplicit = "implicit"
)

// The values of BackupDestination.Auth, for SFTP.
const (
	SFTPPassword = "password"
	SFTPKey      = "key"
)

// BackupDestination is one place copies go.
type BackupDestination struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Kind    string `json:"kind"`
	Enabled bool   `json:"enabled"`
	// Keep is how many copies this destination keeps, the oldest deleted
	// first; 0 is DefaultBackupKeep. Files that are not copies made by
	// SyslogStudio are never touched.
	Keep int `json:"keep,omitempty"`
	// Path is the folder, or the directory on the server.
	Path string `json:"path"`

	Host string `json:"host,omitempty"`
	Port int    `json:"port,omitempty"`
	User string `json:"user,omitempty"`

	// Auth is how an SFTP destination signs in (SFTPPassword, SFTPKey);
	// HostKey is the server's key, as its SHA-256 fingerprint, pinned at the
	// first connection: a server presenting another one is refused.
	Auth    string `json:"auth,omitempty"`
	HostKey string `json:"hostKey,omitempty"`
	// TLS is how an FTPS destination starts TLS (FTPSExplicit,
	// FTPSImplicit). CertPin is the SHA-256 fingerprint of a certificate the
	// system does not trust — a NAS's own — accepted by the user at the first
	// connection; a certificate the system trusts needs none.
	TLS     string `json:"tls,omitempty"`
	CertPin string `json:"certPin,omitempty"`
	// Cleartext is the user's acknowledgement that an FTP destination sends
	// its password unencrypted. The backups themselves stay encrypted.
	Cleartext bool `json:"cleartext,omitempty"`

	// Secret and Passphrase are WRITE-ONLY, as a routing destination's: the
	// password, or the SSH private key (PEM) and its passphrase. They go to
	// the secret store and are never read back; HasSecret says one is there.
	Secret     string `json:"secret,omitempty"`
	Passphrase string `json:"passphrase,omitempty"`
	HasSecret  bool   `json:"hasSecret"`
}

// BackupAccess is what signs in to a destination. It never reaches the
// interface: only the window's own process, to read a backup.
type BackupAccess struct {
	Password   string `json:"password,omitempty"`
	Key        string `json:"key,omitempty"`
	Passphrase string `json:"passphrase,omitempty"`
}

// BackupDestinationCheck is what testing a destination found.
type BackupDestinationCheck struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	// Unknown is a server met for the first time: its key (SFTP) or its
	// certificate (FTPS) is Fingerprint, for the user to compare with the one
	// its administrator gives before trusting it. Changed is a server whose
	// key is no longer the one pinned: someone may be in between.
	Unknown     bool   `json:"unknown,omitempty"`
	Changed     bool   `json:"changed,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	// Detail says what the fingerprint is of: a key type, a certificate's
	// subject.
	Detail string `json:"detail,omitempty"`
}

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
	// BackupLockUnknown is a copy on a server, not made here: what opens it
	// is only known once it is read.
	BackupLockUnknown = ""
)

// BackupFile is one copy.
type BackupFile struct {
	Name string `json:"name"`
	// Destination is where it is (an ID), and DestinationName what the user
	// called that; both empty for a copy made before a restore, which stays
	// on this machine. Path is the file, for a copy on this machine.
	Destination     string  `json:"destination,omitempty"`
	DestinationName string  `json:"destinationName,omitempty"`
	Path            string  `json:"path,omitempty"`
	SizeMB          float64 `json:"sizeMB"`
	Created         string  `json:"created"`
	Lock            string  `json:"lock"`
	// KeyID names the recovery key that opens it, if one does.
	KeyID string `json:"keyId,omitempty"`
	// App is the version that wrote it.
	App string `json:"app,omitempty"`
	// SafetyCopy marks the copy made just before a restore replaced the
	// database.
	SafetyCopy bool `json:"safetyCopy,omitempty"`
}

// BackupRef names one copy: at a destination by its name, or a file on this
// machine by its path.
type BackupRef struct {
	Destination string `json:"destination,omitempty"`
	Name        string `json:"name,omitempty"`
	Path        string `json:"path,omitempty"`
}

// BackupListing is the copies at every destination, and the destinations
// that could not be listed.
type BackupListing struct {
	Files    []BackupFile    `json:"files"`
	Problems []BackupProblem `json:"problems,omitempty"`
}

// BackupProblem is a destination that did not answer.
type BackupProblem struct {
	Destination string `json:"destination"`
	Name        string `json:"name"`
	Error       string `json:"error"`
}

// BackupStatus is what the copies are doing.
type BackupStatus struct {
	Running bool `json:"running"`
	// Phase is what the running copy is doing (BackupPhase*), Target the
	// destination it is being sent to, and Percent how far it all is.
	Phase   string  `json:"phase,omitempty"`
	Target  string  `json:"target,omitempty"`
	Percent float64 `json:"percent"`
	// Next is when the schedule runs next, "" when it is off.
	Next string `json:"next,omitempty"`
	// Lock is what will open the next copy (BackupLock*).
	Lock string `json:"lock"`
	// Destinations is how the last copies went, destination by destination.
	Destinations []BackupDestinationStatus `json:"destinations,omitempty"`
}

// BackupDestinationStatus is how the copies to one destination went.
type BackupDestinationStatus struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// LastAt and LastFile are the last copy that arrived; LastError, why the
	// last attempt did not, cleared by the next one that works.
	LastAt     string  `json:"lastAt,omitempty"`
	LastFile   string  `json:"lastFile,omitempty"`
	LastSizeMB float64 `json:"lastSizeMB,omitempty"`
	LastTookMs int64   `json:"lastTookMs,omitempty"`
	LastError  string  `json:"lastError,omitempty"`
	LastFailAt string  `json:"lastFailAt,omitempty"`
}

// The values of BackupStatus.Phase.
const (
	// BackupPhaseSnapshot copies the database as it stands, BackupPhaseEncrypt
	// encrypts that copy, BackupPhaseVerify reads it back, BackupPhaseUpload
	// sends it to a destination.
	BackupPhaseSnapshot = "snapshot"
	BackupPhaseEncrypt  = "encrypt"
	BackupPhaseVerify   = "verify"
	BackupPhaseUpload   = "upload"
	// BackupPhaseOpen decrypts a copy to restore it, BackupPhaseRestore puts
	// it in place of the database.
	BackupPhaseOpen    = "open"
	BackupPhaseRestore = "restore"
)

// BackupView is a copy opened to be read: the History shows it instead of
// the database until it is closed.
type BackupView struct {
	Open bool      `json:"open"`
	Ref  BackupRef `json:"ref"`
	// Name and Created name the copy; Destination is where it came from.
	Name        string `json:"name,omitempty"`
	Destination string `json:"destination,omitempty"`
	Created     string `json:"created,omitempty"`
	Messages    int64  `json:"messages"`
	Oldest      string `json:"oldest,omitempty"`
	Newest      string `json:"newest,omitempty"`
}
