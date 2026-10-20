package engine

// Certificates: the CA, the server's identity, and keeping both across restarts.

import (
	"fmt"
	"log/slog"

	"SyslogStudio/internal/models"
)

func (e *Engine) GenerateCA(opts models.CertOptions) (models.CertInfo, error) {
	info, err := e.tlsManager.GenerateCA(opts)
	if err != nil {
		return info, err
	}
	e.persistCA()
	return info, nil
}

// persistCA saves the current CA to disk, encrypting it with the session
// password when encryption is enabled. Failures are logged but do not
// abort CA generation, since an in-memory CA is still usable this session.
func (e *Engine) persistCA() {
	if e.caStore == nil || !e.canPersistKeys("CA") {
		return
	}
	certPEM, keyPEM, err := e.tlsManager.GetCAMaterial()
	if err != nil {
		return
	}
	if err := e.caStore.Save(certPEM, keyPEM, e.encryptionPassword); err != nil {
		slog.Warn("failed to persist CA", "error", err)
		return
	}
	if e.encryptionPassword == "" {
		slog.Warn("CA private key persisted unencrypted (0600); enable encryption to protect it at rest")
	}
}

// canPersistKeys reports whether a private key may be written now. With
// encryption on and no session password — a database not yet unlocked — the
// write would land in plaintext and remove the encrypted copy, so it is
// refused; the material stays in memory for this session.
func (e *Engine) canPersistKeys(what string) bool {
	if e.encryptionPassword == "" && e.configStore.LoadStorage().EncryptionEnabled {
		slog.Warn("not persisting a private key while the database is locked", "key", what)
		return false
	}
	return true
}

// persistServerCert saves the server's generated TLS identity. It is called by
// the TLS manager each time one is generated, from the assistant or on a first
// TLS start, and again whenever the encryption password changes.
func (e *Engine) persistServerCert(certPEM, keyPEM []byte) {
	if e.serverCertStore == nil || !e.canPersistKeys("server certificate") {
		return
	}
	if err := e.serverCertStore.Save(certPEM, keyPEM, e.encryptionPassword); err != nil {
		slog.Warn("failed to persist the server certificate", "error", err)
		return
	}
	if e.encryptionPassword == "" {
		slog.Warn("server TLS private key persisted unencrypted (0600); enable encryption to protect it at rest")
	}
}

// repersistServerCert writes the identity in memory again, under the current
// password. Used when encryption is turned on or off, or its password changes.
func (e *Engine) repersistServerCert() {
	if e.tlsManager == nil {
		return
	}
	if certPEM, keyPEM, ok := e.tlsManager.GetServerMaterial(); ok {
		e.persistServerCert(certPEM, keyPEM)
	}
}

// loadPersistedServerCert restores the server identity with the current
// session password. Nothing persisted is not an error.
func (e *Engine) loadPersistedServerCert() error {
	certPEM, keyPEM, err := e.serverCertStore.Load(e.encryptionPassword)
	if err != nil {
		return err
	}
	if len(certPEM) == 0 {
		return nil
	}
	if err := e.tlsManager.LoadServerMaterial(certPEM, keyPEM); err != nil {
		return err
	}
	slog.Info("restored the persisted server certificate")
	return nil
}

// LoadPersistedCA loads an encrypted persisted CA using the current
// session password. Called after the database is unlocked. Returns nil if
// there is no encrypted CA to load.
func (e *Engine) LoadPersistedCA() error {
	if e.caStore == nil || !e.caStore.Exists() || !e.caStore.IsEncrypted() {
		return nil
	}
	certPEM, keyPEM, err := e.caStore.Load(e.encryptionPassword)
	if err != nil {
		return err
	}
	if len(certPEM) == 0 {
		return nil
	}
	return e.tlsManager.LoadCAMaterial(certPEM, keyPEM)
}

// IsCAKeyUnencrypted reports whether a persisted CA private key is stored in
// plaintext on disk (i.e. a CA exists but at-rest encryption is off). The UI
// surfaces this so the user knows the signing key is not protected at rest.
func (e *Engine) IsCAKeyUnencrypted() bool {
	return e.caStore != nil && e.caStore.Exists() && !e.caStore.IsEncrypted()
}

func (e *Engine) GenerateServerCert(opts models.CertOptions) (models.CertInfo, error) {
	return e.tlsManager.GenerateServerCertSignedByCA(opts)
}

func (e *Engine) GenerateCertificate(opts models.CertOptions) (models.CertInfo, error) {
	_, info, err := e.tlsManager.GenerateSelfSignedWithOptions(opts)
	if err != nil {
		return models.CertInfo{}, err
	}
	return info, nil
}

func (e *Engine) GetCACertInfo() (models.CertInfo, error) {
	return e.tlsManager.GetCACertificateInfo()
}

func (e *Engine) GetServerCertInfo() (models.CertInfo, error) {
	return e.tlsManager.GetServerCertificateInfo()
}

func (e *Engine) GetCertificateInfo(config models.ServerConfig) (models.CertInfo, error) {
	return e.tlsManager.GetCertificateInfo(config)
}

func (e *Engine) GetDefaultCertOptions() models.CertOptions {
	return models.DefaultCertOptions()
}

// CACertificatePEM returns the CA certificate, without its key, for a host to
// write wherever its user chooses. The engine does not write it itself: the
// file belongs to whoever asked, and a headless engine runs as someone else.
func (e *Engine) CACertificatePEM() ([]byte, error) {
	if !e.tlsManager.HasCA() {
		return nil, fmt.Errorf("no CA certificate available to export; generate a CA first")
	}
	certPEM, _, err := e.tlsManager.GetCAMaterial()
	return certPEM, err
}

// ServerCertificatePEM returns the server's generated identity, certificate and
// key, for the same reason.
func (e *Engine) ServerCertificatePEM() (certPEM, keyPEM []byte, err error) {
	certPEM, keyPEM, ok := e.tlsManager.GetServerMaterial()
	if !ok {
		return nil, nil, fmt.Errorf("no server certificate available to export")
	}
	return certPEM, keyPEM, nil
}
