package engine

// Handing a configuration from one engine to another — from the desktop
// application to the system service it installs.

import (
	"fmt"
	"os"
	"path/filepath"

	"SyslogStudio/internal/inbox"
	"SyslogStudio/internal/models"
	"SyslogStudio/internal/notify"
	"SyslogStudio/internal/storage"
)

// BundleVersion is bumped when the bundle's shape changes, so an older service
// binary refuses a newer bundle rather than half-reading it.
const BundleVersion = 1

// Bundle is everything a second engine needs to receive the way this one does:
// the listeners, the rules, the routing with its credentials, and the TLS
// identity — but not the messages, and not the encryption password.
//
// It carries secrets in the clear, so it only ever exists in memory or in a
// file readable by the user who made it, for the few seconds an elevated
// installer takes to read and delete it.
type Bundle struct {
	Version int                  `json:"version"`
	Server  models.ServerConfig  `json:"server"`
	Storage models.StorageConfig `json:"storage"`
	Alerts  []models.AlertRule   `json:"alerts"`
	Routes  []notify.Route       `json:"routes"`
	// Sinks carry their credential in Secret. The receiving engine moves it to
	// its secret store; it never reaches a config.json.
	Sinks []notify.SinkConfig `json:"sinks"`

	// TLSCertPEM and TLSKeyPEM are the identity the receiving engine presents,
	// whether this engine generated it or read it from files: the service
	// cannot be assumed to read files in someone's profile.
	TLSCertPEM []byte `json:"tlsCertPem,omitempty"`
	TLSKeyPEM  []byte `json:"tlsKeyPem,omitempty"`
	// ClientCAPEM is the trust anchor for mutual TLS. Public, but copied for
	// the same reason.
	ClientCAPEM []byte `json:"clientCaPem,omitempty"`

	// InboxPublicKey, when set, makes the receiving engine seal what it
	// receives for the holder of the matching private key, and keep no
	// database. Unset, it stores in a database in the clear.
	InboxPublicKey []byte `json:"inboxPublicKey,omitempty"`
}

// ExportBundle describes this engine for another one to adopt.
//
// With encryption on, the credentials and the TLS key are only readable while
// the database is unlocked; exporting a locked engine fails rather than
// handing over an incomplete copy that would fail later, somewhere nobody is
// looking.
func (e *Engine) ExportBundle() (Bundle, error) {
	if e.IsEncryptionLocked() {
		return Bundle{}, fmt.Errorf("unlock the database first: the credentials and the TLS key are encrypted")
	}
	b := Bundle{
		Version: BundleVersion,
		Server:  e.configStore.Load(),
		Alerts:  e.configStore.LoadAlertRules(),
		Routes:  e.configStore.LoadRoutes(),
	}

	// The receiving engine keeps its database in its own directory, and in the
	// clear: the password stays with the person who knows it.
	b.Storage = e.configStore.LoadStorage()
	b.Storage.Path = ""
	b.Storage.EncryptionEnabled = false

	for _, sink := range e.configStore.LoadSinks() {
		if dest, ok := notify.Destination(sink); ok && e.secretStore != nil {
			sink.Secret = e.secretStore.Get(sink.ID, dest)
		}
		sink.HasSecret = false
		b.Sinks = append(b.Sinks, sink)
	}

	if b.Server.TLSEnabled {
		if err := e.exportTLS(&b); err != nil {
			return Bundle{}, err
		}
	}
	return b, nil
}

func (e *Engine) exportTLS(b *Bundle) error {
	cfg := &b.Server
	if cfg.UseSelfSigned {
		if certPEM, keyPEM, ok := e.tlsManager.GetServerMaterial(); ok {
			b.TLSCertPEM, b.TLSKeyPEM = certPEM, keyPEM
		} else if e.serverCertStore != nil && e.serverCertStore.Exists() {
			return fmt.Errorf("the saved TLS certificate is not loaded; unlock the database first")
		}
		// Neither: the receiving engine generates one on its first start, as
		// this one would have.
	} else {
		certPEM, err := os.ReadFile(cfg.CertFile)
		if err != nil {
			return fmt.Errorf("read the TLS certificate: %w", err)
		}
		keyPEM, err := os.ReadFile(cfg.KeyFile)
		if err != nil {
			return fmt.Errorf("read the TLS key: %w", err)
		}
		b.TLSCertPEM, b.TLSKeyPEM = certPEM, keyPEM
		// From here on it is a stored identity, not a pair of paths.
		cfg.UseSelfSigned = true
		cfg.CertFile, cfg.KeyFile = "", ""
	}
	if cfg.MutualTLS {
		caPEM, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return fmt.Errorf("read the client CA for mutual TLS: %w", err)
		}
		b.ClientCAPEM = caPEM
	}
	cfg.CAFile = ""
	return nil
}

// clientCAFile is where an adopted mutual-TLS trust anchor is written, inside
// the engine's own directory.
const clientCAFile = "client-ca.pem"

// ImportBundle makes this engine receive the way the bundle describes. It is
// meant for an engine that is not open yet — a service's, written by its
// installer — and replaces the configuration it covers.
func (e *Engine) ImportBundle(b Bundle) error {
	if b.Version != BundleVersion {
		return fmt.Errorf("configuration bundle version %d is not supported (expected %d)", b.Version, BundleVersion)
	}
	if e.DataDir() == "" {
		return fmt.Errorf("no data directory to write the configuration to")
	}

	server := b.Server
	if len(b.ClientCAPEM) > 0 {
		path := filepath.Join(e.DataDir(), clientCAFile)
		if err := os.WriteFile(path, b.ClientCAPEM, 0644); err != nil {
			return fmt.Errorf("write the client CA: %w", err)
		}
		server.CAFile = path
	}
	if len(b.TLSCertPEM) > 0 {
		if err := e.tlsManager.LoadServerMaterial(b.TLSCertPEM, b.TLSKeyPEM); err != nil {
			return err
		}
		if err := e.serverCertStore.Save(b.TLSCertPEM, b.TLSKeyPEM, ""); err != nil {
			return fmt.Errorf("store the TLS identity: %w", err)
		}
	}

	storageCfg := b.Storage
	storageCfg.Path = ""
	storageCfg.EncryptionEnabled = false

	sinks := make([]notify.SinkConfig, 0, len(b.Sinks))
	keep := make(map[string]bool, len(b.Sinks))
	for _, sink := range b.Sinks {
		if sink.Secret != "" {
			dest, ok := notify.Destination(sink)
			if !ok {
				return fmt.Errorf("destination %q cannot hold a credential", sink.Name)
			}
			if err := e.secretStore.Set(sink.ID, dest, sink.Secret); err != nil {
				return fmt.Errorf("store the credential for %q: %w", sink.Name, err)
			}
		}
		sink.Secret = ""
		sink.HasSecret = false
		keep[sink.ID] = true
		sinks = append(sinks, sink)
	}
	if err := e.secretStore.Prune(keep); err != nil {
		return fmt.Errorf("drop credentials of removed destinations: %w", err)
	}

	if len(b.InboxPublicKey) > 0 {
		if err := inbox.CheckPublicKey(b.InboxPublicKey); err != nil {
			return err
		}
		cfg := models.InboxConfig{PublicKey: b.InboxPublicKey}
		if prev := e.configStore.LoadInbox(); prev != nil {
			cfg.QuotaBytes = prev.QuotaBytes
		}
		e.configStore.SaveInbox(&cfg)
	} else {
		e.configStore.SaveInbox(nil)
	}

	e.configStore.Save(server)
	e.configStore.SaveStorage(storageCfg)
	e.configStore.SaveAlertRules(b.Alerts)
	e.configStore.SaveRoutes(b.Routes)
	e.configStore.SaveSinks(sinks)
	return nil
}

// SetSealer protects what this engine would otherwise write in plaintext —
// its credentials and private keys — with the operating system's key store.
// Called before Open, by a host with no password to offer.
func (e *Engine) SetSealer(s storage.Sealer) {
	e.secretStore.SetSealer(s)
	e.caStore.SetSealer(s)
	e.serverCertStore.SetSealer(s)
	e.inboxKeyStore.SetSealer(s)
}

// StartSaved starts the listeners with the saved configuration. A host that
// starts receiving without a click calls this: a service on boot, the desktop
// application when told to start listening on launch.
func (e *Engine) StartSaved() error {
	return e.StartServer(e.configStore.Load())
}
