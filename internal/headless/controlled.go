package headless

import (
	"errors"

	"SyslogStudio/internal/engine"
	"SyslogStudio/internal/models"
)

// errNoEncryption is what a window gets for asking a host to encrypt its
// database. The host would have no one to type the password when it next
// starts, and a database it cannot open stores nothing.
var errNoEncryption = errors.New("at-rest encryption is not available for the service: " +
	"it would need someone to type the password each time it starts; " +
	"its directory is readable by administrators and the service only")

// controlled is the engine as windows drive it over the control channel: all
// of it, except what a host with nobody at the keyboard cannot do.
type controlled struct {
	*engine.Engine
	host *Host
}

// StartServer and StopServer from a window put it in charge of the
// listeners: the host stops retrying the saved ones.
func (c controlled) StartServer(config models.ServerConfig) error {
	c.host.windowTookOver()
	return c.Engine.StartServer(config)
}

func (c controlled) StopServer() error {
	c.host.windowTookOver()
	return c.Engine.StopServer()
}

func (controlled) UnlockDatabase(string) error                   { return errNoEncryption }
func (controlled) EnableEncryption(string) error                 { return errNoEncryption }
func (controlled) DisableEncryption(string) error                { return errNoEncryption }
func (controlled) ChangeEncryptionPassword(string, string) error { return errNoEncryption }

// SetStorageConfig keeps the database in the host's own directory, and in
// the clear: a path in someone's profile is one the host's account may not
// even reach.
func (c controlled) SetStorageConfig(cfg models.StorageConfig) {
	cfg.Path = ""
	cfg.EncryptionEnabled = false
	c.Engine.SetStorageConfig(cfg)
}
