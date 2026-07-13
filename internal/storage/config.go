package storage

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	"SyslogStudio/internal/models"
)

const configFileName = "config.json"

// ConfigStore handles persisting and loading user configuration.
//
// Every public Load*/Save* is a read-modify-write of config.json (loadAll then
// saveAll). The mutex makes each of those atomic so concurrent savers on
// different Wails goroutines cannot lose each other's changes, and saveAll
// writes via a temp file + rename so a crash mid-write cannot corrupt the file.
type ConfigStore struct {
	dir string
	mu  sync.Mutex
}

// NewConfigStore creates a ConfigStore using the user's config directory.
func NewConfigStore() *ConfigStore {
	configDir, err := os.UserConfigDir()
	if err != nil {
		slog.Warn("cannot determine user config dir, config will not persist", "error", err)
		return &ConfigStore{}
	}
	dir := filepath.Join(configDir, "SyslogStudio")
	return &ConfigStore{dir: dir}
}

func (cs *ConfigStore) path() string {
	return filepath.Join(cs.dir, configFileName)
}

// Dir returns the directory used for persisted configuration, or an empty
// string if configuration persistence is unavailable.
func (cs *ConfigStore) Dir() string {
	return cs.dir
}

func (cs *ConfigStore) loadAll() models.AppConfig {
	if cs.dir == "" {
		return models.AppConfig{Server: models.DefaultServerConfig(), Storage: models.DefaultStorageConfig()}
	}
	data, err := os.ReadFile(cs.path())
	if err != nil {
		return models.AppConfig{Server: models.DefaultServerConfig(), Storage: models.DefaultStorageConfig()}
	}

	var cfg models.AppConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		slog.Warn("failed to parse config file, using defaults", "error", err)
		return models.AppConfig{Server: models.DefaultServerConfig(), Storage: models.DefaultStorageConfig()}
	}

	// Detect old flat format: if server fields are all zero but file exists,
	// try to parse as flat ServerConfig (migration from pre-AppConfig format)
	if cfg.Server.UDPPort == 0 && cfg.Server.TCPPort == 0 && cfg.Server.TLSPort == 0 {
		var legacy models.ServerConfig
		if json.Unmarshal(data, &legacy) == nil && legacy.UDPPort > 0 {
			slog.Info("migrating old config format to new AppConfig")
			cfg.Server = legacy
			cs.saveAll(cfg)
		} else {
			cfg.Server = models.DefaultServerConfig()
		}
	}

	// Fill missing server defaults (ports saved as 0, buffer as 0, etc.)
	defaults := models.DefaultServerConfig()
	if cfg.Server.TCPPort == 0 {
		cfg.Server.TCPPort = defaults.TCPPort
	}
	if cfg.Server.TLSPort == 0 {
		cfg.Server.TLSPort = defaults.TLSPort
	}
	if cfg.Server.MaxBuffer == 0 {
		cfg.Server.MaxBuffer = defaults.MaxBuffer
	}

	// Apply storage defaults if all zero
	if !cfg.Storage.Enabled && cfg.Storage.RetentionDays == 0 && cfg.Storage.MaxMessages == 0 {
		cfg.Storage = models.DefaultStorageConfig()
	}

	// Update preferences: default to auto-check when nothing was persisted yet.
	if cfg.Updates == (models.UpdateConfig{}) {
		cfg.Updates = models.DefaultUpdateConfig()
	}

	return cfg
}

func (cs *ConfigStore) saveAll(cfg models.AppConfig) {
	if cs.dir == "" {
		return
	}
	if err := os.MkdirAll(cs.dir, 0700); err != nil {
		slog.Warn("failed to create config dir", "error", err)
		return
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		slog.Warn("failed to marshal config", "error", err)
		return
	}
	// Write atomically: a partial write (crash/full disk) must not corrupt
	// config.json, which would otherwise fall back to defaults on next load.
	tmp := cs.path() + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		slog.Warn("failed to write config", "error", err)
		return
	}
	if err := os.Rename(tmp, cs.path()); err != nil {
		slog.Warn("failed to replace config", "error", err)
		_ = os.Remove(tmp)
	}
}

// Load reads the saved ServerConfig from disk.
func (cs *ConfigStore) Load() models.ServerConfig {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return cs.loadAll().Server
}

// Save writes the ServerConfig to disk.
func (cs *ConfigStore) Save(cfg models.ServerConfig) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	all := cs.loadAll()
	all.Server = cfg
	cs.saveAll(all)
}

// LoadStorage reads the saved StorageConfig.
func (cs *ConfigStore) LoadStorage() models.StorageConfig {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return cs.loadAll().Storage
}

// SaveStorage writes the StorageConfig.
func (cs *ConfigStore) SaveStorage(cfg models.StorageConfig) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	all := cs.loadAll()
	all.Storage = cfg
	cs.saveAll(all)
}

// LoadAlertRules reads the saved alert rules.
func (cs *ConfigStore) LoadAlertRules() []models.AlertRule {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return cs.loadAll().Alerts
}

// SaveAlertRules writes the alert rules.
func (cs *ConfigStore) SaveAlertRules(rules []models.AlertRule) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	all := cs.loadAll()
	all.Alerts = rules
	cs.saveAll(all)
}

// LoadLockout reads the persisted unlock-lockout state.
func (cs *ConfigStore) LoadLockout() models.LockoutState {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return cs.loadAll().Lockout
}

// SaveLockout writes the unlock-lockout state.
func (cs *ConfigStore) SaveLockout(state models.LockoutState) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	all := cs.loadAll()
	all.Lockout = state
	cs.saveAll(all)
}

// LoadUpdateConfig reads the persisted update-check preferences.
func (cs *ConfigStore) LoadUpdateConfig() models.UpdateConfig {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return cs.loadAll().Updates
}

// SaveUpdateConfig writes the update-check preferences.
func (cs *ConfigStore) SaveUpdateConfig(cfg models.UpdateConfig) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	all := cs.loadAll()
	all.Updates = cfg
	cs.saveAll(all)
}
