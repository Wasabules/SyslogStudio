package storage

import (
	"os"
	"path/filepath"
	"testing"

	"SyslogStudio/internal/models"
)

func TestValidateServerConfig_NoProtocol(t *testing.T) {
	cfg := models.ServerConfig{}
	err := models.ValidateServerConfig(cfg)
	if err == nil {
		t.Fatal("expected error for no protocol enabled")
	}
}

func TestValidateServerConfig_InvalidPort(t *testing.T) {
	tests := []struct {
		name string
		cfg  models.ServerConfig
	}{
		{"UDP port 0", models.ServerConfig{UDPEnabled: true, UDPPort: 0}},
		{"UDP port negative", models.ServerConfig{UDPEnabled: true, UDPPort: -1}},
		{"UDP port too high", models.ServerConfig{UDPEnabled: true, UDPPort: 70000}},
		{"TCP port 0", models.ServerConfig{TCPEnabled: true, TCPPort: 0}},
		{"TLS port 0", models.ServerConfig{TLSEnabled: true, TLSPort: 0, UseSelfSigned: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := models.ValidateServerConfig(tt.cfg); err == nil {
				t.Error("expected error for invalid port")
			}
		})
	}
}

func TestValidateServerConfig_PortConflict(t *testing.T) {
	cfg := models.ServerConfig{
		TCPEnabled: true,
		TCPPort:    514,
		TLSEnabled: true,
		TLSPort:    514,
		UseSelfSigned: true,
	}
	err := models.ValidateServerConfig(cfg)
	if err == nil {
		t.Fatal("expected error for port conflict")
	}
}

func TestValidateServerConfig_ValidConfig(t *testing.T) {
	cfg := models.DefaultServerConfig()
	if err := models.ValidateServerConfig(cfg); err != nil {
		t.Fatalf("default config should be valid: %v", err)
	}
}

func TestValidateServerConfig_TLSMissingCert(t *testing.T) {
	cfg := models.ServerConfig{
		TLSEnabled:    true,
		TLSPort:       6514,
		UseSelfSigned: false,
		CertFile:      "",
		KeyFile:       "",
	}
	if err := models.ValidateServerConfig(cfg); err == nil {
		t.Fatal("expected error for missing TLS cert paths")
	}
}

func TestValidateServerConfig_TLSCertNotFound(t *testing.T) {
	cfg := models.ServerConfig{
		TLSEnabled:    true,
		TLSPort:       6514,
		UseSelfSigned: false,
		CertFile:      "/nonexistent/cert.pem",
		KeyFile:       "/nonexistent/key.pem",
	}
	if err := models.ValidateServerConfig(cfg); err == nil {
		t.Fatal("expected error for missing TLS cert file")
	}
}

func TestValidateServerConfig_TLSValidFiles(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	os.WriteFile(certPath, []byte("cert"), 0600)
	os.WriteFile(keyPath, []byte("key"), 0600)

	cfg := models.ServerConfig{
		TLSEnabled:    true,
		TLSPort:       6514,
		UseSelfSigned: false,
		CertFile:      certPath,
		KeyFile:       keyPath,
	}
	if err := models.ValidateServerConfig(cfg); err != nil {
		t.Fatalf("expected no error: %v", err)
	}
}

func TestValidateServerConfig_AllProtocols(t *testing.T) {
	cfg := models.ServerConfig{
		UDPEnabled:    true,
		UDPPort:       514,
		TCPEnabled:    true,
		TCPPort:       1514,
		TLSEnabled:    true,
		TLSPort:       6514,
		UseSelfSigned: true,
	}
	if err := models.ValidateServerConfig(cfg); err != nil {
		t.Fatalf("expected no error: %v", err)
	}
}

func TestConfigStore_SaveLoad(t *testing.T) {
	dir := t.TempDir()
	cs := &ConfigStore{dir: dir}

	cfg := models.ServerConfig{
		UDPEnabled: true,
		UDPPort:    1514,
		TCPEnabled: true,
		TCPPort:    2514,
		MaxBuffer:  5000,
	}

	cs.Save(cfg)
	loaded := cs.Load()

	if loaded.UDPPort != 1514 || loaded.TCPPort != 2514 || loaded.MaxBuffer != 5000 {
		t.Fatalf("loaded config doesn't match saved: %+v", loaded)
	}
}

func TestConfigStore_LoadMissing(t *testing.T) {
	cs := &ConfigStore{dir: t.TempDir()}
	cfg := cs.Load()
	def := models.DefaultServerConfig()
	if cfg.UDPPort != def.UDPPort {
		t.Fatal("expected default config when file is missing")
	}
}

func TestConfigStore_EmptyDir(t *testing.T) {
	cs := &ConfigStore{}
	cfg := cs.Load()
	def := models.DefaultServerConfig()
	if cfg.UDPPort != def.UDPPort {
		t.Fatal("expected default config when dir is empty")
	}
	cs.Save(cfg) // should not panic
}
