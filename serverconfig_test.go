package main

import (
	"testing"

	"SyslogStudio/internal/models"
	"SyslogStudio/internal/syslog"
)

// Issue #45: TLS certificate paths were saved correctly and then thrown away on
// every launch.
//
// The server only learns its configuration in Start, so before the first start
// it has none. GetStatus reported that emptiness as "the configuration", the
// renderer synced its TLS fields from it, and the blanks landed on top of the
// paths it had just loaded — leaving the user to browse for their certificate
// again, every time, and a "TLS certificate file path is required" on Start.
//
// These pin the answer that fixes it: when nothing is running, the status
// reports what was saved.

func appWithServer(t *testing.T) *App {
	t.Helper()
	a := newTestApp(t)
	a.server = syslog.NewSyslogServer(nil, nil)
	return a
}

func tlsConfig() models.ServerConfig {
	cfg := models.DefaultServerConfig()
	cfg.TLSEnabled = true
	cfg.UseSelfSigned = false
	cfg.CertFile = "/etc/ssl/collector.crt"
	cfg.KeyFile = "/etc/ssl/collector.key"
	cfg.CAFile = "/etc/ssl/ca.crt"
	cfg.MutualTLS = true
	return cfg
}

func TestServerStatus_ReportsSavedConfigWhenStopped(t *testing.T) {
	a := appWithServer(t)
	want := tlsConfig()
	a.configStore.Save(want)

	// A fresh process: the server has been told nothing, which is precisely
	// the state that used to answer with blanks.
	got := a.GetServerStatus()

	if got.Running {
		t.Fatal("a server that was never started reports itself running")
	}
	if got.Config.CertFile != want.CertFile {
		t.Errorf("CertFile = %q, want %q — this is the bug", got.Config.CertFile, want.CertFile)
	}
	if got.Config.KeyFile != want.KeyFile {
		t.Errorf("KeyFile = %q, want %q", got.Config.KeyFile, want.KeyFile)
	}
	if got.Config.CAFile != want.CAFile {
		t.Errorf("CAFile = %q, want %q", got.Config.CAFile, want.CAFile)
	}
	if !got.Config.MutualTLS {
		t.Error("MutualTLS was lost")
	}
	if got.Config.TLSEnabled != want.TLSEnabled {
		t.Errorf("TLSEnabled = %v, want %v", got.Config.TLSEnabled, want.TLSEnabled)
	}
}

func TestSaveServerConfig_PersistsWithoutStarting(t *testing.T) {
	a := appWithServer(t)
	a.SaveServerConfig(tlsConfig())

	// Choosing a certificate and closing the window is the second route to the
	// same complaint: settings used to be written only on a successful start.
	if got := a.GetDefaultConfig(); got.CertFile != "/etc/ssl/collector.crt" {
		t.Fatalf("CertFile = %q after saving without starting", got.CertFile)
	}
	if got := a.GetServerStatus(); got.Config.KeyFile != "/etc/ssl/collector.key" {
		t.Fatalf("the status does not reflect what was just saved: KeyFile = %q", got.Config.KeyFile)
	}
}

// Saving must accept a configuration that is halfway through being made.
// Choosing a certificate and then its key is two steps, and refusing to store
// the first one would put the bug straight back.
func TestSaveServerConfig_AcceptsAnIncompleteChoice(t *testing.T) {
	a := appWithServer(t)

	half := models.DefaultServerConfig()
	half.TLSEnabled = true
	half.UseSelfSigned = false
	half.CertFile = "/etc/ssl/collector.crt" // no key yet
	a.SaveServerConfig(half)

	if got := a.GetDefaultConfig(); got.CertFile != half.CertFile {
		t.Fatalf("a half-made choice was not kept: CertFile = %q", got.CertFile)
	}

	// The gate is Start, where the message can say what is missing.
	if err := models.ValidateServerConfig(half); err == nil {
		t.Error("an incomplete TLS configuration should still be refused when starting")
	}
}
