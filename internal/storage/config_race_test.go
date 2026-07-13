package storage

import (
	"sync"
	"testing"

	"SyslogStudio/internal/models"
)

// TestConfigStore_ConcurrentWrites hammers distinct Save* methods from many
// goroutines. Without the mutex + atomic write, the read-modify-write on
// config.json races and can leave a truncated/corrupted file that loadAll then
// silently replaces with defaults. It must run clean under -race and keep the
// persisted ServerConfig intact.
func TestConfigStore_ConcurrentWrites(t *testing.T) {
	cs := &ConfigStore{dir: t.TempDir()}
	// Seed a distinctive server config; a defaults-reset corruption would put
	// UDPPort back to 514.
	cs.Save(models.ServerConfig{UDPPort: 5514, TCPPort: 5515, TLSPort: 6514, MaxBuffer: 10000})

	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(4)
		go func() { defer wg.Done(); cs.SaveLockout(models.LockoutState{FailedAttempts: 3}) }()
		go func() { defer wg.Done(); cs.SaveUpdateConfig(models.UpdateConfig{AutoCheck: true, IntervalHours: 24}) }()
		go func() { defer wg.Done(); cs.SaveStorage(models.DefaultStorageConfig()) }()
		go func() { defer wg.Done(); _ = cs.LoadAlertRules() }()
	}
	wg.Wait()

	got := cs.Load()
	if got.UDPPort != 5514 || got.TCPPort != 5515 {
		t.Fatalf("server config lost/corrupted under concurrency: %+v", got)
	}
}
