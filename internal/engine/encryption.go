package engine

// At-rest encryption: unlocking, enabling, disabling and changing the password.

import (
	"crypto/subtle"
	"fmt"
	"log/slog"
	"time"

	"SyslogStudio/internal/models"
)

const (
	// unlockAttemptsBeforeBackoff is how many failed unlock attempts are
	// allowed before a backoff delay begins.
	unlockAttemptsBeforeBackoff = 5
	// baseLockoutBackoff is the delay imposed at the first backoff step;
	// it doubles with each subsequent failed attempt.
	baseLockoutBackoff = 30 * time.Second
	// maxLockoutBackoff caps the backoff delay.
	maxLockoutBackoff = 15 * time.Minute
	// minPasswordLen is the minimum at-rest encryption password length. The
	// unlock lockout only rate-limits attempts through the UI; a weak password
	// is brute-forced offline against a copied logs.db.enc, so the strong KDF
	// alone is not enough.
	minPasswordLen = 8
)

// GetUnlockAttemptsRemaining returns how many unlock attempts remain
// before the next backoff delay is applied.
func (e *Engine) GetUnlockAttemptsRemaining() int {
	state := e.configStore.LoadLockout()
	remaining := unlockAttemptsBeforeBackoff - (state.FailedAttempts % unlockAttemptsBeforeBackoff)
	if remaining < 0 {
		remaining = 0
	}
	return remaining
}

// GetUnlockLockoutSeconds returns the number of seconds remaining in the
// current lockout window, or 0 if unlock attempts are currently allowed.
func (e *Engine) GetUnlockLockoutSeconds() int {
	state := e.configStore.LoadLockout()
	if state.LockedUntilUnix == 0 {
		return 0
	}
	remaining := state.LockedUntilUnix - time.Now().Unix()
	if remaining < 0 {
		return 0
	}
	return int(remaining)
}

// IsEncryptionEnabled returns whether encryption is configured.
func (e *Engine) IsEncryptionEnabled() bool {
	return e.configStore.LoadStorage().EncryptionEnabled
}

// IsEncryptionLocked returns true if the database is encrypted and not yet unlocked.
func (e *Engine) IsEncryptionLocked() bool {
	return e.logStore != nil && e.logStore.IsLocked()
}

// lockoutBackoff returns the delay to impose after failedAttempts
// consecutive failures. No delay until the threshold is reached, then an
// exponentially growing delay capped at maxLockoutBackoff.
func lockoutBackoff(failedAttempts int) time.Duration {
	if failedAttempts < unlockAttemptsBeforeBackoff {
		return 0
	}
	steps := failedAttempts - unlockAttemptsBeforeBackoff // 0, 1, 2, ...
	delay := baseLockoutBackoff << steps
	if delay > maxLockoutBackoff || delay <= 0 {
		delay = maxLockoutBackoff
	}
	return delay
}

// UnlockDatabase decrypts the database with the given password and opens it.
// Failed attempts accumulate in persisted state; after a threshold, an
// exponentially growing backoff delay is enforced that survives restarts,
// so relaunching the app cannot be used to reset the counter or bypass
// the delay.
func (e *Engine) UnlockDatabase(password string) error {
	if e.logStore == nil {
		return fmt.Errorf("log store not initialized")
	}

	state := e.configStore.LoadLockout()
	if wait := state.LockedUntilUnix - time.Now().Unix(); state.LockedUntilUnix != 0 && wait > 0 {
		return fmt.Errorf("too many failed attempts — locked for %d more seconds", wait)
	}

	if err := e.logStore.UnlockAndOpen(password); err != nil {
		state.FailedAttempts++
		if backoff := lockoutBackoff(state.FailedAttempts); backoff > 0 {
			state.LockedUntilUnix = time.Now().Add(backoff).Unix()
			e.configStore.SaveLockout(state)
			slog.Warn("unlock failed, backoff enforced", "attempts", state.FailedAttempts, "backoffSeconds", int(backoff.Seconds()))
			return fmt.Errorf("wrong password — locked for %d seconds after %d failed attempts", int(backoff.Seconds()), state.FailedAttempts)
		}
		e.configStore.SaveLockout(state)
		remaining := unlockAttemptsBeforeBackoff - state.FailedAttempts
		slog.Warn("unlock failed", "attempts", state.FailedAttempts, "remaining", remaining)
		return fmt.Errorf("wrong password (%d attempts remaining before lockout)", remaining)
	}

	// Success: clear persisted lockout state.
	e.configStore.SaveLockout(models.LockoutState{})
	e.encryptionPassword = password
	if e.secretStore != nil {
		e.secretStore.SetPassword(password)
	}
	e.server.SetLogStore(e.logStore)

	// Restore alert rules now that the store is available
	rules := e.configStore.LoadAlertRules()
	if len(rules) > 0 {
		e.server.AlertManager.SetRules(rules)
	}

	// Load an encrypted persisted CA and server identity now that the
	// password is available.
	if err := e.LoadPersistedCA(); err != nil {
		slog.Warn("failed to load persisted CA after unlock", "error", err)
	}
	if e.serverCertStore != nil && e.serverCertStore.IsEncrypted() {
		if err := e.loadPersistedServerCert(); err != nil {
			slog.Warn("failed to load the persisted server certificate after unlock", "error", err)
		}
	}
	return nil
}

// EnableEncryption enables at-rest encryption with the given password.
// It refuses to run when encryption is already on: silently accepting a new
// password there would be an unauthenticated password change (the counterpart
// of ChangeEncryptionPassword, which requires the current one), and against a
// still-locked database it would re-key the store to a password that cannot
// decrypt the existing logs.db.enc.
func (e *Engine) EnableEncryption(password string) error {
	if len(password) < minPasswordLen {
		return fmt.Errorf("password must be at least %d characters", minPasswordLen)
	}
	cfg := e.configStore.LoadStorage()
	if cfg.EncryptionEnabled {
		return fmt.Errorf("encryption is already enabled; use the change-password action instead")
	}
	cfg.EncryptionEnabled = true
	e.configStore.SaveStorage(cfg)
	e.encryptionPassword = password
	if e.secretStore != nil {
		e.secretStore.SetPassword(password)
		// Re-persist under the new password, so credentials do not stay behind
		// in the previous form.
		if err := e.secretStore.Rewrite(); err != nil {
			slog.Warn("could not re-encrypt sink credentials", "error", err)
		}
	}
	if e.logStore != nil {
		e.logStore.SetEncryptionPassword(password)
		e.logStore.UpdateConfig(cfg)
	}
	if e.caStore != nil && e.tlsManager.HasCA() {
		e.persistCA()
	}
	e.repersistServerCert()
	return nil
}

// DisableEncryption disables at-rest encryption after verifying the password.
func (e *Engine) DisableEncryption(password string) error {
	cfg := e.configStore.LoadStorage()
	if cfg.EncryptionEnabled {
		// If the session password is not present (e.g. fresh start with a
		// still-locked database), require an unlock first. Previously an
		// empty session password caused the verification to be skipped
		// entirely, allowing encryption to be disabled without knowing
		// the password.
		if e.encryptionPassword == "" {
			return fmt.Errorf("database must be unlocked before disabling encryption")
		}
		if subtle.ConstantTimeCompare([]byte(password), []byte(e.encryptionPassword)) != 1 {
			return fmt.Errorf("incorrect password")
		}
	}
	cfg.EncryptionEnabled = false
	e.configStore.SaveStorage(cfg)
	e.encryptionPassword = ""
	if e.secretStore != nil {
		e.secretStore.SetPassword("")
		if err := e.secretStore.Rewrite(); err != nil {
			slog.Warn("could not rewrite sink credentials in plaintext", "error", err)
		}
	}
	if e.logStore != nil {
		e.logStore.SetEncryptionPassword("")
		e.logStore.UpdateConfig(cfg)
	}
	if e.caStore != nil && e.tlsManager.HasCA() {
		e.persistCA()
	}
	e.repersistServerCert()
	return nil
}

// ChangeEncryptionPassword changes the encryption password.
func (e *Engine) ChangeEncryptionPassword(oldPassword, newPassword string) error {
	if e.encryptionPassword == "" {
		return fmt.Errorf("database must be unlocked before changing the password")
	}
	if subtle.ConstantTimeCompare([]byte(oldPassword), []byte(e.encryptionPassword)) != 1 {
		return fmt.Errorf("incorrect current password")
	}
	if len(newPassword) < minPasswordLen {
		return fmt.Errorf("new password must be at least %d characters", minPasswordLen)
	}
	e.encryptionPassword = newPassword
	if e.secretStore != nil {
		e.secretStore.SetPassword(newPassword)
		if err := e.secretStore.Rewrite(); err != nil {
			slog.Warn("could not re-encrypt sink credentials", "error", err)
		}
	}
	if e.logStore != nil {
		e.logStore.SetEncryptionPassword(newPassword)
	}
	// Re-persist the CA and the server identity (if any) under the new
	// password.
	if e.caStore != nil && e.tlsManager.HasCA() {
		e.persistCA()
	}
	e.repersistServerCert()
	return nil
}
