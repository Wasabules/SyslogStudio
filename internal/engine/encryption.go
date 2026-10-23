package engine

// At-rest encryption: unlocking, enabling, disabling and changing the password.

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"SyslogStudio/internal/models"
	"SyslogStudio/internal/storage"
	"SyslogStudio/internal/vault"
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

// masterFor finds the master secret a password opens. An installation
// encrypted before the keyring has none: its password is its master secret,
// and legacy says so.
func (e *Engine) masterFor(password string) (master string, legacy bool, err error) {
	k, err := storage.LoadKeyring(e.DataDir())
	if errors.Is(err, storage.ErrNoKeyring) || (err == nil && len(k.PasswordSlots()) == 0) {
		return password, true, nil
	}
	if err != nil {
		return "", false, err
	}
	master, err = vault.OpenWithPassword(k.PasswordSlots(), password)
	return master, false, err
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

	var prev string
	var usedPrev bool
	master, legacy, err := e.masterFor(password)
	if err == nil {
		prev, usedPrev, err = e.unlockStore(master)
	}
	if err != nil {
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
	if legacy {
		// Encrypted before the keyring: write one, the password still the
		// master secret, so that nothing else changes. A recovery key and a
		// change of password can build on it.
		k, kerr := storage.LoadKeyring(e.DataDir())
		if kerr != nil && !errors.Is(kerr, storage.ErrNoKeyring) {
			slog.Warn("the keyring could not be read", "error", kerr)
		} else if kerr = k.Lock(master, password); kerr == nil {
			kerr = storage.SaveKeyring(e.DataDir(), k)
		}
		if kerr != nil {
			slog.Warn("could not write the keyring", "error", kerr)
		}
	}
	e.unlockedByKey = false
	e.afterUnlock(master, prev, usedPrev)
	return nil
}

// UnlockWithRecoveryKey opens the database with the recovery key's file
// instead of the password. The password can then be replaced without being
// known (ResetEncryptionPassword).
func (e *Engine) UnlockWithRecoveryKey(keyFile []byte) error {
	if e.logStore == nil || !e.IsEncryptionLocked() {
		return fmt.Errorf("the database is not locked")
	}
	priv, _, err := vault.ParseRecoveryKey(keyFile)
	if err != nil {
		return err
	}
	k, err := storage.LoadKeyring(e.DataDir())
	if errors.Is(err, storage.ErrNoKeyring) || (err == nil && len(k.KeySlots()) == 0) {
		return fmt.Errorf("no recovery key was set up for this installation")
	}
	if err != nil {
		return err
	}
	master, err := vault.OpenWithKey(k.KeySlots(), priv)
	if err != nil {
		return err
	}
	prev, usedPrev, err := e.unlockStore(master)
	if err != nil {
		return fmt.Errorf("the recovery key opened the keyring but not the database: %w", err)
	}
	e.configStore.SaveLockout(models.LockoutState{})
	e.unlockedByKey = true
	e.afterUnlock(master, prev, usedPrev)
	return nil
}

// IsUnlockedByRecoveryKey says the recovery key opened this session, so the
// window can offer to set a new password.
func (e *Engine) IsUnlockedByRecoveryKey() bool { return e.unlockedByKey }

// unlockStore opens the database with master or, while the keyring still
// keeps the master secret being replaced, with that one (usedPrev): the
// database is then written under master when it closes.
func (e *Engine) unlockStore(master string) (prev string, usedPrev bool, err error) {
	if k, kerr := storage.LoadKeyring(e.DataDir()); kerr == nil {
		if prev, kerr = k.PreviousMaster(master); kerr != nil {
			slog.Warn("the keyring's previous master secret does not open", "error", kerr)
		}
	}
	err = e.logStore.UnlockAndOpen(master)
	if err != nil && prev != "" && e.logStore.UnlockAndOpen(prev) == nil {
		e.logStore.SetEncryptionPassword(master)
		return prev, true, nil
	}
	return prev, false, err
}

// afterUnlock puts the master secret to use once the database is open. What
// master does not open, the master secret being replaced (prev) may: it is
// read with that one and written again under master. The keyring forgets
// prev once everything opens with master — at the latest, the next unlock.
func (e *Engine) afterUnlock(master, prev string, usedPrev bool) {
	e.master = master
	if e.secretStore != nil {
		e.secretStore.SetPassword(master)
		if prev != "" && e.secretStore.Readable() != nil {
			usedPrev = true
			e.secretStore.SetPassword(prev)
			if err := e.secretStore.Rekey(master); err != nil {
				slog.Warn("failed to read the sink credentials after unlock", "error", err)
				e.secretStore.SetPassword(master)
			}
		}
	}
	e.server.SetLogStore(e.logStore)

	// Restore alert rules now that the store is available
	rules := e.configStore.LoadAlertRules()
	if len(rules) > 0 {
		e.server.AlertManager.SetRules(rules)
	}

	// Load an encrypted persisted CA, server identity and inbox key now that
	// the master secret is available.
	load := func(what string, with func(string) error, persist func()) {
		err := with(master)
		if err != nil && prev != "" {
			if err = with(prev); err == nil {
				usedPrev = true
				persist()
			}
		}
		if err != nil {
			slog.Warn("failed to load the "+what+" after unlock", "error", err)
		}
	}
	load("CA", e.loadCAWith, e.persistCA)
	if e.serverCertStore != nil && e.serverCertStore.IsEncrypted() {
		load("server certificate", e.loadServerCertWith, e.repersistServerCert)
	}
	load("inbox key", e.loadInboxKeyWith, e.repersistInboxKey)

	if prev != "" && !usedPrev && e.readableWith(master) == nil {
		e.forgetPrevious()
	}
}

// rekey encrypts everything again with master: the credentials, the CA, the
// server identity and the inbox key now, the database when it closes.
func (e *Engine) rekey(master string) {
	e.master = master
	if e.secretStore != nil {
		// Re-persist under the new secret, so credentials do not stay behind
		// in the previous form.
		if err := e.secretStore.Rekey(master); err != nil {
			slog.Warn("could not re-encrypt sink credentials", "error", err)
		}
	}
	if e.logStore != nil {
		e.logStore.SetEncryptionPassword(master)
	}
	if e.caStore != nil && e.tlsManager.HasCA() {
		e.persistCA()
	}
	e.repersistServerCert()
	e.repersistInboxKey()
}

// readableWith says whether every key file encrypted at rest opens with
// master.
func (e *Engine) readableWith(master string) error {
	if e.secretStore != nil && e.secretStore.IsEncrypted() {
		probe := storage.NewSecretStore(e.DataDir())
		probe.SetPassword(master)
		if err := probe.Readable(); err != nil {
			return fmt.Errorf("sink credentials: %w", err)
		}
	}
	for what, store := range map[string]*storage.PEMStore{"CA": e.caStore, "server certificate": e.serverCertStore, "inbox key": e.inboxKeyStore} {
		if store == nil || !store.Exists() || !store.IsEncrypted() {
			continue
		}
		if _, _, err := store.Load(master); err != nil {
			return fmt.Errorf("%s: %w", what, err)
		}
	}
	return nil
}

// rotate replaces a master secret that was the password itself with a random
// one, locked by password — and by the recovery key, if one is set. The
// keyring goes first: written whole or not at all, it is what commits the
// change, and it keeps the old secret, sealed by the new one, until
// everything the old one encrypted has been written again. A file the rewrite
// missed, through an interruption or a full disk, still opens.
func (e *Engine) rotate(k storage.Keyring, password string) error {
	master := vault.NewMaster()
	if err := k.Lock(master, password); err != nil {
		return err
	}
	if err := k.SetPrevious(e.master, master); err != nil {
		return err
	}
	if err := storage.SaveKeyring(e.DataDir(), k); err != nil {
		return fmt.Errorf("write the keyring: %w", err)
	}
	e.rekey(master)
	if err := e.readableWith(master); err != nil {
		slog.Warn("the previous master secret is kept until everything is written under the new one", "error", err)
		return nil
	}
	e.forgetPrevious()
	return nil
}

// forgetPrevious drops the master secret being replaced from the keyring.
func (e *Engine) forgetPrevious() {
	k, err := storage.LoadKeyring(e.DataDir())
	if err != nil || len(k.Previous) == 0 {
		return
	}
	k.Previous = nil
	if err := storage.SaveKeyring(e.DataDir(), k); err != nil {
		slog.Warn("could not update the keyring", "error", err)
	}
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
	// A random master secret, locked by the password — and by the recovery
	// key, if one is set up already.
	master := vault.NewMaster()
	k, err := storage.LoadKeyring(e.DataDir())
	if err != nil && !errors.Is(err, storage.ErrNoKeyring) {
		return err
	}
	if err := k.Lock(master, password); err != nil {
		return err
	}
	k.Previous = nil
	if err := storage.SaveKeyring(e.DataDir(), k); err != nil {
		return fmt.Errorf("write the keyring: %w", err)
	}
	cfg.EncryptionEnabled = true
	e.configStore.SaveStorage(cfg)
	if e.logStore != nil {
		e.logStore.UpdateConfig(e.withDBPath(cfg))
	}
	e.rekey(master)
	return nil
}

// checkPassword says whether password is the one that opens this session's
// master secret.
func (e *Engine) checkPassword(password string) bool {
	master, _, err := e.masterFor(password)
	return err == nil && subtle.ConstantTimeCompare([]byte(master), []byte(e.master)) == 1
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
		if e.master == "" {
			return fmt.Errorf("database must be unlocked before disabling encryption")
		}
		if !e.checkPassword(password) {
			return fmt.Errorf("incorrect password")
		}
	}
	cfg.EncryptionEnabled = false
	e.configStore.SaveStorage(cfg)
	// The locks go; the recovery key's public half stays, for backups.
	if k, err := storage.LoadKeyring(e.DataDir()); err == nil {
		k.Slots, k.Previous = nil, nil
		if err := storage.SaveKeyring(e.DataDir(), k); err != nil {
			slog.Warn("could not clear the keyring", "error", err)
		}
	}
	e.unlockedByKey = false
	e.master = ""
	if e.secretStore != nil {
		if err := e.secretStore.Rekey(""); err != nil {
			slog.Warn("could not rewrite sink credentials in plaintext", "error", err)
		}
	}
	if e.logStore != nil {
		e.logStore.SetEncryptionPassword("")
		e.logStore.UpdateConfig(e.withDBPath(cfg))
	}
	if e.caStore != nil && e.tlsManager.HasCA() {
		e.persistCA()
	}
	e.repersistServerCert()
	e.repersistInboxKey()
	return nil
}

// ChangeEncryptionPassword changes the encryption password.
func (e *Engine) ChangeEncryptionPassword(oldPassword, newPassword string) error {
	if e.master == "" {
		return fmt.Errorf("database must be unlocked before changing the password")
	}
	if !e.checkPassword(oldPassword) {
		return fmt.Errorf("incorrect current password")
	}
	return e.setPassword(newPassword)
}

// ResetEncryptionPassword sets a new password without the current one, in a
// session the recovery key opened: what the recovery key is for.
func (e *Engine) ResetEncryptionPassword(newPassword string) error {
	if e.master == "" || !e.unlockedByKey {
		return fmt.Errorf("only a session unlocked with the recovery key can set a password without the current one")
	}
	if err := e.setPassword(newPassword); err != nil {
		return err
	}
	e.unlockedByKey = false
	return nil
}

// setPassword locks the master secret with a new password. A master secret
// that was the password itself — an installation encrypted before the
// keyring — is replaced at the same time, so the old password opens nothing.
func (e *Engine) setPassword(password string) error {
	if len(password) < minPasswordLen {
		return fmt.Errorf("new password must be at least %d characters", minPasswordLen)
	}
	k, err := storage.LoadKeyring(e.DataDir())
	if err != nil && !errors.Is(err, storage.ErrNoKeyring) {
		return err
	}
	if vault.IsGenerated(e.master) {
		if err := k.Relock(e.master, password); err != nil {
			return err
		}
		return storage.SaveKeyring(e.DataDir(), k)
	}
	return e.rotate(k, password)
}

// --- the recovery key ---------------------------------------------------------------

// GetRecoveryKey says whether a recovery key is set up, and which.
func (e *Engine) GetRecoveryKey() models.RecoveryKeyInfo {
	k, err := storage.LoadKeyring(e.DataDir())
	if err != nil || k.Recovery == nil {
		return models.RecoveryKeyInfo{}
	}
	return models.RecoveryKeyInfo{Set: true, ID: k.Recovery.ID, Created: k.Recovery.Created}
}

// SetRecoveryKey locks this installation's data to a recovery key too, given
// its public half: the window makes the pair and keeps the private half to
// hand to the user, so it never travels. With encryption off, backups are
// locked to it alone.
func (e *Engine) SetRecoveryKey(pub []byte) (models.RecoveryKeyInfo, error) {
	enabled := e.configStore.LoadStorage().EncryptionEnabled
	if enabled && e.master == "" {
		return models.RecoveryKeyInfo{}, fmt.Errorf("unlock the database before setting a recovery key")
	}
	if _, err := vault.KeySlot(vault.NewMaster(), pub); err != nil {
		return models.RecoveryKeyInfo{}, err
	}
	k, err := storage.LoadKeyring(e.DataDir())
	if err != nil && !errors.Is(err, storage.ErrNoKeyring) {
		return models.RecoveryKeyInfo{}, err
	}
	k.Recovery = &storage.RecoveryKey{ID: vault.KeyID(pub), Created: time.Now().UTC().Format(time.RFC3339), Public: pub}
	if enabled && !vault.IsGenerated(e.master) {
		// The master secret is still the password: the recovery key would
		// hand it over. Replace it, keeping the password.
		if err := e.rotate(k, e.master); err != nil {
			return models.RecoveryKeyInfo{}, err
		}
		return e.GetRecoveryKey(), nil
	}
	if enabled {
		slot, err := vault.KeySlot(e.master, pub)
		if err != nil {
			return models.RecoveryKeyInfo{}, err
		}
		k.Slots = append(k.PasswordSlots(), slot)
	}
	if err := storage.SaveKeyring(e.DataDir(), k); err != nil {
		return models.RecoveryKeyInfo{}, err
	}
	return e.GetRecoveryKey(), nil
}

// RemoveRecoveryKey takes the recovery key's lock away: the key file opens
// nothing written from now on. Backups made before keep their own locks.
func (e *Engine) RemoveRecoveryKey() error {
	k, err := storage.LoadKeyring(e.DataDir())
	if errors.Is(err, storage.ErrNoKeyring) {
		return nil
	}
	if err != nil {
		return err
	}
	k.Recovery = nil
	k.Slots = k.PasswordSlots()
	return storage.SaveKeyring(e.DataDir(), k)
}
