package models

// The sealed inbox lets a service keep receiving for someone whose database
// is encrypted, without ever holding their password: it seals what it
// receives with a public key, and only the window that knows the password —
// which protects the private key — can open it, then moves the messages into
// the encrypted database.

// DefaultInboxQuota caps the sealed batches waiting to be collected, so a
// window nobody opens for months cannot fill the disk.
const DefaultInboxQuota int64 = 1 << 30

// InboxConfig is a service's sealed inbox. Present, the service stores
// nothing in the clear: no database, only sealed batches.
type InboxConfig struct {
	// PublicKey seals each batch (HPKE).
	PublicKey []byte `json:"publicKey"`
	// QuotaBytes caps what waits; zero means DefaultInboxQuota.
	QuotaBytes int64 `json:"quotaBytes,omitempty"`
}

// Quota is the cap in effect.
func (c InboxConfig) Quota() int64 {
	if c.QuotaBytes > 0 {
		return c.QuotaBytes
	}
	return DefaultInboxQuota
}

// InboxStatus is what a service's inbox holds.
type InboxStatus struct {
	// Sealed is whether the service seals what it receives.
	Sealed bool `json:"sealed"`
	// KeyID names the public key batches are sealed for.
	KeyID   string `json:"keyId,omitempty"`
	Batches int    `json:"batches"`
	Bytes   int64  `json:"bytes"`
	Quota   int64  `json:"quota"`
	// Dropped counts the messages not kept since the service started,
	// because the inbox was full or could not be written.
	Dropped int64 `json:"dropped"`
	// Error is why the last batch could not be written.
	Error string `json:"error,omitempty"`
}

// Filling reports whether the inbox is four-fifths full or more: time to
// warn, before anything is dropped.
func (s InboxStatus) Filling() bool {
	return s.Quota > 0 && s.Bytes*5 >= s.Quota*4
}

// InboxBatch is one sealed batch waiting in an inbox.
type InboxBatch struct {
	ID    string `json:"id"`
	Bytes int64  `json:"bytes"`
}
