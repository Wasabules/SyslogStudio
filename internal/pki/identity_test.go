package pki

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"os"
	"path/filepath"
	"testing"
	"time"

	"SyslogStudio/internal/models"
)

// servedCertificate returns the certificate a client without SNI would be
// handed, whichever way the config provides it.
func servedCertificate(t *testing.T, cfg *tls.Config) *tls.Certificate {
	t.Helper()
	if cfg.GetCertificate != nil {
		cert, err := cfg.GetCertificate(&tls.ClientHelloInfo{})
		if err != nil {
			t.Fatalf("GetCertificate: %v", err)
		}
		return cert
	}
	if len(cfg.Certificates) == 0 {
		return nil
	}
	return &cfg.Certificates[0]
}

func fingerprint(t *testing.T, cert *tls.Certificate) [32]byte {
	t.Helper()
	if cert == nil || len(cert.Certificate) == 0 {
		t.Fatal("no certificate")
	}
	return sha256.Sum256(cert.Certificate[0])
}

// The defect this guards against: the assistant's CA-signed certificate lived
// in memory only, so after a restart the listener fell back to a fresh
// self-signed one and every client that trusted the CA refused it. Restoring
// the persisted material must bring back the very same certificate.
func TestServerIdentity_SurvivesARestart(t *testing.T) {
	before := NewTLSManager()
	if _, err := before.GenerateCA(models.CertOptions{Algorithm: "ECDSA-P256"}); err != nil {
		t.Fatal(err)
	}
	if _, err := before.GenerateServerCertSignedByCA(models.CertOptions{Algorithm: "ECDSA-P256"}); err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, ok := before.GetServerMaterial()
	if !ok {
		t.Fatal("no server material after generating one")
	}
	cfg, err := before.GetTLSConfig(models.ServerConfig{UseSelfSigned: true})
	if err != nil {
		t.Fatal(err)
	}
	want := fingerprint(t, servedCertificate(t, cfg))

	// "Restart": a fresh manager, restored from what was persisted.
	after := NewTLSManager()
	if err := after.LoadServerMaterial(certPEM, keyPEM); err != nil {
		t.Fatalf("LoadServerMaterial: %v", err)
	}
	cfg, err = after.GetTLSConfig(models.ServerConfig{UseSelfSigned: true})
	if err != nil {
		t.Fatal(err)
	}
	got := servedCertificate(t, cfg)
	if fingerprint(t, got) != want {
		t.Fatal("the restored listener presents a different certificate")
	}
	if got.Leaf == nil || got.Leaf.Issuer.CommonName == got.Leaf.Subject.CommonName {
		t.Error("the restored certificate should still be the CA-signed one, not self-signed")
	}
}

// Every generated identity is reported, so the caller can persist it — and a
// restored one is not, since writing back what was just read is pointless and,
// before an unlock, would overwrite the encrypted copy with a plaintext one.
func TestServerIdentity_GenerationIsReportedRestoreIsNot(t *testing.T) {
	tm := NewTLSManager()
	var reported [][]byte
	tm.SetOnServerCertGenerated(func(certPEM, keyPEM []byte) {
		reported = append(reported, certPEM)
	})

	if _, _, err := tm.GenerateSelfSignedWithOptions(models.CertOptions{Algorithm: "ECDSA-P256"}); err != nil {
		t.Fatal(err)
	}
	if _, err := tm.GenerateCA(models.CertOptions{Algorithm: "ECDSA-P256"}); err != nil {
		t.Fatal(err)
	}
	if _, err := tm.GenerateServerCertSignedByCA(models.CertOptions{Algorithm: "ECDSA-P256"}); err != nil {
		t.Fatal(err)
	}
	if len(reported) != 2 {
		t.Fatalf("reported %d identities, want 2 (self-signed, then CA-signed); the CA is not a server identity", len(reported))
	}

	certPEM, keyPEM, _ := tm.GetServerMaterial()
	if !bytes.Equal(certPEM, reported[1]) {
		t.Error("the last report should be the identity now in use")
	}
	other := NewTLSManager()
	other.SetOnServerCertGenerated(func([]byte, []byte) { t.Error("restoring must not report a generation") })
	if err := other.LoadServerMaterial(certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
}

// When no identity exists yet, starting TLS generates one — and that one is
// reported too, so the certificate a client first meets is the one it keeps
// meeting.
func TestServerIdentity_GeneratedOnFirstStartIsReported(t *testing.T) {
	tm := NewTLSManager()
	var calls int
	tm.SetOnServerCertGenerated(func([]byte, []byte) { calls++ })
	if _, err := tm.GetTLSConfig(models.ServerConfig{UseSelfSigned: true,
		CertOptions: models.CertOptions{Algorithm: "ECDSA-P256"}}); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("first start reported %d generations, want 1", calls)
	}
	if _, err := tm.GetTLSConfig(models.ServerConfig{UseSelfSigned: true}); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatal("a second start must reuse the identity, not make another")
	}
}

func TestLoadServerMaterial_RejectsAMismatchedPair(t *testing.T) {
	a := NewTLSManager()
	b := NewTLSManager()
	if _, _, err := a.GenerateSelfSignedWithOptions(models.CertOptions{Algorithm: "ECDSA-P256"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.GenerateSelfSignedWithOptions(models.CertOptions{Algorithm: "ECDSA-P256"}); err != nil {
		t.Fatal(err)
	}
	certA, _, _ := a.GetServerMaterial()
	_, keyB, _ := b.GetServerMaterial()

	tm := NewTLSManager()
	if err := tm.LoadServerMaterial(certA, keyB); err == nil {
		t.Fatal("a certificate with someone else's key must be refused")
	}
	if tm.HasServerCert() {
		t.Error("a refused pair must not be installed")
	}
}

// writePair generates a self-signed pair and writes it where the listener will
// read it, with a modification time the test controls.
func writePair(t *testing.T, certPath, keyPath string, mod time.Time) [32]byte {
	t.Helper()
	gen := NewTLSManager()
	if _, _, err := gen.GenerateSelfSignedWithOptions(models.CertOptions{Algorithm: "ECDSA-P256"}); err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, _ := gen.GetServerMaterial()
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{certPath, keyPath} {
		if err := os.Chtimes(p, mod, mod); err != nil {
			t.Fatal(err)
		}
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return sha256.Sum256(pair.Certificate[0])
}

// A certificate renewed on disk — by certbot, by a corporate PKI — is served
// without restarting the listener.
func TestFileCertificate_PicksUpARenewal(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	first := writePair(t, certPath, keyPath, time.Now().Add(-time.Hour))

	fc, err := newFileCertificate(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := fc.GetCertificate(nil)
	if fingerprint(t, cert) != first {
		t.Fatal("not serving the files' certificate")
	}

	renewed := writePair(t, certPath, keyPath, time.Now())
	// Within the recheck window nothing is re-read: a handshake does not pay
	// for a stat every time.
	cert, _ = fc.GetCertificate(nil)
	if fingerprint(t, cert) != first {
		t.Fatal("re-read the files inside the recheck window")
	}

	fc.mu.Lock()
	fc.checked = time.Now().Add(-2 * fileCertRecheck)
	fc.mu.Unlock()
	cert, _ = fc.GetCertificate(nil)
	if fingerprint(t, cert) != renewed {
		t.Fatal("a renewed certificate was not picked up")
	}
}

// A renewal caught half-written — new certificate, old key — must not take the
// listener down: the previous pair stays in service until the files agree.
func TestFileCertificate_KeepsServingThroughAHalfWrittenRenewal(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	first := writePair(t, certPath, keyPath, time.Now().Add(-time.Hour))
	fc, err := newFileCertificate(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}

	// Only the certificate has been replaced so far.
	other := filepath.Join(dir, "other")
	if err := os.MkdirAll(other, 0700); err != nil {
		t.Fatal(err)
	}
	writePair(t, filepath.Join(other, "cert.pem"), filepath.Join(other, "key.pem"), time.Now())
	newCert, err := os.ReadFile(filepath.Join(other, "cert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, newCert, 0644); err != nil {
		t.Fatal(err)
	}

	fc.mu.Lock()
	fc.checked = time.Now().Add(-2 * fileCertRecheck)
	fc.mu.Unlock()
	cert, err := fc.GetCertificate(nil)
	if err != nil || cert == nil {
		t.Fatalf("a half-written renewal broke the handshake: %v", err)
	}
	if fingerprint(t, cert) != first {
		t.Fatal("served a pair that does not match")
	}
}
