package syslog

import (
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"SyslogStudio/internal/event"
	"SyslogStudio/internal/models"
	"SyslogStudio/internal/pki"
)

// A certificate given as files is served through GetCertificate, so it can be
// renewed on disk. This drives a real listener the way a syslog sender does —
// by address, with no SNI — because that is the case crypto/tls would answer
// from a static certificate list instead, and the reason that list is empty.
func TestTLSListener_ServesFileCertificateWithoutSNI(t *testing.T) {
	gen := pki.NewTLSManager()
	if _, _, err := gen.GenerateSelfSignedWithOptions(models.CertOptions{
		Algorithm: "ECDSA-P256", IPAddresses: []string{"127.0.0.1"},
	}); err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, _ := gen.GetServerMaterial()
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(pair.Certificate[0])

	s := NewSyslogServer(event.NewMockEventEmitter(), pki.NewTLSManager())
	cfg := models.DefaultServerConfig()
	cfg.UDPEnabled, cfg.TCPEnabled, cfg.TLSEnabled = false, false, true
	cfg.BindAddress = "127.0.0.1"
	cfg.TLSPort = freeTCPPort(t)
	cfg.UseSelfSigned = false
	cfg.CertFile, cfg.KeyFile = certPath, keyPath
	if err := s.Start(cfg); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer s.Stop()

	// Dialled by IP literal, so the client sends no server name.
	conn, err := tls.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", cfg.TLSPort),
		&tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	defer conn.Close()

	peer := conn.ConnectionState().PeerCertificates
	if len(peer) == 0 || sha256.Sum256(peer[0].Raw) != want {
		t.Fatal("the listener did not present the certificate from the files")
	}

	if _, err := conn.Write([]byte("<134>1 2026-03-17T21:42:10Z web-1 sshd 4242 - - over tls\n")); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if msgs := s.GetMessages(models.FilterCriteria{}); len(msgs) > 0 {
			if msgs[0].Message != "over tls" {
				t.Fatalf("received %q", msgs[0].Message)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("no message arrived over TLS")
}
