package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// 1. GenerateCA
// ---------------------------------------------------------------------------

func TestGenerateCA_DefaultOptions(t *testing.T) {
	tm := NewTLSManager()
	info, err := tm.GenerateCA(CertOptions{})
	if err != nil {
		t.Fatalf("GenerateCA with empty options failed: %v", err)
	}

	// Defaults should be applied
	if !strings.Contains(info.Subject, "Syslog CA") {
		t.Errorf("expected default CN 'Syslog CA' in subject, got %s", info.Subject)
	}
	if !strings.Contains(info.Subject, "SyslogStudio") {
		t.Errorf("expected default org 'SyslogStudio' in subject, got %s", info.Subject)
	}
	if info.Algorithm != "RSA-2048" {
		t.Errorf("expected default algorithm RSA-2048, got %s", info.Algorithm)
	}
	if !info.IsSelfSigned {
		t.Error("CA certificate should be self-signed")
	}
	if !info.IsValid {
		t.Error("CA certificate should be valid right after generation")
	}
	if info.IsExpired {
		t.Error("CA certificate should not be expired right after generation")
	}
}

func TestGenerateCA_RespectsOptions(t *testing.T) {
	tests := []struct {
		name      string
		opts      CertOptions
		wantCN    string
		wantOrg   string
		wantAlgo  string
	}{
		{
			name: "ECDSA-P256 custom",
			opts: CertOptions{
				Algorithm:    "ECDSA-P256",
				ValidityDays: 30,
				CommonName:   "My CA",
				Organization: "MyOrg",
			},
			wantCN:   "My CA",
			wantOrg:  "MyOrg",
			wantAlgo: "ECDSA-P256",
		},
		{
			name: "RSA-4096 custom",
			opts: CertOptions{
				Algorithm:    "RSA-4096",
				ValidityDays: 730,
				CommonName:   "Big RSA CA",
				Organization: "BigOrg",
			},
			wantCN:   "Big RSA CA",
			wantOrg:  "BigOrg",
			wantAlgo: "RSA-4096",
		},
		{
			name: "ECDSA-P384 custom",
			opts: CertOptions{
				Algorithm:    "ECDSA-P384",
				ValidityDays: 100,
				CommonName:   "P384 CA",
				Organization: "P384Org",
			},
			wantCN:   "P384 CA",
			wantOrg:  "P384Org",
			wantAlgo: "ECDSA-P384",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tm := NewTLSManager()
			info, err := tm.GenerateCA(tc.opts)
			if err != nil {
				t.Fatalf("GenerateCA failed: %v", err)
			}
			if !strings.Contains(info.Subject, tc.wantCN) {
				t.Errorf("subject %q does not contain CN %q", info.Subject, tc.wantCN)
			}
			if !strings.Contains(info.Subject, tc.wantOrg) {
				t.Errorf("subject %q does not contain org %q", info.Subject, tc.wantOrg)
			}
			if info.Algorithm != tc.wantAlgo {
				t.Errorf("expected algorithm %s, got %s", tc.wantAlgo, info.Algorithm)
			}
			if !info.IsSelfSigned {
				t.Error("CA should be self-signed")
			}
		})
	}
}

func TestGenerateCA_ValidityDates(t *testing.T) {
	tm := NewTLSManager()
	days := 10
	info, err := tm.GenerateCA(CertOptions{ValidityDays: days})
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	notBefore, err := time.Parse("2006-01-02 15:04:05", info.NotBefore)
	if err != nil {
		t.Fatalf("failed to parse NotBefore: %v", err)
	}
	notAfter, err := time.Parse("2006-01-02 15:04:05", info.NotAfter)
	if err != nil {
		t.Fatalf("failed to parse NotAfter: %v", err)
	}

	duration := notAfter.Sub(notBefore)
	expectedDuration := time.Duration(days) * 24 * time.Hour
	// Allow a small tolerance (1 second)
	if diff := duration - expectedDuration; diff < -time.Second || diff > time.Second {
		t.Errorf("expected validity of %v, got %v", expectedDuration, duration)
	}
}

func TestGenerateCA_ProducesValidX509(t *testing.T) {
	tm := NewTLSManager()
	_, err := tm.GenerateCA(CertOptions{Algorithm: "RSA-2048"})
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	// The PEM should be parseable as a valid CA certificate.
	tm.mu.Lock()
	certPEM := tm.caCertPEM
	tm.mu.Unlock()

	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("failed to decode CA cert PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse CA cert: %v", err)
	}
	if !cert.IsCA {
		t.Error("certificate should have IsCA=true")
	}
	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("CA should have KeyUsageCertSign")
	}
}

// ---------------------------------------------------------------------------
// 2. GenerateServerCertSignedByCA
// ---------------------------------------------------------------------------

func TestGenerateServerCertSignedByCA_NoCA(t *testing.T) {
	tm := NewTLSManager()
	_, err := tm.GenerateServerCertSignedByCA(CertOptions{})
	if err == nil {
		t.Fatal("expected error when no CA exists, got nil")
	}
	if !strings.Contains(err.Error(), "no CA certificate") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestGenerateServerCertSignedByCA_Success(t *testing.T) {
	tm := NewTLSManager()
	_, err := tm.GenerateCA(CertOptions{Algorithm: "ECDSA-P256"})
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	info, err := tm.GenerateServerCertSignedByCA(CertOptions{
		Algorithm:    "ECDSA-P256",
		ValidityDays: 90,
		CommonName:   "myserver",
		Organization: "TestOrg",
		DNSNames:     []string{"myserver.local", "localhost"},
		IPAddresses:  []string{"10.0.0.1", "::1"},
	})
	if err != nil {
		t.Fatalf("GenerateServerCertSignedByCA failed: %v", err)
	}

	if !strings.Contains(info.Subject, "myserver") {
		t.Errorf("expected CN myserver in subject, got %s", info.Subject)
	}
	// The cert is signed by CA, so issuer != subject (CA CN is different from server CN)
	if info.IsSelfSigned {
		t.Error("server cert signed by CA should not be self-signed")
	}
	if !info.IsValid {
		t.Error("server cert should be valid")
	}

	// Check SAN DNS names
	for _, dns := range []string{"myserver.local", "localhost"} {
		found := false
		for _, d := range info.DNSNames {
			if d == dns {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected DNS name %s in cert, got %v", dns, info.DNSNames)
		}
	}

	// Check SAN IP addresses
	for _, ip := range []string{"10.0.0.1", "::1"} {
		found := false
		for _, i := range info.IPAddresses {
			if i == ip {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected IP %s in cert, got %v", ip, info.IPAddresses)
		}
	}
}

func TestGenerateServerCertSignedByCA_VerifiableByCA(t *testing.T) {
	tm := NewTLSManager()
	_, err := tm.GenerateCA(CertOptions{Algorithm: "RSA-2048"})
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	_, err = tm.GenerateServerCertSignedByCA(CertOptions{
		Algorithm: "RSA-2048",
		DNSNames:  []string{"localhost"},
	})
	if err != nil {
		t.Fatalf("GenerateServerCertSignedByCA failed: %v", err)
	}

	// Parse CA cert
	tm.mu.Lock()
	caCertPEM := tm.caCertPEM
	serverCertPEM := tm.serverCertPEM
	tm.mu.Unlock()

	caBlock, _ := pem.Decode(caCertPEM)
	caCert, _ := x509.ParseCertificate(caBlock.Bytes)

	serverBlock, _ := pem.Decode(serverCertPEM)
	serverCert, _ := x509.ParseCertificate(serverBlock.Bytes)

	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	_, err = serverCert.Verify(x509.VerifyOptions{
		Roots:     pool,
		DNSName:   "localhost",
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		t.Fatalf("server cert should verify against CA: %v", err)
	}
}

func TestGenerateServerCertSignedByCA_Defaults(t *testing.T) {
	tm := NewTLSManager()
	_, err := tm.GenerateCA(CertOptions{})
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	info, err := tm.GenerateServerCertSignedByCA(CertOptions{})
	if err != nil {
		t.Fatalf("GenerateServerCertSignedByCA with empty opts failed: %v", err)
	}

	if !strings.Contains(info.Subject, "SyslogStudio Server") {
		t.Errorf("expected default CN 'SyslogStudio Server' in subject, got %s", info.Subject)
	}
	if info.Algorithm != "RSA-2048" {
		t.Errorf("expected default algorithm RSA-2048, got %s", info.Algorithm)
	}
}

// ---------------------------------------------------------------------------
// 3. GenerateSelfSignedWithOptions
// ---------------------------------------------------------------------------

func TestGenerateSelfSignedWithOptions_Defaults(t *testing.T) {
	tm := NewTLSManager()
	tlsConfig, info, err := tm.GenerateSelfSignedWithOptions(CertOptions{})
	if err != nil {
		t.Fatalf("GenerateSelfSignedWithOptions failed: %v", err)
	}
	if tlsConfig == nil {
		t.Fatal("expected non-nil TLS config")
	}
	if len(tlsConfig.Certificates) == 0 {
		t.Fatal("expected at least one certificate in TLS config")
	}
	if tlsConfig.MinVersion != tls.VersionTLS12 {
		t.Errorf("expected MinVersion TLS 1.2, got %d", tlsConfig.MinVersion)
	}
	if info.Algorithm != "ECDSA-P256" {
		t.Errorf("expected default algorithm ECDSA-P256, got %s", info.Algorithm)
	}
	if !info.IsSelfSigned {
		t.Error("self-signed cert should report IsSelfSigned=true")
	}
	if !info.IsValid {
		t.Error("cert should be valid right after generation")
	}
	// Defaults: localhost DNS, 127.0.0.1 and ::1 IPs
	if len(info.DNSNames) == 0 || info.DNSNames[0] != "localhost" {
		t.Errorf("expected default DNS name 'localhost', got %v", info.DNSNames)
	}
}

func TestGenerateSelfSignedWithOptions_CustomOptions(t *testing.T) {
	tm := NewTLSManager()
	opts := CertOptions{
		Algorithm:    "RSA-4096",
		ValidityDays: 7,
		CommonName:   "TestServer",
		Organization: "TestOrg",
		DNSNames:     []string{"test.example.com"},
		IPAddresses:  []string{"192.168.1.1"},
	}
	tlsConfig, info, err := tm.GenerateSelfSignedWithOptions(opts)
	if err != nil {
		t.Fatalf("GenerateSelfSignedWithOptions failed: %v", err)
	}
	if tlsConfig == nil {
		t.Fatal("expected non-nil TLS config")
	}
	if info.Algorithm != "RSA-4096" {
		t.Errorf("expected RSA-4096, got %s", info.Algorithm)
	}
	if !strings.Contains(info.Subject, "TestServer") {
		t.Errorf("expected CN TestServer in subject, got %s", info.Subject)
	}
	found := false
	for _, d := range info.DNSNames {
		if d == "test.example.com" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected DNS name test.example.com, got %v", info.DNSNames)
	}
}

func TestGenerateSelfSignedWithOptions_StoresCertInManager(t *testing.T) {
	tm := NewTLSManager()
	_, _, err := tm.GenerateSelfSignedWithOptions(CertOptions{})
	if err != nil {
		t.Fatalf("GenerateSelfSignedWithOptions failed: %v", err)
	}
	if !tm.HasServerCert() {
		t.Error("after GenerateSelfSignedWithOptions, HasServerCert should be true")
	}
}

// ---------------------------------------------------------------------------
// 4. HasCA / HasServerCert
// ---------------------------------------------------------------------------

func TestHasCA_InitiallyFalse(t *testing.T) {
	tm := NewTLSManager()
	if tm.HasCA() {
		t.Error("HasCA should be false on fresh manager")
	}
}

func TestHasCA_TrueAfterGeneration(t *testing.T) {
	tm := NewTLSManager()
	_, err := tm.GenerateCA(CertOptions{})
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}
	if !tm.HasCA() {
		t.Error("HasCA should be true after GenerateCA")
	}
}

func TestHasServerCert_InitiallyFalse(t *testing.T) {
	tm := NewTLSManager()
	if tm.HasServerCert() {
		t.Error("HasServerCert should be false on fresh manager")
	}
}

func TestHasServerCert_TrueAfterGeneration(t *testing.T) {
	tm := NewTLSManager()
	_, err := tm.GenerateCA(CertOptions{})
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}
	_, err = tm.GenerateServerCertSignedByCA(CertOptions{})
	if err != nil {
		t.Fatalf("GenerateServerCertSignedByCA failed: %v", err)
	}
	if !tm.HasServerCert() {
		t.Error("HasServerCert should be true after GenerateServerCertSignedByCA")
	}
}

func TestHasServerCert_TrueAfterSelfSigned(t *testing.T) {
	tm := NewTLSManager()
	_, _, err := tm.GenerateSelfSignedWithOptions(CertOptions{})
	if err != nil {
		t.Fatalf("GenerateSelfSignedWithOptions failed: %v", err)
	}
	if !tm.HasServerCert() {
		t.Error("HasServerCert should be true after GenerateSelfSignedWithOptions")
	}
}

// ---------------------------------------------------------------------------
// 5. GetCACertificateInfo / GetServerCertificateInfo
// ---------------------------------------------------------------------------

func TestGetCACertificateInfo_ErrorWhenNoCert(t *testing.T) {
	tm := NewTLSManager()
	_, err := tm.GetCACertificateInfo()
	if err == nil {
		t.Fatal("expected error when no CA cert exists")
	}
	if !strings.Contains(err.Error(), "no CA certificate") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestGetCACertificateInfo_ReturnsValidInfo(t *testing.T) {
	tm := NewTLSManager()
	_, err := tm.GenerateCA(CertOptions{
		CommonName:   "InfoTest CA",
		Organization: "InfoTestOrg",
		Algorithm:    "ECDSA-P384",
	})
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	info, err := tm.GetCACertificateInfo()
	if err != nil {
		t.Fatalf("GetCACertificateInfo failed: %v", err)
	}
	if !strings.Contains(info.Subject, "InfoTest CA") {
		t.Errorf("unexpected subject: %s", info.Subject)
	}
	if info.SHA256Fingerprint == "" {
		t.Error("fingerprint should not be empty")
	}
	if info.SerialNumber == "" {
		t.Error("serial number should not be empty")
	}
	if !info.IsSelfSigned {
		t.Error("CA should be self-signed")
	}
}

func TestGetServerCertificateInfo_ErrorWhenNoCert(t *testing.T) {
	tm := NewTLSManager()
	_, err := tm.GetServerCertificateInfo()
	if err == nil {
		t.Fatal("expected error when no server cert exists")
	}
	if !strings.Contains(err.Error(), "no server certificate") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestGetServerCertificateInfo_ReturnsValidInfo(t *testing.T) {
	tm := NewTLSManager()
	_, err := tm.GenerateCA(CertOptions{})
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}
	_, err = tm.GenerateServerCertSignedByCA(CertOptions{
		CommonName: "ServerInfoTest",
		DNSNames:   []string{"srv.local"},
	})
	if err != nil {
		t.Fatalf("GenerateServerCertSignedByCA failed: %v", err)
	}

	info, err := tm.GetServerCertificateInfo()
	if err != nil {
		t.Fatalf("GetServerCertificateInfo failed: %v", err)
	}
	if !strings.Contains(info.Subject, "ServerInfoTest") {
		t.Errorf("unexpected subject: %s", info.Subject)
	}
	if info.SHA256Fingerprint == "" {
		t.Error("fingerprint should not be empty")
	}
	if !info.IsValid {
		t.Error("server cert should be valid")
	}
}

// ---------------------------------------------------------------------------
// 6. SaveCACertificateToFile / SaveServerCertificateToFile
// ---------------------------------------------------------------------------

func TestSaveCACertificateToFile_NoCA(t *testing.T) {
	tm := NewTLSManager()
	tmpDir := t.TempDir()
	err := tm.SaveCACertificateToFile(filepath.Join(tmpDir, "ca.pem"))
	if err == nil {
		t.Fatal("expected error when no CA exists")
	}
}

func TestSaveCACertificateToFile_WritesFile(t *testing.T) {
	tm := NewTLSManager()
	_, err := tm.GenerateCA(CertOptions{})
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "ca.pem")
	err = tm.SaveCACertificateToFile(certPath)
	if err != nil {
		t.Fatalf("SaveCACertificateToFile failed: %v", err)
	}

	data, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("failed to read saved CA file: %v", err)
	}
	if len(data) == 0 {
		t.Error("saved CA file should not be empty")
	}

	// Should be valid PEM
	block, _ := pem.Decode(data)
	if block == nil {
		t.Error("saved file should contain valid PEM data")
	}
	if block.Type != "CERTIFICATE" {
		t.Errorf("expected PEM type CERTIFICATE, got %s", block.Type)
	}
}

func TestSaveServerCertificateToFile_NoCert(t *testing.T) {
	tm := NewTLSManager()
	tmpDir := t.TempDir()
	err := tm.SaveServerCertificateToFile(
		filepath.Join(tmpDir, "server.pem"),
		filepath.Join(tmpDir, "server-key.pem"),
	)
	if err == nil {
		t.Fatal("expected error when no server cert exists")
	}
}

func TestSaveServerCertificateToFile_WritesFiles(t *testing.T) {
	tm := NewTLSManager()
	_, err := tm.GenerateCA(CertOptions{})
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}
	_, err = tm.GenerateServerCertSignedByCA(CertOptions{})
	if err != nil {
		t.Fatalf("GenerateServerCertSignedByCA failed: %v", err)
	}

	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "server.pem")
	keyPath := filepath.Join(tmpDir, "server-key.pem")
	err = tm.SaveServerCertificateToFile(certPath, keyPath)
	if err != nil {
		t.Fatalf("SaveServerCertificateToFile failed: %v", err)
	}

	// Verify cert file
	certData, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("failed to read cert file: %v", err)
	}
	block, _ := pem.Decode(certData)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Error("cert file should contain a valid CERTIFICATE PEM block")
	}

	// Verify key file
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("failed to read key file: %v", err)
	}
	keyBlock, _ := pem.Decode(keyData)
	if keyBlock == nil {
		t.Error("key file should contain a valid PEM block")
	}
	if keyBlock.Type != "RSA PRIVATE KEY" && keyBlock.Type != "EC PRIVATE KEY" {
		t.Errorf("unexpected key PEM type: %s", keyBlock.Type)
	}

	// Verify key file permissions (on non-Windows)
	// On Windows, os.FileMode for permissions behaves differently,
	// so we just verify the files exist and are non-empty.
	if len(certData) == 0 {
		t.Error("cert file should not be empty")
	}
	if len(keyData) == 0 {
		t.Error("key file should not be empty")
	}
}

func TestSaveServerCertificateToFile_LoadableByTLS(t *testing.T) {
	tm := NewTLSManager()
	_, err := tm.GenerateCA(CertOptions{Algorithm: "RSA-2048"})
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}
	_, err = tm.GenerateServerCertSignedByCA(CertOptions{Algorithm: "RSA-2048"})
	if err != nil {
		t.Fatalf("GenerateServerCertSignedByCA failed: %v", err)
	}

	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "server.pem")
	keyPath := filepath.Join(tmpDir, "server-key.pem")
	if err := tm.SaveServerCertificateToFile(certPath, keyPath); err != nil {
		t.Fatalf("SaveServerCertificateToFile failed: %v", err)
	}

	// Should be loadable as a TLS certificate
	_, err = tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatalf("saved cert/key should be loadable as X509 key pair: %v", err)
	}
}

// ---------------------------------------------------------------------------
// 7. LoadCertificate
// ---------------------------------------------------------------------------

func TestLoadCertificate_LoadsFromFiles(t *testing.T) {
	// First, generate and save a certificate
	tm := NewTLSManager()
	_, _, err := tm.GenerateSelfSignedWithOptions(CertOptions{Algorithm: "ECDSA-P256"})
	if err != nil {
		t.Fatalf("GenerateSelfSignedWithOptions failed: %v", err)
	}

	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "cert.pem")
	keyPath := filepath.Join(tmpDir, "key.pem")

	// Save to disk manually
	tm.mu.Lock()
	certPEM := tm.serverCertPEM
	keyPEM := tm.serverKeyPEM
	tm.mu.Unlock()

	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		t.Fatalf("failed to write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatalf("failed to write key: %v", err)
	}

	// Load into a fresh manager
	tm2 := NewTLSManager()
	if tm2.HasServerCert() {
		t.Error("fresh manager should not have server cert")
	}

	tlsConfig, err := tm2.LoadCertificate(certPath, keyPath)
	if err != nil {
		t.Fatalf("LoadCertificate failed: %v", err)
	}
	if tlsConfig == nil {
		t.Fatal("expected non-nil TLS config")
	}
	if len(tlsConfig.Certificates) == 0 {
		t.Error("TLS config should have at least one certificate")
	}
	if tlsConfig.MinVersion != tls.VersionTLS12 {
		t.Errorf("expected MinVersion TLS 1.2, got %d", tlsConfig.MinVersion)
	}

	// Should now be stored in manager
	if !tm2.HasServerCert() {
		t.Error("after LoadCertificate, HasServerCert should be true")
	}
}

func TestLoadCertificate_FailsWithMissingFiles(t *testing.T) {
	tm := NewTLSManager()
	_, err := tm.LoadCertificate("/nonexistent/cert.pem", "/nonexistent/key.pem")
	if err == nil {
		t.Fatal("expected error for missing files")
	}
}

func TestLoadCertificate_FailsWithMismatchedKeyPair(t *testing.T) {
	// Generate two different certs
	tm1 := NewTLSManager()
	_, _, err := tm1.GenerateSelfSignedWithOptions(CertOptions{Algorithm: "ECDSA-P256", CommonName: "cert1"})
	if err != nil {
		t.Fatalf("first GenerateSelfSignedWithOptions failed: %v", err)
	}
	tm1.mu.Lock()
	cert1PEM := tm1.serverCertPEM
	tm1.mu.Unlock()

	tm2 := NewTLSManager()
	_, _, err = tm2.GenerateSelfSignedWithOptions(CertOptions{Algorithm: "ECDSA-P256", CommonName: "cert2"})
	if err != nil {
		t.Fatalf("second GenerateSelfSignedWithOptions failed: %v", err)
	}
	tm2.mu.Lock()
	key2PEM := tm2.serverKeyPEM
	tm2.mu.Unlock()

	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "cert.pem")
	keyPath := filepath.Join(tmpDir, "key.pem")
	os.WriteFile(certPath, cert1PEM, 0644)
	os.WriteFile(keyPath, key2PEM, 0600)

	tm3 := NewTLSManager()
	_, err = tm3.LoadCertificate(certPath, keyPath)
	if err == nil {
		t.Fatal("expected error for mismatched cert/key")
	}
}

// ---------------------------------------------------------------------------
// 8. GetTLSConfig
// ---------------------------------------------------------------------------

func TestGetTLSConfig_SelfSigned_GeneratesOnTheFly(t *testing.T) {
	tm := NewTLSManager()
	config := ServerConfig{
		UseSelfSigned: true,
		CertOptions:   CertOptions{Algorithm: "ECDSA-P256"},
	}
	tlsConfig, err := tm.GetTLSConfig(config)
	if err != nil {
		t.Fatalf("GetTLSConfig failed: %v", err)
	}
	if tlsConfig == nil {
		t.Fatal("expected non-nil TLS config")
	}
	if len(tlsConfig.Certificates) == 0 {
		t.Error("expected at least one certificate")
	}
}

func TestGetTLSConfig_SelfSigned_UsesExistingCert(t *testing.T) {
	tm := NewTLSManager()
	// Pre-generate
	_, _, err := tm.GenerateSelfSignedWithOptions(CertOptions{Algorithm: "ECDSA-P256"})
	if err != nil {
		t.Fatalf("GenerateSelfSignedWithOptions failed: %v", err)
	}

	config := ServerConfig{
		UseSelfSigned: true,
	}
	tlsConfig, err := tm.GetTLSConfig(config)
	if err != nil {
		t.Fatalf("GetTLSConfig failed: %v", err)
	}
	if tlsConfig == nil {
		t.Fatal("expected non-nil TLS config")
	}
	if len(tlsConfig.Certificates) == 0 {
		t.Error("expected at least one certificate")
	}
}

func TestGetTLSConfig_FromFiles(t *testing.T) {
	// Generate a cert, save to files, load from files
	gen := NewTLSManager()
	_, _, err := gen.GenerateSelfSignedWithOptions(CertOptions{Algorithm: "RSA-2048"})
	if err != nil {
		t.Fatalf("GenerateSelfSignedWithOptions failed: %v", err)
	}

	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "server.pem")
	keyPath := filepath.Join(tmpDir, "server-key.pem")

	gen.mu.Lock()
	os.WriteFile(certPath, gen.serverCertPEM, 0644)
	os.WriteFile(keyPath, gen.serverKeyPEM, 0600)
	gen.mu.Unlock()

	tm := NewTLSManager()
	config := ServerConfig{
		UseSelfSigned: false,
		CertFile:      certPath,
		KeyFile:       keyPath,
	}
	tlsConfig, err := tm.GetTLSConfig(config)
	if err != nil {
		t.Fatalf("GetTLSConfig failed: %v", err)
	}
	if len(tlsConfig.Certificates) == 0 {
		t.Error("expected at least one certificate")
	}
}

func TestGetTLSConfig_RequiresCertAndKeyPaths(t *testing.T) {
	tm := NewTLSManager()
	config := ServerConfig{
		UseSelfSigned: false,
		CertFile:      "",
		KeyFile:       "",
	}
	_, err := tm.GetTLSConfig(config)
	if err == nil {
		t.Fatal("expected error when cert/key paths are empty")
	}
	if !strings.Contains(err.Error(), "required") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestGetTLSConfig_MutualTLS(t *testing.T) {
	// Generate CA and server cert
	tm := NewTLSManager()
	_, err := tm.GenerateCA(CertOptions{Algorithm: "RSA-2048"})
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}
	_, err = tm.GenerateServerCertSignedByCA(CertOptions{Algorithm: "RSA-2048"})
	if err != nil {
		t.Fatalf("GenerateServerCertSignedByCA failed: %v", err)
	}

	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "server.pem")
	keyPath := filepath.Join(tmpDir, "server-key.pem")
	caPath := filepath.Join(tmpDir, "ca.pem")

	if err := tm.SaveServerCertificateToFile(certPath, keyPath); err != nil {
		t.Fatalf("SaveServerCertificateToFile failed: %v", err)
	}
	if err := tm.SaveCACertificateToFile(caPath); err != nil {
		t.Fatalf("SaveCACertificateToFile failed: %v", err)
	}

	// Fresh manager to test from-files + mutual TLS
	tm2 := NewTLSManager()
	config := ServerConfig{
		UseSelfSigned: false,
		CertFile:      certPath,
		KeyFile:       keyPath,
		MutualTLS:     true,
		CAFile:        caPath,
	}
	tlsConfig, err := tm2.GetTLSConfig(config)
	if err != nil {
		t.Fatalf("GetTLSConfig with mutual TLS failed: %v", err)
	}
	if tlsConfig.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("expected ClientAuth RequireAndVerifyClientCert, got %v", tlsConfig.ClientAuth)
	}
	if tlsConfig.ClientCAs == nil {
		t.Error("ClientCAs pool should not be nil for mutual TLS")
	}
}

func TestGetTLSConfig_MutualTLS_BadCAFile(t *testing.T) {
	tm := NewTLSManager()
	_, _, err := tm.GenerateSelfSignedWithOptions(CertOptions{})
	if err != nil {
		t.Fatalf("GenerateSelfSignedWithOptions failed: %v", err)
	}

	config := ServerConfig{
		UseSelfSigned: true,
		MutualTLS:     true,
		CAFile:        "/nonexistent/ca.pem",
	}
	_, err = tm.GetTLSConfig(config)
	if err == nil {
		t.Fatal("expected error for bad CA file path")
	}
}

// ---------------------------------------------------------------------------
// 9. Different algorithms
// ---------------------------------------------------------------------------

func TestAlgorithms_TableDriven(t *testing.T) {
	algorithms := []struct {
		name           string
		algorithm      string
		wantKeySize    string
		wantPEMKeyType string
	}{
		{
			name:           "ECDSA-P256",
			algorithm:      "ECDSA-P256",
			wantKeySize:    "256 bits",
			wantPEMKeyType: "EC PRIVATE KEY",
		},
		{
			name:           "ECDSA-P384",
			algorithm:      "ECDSA-P384",
			wantKeySize:    "384 bits",
			wantPEMKeyType: "EC PRIVATE KEY",
		},
		{
			name:           "RSA-2048",
			algorithm:      "RSA-2048",
			wantKeySize:    "2048 bits",
			wantPEMKeyType: "RSA PRIVATE KEY",
		},
		{
			name:           "RSA-4096",
			algorithm:      "RSA-4096",
			wantKeySize:    "4096 bits",
			wantPEMKeyType: "RSA PRIVATE KEY",
		},
	}

	for _, tc := range algorithms {
		t.Run(tc.name+"_CA", func(t *testing.T) {
			tm := NewTLSManager()
			info, err := tm.GenerateCA(CertOptions{Algorithm: tc.algorithm})
			if err != nil {
				t.Fatalf("GenerateCA with %s failed: %v", tc.algorithm, err)
			}
			if info.Algorithm != tc.algorithm {
				t.Errorf("expected algorithm %s, got %s", tc.algorithm, info.Algorithm)
			}
			// Verify key PEM type
			tm.mu.Lock()
			keyPEM := tm.caKeyPEM
			tm.mu.Unlock()
			block, _ := pem.Decode(keyPEM)
			if block == nil {
				t.Fatal("failed to decode key PEM")
			}
			if block.Type != tc.wantPEMKeyType {
				t.Errorf("expected key PEM type %s, got %s", tc.wantPEMKeyType, block.Type)
			}
		})

		t.Run(tc.name+"_SelfSigned", func(t *testing.T) {
			tm := NewTLSManager()
			_, info, err := tm.GenerateSelfSignedWithOptions(CertOptions{Algorithm: tc.algorithm})
			if err != nil {
				t.Fatalf("GenerateSelfSignedWithOptions with %s failed: %v", tc.algorithm, err)
			}
			if info.Algorithm != tc.algorithm {
				t.Errorf("expected algorithm %s, got %s", tc.algorithm, info.Algorithm)
			}
			if info.KeySize != tc.wantKeySize {
				t.Errorf("expected key size %s, got %s", tc.wantKeySize, info.KeySize)
			}
		})

		t.Run(tc.name+"_ServerCertSignedByCA", func(t *testing.T) {
			tm := NewTLSManager()
			_, err := tm.GenerateCA(CertOptions{Algorithm: tc.algorithm})
			if err != nil {
				t.Fatalf("GenerateCA failed: %v", err)
			}
			info, err := tm.GenerateServerCertSignedByCA(CertOptions{Algorithm: tc.algorithm})
			if err != nil {
				t.Fatalf("GenerateServerCertSignedByCA with %s failed: %v", tc.algorithm, err)
			}
			if info.Algorithm != tc.algorithm {
				t.Errorf("expected algorithm %s, got %s", tc.algorithm, info.Algorithm)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 10. buildCertInfoFromX509
// ---------------------------------------------------------------------------

func TestBuildCertInfoFromX509_CorrectFingerprint(t *testing.T) {
	tm := NewTLSManager()
	_, _, err := tm.GenerateSelfSignedWithOptions(CertOptions{Algorithm: "ECDSA-P256"})
	if err != nil {
		t.Fatalf("GenerateSelfSignedWithOptions failed: %v", err)
	}

	tm.mu.Lock()
	certPEM := tm.serverCertPEM
	tm.mu.Unlock()

	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse cert: %v", err)
	}

	info := tm.buildCertInfoFromX509(cert)

	// Manually compute fingerprint
	fingerprint := sha256.Sum256(cert.Raw)
	fpHex := fmt.Sprintf("%X", fingerprint)
	var fpParts []string
	for i := 0; i < len(fpHex); i += 2 {
		end := i + 2
		if end > len(fpHex) {
			end = len(fpHex)
		}
		fpParts = append(fpParts, fpHex[i:end])
	}
	expectedFP := strings.Join(fpParts, ":")

	if info.SHA256Fingerprint != expectedFP {
		t.Errorf("fingerprint mismatch:\n  got:  %s\n  want: %s", info.SHA256Fingerprint, expectedFP)
	}
}

func TestBuildCertInfoFromX509_Dates(t *testing.T) {
	tm := NewTLSManager()

	// Create a cert with known validity
	// x509 certificates store times in UTC, so use UTC for comparison.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now().UTC()
	notBefore := now.Truncate(time.Second)
	notAfter := notBefore.Add(30 * 24 * time.Hour)

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "DateTest",
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create cert: %v", err)
	}
	cert, _ := x509.ParseCertificate(certDER)

	info := tm.buildCertInfoFromX509(cert)

	expectedNotBefore := notBefore.Format("2006-01-02 15:04:05")
	expectedNotAfter := notAfter.Format("2006-01-02 15:04:05")
	if info.NotBefore != expectedNotBefore {
		t.Errorf("NotBefore mismatch: got %s, want %s", info.NotBefore, expectedNotBefore)
	}
	if info.NotAfter != expectedNotAfter {
		t.Errorf("NotAfter mismatch: got %s, want %s", info.NotAfter, expectedNotAfter)
	}
}

func TestBuildCertInfoFromX509_AlgorithmDetection(t *testing.T) {
	tests := []struct {
		name      string
		genKey    func() (interface{}, interface{}) // returns (private, public)
		wantAlgo  string
		wantSize  string
	}{
		{
			name: "ECDSA-P256",
			genKey: func() (interface{}, interface{}) {
				key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				return key, &key.PublicKey
			},
			wantAlgo: "ECDSA-P-256",
			wantSize: "256 bits",
		},
		{
			name: "ECDSA-P384",
			genKey: func() (interface{}, interface{}) {
				key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				return key, &key.PublicKey
			},
			wantAlgo: "ECDSA-P-384",
			wantSize: "384 bits",
		},
		{
			name: "RSA-2048",
			genKey: func() (interface{}, interface{}) {
				key, _ := rsa.GenerateKey(rand.Reader, 2048)
				return key, &key.PublicKey
			},
			wantAlgo: "RSA",
			wantSize: "2048 bits",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tm := NewTLSManager()
			privKey, pubKey := tc.genKey()

			serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
			template := x509.Certificate{
				SerialNumber: serialNumber,
				Subject:      pkix.Name{CommonName: "AlgoTest"},
				NotBefore:    time.Now(),
				NotAfter:     time.Now().Add(24 * time.Hour),
			}

			certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, pubKey, privKey)
			if err != nil {
				t.Fatalf("failed to create cert: %v", err)
			}
			cert, _ := x509.ParseCertificate(certDER)

			info := tm.buildCertInfoFromX509(cert)
			if info.Algorithm != tc.wantAlgo {
				t.Errorf("expected algorithm %s, got %s", tc.wantAlgo, info.Algorithm)
			}
			if info.KeySize != tc.wantSize {
				t.Errorf("expected key size %s, got %s", tc.wantSize, info.KeySize)
			}
		})
	}
}

func TestBuildCertInfoFromX509_SelfSignedDetection(t *testing.T) {
	tm := NewTLSManager()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	// Self-signed: issuer == subject
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: "SelfSigned"},
		Issuer:       pkix.Name{CommonName: "SelfSigned"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	info := tm.buildCertInfoFromX509(cert)
	if !info.IsSelfSigned {
		t.Error("cert with matching issuer/subject CN should be detected as self-signed")
	}
}

func TestBuildCertInfoFromX509_IsExpired(t *testing.T) {
	tm := NewTLSManager()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	// Expired cert
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: "Expired"},
		NotBefore:    time.Now().Add(-48 * time.Hour),
		NotAfter:     time.Now().Add(-24 * time.Hour),
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	info := tm.buildCertInfoFromX509(cert)
	if !info.IsExpired {
		t.Error("expired cert should have IsExpired=true")
	}
	if info.IsValid {
		t.Error("expired cert should have IsValid=false")
	}
}

func TestBuildCertInfoFromX509_NotYetValid(t *testing.T) {
	tm := NewTLSManager()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	// Future cert
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: "FutureCert"},
		NotBefore:    time.Now().Add(24 * time.Hour),
		NotAfter:     time.Now().Add(48 * time.Hour),
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	info := tm.buildCertInfoFromX509(cert)
	if info.IsValid {
		t.Error("not-yet-valid cert should have IsValid=false")
	}
	if info.IsExpired {
		t.Error("not-yet-valid cert should not be expired")
	}
}

func TestBuildCertInfoFromX509_DNSAndIPAddresses(t *testing.T) {
	tm := NewTLSManager()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: "SANTest"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"foo.example.com", "bar.example.com"},
		IPAddresses:  []net.IP{net.ParseIP("10.0.0.1"), net.ParseIP("::1")},
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	info := tm.buildCertInfoFromX509(cert)
	if len(info.DNSNames) != 2 {
		t.Errorf("expected 2 DNS names, got %d: %v", len(info.DNSNames), info.DNSNames)
	}
	if len(info.IPAddresses) != 2 {
		t.Errorf("expected 2 IP addresses, got %d: %v", len(info.IPAddresses), info.IPAddresses)
	}
	// Verify specific values
	foundDNS := map[string]bool{}
	for _, d := range info.DNSNames {
		foundDNS[d] = true
	}
	if !foundDNS["foo.example.com"] || !foundDNS["bar.example.com"] {
		t.Errorf("expected foo.example.com and bar.example.com in DNS names, got %v", info.DNSNames)
	}
	foundIP := map[string]bool{}
	for _, ip := range info.IPAddresses {
		foundIP[ip] = true
	}
	if !foundIP["10.0.0.1"] {
		t.Errorf("expected 10.0.0.1 in IP addresses, got %v", info.IPAddresses)
	}
	// ::1 may be stored as "::1" -- check
	hasIPv6 := false
	for _, ip := range info.IPAddresses {
		if ip == "::1" {
			hasIPv6 = true
		}
	}
	if !hasIPv6 {
		t.Errorf("expected ::1 in IP addresses, got %v", info.IPAddresses)
	}
}

// ---------------------------------------------------------------------------
// Additional: LoadCACertificateFromFile
// ---------------------------------------------------------------------------

func TestLoadCACertificateFromFile(t *testing.T) {
	tm := NewTLSManager()
	_, err := tm.GenerateCA(CertOptions{Algorithm: "ECDSA-P256"})
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	tmpDir := t.TempDir()
	caPath := filepath.Join(tmpDir, "ca.pem")
	if err := tm.SaveCACertificateToFile(caPath); err != nil {
		t.Fatalf("SaveCACertificateToFile failed: %v", err)
	}

	pool, err := tm.LoadCACertificateFromFile(caPath)
	if err != nil {
		t.Fatalf("LoadCACertificateFromFile failed: %v", err)
	}
	if pool == nil {
		t.Error("expected non-nil cert pool")
	}
}

func TestLoadCACertificateFromFile_InvalidFile(t *testing.T) {
	tm := NewTLSManager()
	tmpDir := t.TempDir()
	badPath := filepath.Join(tmpDir, "bad.pem")
	os.WriteFile(badPath, []byte("not a real PEM"), 0644)

	_, err := tm.LoadCACertificateFromFile(badPath)
	if err == nil {
		t.Fatal("expected error for invalid PEM file")
	}
}

func TestLoadCACertificateFromFile_MissingFile(t *testing.T) {
	tm := NewTLSManager()
	_, err := tm.LoadCACertificateFromFile("/nonexistent/ca.pem")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

// ---------------------------------------------------------------------------
// Additional: GetCertificateInfo (config-based)
// ---------------------------------------------------------------------------

func TestGetCertificateInfo_SelfSigned(t *testing.T) {
	tm := NewTLSManager()
	_, _, err := tm.GenerateSelfSignedWithOptions(CertOptions{CommonName: "CertInfoTest"})
	if err != nil {
		t.Fatalf("GenerateSelfSignedWithOptions failed: %v", err)
	}

	info, err := tm.GetCertificateInfo(ServerConfig{UseSelfSigned: true})
	if err != nil {
		t.Fatalf("GetCertificateInfo failed: %v", err)
	}
	if !strings.Contains(info.Subject, "CertInfoTest") {
		t.Errorf("unexpected subject: %s", info.Subject)
	}
}

func TestGetCertificateInfo_NoCert(t *testing.T) {
	tm := NewTLSManager()
	_, err := tm.GetCertificateInfo(ServerConfig{UseSelfSigned: true})
	if err == nil {
		t.Fatal("expected error when no cert exists")
	}
}

func TestGetCertificateInfo_FromFile(t *testing.T) {
	gen := NewTLSManager()
	_, _, err := gen.GenerateSelfSignedWithOptions(CertOptions{Algorithm: "RSA-2048", CommonName: "FileInfoTest"})
	if err != nil {
		t.Fatalf("GenerateSelfSignedWithOptions failed: %v", err)
	}

	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "cert.pem")
	keyPath := filepath.Join(tmpDir, "key.pem")

	gen.mu.Lock()
	os.WriteFile(certPath, gen.serverCertPEM, 0644)
	os.WriteFile(keyPath, gen.serverKeyPEM, 0600)
	gen.mu.Unlock()

	tm := NewTLSManager()
	info, err := tm.GetCertificateInfo(ServerConfig{
		UseSelfSigned: false,
		CertFile:      certPath,
	})
	if err != nil {
		t.Fatalf("GetCertificateInfo from file failed: %v", err)
	}
	if !strings.Contains(info.Subject, "FileInfoTest") {
		t.Errorf("unexpected subject: %s", info.Subject)
	}
}

func TestGetCertificateInfo_NoCertFile(t *testing.T) {
	tm := NewTLSManager()
	_, err := tm.GetCertificateInfo(ServerConfig{UseSelfSigned: false, CertFile: ""})
	if err == nil {
		t.Fatal("expected error when no cert file specified")
	}
}

// ---------------------------------------------------------------------------
// Additional: parsePrivateKey
// ---------------------------------------------------------------------------

func TestParsePrivateKey_RSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	pemBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	parsed, err := parsePrivateKey(pemBlock)
	if err != nil {
		t.Fatalf("parsePrivateKey failed: %v", err)
	}
	if _, ok := parsed.(*rsa.PrivateKey); !ok {
		t.Errorf("expected *rsa.PrivateKey, got %T", parsed)
	}
}

func TestParsePrivateKey_ECDSA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("failed to marshal EC key: %v", err)
	}
	pemBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: der,
	})
	parsed, err := parsePrivateKey(pemBlock)
	if err != nil {
		t.Fatalf("parsePrivateKey failed: %v", err)
	}
	if _, ok := parsed.(*ecdsa.PrivateKey); !ok {
		t.Errorf("expected *ecdsa.PrivateKey, got %T", parsed)
	}
}

func TestParsePrivateKey_PKCS8(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("failed to marshal PKCS8: %v", err)
	}
	pemBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	})
	parsed, err := parsePrivateKey(pemBlock)
	if err != nil {
		t.Fatalf("parsePrivateKey failed: %v", err)
	}
	if parsed == nil {
		t.Error("expected non-nil key")
	}
}

func TestParsePrivateKey_InvalidPEM(t *testing.T) {
	_, err := parsePrivateKey([]byte("not a pem block"))
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}

func TestParsePrivateKey_UnsupportedType(t *testing.T) {
	pemBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "UNKNOWN KEY TYPE",
		Bytes: []byte("fake"),
	})
	_, err := parsePrivateKey(pemBlock)
	if err == nil {
		t.Fatal("expected error for unsupported key type")
	}
	if !strings.Contains(err.Error(), "unsupported key type") {
		t.Errorf("unexpected error message: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Additional: generateKeyPair
// ---------------------------------------------------------------------------

func TestGenerateKeyPair_AllAlgorithms(t *testing.T) {
	tests := []struct {
		algorithm    string
		wantPEMType  string
		wantPubType  string
	}{
		{"ECDSA-P256", "EC PRIVATE KEY", "*ecdsa.PublicKey"},
		{"ECDSA-P384", "EC PRIVATE KEY", "*ecdsa.PublicKey"},
		{"RSA-2048", "RSA PRIVATE KEY", "*rsa.PublicKey"},
		{"RSA-4096", "RSA PRIVATE KEY", "*rsa.PublicKey"},
		{"", "EC PRIVATE KEY", "*ecdsa.PublicKey"}, // default falls through to ECDSA-P256
	}

	for _, tc := range tests {
		name := tc.algorithm
		if name == "" {
			name = "default"
		}
		t.Run(name, func(t *testing.T) {
			privKey, pubKey, pemBlock, err := generateKeyPair(tc.algorithm)
			if err != nil {
				t.Fatalf("generateKeyPair(%q) failed: %v", tc.algorithm, err)
			}
			if privKey == nil {
				t.Error("privateKey should not be nil")
			}
			if pubKey == nil {
				t.Error("publicKey should not be nil")
			}
			if pemBlock == nil {
				t.Fatal("keyPEMBlock should not be nil")
			}
			if pemBlock.Type != tc.wantPEMType {
				t.Errorf("expected PEM type %s, got %s", tc.wantPEMType, pemBlock.Type)
			}
			pubType := fmt.Sprintf("%T", pubKey)
			if pubType != tc.wantPubType {
				t.Errorf("expected public key type %s, got %s", tc.wantPubType, pubType)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Additional: Concurrency safety
// ---------------------------------------------------------------------------

func TestConcurrentAccess(t *testing.T) {
	tm := NewTLSManager()

	// Generate CA first
	_, err := tm.GenerateCA(CertOptions{Algorithm: "ECDSA-P256"})
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	done := make(chan struct{})
	errs := make(chan error, 10)

	// Run multiple goroutines accessing the manager concurrently
	for i := 0; i < 5; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			_, e := tm.GenerateServerCertSignedByCA(CertOptions{Algorithm: "ECDSA-P256"})
			if e != nil {
				errs <- e
			}
		}()
	}

	for i := 0; i < 5; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			_ = tm.HasCA()
			_ = tm.HasServerCert()
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}

	close(errs)
	for e := range errs {
		t.Errorf("concurrent error: %v", e)
	}
}
