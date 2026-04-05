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
	"strings"
	"sync"
	"time"
)

// TLSManager handles TLS certificate operations including CA and server cert generation.
type TLSManager struct {
	mu sync.Mutex

	// CA certificate (self-signed root)
	caCertPEM []byte
	caKeyPEM  []byte

	// Server certificate (signed by CA or self-signed)
	serverCertPEM []byte
	serverKeyPEM  []byte
}

// NewTLSManager creates a new TLSManager.
func NewTLSManager() *TLSManager {
	return &TLSManager{}
}

// GetTLSConfig returns a tls.Config based on server configuration.
func (t *TLSManager) GetTLSConfig(config ServerConfig) (*tls.Config, error) {
	var tlsConfig *tls.Config
	var err error

	if config.UseSelfSigned {
		// Use pre-generated server cert if available, otherwise generate on the fly
		t.mu.Lock()
		hasCert := len(t.serverCertPEM) > 0 && len(t.serverKeyPEM) > 0
		certPEM := t.serverCertPEM
		keyPEM := t.serverKeyPEM
		t.mu.Unlock()

		if hasCert {
			cert, cerr := tls.X509KeyPair(certPEM, keyPEM)
			if cerr != nil {
				return nil, fmt.Errorf("failed to load generated certificate: %w", cerr)
			}
			tlsConfig = &tls.Config{
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS12,
			}
		} else {
			tlsConfig, _, err = t.GenerateSelfSignedWithOptions(config.CertOptions)
			if err != nil {
				return nil, err
			}
		}
	} else {
		if config.CertFile == "" || config.KeyFile == "" {
			return nil, fmt.Errorf("certificate and key file paths are required")
		}
		tlsConfig, err = t.LoadCertificate(config.CertFile, config.KeyFile)
		if err != nil {
			return nil, err
		}
	}

	// Apply mutual TLS if enabled
	if config.MutualTLS && config.CAFile != "" {
		caPool, caErr := t.LoadCACertificateFromFile(config.CAFile)
		if caErr != nil {
			return nil, fmt.Errorf("failed to load CA for mutual TLS: %w", caErr)
		}
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		tlsConfig.ClientCAs = caPool
	}

	return tlsConfig, nil
}

// LoadCertificate loads a TLS certificate and key from PEM files.
func (t *TLSManager) LoadCertificate(certFile, keyFile string) (*tls.Config, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file: %w", err)
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate: %w", err)
	}

	t.mu.Lock()
	t.serverCertPEM = certPEM
	t.serverKeyPEM = keyPEM
	t.mu.Unlock()

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// --- CA Certificate Operations ---

// GenerateCA creates a self-signed CA certificate.
func (t *TLSManager) GenerateCA(opts CertOptions) (CertInfo, error) {
	if opts.ValidityDays <= 0 {
		opts.ValidityDays = 3650
	}
	if opts.CommonName == "" {
		opts.CommonName = "Syslog CA"
	}
	if opts.Organization == "" {
		opts.Organization = "SyslogStudio"
	}
	if opts.Algorithm == "" {
		opts.Algorithm = "RSA-2048"
	}

	privateKey, publicKey, keyPEMBlock, err := generateKeyPair(opts.Algorithm)
	if err != nil {
		return CertInfo{}, err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return CertInfo{}, fmt.Errorf("failed to generate serial number: %w", err)
	}

	now := time.Now()
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   opts.CommonName,
			Organization: []string{opts.Organization},
		},
		NotBefore:             now,
		NotAfter:              now.Add(time.Duration(opts.ValidityDays) * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey, privateKey)
	if err != nil {
		return CertInfo{}, fmt.Errorf("failed to create CA certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(keyPEMBlock)

	t.mu.Lock()
	t.caCertPEM = certPEM
	t.caKeyPEM = keyPEM
	t.mu.Unlock()

	return t.buildCertInfo(certDER, opts.Algorithm), nil
}

// GenerateServerCertSignedByCA creates a server certificate signed by the stored CA.
func (t *TLSManager) GenerateServerCertSignedByCA(opts CertOptions) (CertInfo, error) {
	t.mu.Lock()
	caCertPEM := t.caCertPEM
	caKeyPEM := t.caKeyPEM
	t.mu.Unlock()

	if len(caCertPEM) == 0 || len(caKeyPEM) == 0 {
		return CertInfo{}, fmt.Errorf("no CA certificate available; generate a CA first")
	}

	// Parse CA certificate
	caBlock, _ := pem.Decode(caCertPEM)
	if caBlock == nil {
		return CertInfo{}, fmt.Errorf("failed to decode CA certificate PEM")
	}
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return CertInfo{}, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	// Parse CA private key
	caKey, err := parsePrivateKey(caKeyPEM)
	if err != nil {
		return CertInfo{}, fmt.Errorf("failed to parse CA key: %w", err)
	}

	// Apply defaults for server cert
	if opts.Algorithm == "" {
		opts.Algorithm = "RSA-2048"
	}
	if opts.ValidityDays <= 0 {
		opts.ValidityDays = 3650
	}
	if opts.CommonName == "" {
		opts.CommonName = "SyslogStudio Server"
	}
	if opts.Organization == "" {
		opts.Organization = "SyslogStudio"
	}

	// Generate server key pair
	serverKey, serverPub, serverKeyPEMBlock, err := generateKeyPair(opts.Algorithm)
	_ = serverKey // used only for PEM encoding above
	if err != nil {
		return CertInfo{}, err
	}

	// Parse IP addresses for SAN
	var ips []net.IP
	for _, ipStr := range opts.IPAddresses {
		ipStr = strings.TrimSpace(ipStr)
		if ipStr == "" {
			continue
		}
		ip := net.ParseIP(ipStr)
		if ip != nil {
			ips = append(ips, ip)
		}
	}

	// Clean DNS names
	var dnsNames []string
	for _, dns := range opts.DNSNames {
		dns = strings.TrimSpace(dns)
		if dns != "" {
			dnsNames = append(dnsNames, dns)
		}
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return CertInfo{}, fmt.Errorf("failed to generate serial number: %w", err)
	}

	now := time.Now()
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   opts.CommonName,
			Organization: []string{opts.Organization},
		},
		NotBefore:             now,
		NotAfter:              now.Add(time.Duration(opts.ValidityDays) * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
		IPAddresses:           ips,
	}

	// Sign with CA (not self-signed!)
	certDER, err := x509.CreateCertificate(rand.Reader, &template, caCert, serverPub, caKey)
	if err != nil {
		return CertInfo{}, fmt.Errorf("failed to create server certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(serverKeyPEMBlock)

	t.mu.Lock()
	t.serverCertPEM = certPEM
	t.serverKeyPEM = keyPEM
	t.mu.Unlock()

	return t.buildCertInfo(certDER, opts.Algorithm), nil
}

// HasCA returns true if a CA certificate is available.
func (t *TLSManager) HasCA() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.caCertPEM) > 0 && len(t.caKeyPEM) > 0
}

// HasServerCert returns true if a server certificate is available.
func (t *TLSManager) HasServerCert() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.serverCertPEM) > 0 && len(t.serverKeyPEM) > 0
}

// GetCACertificateInfo returns details about the stored CA certificate.
func (t *TLSManager) GetCACertificateInfo() (CertInfo, error) {
	t.mu.Lock()
	certPEM := t.caCertPEM
	t.mu.Unlock()

	if len(certPEM) == 0 {
		return CertInfo{}, fmt.Errorf("no CA certificate has been generated")
	}
	return t.parseCertPEMInfo(certPEM)
}

// GetServerCertificateInfo returns details about the stored server certificate.
func (t *TLSManager) GetServerCertificateInfo() (CertInfo, error) {
	t.mu.Lock()
	certPEM := t.serverCertPEM
	t.mu.Unlock()

	if len(certPEM) == 0 {
		return CertInfo{}, fmt.Errorf("no server certificate available")
	}
	return t.parseCertPEMInfo(certPEM)
}

// SaveCACertificateToFile exports the CA certificate (no key) to a PEM file.
func (t *TLSManager) SaveCACertificateToFile(certPath string) error {
	t.mu.Lock()
	certPEM := t.caCertPEM
	t.mu.Unlock()

	if len(certPEM) == 0 {
		return fmt.Errorf("no CA certificate available to export")
	}
	return os.WriteFile(certPath, certPEM, 0644)
}

// SaveServerCertificateToFile exports the server cert and key to PEM files.
func (t *TLSManager) SaveServerCertificateToFile(certPath, keyPath string) error {
	t.mu.Lock()
	certPEM := t.serverCertPEM
	keyPEM := t.serverKeyPEM
	t.mu.Unlock()

	if len(certPEM) == 0 || len(keyPEM) == 0 {
		return fmt.Errorf("no server certificate available to export")
	}

	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("failed to write key: %w", err)
	}
	return nil
}

// --- Self-signed (legacy/quick) ---

// GenerateSelfSignedWithOptions creates a self-signed certificate with customizable options.
func (t *TLSManager) GenerateSelfSignedWithOptions(opts CertOptions) (*tls.Config, CertInfo, error) {
	if opts.Algorithm == "" {
		opts.Algorithm = "ECDSA-P256"
	}
	if opts.ValidityDays <= 0 {
		opts.ValidityDays = 365
	}
	if opts.CommonName == "" {
		opts.CommonName = "SyslogStudio"
	}
	if opts.Organization == "" {
		opts.Organization = "SyslogStudio"
	}
	if len(opts.DNSNames) == 0 {
		opts.DNSNames = []string{"localhost"}
	}
	if len(opts.IPAddresses) == 0 {
		opts.IPAddresses = []string{"127.0.0.1", "::1"}
	}

	privateKey, publicKey, keyPEMBlock, err := generateKeyPair(opts.Algorithm)
	if err != nil {
		return nil, CertInfo{}, err
	}

	var ips []net.IP
	for _, ipStr := range opts.IPAddresses {
		ipStr = strings.TrimSpace(ipStr)
		if ipStr != "" {
			if ip := net.ParseIP(ipStr); ip != nil {
				ips = append(ips, ip)
			}
		}
	}

	var dnsNames []string
	for _, dns := range opts.DNSNames {
		dns = strings.TrimSpace(dns)
		if dns != "" {
			dnsNames = append(dnsNames, dns)
		}
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, CertInfo{}, fmt.Errorf("failed to generate serial number: %w", err)
	}

	now := time.Now()
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   opts.CommonName,
			Organization: []string{opts.Organization},
		},
		NotBefore:             now,
		NotAfter:              now.Add(time.Duration(opts.ValidityDays) * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
		IPAddresses:           ips,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey, privateKey)
	if err != nil {
		return nil, CertInfo{}, fmt.Errorf("failed to create certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(keyPEMBlock)

	t.mu.Lock()
	t.serverCertPEM = certPEM
	t.serverKeyPEM = keyPEM
	t.mu.Unlock()

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, CertInfo{}, fmt.Errorf("failed to create TLS certificate: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	return tlsConfig, t.buildCertInfo(certDER, opts.Algorithm), nil
}

// --- File loading helpers ---

// LoadCACertificateFromFile loads a CA certificate pool from a PEM file.
func (t *TLSManager) LoadCACertificateFromFile(caPath string) (*x509.CertPool, error) {
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA file: %w", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}
	return pool, nil
}

// GetCertificateInfo extracts details from the current configuration's certificate.
func (t *TLSManager) GetCertificateInfo(config ServerConfig) (CertInfo, error) {
	var certPEM []byte

	if config.UseSelfSigned {
		t.mu.Lock()
		certPEM = t.serverCertPEM
		t.mu.Unlock()
		if len(certPEM) == 0 {
			return CertInfo{}, fmt.Errorf("no server certificate has been generated yet")
		}
	} else {
		if config.CertFile == "" {
			return CertInfo{}, fmt.Errorf("no certificate file specified")
		}
		data, err := os.ReadFile(config.CertFile)
		if err != nil {
			return CertInfo{}, fmt.Errorf("failed to read certificate: %w", err)
		}
		certPEM = data
	}

	return t.parseCertPEMInfo(certPEM)
}

// --- Internal helpers ---

// generateKeyPair generates a private/public key pair and PEM block based on algorithm string.
func generateKeyPair(algorithm string) (privateKey interface{}, publicKey interface{}, keyPEMBlock *pem.Block, err error) {
	switch strings.ToUpper(algorithm) {
	case "RSA-2048":
		key, gerr := rsa.GenerateKey(rand.Reader, 2048)
		if gerr != nil {
			return nil, nil, nil, fmt.Errorf("failed to generate RSA-2048 key: %w", gerr)
		}
		return key, &key.PublicKey, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}, nil
	case "RSA-4096":
		key, gerr := rsa.GenerateKey(rand.Reader, 4096)
		if gerr != nil {
			return nil, nil, nil, fmt.Errorf("failed to generate RSA-4096 key: %w", gerr)
		}
		return key, &key.PublicKey, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}, nil
	case "ECDSA-P384":
		key, gerr := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if gerr != nil {
			return nil, nil, nil, fmt.Errorf("failed to generate ECDSA P-384 key: %w", gerr)
		}
		der, merr := x509.MarshalECPrivateKey(key)
		if merr != nil {
			return nil, nil, nil, fmt.Errorf("failed to marshal EC key: %w", merr)
		}
		return key, &key.PublicKey, &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}, nil
	default: // ECDSA-P256
		key, gerr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if gerr != nil {
			return nil, nil, nil, fmt.Errorf("failed to generate ECDSA P-256 key: %w", gerr)
		}
		der, merr := x509.MarshalECPrivateKey(key)
		if merr != nil {
			return nil, nil, nil, fmt.Errorf("failed to marshal EC key: %w", merr)
		}
		return key, &key.PublicKey, &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}, nil
	}
}

// parsePrivateKey decodes a PEM-encoded private key (RSA or ECDSA).
func parsePrivateKey(keyPEM []byte) (interface{}, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		return x509.ParsePKCS8PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported key type: %s", block.Type)
	}
}

// parseCertPEMInfo parses a PEM certificate and returns CertInfo.
func (t *TLSManager) parseCertPEMInfo(certPEM []byte) (CertInfo, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return CertInfo{}, fmt.Errorf("failed to decode PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return CertInfo{}, fmt.Errorf("failed to parse certificate: %w", err)
	}
	return t.buildCertInfoFromX509(cert), nil
}

// buildCertInfo creates a CertInfo from raw DER certificate bytes and algorithm hint.
func (t *TLSManager) buildCertInfo(certDER []byte, algorithm string) CertInfo {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return CertInfo{}
	}
	info := t.buildCertInfoFromX509(cert)
	if algorithm != "" {
		info.Algorithm = algorithm
	}
	return info
}

// buildCertInfoFromX509 creates a CertInfo from a parsed x509 certificate.
func (t *TLSManager) buildCertInfoFromX509(cert *x509.Certificate) CertInfo {
	now := time.Now()
	fingerprint := sha256.Sum256(cert.Raw)

	algorithm := ""
	keySize := ""
	switch pub := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		algorithm = fmt.Sprintf("ECDSA-%s", pub.Curve.Params().Name)
		keySize = fmt.Sprintf("%d bits", pub.Curve.Params().BitSize)
	case *rsa.PublicKey:
		algorithm = "RSA"
		keySize = fmt.Sprintf("%d bits", pub.N.BitLen())
	default:
		algorithm = cert.PublicKeyAlgorithm.String()
	}

	var ipStrings []string
	for _, ip := range cert.IPAddresses {
		ipStrings = append(ipStrings, ip.String())
	}

	isSelfSigned := cert.Issuer.CommonName == cert.Subject.CommonName

	fpHex := fmt.Sprintf("%X", fingerprint)
	var fpParts []string
	for i := 0; i < len(fpHex); i += 2 {
		end := i + 2
		if end > len(fpHex) {
			end = len(fpHex)
		}
		fpParts = append(fpParts, fpHex[i:end])
	}

	return CertInfo{
		Subject:           cert.Subject.String(),
		Issuer:            cert.Issuer.String(),
		NotBefore:         cert.NotBefore.Format("2006-01-02 15:04:05"),
		NotAfter:          cert.NotAfter.Format("2006-01-02 15:04:05"),
		SerialNumber:      cert.SerialNumber.Text(16),
		SHA256Fingerprint: strings.Join(fpParts, ":"),
		Algorithm:         algorithm,
		KeySize:           keySize,
		DNSNames:          cert.DNSNames,
		IPAddresses:       ipStrings,
		IsSelfSigned:      isSelfSigned,
		IsExpired:         now.After(cert.NotAfter),
		IsValid:           now.After(cert.NotBefore) && now.Before(cert.NotAfter),
	}
}
