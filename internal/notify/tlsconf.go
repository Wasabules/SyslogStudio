package notify

import (
	"crypto/tls"
	"crypto/x509"
	"os"
)

// TLSFiles is the certificate material a sink needs to speak TLS to something
// that is not on the public web: a trust anchor of its own, and a client pair
// for mutual TLS.
//
// It is shared by the syslog and e-mail sinks. A collector and a mail relay
// present the same problem — an internal service whose certificate the system
// pool has never heard of, and which may want the client to prove itself in
// return — and there is no reason for the two to answer it differently.
type TLSFiles struct {
	// CAFile verifies the far end. Empty means the system pool, which is the
	// right answer for a public relay and the wrong one for an internal CA.
	CAFile string `json:"caFile,omitempty"`
	// ClientCertFile and ClientKeyFile enable mutual TLS. The far end can be
	// signed by an authority entirely unrelated to the one this app serves its
	// own listener with: CAFile is that side's anchor, nothing more.
	ClientCertFile string `json:"clientCertFile,omitempty"`
	ClientKeyFile  string `json:"clientKeyFile,omitempty"`
	// InsecureSkipVerify accepts any certificate. Opt-in, per sink, and
	// surfaced in the UI — never a default.
	InsecureSkipVerify bool `json:"insecureSkipVerify,omitempty"`
}

// buildTLS turns the configured files into a client TLS configuration.
func buildTLS(serverName string, f TLSFiles) (*tls.Config, error) {
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ServerName:         serverName,
		InsecureSkipVerify: f.InsecureSkipVerify, //nolint:gosec // opt-in, per sink, shown in the UI
	}

	if f.CAFile != "" {
		pem, err := os.ReadFile(f.CAFile)
		if err != nil {
			return nil, errf("read CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errf("CA file %q contains no usable certificate", f.CAFile)
		}
		cfg.RootCAs = pool
	}

	// Both halves or neither: a certificate without its key is a configuration
	// that silently falls back to anonymous, which is not what was asked for.
	if (f.ClientCertFile == "") != (f.ClientKeyFile == "") {
		return nil, errf("mutual TLS needs both a client certificate and a key")
	}
	if f.ClientCertFile != "" {
		pair, err := tls.LoadX509KeyPair(f.ClientCertFile, f.ClientKeyFile)
		if err != nil {
			return nil, errf("load client certificate: %w", err)
		}
		cfg.Certificates = []tls.Certificate{pair}
	}

	return cfg, nil
}

// validateTLSFiles rejects material that cannot work before anything is sent,
// so the operator hears about it while saving rather than on the first
// undelivered message.
func validateTLSFiles(f TLSFiles) error {
	if (f.ClientCertFile == "") != (f.ClientKeyFile == "") {
		return errf("mutual TLS needs both a client certificate and a key")
	}
	return nil
}
