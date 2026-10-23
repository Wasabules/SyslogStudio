package backup

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	ftpserver "github.com/fclairamb/ftpserverlib"
	"github.com/pkg/sftp"
	"github.com/spf13/afero"
	"golang.org/x/crypto/ssh"

	"SyslogStudio/internal/models"
)

// Real servers, in the test's process: an SSH server offering SFTP, and an
// FTP server in the clear, with explicit TLS and with implicit TLS.

const (
	serverUser     = "backup"
	serverPassword = "server password"
)

// --- SFTP -------------------------------------------------------------------

type sftpServer struct {
	addr    string
	hostKey ssh.PublicKey
	dir     string
}

func startSFTP(t *testing.T, authorized ssh.PublicKey) sftpServer {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
			if c.User() == serverUser && string(p) == serverPassword {
				return nil, nil
			}
			return nil, errors.New("denied")
		},
		PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if authorized != nil && c.User() == serverUser && bytes.Equal(key.Marshal(), authorized.Marshal()) {
				return nil, nil
			}
			return nil, errors.New("denied")
		},
	}
	cfg.AddHostKey(signer)
	dir := t.TempDir()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			go serveSSH(nc, cfg, dir)
		}
	}()
	return sftpServer{addr: ln.Addr().String(), hostKey: signer.PublicKey(), dir: dir}
}

func serveSSH(nc net.Conn, cfg *ssh.ServerConfig, dir string) {
	conn, chans, reqs, err := ssh.NewServerConn(nc, cfg)
	if err != nil {
		nc.Close()
		return
	}
	defer conn.Close()
	go ssh.DiscardRequests(reqs)
	for nch := range chans {
		if nch.ChannelType() != "session" {
			nch.Reject(ssh.UnknownChannelType, "")
			continue
		}
		ch, in, err := nch.Accept()
		if err != nil {
			continue
		}
		go func() {
			for req := range in {
				ok := req.Type == "subsystem" && len(req.Payload) > 4 && string(req.Payload[4:]) == "sftp"
				req.Reply(ok, nil)
				if ok {
					srv, err := sftp.NewServer(ch, sftp.WithServerWorkingDirectory(dir))
					if err == nil {
						srv.Serve()
						srv.Close()
					}
					return
				}
			}
		}()
	}
}

func hostAndPort(t *testing.T, addr string) (string, int) {
	t.Helper()
	host, p, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(p)
	return host, port
}

// exercise sends a copy to the destination, reads it back, lists it, and
// prunes, as a backup run does.
func exercise(t *testing.T, d models.BackupDestination, a models.BackupAccess) {
	t.Helper()
	tg, err := Connect(context.Background(), d, a)
	if err != nil {
		t.Fatal(err)
	}
	defer tg.Close()

	src := filepath.Join(t.TempDir(), "copy")
	payload := bytes.Repeat([]byte("encrypted backup bytes "), 50000)
	if err := os.WriteFile(src, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 10, 1, 3, 0, 0, 0, time.Local)
	var names []string
	for i := 0; i < 3; i++ {
		name := Name(base.AddDate(0, 0, i), false, true)
		var last float64
		if err := Upload(tg, src, name, func(p float64) { last = p }); err != nil {
			t.Fatalf("upload %s: %v", name, err)
		}
		if last != 1 {
			t.Errorf("upload progress ended at %v", last)
		}
		names = append(names, name)
	}
	files, err := List(tg)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 3 || files[0].Name != names[2] || files[0].SizeMB <= 0 {
		t.Fatalf("listed %+v", files)
	}
	rc, err := tg.Open(names[0])
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(rc)
	rc.Close()
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("read back %d bytes (%v), want the %d sent", len(got), err, len(payload))
	}
	removed, err := Prune(tg, 2)
	if err != nil || len(removed) != 1 || removed[0] != names[0] {
		t.Fatalf("pruned %v (%v), want the oldest", removed, err)
	}
	if files, _ := List(tg); len(files) != 2 {
		t.Fatalf("after pruning %d copies, want 2", len(files))
	}
}

func TestSFTP(t *testing.T) {
	keyPub, keyPriv, _ := ed25519.GenerateKey(rand.Reader)
	sshPub, _ := ssh.NewPublicKey(keyPub)
	block, err := ssh.MarshalPrivateKeyWithPassphrase(keyPriv, "", []byte("key passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := string(pem.EncodeToMemory(block))
	srv := startSFTP(t, sshPub)
	host, port := hostAndPort(t, srv.addr)
	d := models.BackupDestination{ID: "s", Name: "nas", Kind: models.BackupToSFTP, Enabled: true,
		Host: host, Port: port, User: serverUser, Auth: models.SFTPPassword, Path: "backups/nightly"}
	pw := models.BackupAccess{Password: serverPassword}

	// First meeting: the server's key is named, not trusted.
	_, err = Connect(context.Background(), d, pw)
	var unknown *UnknownServerError
	if !errors.As(err, &unknown) || unknown.Fingerprint != ssh.FingerprintSHA256(srv.hostKey) {
		t.Fatalf("an unknown server: %v", err)
	}
	// Another key pinned: refused, and said so.
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	otherKey, _ := ssh.NewPublicKey(other)
	d.HostKey = ssh.FingerprintSHA256(otherKey)
	var changed *ChangedServerError
	if _, err := Connect(context.Background(), d, pw); !errors.As(err, &changed) {
		t.Fatalf("a server whose key changed: %v", err)
	}

	d.HostKey = unknown.Fingerprint
	if _, err := Connect(context.Background(), d, models.BackupAccess{Password: "wrong"}); err == nil {
		t.Fatal("a wrong password signed in")
	}
	exercise(t, d, pw)
	if _, err := os.Stat(filepath.Join(srv.dir, "backups", "nightly")); err != nil {
		t.Errorf("the folder was not made on the server: %v", err)
	}

	d.Auth = models.SFTPKey
	if _, err := Connect(context.Background(), d, models.BackupAccess{Key: keyPEM}); err == nil {
		t.Error("a key protected by a passphrase was used without it")
	}
	exercise(t, d, models.BackupAccess{Key: keyPEM, Passphrase: "key passphrase"})
}

// --- FTP --------------------------------------------------------------------

type ftpDriver struct {
	dir      string
	settings *ftpserver.Settings
	tls      *tls.Config
}

func (d *ftpDriver) GetSettings() (*ftpserver.Settings, error)               { return d.settings, nil }
func (d *ftpDriver) ClientConnected(ftpserver.ClientContext) (string, error) { return "test", nil }
func (d *ftpDriver) ClientDisconnected(ftpserver.ClientContext)              {}
func (d *ftpDriver) GetTLSConfig() (*tls.Config, error)                      { return d.tls, nil }
func (d *ftpDriver) AuthUser(_ ftpserver.ClientContext, user, pass string) (ftpserver.ClientDriver, error) {
	if user == serverUser && pass == serverPassword {
		return afero.NewBasePathFs(afero.NewOsFs(), d.dir), nil
	}
	return nil, errors.New("denied")
}

func selfSigned(t *testing.T) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "nas.example"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, DNSNames: []string{"localhost"},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, cert
}

func startFTP(t *testing.T, mode ftpserver.TLSRequirement, withTLS bool) (string, *x509.Certificate, string) {
	t.Helper()
	dir := t.TempDir()
	d := &ftpDriver{dir: dir, settings: &ftpserver.Settings{ListenAddr: "127.0.0.1:0", TLSRequired: mode}}
	var leaf *x509.Certificate
	if withTLS {
		var cert tls.Certificate
		cert, leaf = selfSigned(t)
		d.tls = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	}
	srv := ftpserver.NewFtpServer(d)
	if err := srv.Listen(); err != nil {
		t.Fatal(err)
	}
	go srv.Serve()
	t.Cleanup(func() { srv.Stop() })
	return srv.Addr(), leaf, dir
}

func TestFTPS(t *testing.T) {
	for _, c := range []struct {
		name string
		mode ftpserver.TLSRequirement
		tls  string
	}{
		{"explicit", ftpserver.MandatoryEncryption, models.FTPSExplicit},
		{"implicit", ftpserver.ImplicitEncryption, models.FTPSImplicit},
	} {
		t.Run(c.name, func(t *testing.T) {
			addr, leaf, _ := startFTP(t, c.mode, true)
			host, port := hostAndPort(t, addr)
			d := models.BackupDestination{ID: "f", Name: "nas", Kind: models.BackupToFTPS, Enabled: true,
				Host: host, Port: port, User: serverUser, TLS: c.tls, Path: "backups"}
			pw := models.BackupAccess{Password: serverPassword}

			// A certificate the system does not trust: named, not accepted.
			_, err := Connect(context.Background(), d, pw)
			var unknown *UnknownServerError
			if !errors.As(err, &unknown) || unknown.Fingerprint != CertFingerprint(leaf) {
				t.Fatalf("an unknown certificate: %v", err)
			}
			d.CertPin = "SHA256:somethingelse"
			var changed *ChangedServerError
			if _, err := Connect(context.Background(), d, pw); !errors.As(err, &changed) {
				t.Fatalf("a certificate that changed: %v", err)
			}
			d.CertPin = unknown.Fingerprint
			exercise(t, d, pw)
		})
	}
}

func TestFTP(t *testing.T) {
	addr, _, dir := startFTP(t, ftpserver.ClearOrEncrypted, false)
	host, port := hostAndPort(t, addr)
	d := models.BackupDestination{ID: "p", Name: "old nas", Kind: models.BackupToFTP, Enabled: true,
		Host: host, Port: port, User: serverUser, Path: "/backups"}
	pw := models.BackupAccess{Password: serverPassword}
	if _, err := Connect(context.Background(), d, pw); err == nil {
		t.Fatal("FTP in the clear was used without being acknowledged")
	}
	d.Cleartext = true
	exercise(t, d, pw)
	if _, err := os.Stat(filepath.Join(dir, "backups")); err != nil {
		t.Errorf("the folder was not made on the server: %v", err)
	}
}

// A folder destination behaves as the servers do.
func TestFolder(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "usb", "backups")
	exercise(t, models.BackupDestination{ID: "d", Name: "usb", Kind: models.BackupToFolder, Enabled: true, Path: dir},
		models.BackupAccess{})
	if _, err := Connect(context.Background(), models.BackupDestination{Kind: models.BackupToFolder, Path: "relative"}, models.BackupAccess{}); err == nil {
		t.Error("a relative folder was accepted")
	}
}

// Cancelling a run cuts the connection to a server that does not answer.
func TestConnectGivesUpWhenCancelled(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close() // accepts, then says nothing
		}
	}()
	host, port := hostAndPort(t, ln.Addr().String())
	silent := models.BackupDestination{Kind: models.BackupToSFTP, Host: host, Port: port,
		User: "u", Auth: models.SFTPPassword}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = Connect(ctx, silent, models.BackupAccess{Password: "p"})
	if err == nil || time.Since(start) > 10*time.Second {
		t.Fatalf("a silent server held the connection for %s (%v)", time.Since(start), err)
	}

	// Not cancelled: the handshake's own limit gives up on it.
	saved := dialTimeout
	dialTimeout = 300 * time.Millisecond
	defer func() { dialTimeout = saved }()
	start = time.Now()
	for _, kind := range []string{models.BackupToSFTP, models.BackupToFTPS} {
		d := silent
		d.Kind, d.TLS = kind, models.FTPSImplicit
		if _, err := Connect(context.Background(), d, models.BackupAccess{Password: "p"}); err == nil {
			t.Fatalf("%s: a silent server was taken for one", kind)
		}
	}
	if took := time.Since(start); took > 10*time.Second {
		t.Fatalf("a silent server held the handshake for %s", took)
	}
}
