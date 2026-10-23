package backup

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"path"
	"strings"

	"github.com/jlaffaye/ftp"

	"SyslogStudio/internal/models"
)

// ftpTarget is a directory on an FTP server, over TLS (FTPS) or in the clear.
type ftpTarget struct {
	c     *ftp.ServerConn
	dir   string
	guard *guard
}

// CertFingerprint is how a certificate is named for pinning: its SHA-256.
func CertFingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

// ftpsConfig trusts what the system trusts, and otherwise only the
// certificate the user pinned: a NAS's own certificate is the common case,
// and refusing it would push people to plain FTP.
func ftpsConfig(d models.BackupDestination) *tls.Config {
	return &tls.Config{
		ServerName: d.Host,
		MinVersion: tls.VersionTLS12,
		// Data connections resume the control connection's session, which
		// many servers require (vsftpd's require_ssl_reuse).
		ClientSessionCache: tls.NewLRUClientSessionCache(4),
		// Verified below, by VerifyConnection: trusted chain, or the pin.
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("the server presented no certificate")
			}
			leaf := cs.PeerCertificates[0]
			if cs.DidResume {
				// Resumed from a session whose certificate was checked.
				return nil
			}
			inter := x509.NewCertPool()
			for _, c := range cs.PeerCertificates[1:] {
				inter.AddCert(c)
			}
			if _, err := leaf.Verify(x509.VerifyOptions{DNSName: d.Host, Intermediates: inter}); err == nil {
				return nil
			}
			fp := CertFingerprint(leaf)
			detail := leaf.Subject.String()
			switch {
			case d.CertPin == "":
				return &UnknownServerError{Fingerprint: fp, Detail: detail}
			case fp != d.CertPin:
				return &ChangedServerError{Pinned: d.CertPin, Fingerprint: fp, Detail: detail}
			}
			return nil
		},
	}
}

func dialFTP(ctx context.Context, d models.BackupDestination, a models.BackupAccess) (Target, error) {
	port := 21
	var cfg *tls.Config
	opts := []ftp.DialOption{ftp.DialWithContext(ctx), ftp.DialWithTimeout(dialTimeout)}
	if d.Kind == models.BackupToFTPS {
		cfg = ftpsConfig(d)
		if d.TLS == models.FTPSImplicit {
			port = 990
			opts = append(opts, ftp.DialWithTLS(cfg))
		} else {
			opts = append(opts, ftp.DialWithExplicitTLS(cfg))
		}
	}
	// Every connection, control and data, gives up when idle. Given a dial
	// function, the library no longer wraps anything in TLS itself but the
	// control connection it upgrades after AUTH TLS: implicit TLS starts
	// encrypted, and data connections are encrypted in both modes (it asks
	// for that with PROT P).
	g := newGuard(ctx)
	calls := 0
	opts = append(opts, ftp.DialWithDialFunc(func(_, address string) (net.Conn, error) {
		calls++
		conn, err := g.dial(ctx, address)
		if err != nil || cfg == nil {
			return conn, err
		}
		if calls == 1 && d.TLS != models.FTPSImplicit {
			return conn, nil
		}
		return tls.Client(conn, cfg), nil
	}))
	c, err := ftp.Dial(hostPort(d.Host, d.Port, port), opts...)
	if err != nil {
		g.release()
		return nil, unwrapTLS(err)
	}
	user := d.User
	if user == "" {
		user = "anonymous"
	}
	if err := c.Login(user, a.Password); err != nil {
		c.Quit()
		g.release()
		return nil, unwrapTLS(fmt.Errorf("sign-in refused: %w", err))
	}
	g.signedIn()
	dir := strings.TrimSuffix(d.Path, "/")
	if dir == "" {
		dir = "."
	}
	if err := ftpMkdirAll(c, dir); err != nil {
		c.Quit()
		g.release()
		return nil, fmt.Errorf("the folder %s cannot be made on the server: %w", dir, err)
	}
	return &ftpTarget{c: c, dir: dir, guard: g}, nil
}

// unwrapTLS brings a pin refusal up from inside the TLS handshake error.
func unwrapTLS(err error) error {
	var unknown *UnknownServerError
	if errors.As(err, &unknown) {
		return unknown
	}
	var changed *ChangedServerError
	if errors.As(err, &changed) {
		return changed
	}
	return err
}

// ftpMkdirAll makes dir and its parents, as far as the server lets it: a
// folder that already exists answers an error too, so only the last step's
// says anything.
func ftpMkdirAll(c *ftp.ServerConn, dir string) error {
	if dir == "." || dir == "/" {
		return nil
	}
	cur := ""
	if strings.HasPrefix(dir, "/") {
		cur = "/"
	}
	for _, part := range strings.Split(strings.Trim(dir, "/"), "/") {
		cur = path.Join(cur, part)
		c.MakeDir(cur)
	}
	if _, err := c.List(dir); err != nil {
		return err
	}
	return nil
}

func (t *ftpTarget) path(name string) (string, error) {
	if name == "" || name != path.Base(name) || name == "." || name == ".." {
		return "", fmt.Errorf("not a file name: %q", name)
	}
	return path.Join(t.dir, name), nil
}

func (t *ftpTarget) Put(name string, r io.Reader) error {
	p, err := t.path(name)
	if err != nil {
		return err
	}
	part := p + partExt
	if err := t.c.Stor(part, r); err != nil {
		t.c.Delete(part)
		return unwrapTLS(err)
	}
	t.c.Delete(p)
	if err := t.c.Rename(part, p); err != nil {
		t.c.Delete(part)
		return err
	}
	return nil
}

func (t *ftpTarget) Check(name string, size int64, _ []byte) error {
	p, err := t.path(name)
	if err != nil {
		return err
	}
	got, err := t.c.FileSize(p)
	if err != nil {
		// SIZE is optional: the listing says it too.
		entries, lerr := t.List()
		if lerr != nil {
			return err
		}
		got = -1
		for _, e := range entries {
			if e.Name == name {
				got = e.Size
			}
		}
	}
	if got != size {
		return fmt.Errorf("%d bytes on the server, %d sent", got, size)
	}
	return nil
}

func (t *ftpTarget) Open(name string) (io.ReadCloser, error) {
	p, err := t.path(name)
	if err != nil {
		return nil, err
	}
	resp, err := t.c.Retr(p)
	if err != nil {
		return nil, unwrapTLS(err)
	}
	return resp, nil
}

func (t *ftpTarget) List() ([]Entry, error) {
	entries, err := t.c.List(t.dir)
	if err != nil {
		return nil, err
	}
	var out []Entry
	for _, e := range entries {
		if e.Type == ftp.EntryTypeFile {
			out = append(out, Entry{Name: path.Base(e.Name), Size: int64(e.Size), ModTime: e.Time})
		}
	}
	return out, nil
}

func (t *ftpTarget) Remove(name string) error {
	p, err := t.path(name)
	if err != nil {
		return err
	}
	return t.c.Delete(p)
}

func (t *ftpTarget) Close() error {
	t.guard.release()
	return t.c.Quit()
}
