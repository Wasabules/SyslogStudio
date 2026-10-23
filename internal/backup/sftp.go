package backup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"SyslogStudio/internal/models"
)

// sftpTarget is a directory on a server reached over SSH.
type sftpTarget struct {
	ssh   *ssh.Client
	c     *sftp.Client
	dir   string
	guard *guard
}

func sftpAuth(d models.BackupDestination, a models.BackupAccess) ([]ssh.AuthMethod, error) {
	if d.Auth == models.SFTPKey {
		if a.Key == "" {
			return nil, errors.New("the private key is missing")
		}
		var signer ssh.Signer
		var err error
		if a.Passphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(a.Key), []byte(a.Passphrase))
		} else {
			signer, err = ssh.ParsePrivateKey([]byte(a.Key))
		}
		var missing *ssh.PassphraseMissingError
		if errors.As(err, &missing) {
			return nil, errors.New("the private key is protected by a passphrase: enter it")
		}
		if err != nil {
			return nil, fmt.Errorf("the private key does not read: %w", err)
		}
		return []ssh.AuthMethod{ssh.PublicKeys(signer)}, nil
	}
	// Some servers ask for the password through keyboard-interactive.
	answer := func(_, _ string, questions []string, _ []bool) ([]string, error) {
		answers := make([]string, len(questions))
		for i := range answers {
			answers[i] = a.Password
		}
		return answers, nil
	}
	return []ssh.AuthMethod{ssh.Password(a.Password), ssh.KeyboardInteractive(answer)}, nil
}

// pinnedHostKey accepts the server's key only when it is the one pinned.
func pinnedHostKey(pinned string) ssh.HostKeyCallback {
	return func(_ string, _ net.Addr, key ssh.PublicKey) error {
		fp := ssh.FingerprintSHA256(key)
		switch {
		case pinned == "":
			return &UnknownServerError{Fingerprint: fp, Detail: key.Type()}
		case fp != pinned:
			return &ChangedServerError{Pinned: pinned, Fingerprint: fp, Detail: key.Type()}
		}
		return nil
	}
}

func dialSFTP(ctx context.Context, d models.BackupDestination, a models.BackupAccess) (Target, error) {
	auth, err := sftpAuth(d, a)
	if err != nil {
		return nil, err
	}
	address := hostPort(d.Host, d.Port, 22)
	g := newGuard(ctx)
	conn, err := g.dial(ctx, address)
	if err != nil {
		g.release()
		return nil, err
	}
	cfg := &ssh.ClientConfig{User: d.User, Auth: auth, HostKeyCallback: pinnedHostKey(d.HostKey), Timeout: dialTimeout}
	sc, chans, reqs, err := ssh.NewClientConn(conn, address, cfg)
	if err != nil {
		conn.Close()
		g.release()
		return nil, err
	}
	g.signedIn()
	client := ssh.NewClient(sc, chans, reqs)
	c, err := sftp.NewClient(client)
	if err != nil {
		client.Close()
		g.release()
		return nil, fmt.Errorf("the server does not offer SFTP: %w", err)
	}
	dir := d.Path
	if dir == "" {
		dir = "."
	}
	if err := c.MkdirAll(dir); err != nil {
		c.Close()
		client.Close()
		g.release()
		return nil, fmt.Errorf("the folder %s cannot be made on the server: %w", dir, err)
	}
	return &sftpTarget{ssh: client, c: c, dir: dir, guard: g}, nil
}

func (t *sftpTarget) path(name string) (string, error) {
	if name == "" || name != path.Base(name) || name == "." || name == ".." {
		return "", fmt.Errorf("not a file name: %q", name)
	}
	return path.Join(t.dir, name), nil
}

func (t *sftpTarget) Put(name string, r io.Reader) error {
	p, err := t.path(name)
	if err != nil {
		return err
	}
	part := p + partExt
	f, err := t.c.OpenFile(part, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		return err
	}
	// Several writes in flight, whatever r is: one at a time, each waiting
	// for its answer, a server a few tens of milliseconds away takes a
	// megabyte a second. ReadFrom only does so for a reader of known size.
	_, err = f.ReadFromWithConcurrency(r, 0)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		t.c.Remove(part)
		return err
	}
	// The name is new, but a rename onto an existing file fails in SFTP v3.
	t.c.Remove(p)
	if err := t.c.Rename(part, p); err != nil {
		t.c.Remove(part)
		return err
	}
	return nil
}

func (t *sftpTarget) Check(name string, size int64, _ []byte) error {
	p, err := t.path(name)
	if err != nil {
		return err
	}
	fi, err := t.c.Stat(p)
	if err != nil {
		return err
	}
	if fi.Size() != size {
		return fmt.Errorf("%d bytes on the server, %d sent", fi.Size(), size)
	}
	return nil
}

func (t *sftpTarget) Open(name string) (io.ReadCloser, error) {
	p, err := t.path(name)
	if err != nil {
		return nil, err
	}
	return t.c.Open(p)
}

func (t *sftpTarget) List() ([]Entry, error) {
	infos, err := t.c.ReadDir(t.dir)
	if err != nil {
		return nil, err
	}
	var out []Entry
	for _, fi := range infos {
		if fi.Mode().IsRegular() {
			out = append(out, Entry{Name: fi.Name(), Size: fi.Size(), ModTime: fi.ModTime()})
		}
	}
	return out, nil
}

func (t *sftpTarget) Remove(name string) error {
	p, err := t.path(name)
	if err != nil {
		return err
	}
	return t.c.Remove(p)
}

func (t *sftpTarget) Close() error {
	t.guard.release()
	t.c.Close()
	return t.ssh.Close()
}
