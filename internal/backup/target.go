package backup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"SyslogStudio/internal/models"
	"SyslogStudio/internal/vault"
)

// Target is a place copies go: a folder of this machine, or a server.
type Target interface {
	// Put stores what r holds as name: under a temporary name first, renamed
	// once whole, so that a copy cut short never passes for one.
	Put(name string, r io.Reader) error
	// Check says whether name arrived as it was sent: size bytes, whose
	// SHA-256 is sum. A folder reads it back; a server says its size.
	Check(name string, size int64, sum []byte) error
	Open(name string) (io.ReadCloser, error)
	List() ([]Entry, error)
	Remove(name string) error
	Close() error
}

// Entry is a file at a target.
type Entry struct {
	Name    string
	Size    int64
	ModTime time.Time
}

// dialTimeout bounds reaching a server and signing in; idleTimeout, how long
// a connection may go without moving a byte before it is given up — a server
// gone quiet must not hold a backup up for ever. Variables for the tests.
var (
	dialTimeout = 15 * time.Second
	idleTimeout = 2 * time.Minute
)

// UnknownServerError is a server met for the first time: the user compares
// its fingerprint with the one its administrator gives, then trusts it.
type UnknownServerError struct {
	Fingerprint string
	Detail      string
}

func (e *UnknownServerError) Error() string {
	return fmt.Sprintf("this server is not trusted yet: its fingerprint is %s (%s)", e.Fingerprint, e.Detail)
}

// ChangedServerError is a server that no longer presents the key or
// certificate pinned: it was reinstalled, or someone is in between.
type ChangedServerError struct {
	Pinned, Fingerprint, Detail string
}

func (e *ChangedServerError) Error() string {
	return fmt.Sprintf("the server's identity changed: %s instead of the trusted %s — refusing to connect, someone may be in between", e.Fingerprint, e.Pinned)
}

// Connect reaches the destination d, signing in with a. Closing ctx cuts the
// connection: a backup being stopped does not wait for a server.
func Connect(ctx context.Context, d models.BackupDestination, a models.BackupAccess) (Target, error) {
	if err := Validate(d); err != nil {
		return nil, err
	}
	switch d.Kind {
	case models.BackupToFolder:
		return openFolder(d.Path)
	case models.BackupToSFTP:
		return dialSFTP(ctx, d, a)
	case models.BackupToFTPS, models.BackupToFTP:
		return dialFTP(ctx, d, a)
	}
	return nil, fmt.Errorf("unknown destination kind %q", d.Kind)
}

// Validate says what is missing or wrong in a destination.
func Validate(d models.BackupDestination) error {
	if d.Keep < 0 || d.Keep > 1000 {
		return fmt.Errorf("keep between 1 and 1000 backups")
	}
	if d.Port < 0 || d.Port > 65535 {
		return fmt.Errorf("the port must be between 1 and 65535")
	}
	switch d.Kind {
	case models.BackupToFolder:
		if !filepath.IsAbs(d.Path) {
			return fmt.Errorf("the folder must be a full path")
		}
		return nil
	case models.BackupToSFTP:
		if d.Auth != models.SFTPPassword && d.Auth != models.SFTPKey {
			return fmt.Errorf("choose how to sign in: a password or a key")
		}
	case models.BackupToFTPS:
		if d.TLS != models.FTPSExplicit && d.TLS != models.FTPSImplicit {
			return fmt.Errorf("choose explicit or implicit TLS")
		}
	case models.BackupToFTP:
		if !d.Cleartext {
			return fmt.Errorf("FTP sends the password in the clear: acknowledge it, or use SFTP or FTPS")
		}
	default:
		return fmt.Errorf("unknown destination kind %q", d.Kind)
	}
	if strings.TrimSpace(d.Host) == "" {
		return fmt.Errorf("the server's address is missing")
	}
	if strings.ContainsAny(d.Host, "/ ") {
		return fmt.Errorf("the server's address is a host name or an IP address, without a scheme or a path")
	}
	if d.User == "" && d.Kind == models.BackupToSFTP {
		return fmt.Errorf("the user name is missing")
	}
	return nil
}

// AccessKey names what a destination's credential was given for: the
// server, the account and how it signs in. A credential stored for one is
// never sent to another — moving a destination means typing it again.
func AccessKey(d models.BackupDestination) string {
	return strings.Join([]string{"backup", d.Kind, d.User + "@" + d.Host + ":" + strconv.Itoa(d.Port), d.Auth, d.TLS}, "|")
}

// NeedsSecret says whether a destination signs in with something to keep.
func NeedsSecret(d models.BackupDestination) bool {
	return d.Kind == models.BackupToSFTP || ((d.Kind == models.BackupToFTPS || d.Kind == models.BackupToFTP) && d.User != "")
}

// Upload sends the copy at src, a file on this machine, to t as name, and
// checks that it arrived whole.
func Upload(t Target, src, name string, progress Progress) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	size := fileSize(src)
	sum := sha256.New()
	r := io.TeeReader(&progressReader{r: in, progress: scaled(progress, size)}, sum)
	if err := t.Put(name, r); err != nil {
		return err
	}
	if err := t.Check(name, size, sum.Sum(nil)); err != nil {
		t.Remove(name)
		return fmt.Errorf("the backup did not arrive whole: %w", err)
	}
	return nil
}

// List lists the copies made here that t holds, newest first.
func List(t Target) ([]models.BackupFile, error) {
	entries, err := t.List()
	if err != nil {
		return nil, err
	}
	var out []models.BackupFile
	for _, e := range entries {
		if IsName(e.Name) {
			out = append(out, fromName(e.Name, e.Size, e.ModTime))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name > out[j].Name })
	return out, nil
}

// Prune deletes the oldest copies at t beyond keep, and says which, along
// with what a copy cut short left behind. The copies made before a restore
// are left to the user: they are what undoes it.
func Prune(t Target, keep int) ([]string, error) {
	if keep < 1 {
		keep = models.DefaultBackupKeep
	}
	entries, err := t.List()
	if err != nil {
		return nil, err
	}
	var copies []string
	var removed []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name, partExt) && IsName(strings.TrimSuffix(e.Name, partExt)) &&
			time.Since(e.ModTime) > time.Hour && !e.ModTime.IsZero() {
			if t.Remove(e.Name) == nil {
				removed = append(removed, e.Name)
			}
			continue
		}
		if _, safety, ok := parseName(e.Name); ok && !safety {
			copies = append(copies, e.Name)
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(copies)))
	for i, name := range copies {
		if i < keep {
			continue
		}
		if err := t.Remove(name); err != nil {
			return removed, err
		}
		removed = append(removed, name)
	}
	return removed, nil
}

// --- connections ------------------------------------------------------------

// idleConn gives up on a connection that moves nothing for idleTimeout.
type idleConn struct {
	net.Conn
	closed *atomicBool
}

type atomicBool struct{ atomic.Bool }

func (c idleConn) open() bool { return !c.closed.Load() }

func (c idleConn) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

func (c idleConn) Read(b []byte) (int, error) {
	c.Conn.SetDeadline(time.Now().Add(idleTimeout))
	return c.Conn.Read(b)
}

func (c idleConn) Write(b []byte) (int, error) {
	c.Conn.SetDeadline(time.Now().Add(idleTimeout))
	return c.Conn.Write(b)
}

// guard holds the connections a target dials, to cut them when its context
// ends — a backup being stopped does not wait for a server — or when signing
// in takes longer than dialTimeout: a server that accepts and then says
// nothing would otherwise hold the handshake for the whole idleTimeout.
type guard struct {
	mu        sync.Mutex
	conns     []net.Conn
	cut       bool
	done      chan struct{}
	once      sync.Once
	handshake *time.Timer
}

func newGuard(ctx context.Context) *guard {
	g := &guard{done: make(chan struct{})}
	g.handshake = time.AfterFunc(dialTimeout, g.cutAll)
	go func() {
		select {
		case <-ctx.Done():
			g.cutAll()
		case <-g.done:
		}
	}()
	return g
}

// dial reaches address, the connection held by the guard and given up when
// idle.
func (g *guard) dial(ctx context.Context, address string) (net.Conn, error) {
	d := net.Dialer{Timeout: dialTimeout}
	conn, err := d.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.cut {
		conn.Close()
		return nil, errors.New("the connection was given up")
	}
	// Data connections come and go; keep the live ones only.
	live := g.conns[:0]
	for _, c := range g.conns {
		if c.(idleConn).open() {
			live = append(live, c)
		}
	}
	ic := idleConn{Conn: conn, closed: new(atomicBool)}
	g.conns = append(live, ic)
	return ic, nil
}

// signedIn ends the handshake's time limit.
func (g *guard) signedIn() { g.handshake.Stop() }

func (g *guard) cutAll() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.cut = true
	for _, c := range g.conns {
		c.Close()
	}
}

// release lets the connections go: the target is closed.
func (g *guard) release() {
	g.handshake.Stop()
	g.once.Do(func() { close(g.done) })
}

func hostPort(host string, port, def int) string {
	if port == 0 {
		port = def
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

// --- a folder ---------------------------------------------------------------

type folder struct{ dir string }

func openFolder(dir string) (Target, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return folder{dir}, nil
}

func (f folder) path(name string) (string, error) {
	if name == "" || name != filepath.Base(name) || name == "." || name == ".." {
		return "", fmt.Errorf("not a file name: %q", name)
	}
	return filepath.Join(f.dir, name), nil
}

func (f folder) Put(name string, r io.Reader) error {
	p, err := f.path(name)
	if err != nil {
		return err
	}
	return vaultWriteAtomically(p, r)
}

func (f folder) Check(name string, size int64, sum []byte) error {
	p, err := f.path(name)
	if err != nil {
		return err
	}
	in, err := os.Open(p)
	if err != nil {
		return err
	}
	defer in.Close()
	h := sha256.New()
	n, err := io.Copy(h, in)
	if err != nil {
		return err
	}
	if n != size || !bytes.Equal(h.Sum(nil), sum) {
		return errors.New("what was written does not read back the same")
	}
	return nil
}

func (f folder) Open(name string) (io.ReadCloser, error) {
	p, err := f.path(name)
	if err != nil {
		return nil, err
	}
	return os.Open(p)
}

func (f folder) List() ([]Entry, error) {
	des, err := os.ReadDir(f.dir)
	if err != nil {
		return nil, err
	}
	var out []Entry
	for _, de := range des {
		if de.IsDir() {
			continue
		}
		info, err := de.Info()
		if err != nil {
			continue
		}
		out = append(out, Entry{Name: de.Name(), Size: info.Size(), ModTime: info.ModTime()})
	}
	return out, nil
}

func (f folder) Remove(name string) error {
	p, err := f.path(name)
	if err != nil {
		return err
	}
	return os.Remove(p)
}

func (folder) Close() error { return nil }

func vaultWriteAtomically(path string, r io.Reader) error {
	return vault.WriteAtomically(path, func(w io.Writer) error {
		_, err := io.Copy(w, r)
		return err
	})
}

// Fetch opens the copy name at d, as a reader that closes the connection
// with it, and says its size if the destination does.
func Fetch(ctx context.Context, d models.BackupDestination, a models.BackupAccess, name string) (io.ReadCloser, int64, error) {
	t, err := Connect(ctx, d, a)
	if err != nil {
		return nil, 0, err
	}
	var size int64
	if entries, err := t.List(); err == nil {
		for _, e := range entries {
			if e.Name == name {
				size = e.Size
			}
		}
	}
	r, err := t.Open(name)
	if err != nil {
		t.Close()
		return nil, 0, err
	}
	return fetched{r, t}, size, nil
}

type fetched struct {
	io.ReadCloser
	t Target
}

func (f fetched) Close() error {
	f.ReadCloser.Close()
	return f.t.Close()
}

// WriteTo lets a server's own concurrent reading through: an SFTP file read
// a packet at a time, each waiting for its answer, crawls.
func (f fetched) WriteTo(w io.Writer) (int64, error) {
	if wt, ok := f.ReadCloser.(io.WriterTo); ok {
		return wt.WriteTo(w)
	}
	return io.Copy(w, struct{ io.Reader }{f.ReadCloser})
}
