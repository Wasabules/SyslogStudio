package vault

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// A vault file:
//
//	"SSVAULT1"        8 bytes
//	header length     4 bytes, big-endian
//	header            JSON (Header)
//	chunks            each: 4-byte big-endian length, 1 flag byte (1 on the
//	                  last chunk), then the AES-256-GCM ciphertext of at most
//	                  ChunkSize bytes
//
// The file key is Argon2id(master, Header.Salt): a fresh salt per file, so no
// two files share a key. Chunk i is sealed with the nonce 0000‖i and the
// additional data SHA-256(magic‖length‖header)‖i‖flag. So the header cannot
// be altered, nor chunks reordered or dropped, nor the file cut short: the
// last chunk says it is the last, and nothing may follow it.
//
// It is read and written a chunk at a time: the memory it takes does not
// grow with the file, where the format before it held the whole database.

const (
	// FormatVersion is the version this code writes. Every version it ever
	// wrote stays readable: testdata holds one file of each.
	FormatVersion = 1
	// ChunkSize is how much plaintext one chunk holds.
	ChunkSize = 1 << 20

	maxHeader = 1 << 20
)

var magic = []byte("SSVAULT1")

// chunkSize is what Encrypt writes: ChunkSize, but for tests that need a
// file of many chunks without megabytes of it. Decrypt reads the size from
// the header.
var chunkSize = ChunkSize

// The kinds of vault file.
const (
	KindDatabase = "database"
	KindBackup   = "backup"
)

var (
	// ErrNotVault is a file that is not in this format at all.
	ErrNotVault = errors.New("not an encrypted SyslogStudio file")
	// ErrDamaged is a file that does not authenticate: the wrong key, or
	// altered, or damaged on disk.
	ErrDamaged = errors.New("the file does not decrypt: wrong key, or damaged")
	// ErrTruncated is a file that ends before its last chunk.
	ErrTruncated = errors.New("the file is incomplete: it ends before its last part")
)

// Header is what a vault file says about itself in the clear.
type Header struct {
	Version   int    `json:"v"`
	Kind      string `json:"kind"`
	Created   string `json:"created"`
	Salt      []byte `json:"salt"`
	ChunkSize int    `json:"chunk"`
	// Slots are the locks that open the master secret, for a file that must
	// open on its own: a backup. A database's are in the installation's
	// keyring instead.
	Slots []Slot `json:"slots,omitempty"`
	// App is the version that wrote the file.
	App string `json:"app,omitempty"`
}

// IsVault reports whether data starts like a vault file.
func IsVault(prefix []byte) bool {
	return len(prefix) >= len(magic) && string(prefix[:len(magic)]) == string(magic)
}

// IsVaultFile reports whether the file at path is a vault file.
func IsVaultFile(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	head := make([]byte, len(magic))
	if _, err := io.ReadFull(f, head); err != nil {
		return false
	}
	return IsVault(head)
}

func chunkAAD(headerSum []byte, index uint64, last bool) []byte {
	aad := make([]byte, 0, len(headerSum)+9)
	aad = append(aad, headerSum...)
	aad = binary.BigEndian.AppendUint64(aad, index)
	if last {
		return append(aad, 1)
	}
	return append(aad, 0)
}

func chunkNonce(index uint64) []byte {
	n := make([]byte, 12)
	binary.BigEndian.PutUint64(n[4:], index)
	return n
}

// Encrypt writes r to w encrypted with master. h says what the file is and
// carries its slots; the rest of it is filled in. progress, if not nil, is
// told how many plaintext bytes are done.
func Encrypt(w io.Writer, r io.Reader, master string, h Header, progress func(int64)) error {
	h.Version, h.Created, h.Salt, h.ChunkSize = FormatVersion, now(), random(16), chunkSize
	head, err := json.Marshal(h)
	if err != nil {
		return err
	}
	// What readPrelude refuses is not written: the file would not open.
	if len(head) > maxHeader {
		return fmt.Errorf("the header is too large: %d bytes", len(head))
	}
	prelude := make([]byte, 0, len(magic)+4+len(head))
	prelude = append(prelude, magic...)
	prelude = binary.BigEndian.AppendUint32(prelude, uint32(len(head)))
	prelude = append(prelude, head...)
	if _, err := w.Write(prelude); err != nil {
		return err
	}
	sum := sha256.Sum256(prelude)
	g, err := gcm(deriveKey(master, h.Salt))
	if err != nil {
		return err
	}

	br := bufio.NewReaderSize(r, chunkSize)
	cur := make([]byte, chunkSize)
	next := make([]byte, chunkSize)
	n, err := io.ReadFull(br, cur)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return err
	}
	var done int64
	out := make([]byte, 0, 5+chunkSize+g.Overhead())
	for index := uint64(0); ; index++ {
		// Read ahead: a chunk is the last when nothing follows it.
		m := 0
		last := err != nil
		if !last {
			m, err = io.ReadFull(br, next)
			if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
				return err
			}
			last = m == 0
		}
		ct := g.Seal(nil, chunkNonce(index), cur[:n], chunkAAD(sum[:], index, last))
		out = binary.BigEndian.AppendUint32(out[:0], uint32(len(ct)))
		if last {
			out = append(out, 1)
		} else {
			out = append(out, 0)
		}
		if _, werr := w.Write(append(out, ct...)); werr != nil {
			return werr
		}
		done += int64(n)
		if progress != nil {
			progress(done)
		}
		if last {
			return nil
		}
		cur, next, n = next, cur, m
	}
}

func readPrelude(r io.Reader) (Header, []byte, error) {
	fixed := make([]byte, len(magic)+4)
	if _, err := io.ReadFull(r, fixed); err != nil {
		return Header{}, nil, ErrNotVault
	}
	if !IsVault(fixed) {
		return Header{}, nil, ErrNotVault
	}
	size := binary.BigEndian.Uint32(fixed[len(magic):])
	if size > maxHeader {
		return Header{}, nil, ErrNotVault
	}
	head := make([]byte, size)
	if _, err := io.ReadFull(r, head); err != nil {
		return Header{}, nil, ErrTruncated
	}
	var h Header
	if err := json.Unmarshal(head, &h); err != nil {
		return Header{}, nil, fmt.Errorf("%w: unreadable header", ErrNotVault)
	}
	if h.Version < 1 || h.Version > FormatVersion {
		return Header{}, nil, fmt.Errorf("written by a newer SyslogStudio (format %d): update to open it", h.Version)
	}
	if h.ChunkSize <= 0 || h.ChunkSize > 64<<20 {
		return Header{}, nil, fmt.Errorf("%w: bad chunk size", ErrNotVault)
	}
	return h, append(fixed, head...), nil
}

// PeekReader wraps r so that PeekHeader can read what a vault stream says
// about itself without consuming it: Decrypt then reads it from the start.
func PeekReader(r io.Reader) *bufio.Reader {
	return bufio.NewReaderSize(r, len(magic)+4+maxHeader)
}

// PeekHeader is ReadHeader of a PeekReader, leaving it where it was.
func PeekHeader(br *bufio.Reader) (Header, error) {
	fixed, err := br.Peek(len(magic) + 4)
	if err != nil || !IsVault(fixed) {
		return Header{}, ErrNotVault
	}
	size := binary.BigEndian.Uint32(fixed[len(magic):])
	if size > maxHeader {
		return Header{}, ErrNotVault
	}
	prelude, err := br.Peek(len(magic) + 4 + int(size))
	if err != nil {
		return Header{}, ErrTruncated
	}
	return ReadHeader(bytes.NewReader(prelude))
}

// ReadHeader reads what a vault file says about itself, without decrypting it.
func ReadHeader(r io.Reader) (Header, error) {
	h, _, err := readPrelude(r)
	return h, err
}

// ReadFileHeader is ReadHeader of the file at path.
func ReadFileHeader(path string) (Header, error) {
	f, err := os.Open(path)
	if err != nil {
		return Header{}, err
	}
	defer f.Close()
	return ReadHeader(bufio.NewReader(f))
}

// Decrypt writes what r holds to w, decrypted with master, and says what the
// file said about itself. Nothing of a chunk reaches w before it has
// authenticated.
func Decrypt(w io.Writer, r io.Reader, master string, progress func(int64)) (Header, error) {
	br := bufio.NewReaderSize(r, ChunkSize+64)
	h, prelude, err := readPrelude(br)
	if err != nil {
		return h, err
	}
	sum := sha256.Sum256(prelude)
	g, err := gcm(deriveKey(master, h.Salt))
	if err != nil {
		return h, err
	}
	var done int64
	frame := make([]byte, 5)
	ct := make([]byte, 0, h.ChunkSize+g.Overhead())
	for index := uint64(0); ; index++ {
		if _, err := io.ReadFull(br, frame); err != nil {
			return h, ErrTruncated
		}
		size := binary.BigEndian.Uint32(frame)
		last := frame[4] == 1
		if size > uint32(h.ChunkSize+g.Overhead()) || frame[4] > 1 {
			return h, ErrDamaged
		}
		ct = ct[:size]
		if _, err := io.ReadFull(br, ct); err != nil {
			return h, ErrTruncated
		}
		plain, err := g.Open(nil, chunkNonce(index), ct, chunkAAD(sum[:], index, last))
		if err != nil {
			return h, ErrDamaged
		}
		if _, err := w.Write(plain); err != nil {
			return h, err
		}
		done += int64(len(plain))
		if progress != nil {
			progress(done)
		}
		if last {
			if _, err := br.ReadByte(); err != io.EOF {
				return h, fmt.Errorf("%w: data after the last part", ErrDamaged)
			}
			return h, nil
		}
	}
}

// EncryptFile encrypts the file at src into dst. dst appears whole or not at
// all: it is written beside, synced, then renamed into place.
func EncryptFile(src, dst, master string, h Header, progress func(int64)) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	return writeAtomically(dst, func(w io.Writer) error {
		return Encrypt(w, in, master, h, progress)
	})
}

// DecryptFile decrypts the file at src into dst, which appears only once the
// whole file has authenticated.
func DecryptFile(src, dst, master string, progress func(int64)) (Header, error) {
	in, err := os.Open(src)
	if err != nil {
		return Header{}, err
	}
	defer in.Close()
	var h Header
	err = writeAtomically(dst, func(w io.Writer) error {
		var derr error
		h, derr = Decrypt(w, in, master, progress)
		return derr
	})
	return h, err
}

// Verify decrypts a file without writing it anywhere: it is whole, and
// master opens it.
func Verify(path, master string, progress func(int64)) (Header, error) {
	in, err := os.Open(path)
	if err != nil {
		return Header{}, err
	}
	defer in.Close()
	return Decrypt(io.Discard, in, master, progress)
}

// WriteAtomically writes dst through write: beside it first, synced, then
// renamed into place, so that it appears whole or not at all.
func WriteAtomically(dst string, write func(io.Writer) error) error {
	return writeAtomically(dst, write)
}

func writeAtomically(dst string, write func(io.Writer) error) error {
	tmp := dst + ".part"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	bw := bufio.NewWriterSize(f, 4<<20)
	err = write(bw)
	if err == nil {
		err = bw.Flush()
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		os.Remove(tmp)
		return err
	}
	syncDir(filepath.Dir(dst))
	return nil
}
