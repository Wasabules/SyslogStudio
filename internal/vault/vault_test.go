package vault

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var writeFixture = flag.Bool("write-fixture", false, "write testdata/v1 — once, for a new format version")

func data(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7 + i/1000)
	}
	return b
}

func seal(t *testing.T, plain []byte, master string, h Header) []byte {
	t.Helper()
	var out bytes.Buffer
	if err := Encrypt(&out, bytes.NewReader(plain), master, h, nil); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func TestRoundTrip(t *testing.T) {
	master := NewMaster()
	for _, n := range []int{0, 1, ChunkSize - 1, ChunkSize, ChunkSize + 1, 3*ChunkSize + ChunkSize/2} {
		plain := data(n)
		var seen int64
		var out bytes.Buffer
		if err := Encrypt(&out, bytes.NewReader(plain), master, Header{Kind: KindDatabase}, func(d int64) { seen = d }); err != nil {
			t.Fatal(err)
		}
		if seen != int64(n) {
			t.Errorf("%d bytes: progress said %d", n, seen)
		}
		var back bytes.Buffer
		h, err := Decrypt(&back, bytes.NewReader(out.Bytes()), master, nil)
		if err != nil {
			t.Fatalf("%d bytes: %v", n, err)
		}
		if !bytes.Equal(back.Bytes(), plain) || h.Kind != KindDatabase || h.Version != FormatVersion {
			t.Fatalf("%d bytes: did not round-trip (header %+v)", n, h)
		}
	}
}

// Every way a file can be wrong is refused, and nothing of it is trusted.
func TestTampering(t *testing.T) {
	master := NewMaster()
	plain := data(2*ChunkSize + 100)
	file := seal(t, plain, master, Header{Kind: KindBackup})
	open := func(b []byte, key string) error {
		_, err := Decrypt(&bytes.Buffer{}, bytes.NewReader(b), key, nil)
		return err
	}
	headLen := len(magic) + 4 + int(binary.BigEndian.Uint32(file[len(magic):]))
	first := headLen // first chunk frame
	chunkLen := 5 + int(binary.BigEndian.Uint32(file[first:]))

	cases := map[string]struct {
		file []byte
		key  string
		want error
	}{
		"another master":    {file, NewMaster(), ErrDamaged},
		"cut short":         {file[:len(file)-10], master, ErrTruncated},
		"last part missing": {file[:first+2*chunkLen], master, ErrTruncated},
		"data appended":     {append(append([]byte{}, file...), 0), master, ErrDamaged},
		"a bit flipped": {func() []byte {
			b := append([]byte{}, file...)
			b[first+chunkLen+100] ^= 1
			return b
		}(), master, ErrDamaged},
		"first part marked last": {func() []byte {
			b := append([]byte{}, file[:first+chunkLen]...)
			b[first+4] = 1
			return b
		}(), master, ErrDamaged},
		"parts swapped": {func() []byte {
			b := append([]byte{}, file[:first]...)
			b = append(b, file[first+chunkLen:first+2*chunkLen]...)
			b = append(b, file[first:first+chunkLen]...)
			return append(b, file[first+2*chunkLen:]...)
		}(), master, ErrDamaged},
		"header altered": {func() []byte {
			b := append([]byte{}, file...)
			i := bytes.Index(b, []byte(`"backup"`))
			copy(b[i:], `"bockup"`)
			return b
		}(), master, ErrDamaged},
		"not a vault file": {[]byte("SQLite format 3\x00 and so on"), master, ErrNotVault},
	}
	for name, c := range cases {
		if err := open(c.file, c.key); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}
}

func TestNewerFormatIsRefusedPlainly(t *testing.T) {
	h, _ := json.Marshal(Header{Version: FormatVersion + 1, ChunkSize: ChunkSize})
	b := append(append([]byte{}, magic...), binary.BigEndian.AppendUint32(nil, uint32(len(h)))...)
	b = append(b, h...)
	_, err := Decrypt(&bytes.Buffer{}, bytes.NewReader(b), NewMaster(), nil)
	if err == nil || !strings.Contains(err.Error(), "newer") {
		t.Fatalf("a newer format: %v", err)
	}
}

func TestSlots(t *testing.T) {
	master := NewMaster()
	pw, err := PasswordSlot(master, "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	file, pub, id, err := GenerateRecoveryKey()
	if err != nil {
		t.Fatal(err)
	}
	key, err := KeySlot(master, pub)
	if err != nil {
		t.Fatal(err)
	}
	slots := []Slot{pw, key}
	if got, err := OpenWithPassword(slots, "correct horse battery"); err != nil || got != master {
		t.Fatalf("password: %v", err)
	}
	if _, err := OpenWithPassword(slots, "wrong horse battery"); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("wrong password: %v", err)
	}
	priv, pid, err := ParseRecoveryKey(file)
	if err != nil || pid != id || key.KeyID != id {
		t.Fatalf("key file: %v %s %s", err, pid, id)
	}
	if got, err := OpenWithKey(slots, priv); err != nil || got != master {
		t.Fatalf("recovery key: %v", err)
	}
	other, _, _, _ := GenerateRecoveryKey()
	otherPriv, _, _ := ParseRecoveryKey(other)
	if _, err := OpenWithKey(slots, otherPriv); !errors.Is(err, ErrNoSlotForKey) {
		t.Fatalf("another key: %v", err)
	}
	// A key file damaged in transit is refused, not taken for another key.
	broken := bytes.Replace(file, []byte("Key-ID: "+id), []byte("Key-ID: 0000000000000000"), 1)
	if _, _, err := ParseRecoveryKey(broken); err == nil {
		t.Error("a key file whose name does not match its key was accepted")
	}
	if _, _, err := ParseRecoveryKey([]byte("hello")); err == nil {
		t.Error("not a key file, accepted")
	}
	if !IsGenerated(master) || IsGenerated("an old password") {
		t.Error("IsGenerated")
	}
}

// A file written by format version 1 opens with every later version: the
// one in testdata was written once, by the code that introduced the format,
// with a password slot and a recovery key slot, and is never rewritten.
func TestFormatV1StillOpens(t *testing.T) {
	dir := filepath.Join("testdata", "v1")
	const password = "vault v1 fixture password"
	// Small chunks: several of them, in a fixture of a few kilobytes.
	plain := data(3*1024 + 321)
	if *writeFixture {
		chunkSize = 1024
		defer func() { chunkSize = ChunkSize }()
		if _, err := os.Stat(dir); err == nil {
			t.Fatal("testdata/v1 exists: a fixture is never rewritten")
		}
		os.MkdirAll(dir, 0o755)
		master := NewMaster()
		pw, _ := PasswordSlot(master, password)
		file, pub, _, _ := GenerateRecoveryKey()
		key, _ := KeySlot(master, pub)
		out := seal(t, plain, master, Header{Kind: KindBackup, Slots: []Slot{pw, key}, App: "fixture"})
		os.WriteFile(filepath.Join(dir, "backup.ssbackup"), out, 0o644)
		os.WriteFile(filepath.Join(dir, "recovery.key"), file, 0o644)
	}
	file, err := os.ReadFile(filepath.Join(dir, "backup.ssbackup"))
	if err != nil {
		t.Fatal(err)
	}
	keyFile, err := os.ReadFile(filepath.Join(dir, "recovery.key"))
	if err != nil {
		t.Fatal(err)
	}
	h, err := ReadHeader(bytes.NewReader(file))
	if err != nil || h.Version != 1 || len(h.Slots) != 2 || h.ChunkSize != 1024 {
		t.Fatalf("header %+v: %v", h, err)
	}
	byPassword, err := OpenWithPassword(h.Slots, password)
	if err != nil {
		t.Fatal(err)
	}
	priv, _, err := ParseRecoveryKey(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	byKey, err := OpenWithKey(h.Slots, priv)
	if err != nil || byKey != byPassword {
		t.Fatalf("the key opens %q (%v), the password %q", byKey, err, byPassword)
	}
	var back bytes.Buffer
	if _, err := Decrypt(&back, bytes.NewReader(file), byPassword, nil); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back.Bytes(), plain) {
		t.Fatal("the v1 fixture decrypts to something else")
	}
}

func TestFiles(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "plain.db")
	os.WriteFile(src, data(ChunkSize*2+7), 0o600)
	master := NewMaster()
	enc := filepath.Join(dir, "x.enc")
	if err := EncryptFile(src, enc, master, Header{Kind: KindDatabase}, nil); err != nil {
		t.Fatal(err)
	}
	if !IsVaultFile(enc) || IsVaultFile(src) {
		t.Fatal("IsVaultFile")
	}
	if _, err := Verify(enc, master); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "back.db")
	if _, err := DecryptFile(enc, out, NewMaster(), nil); err == nil {
		t.Fatal("decrypted with another master")
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("a file that did not authenticate was left behind")
	}
	if _, err := DecryptFile(enc, out, master, nil); err != nil {
		t.Fatal(err)
	}
	a, _ := os.ReadFile(src)
	b, _ := os.ReadFile(out)
	if !bytes.Equal(a, b) {
		t.Fatal("files did not round-trip")
	}
}
