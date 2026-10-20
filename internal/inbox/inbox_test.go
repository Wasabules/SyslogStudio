package inbox

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"SyslogStudio/internal/models"
)

func messages(n int) []models.SyslogMessage {
	out := make([]models.SyslogMessage, n)
	for i := range out {
		out[i] = models.SyslogMessage{
			ID:         strings.Repeat("x", 4) + string(rune('a'+i%26)) + time.Now().Format("150405.000000000"),
			Hostname:   "web-01",
			Message:    "disk almost full on /var",
			ReceivedAt: time.Date(2026, 10, 20, 12, 0, i, 0, time.UTC),
		}
	}
	return out
}

func TestSeal_OpensWithItsKeyOnly(t *testing.T) {
	priv, pub, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	in := messages(3)
	sealed, err := Seal(pub, in)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("disk almost full")) || bytes.Contains(sealed, []byte("web-01")) {
		t.Fatal("the message text is readable in the sealed batch")
	}

	out, err := Open(priv, sealed)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 3 || out[1].Message != in[1].Message || !out[2].ReceivedAt.Equal(in[2].ReceivedAt) {
		t.Fatalf("opened: %+v", out)
	}

	other, _, _ := GenerateKey()
	var oke *OtherKeyError
	if _, err := Open(other, sealed); !errors.As(err, &oke) || oke.Batch != KeyID(pub) {
		t.Fatalf("opened with another key: %v", err)
	}
	if got, _ := PublicKeyOf(priv); !bytes.Equal(got, pub) {
		t.Fatal("PublicKeyOf does not give back the public key")
	}
}

func TestOpen_RefusesAlteredBatches(t *testing.T) {
	priv, pub, _ := GenerateKey()
	sealed, _ := Seal(pub, messages(1))

	flipped := bytes.Clone(sealed)
	flipped[len(flipped)-5] ^= 1
	if _, err := Open(priv, flipped); err == nil {
		t.Fatal("an altered batch opened")
	}
	if _, err := Open(priv, []byte("plain text, not a batch")); !errors.Is(err, ErrNotABatch) {
		t.Fatalf("not a batch: %v", err)
	}
}

func TestBox_RefusesNamesThatAreNotBatches(t *testing.T) {
	b := Box{Dir: t.TempDir()}
	for _, id := range []string{"../config", `..\config`, "00000000000000000001-000001/../../x", ""} {
		if _, err := b.Read(id); !errors.Is(err, ErrBadID) {
			t.Fatalf("Read(%q): %v", id, err)
		}
		if _, err := b.Remove(id); !errors.Is(err, ErrBadID) {
			t.Fatalf("Remove(%q): %v", id, err)
		}
	}
}

func TestWriter_SealsCollectsAndCounts(t *testing.T) {
	dir := t.TempDir()
	priv, pub, _ := GenerateKey()
	var batches atomic.Int32
	w, err := NewWriter(dir, models.InboxConfig{PublicKey: pub}, nil, func() { batches.Add(1) })
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range messages(5) {
		w.Add(m)
	}
	w.Close()

	if batches.Load() != 1 {
		t.Fatalf("%d batches written, want 1", batches.Load())
	}
	list, err := w.Box().List()
	if err != nil || len(list) != 1 {
		t.Fatalf("list: %+v %v", list, err)
	}
	st := w.Status()
	if !st.Sealed || st.Batches != 1 || st.Bytes != list[0].Bytes || st.KeyID != KeyID(pub) {
		t.Fatalf("status: %+v", st)
	}

	data, err := w.Box().Read(list[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	msgs, err := Open(priv, data)
	if err != nil || len(msgs) != 5 {
		t.Fatalf("collected %d messages: %v", len(msgs), err)
	}

	if err := w.Remove(list[0].ID); err != nil {
		t.Fatal(err)
	}
	if st := w.Status(); st.Batches != 0 || st.Bytes != 0 {
		t.Fatalf("after collecting: %+v", st)
	}
	if err := w.Remove(list[0].ID); err != nil {
		t.Fatalf("a second window collecting the same batch: %v", err)
	}

	// A new writer on the same directory counts what is already there.
	w2, _ := NewWriter(dir, models.InboxConfig{PublicKey: pub}, nil, nil)
	w2.WriteNow(messages(2))
	w2.Close()
	w3, _ := NewWriter(dir, models.InboxConfig{PublicKey: pub}, nil, nil)
	defer w3.Close()
	if st := w3.Status(); st.Batches != 1 {
		t.Fatalf("a restarted writer counts %d batches, want 1", st.Batches)
	}
}

// What a window nobody opens must not do: fill the disk. Past the quota,
// what arrives is dropped, counted, and said.
func TestWriter_KeepsToItsQuota(t *testing.T) {
	_, pub, _ := GenerateKey()
	one, _ := Seal(pub, messages(1))
	quota := int64(len(one))*2 + 10

	w, err := NewWriter(t.TempDir(), models.InboxConfig{PublicKey: pub, QuotaBytes: quota}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	for range 3 {
		w.write(messages(1), true)
	}
	st := w.Status()
	if st.Batches != 2 || st.Dropped != 1 || st.Error == "" {
		t.Fatalf("over the quota: %+v", st)
	}
	if !st.Filling() {
		t.Fatal("a full inbox does not report filling")
	}

	list, _ := w.Box().List()
	w.Remove(list[0].ID)
	if err := w.write(messages(1), true); err != nil {
		t.Fatalf("after a batch was collected: %v", err)
	}
	if st := w.Status(); st.Error != "" {
		t.Fatalf("the error stayed once there was room: %+v", st)
	}
}

func TestWriter_LeavesNoTemporaryFiles(t *testing.T) {
	dir := t.TempDir()
	_, pub, _ := GenerateKey()
	w, _ := NewWriter(dir, models.InboxConfig{PublicKey: pub}, nil, nil)
	w.WriteNow(messages(2))
	w.Close()
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if filepath.Ext(e.Name()) != ext {
			t.Fatalf("left behind: %s", e.Name())
		}
	}
}
