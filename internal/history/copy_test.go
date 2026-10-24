package history

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"SyslogStudio/internal/models"
	"SyslogStudio/internal/storage"
	"SyslogStudio/internal/testenv"
)

// TestMain keeps the tests away from the user's own files (see testenv), and
// copies in batches of 100.
func TestMain(m *testing.M) {
	batch = 100
	os.Exit(testenv.Run(m))
}

func store(t *testing.T) *storage.LogStore {
	t.Helper()
	ls, err := storage.NewLogStore(models.StorageConfig{Enabled: true, Path: filepath.Join(t.TempDir(), "logs.db")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ls.Close)
	ls.WaitReady()
	return ls
}

func messages(prefix string, from, n int) []models.SyslogMessage {
	out := make([]models.SyslogMessage, n)
	now := time.Now()
	for i := range out {
		out[i] = models.SyslogMessage{
			ID:         fmt.Sprintf("%s-%05d", prefix, from+i),
			Hostname:   "fw-01",
			Message:    fmt.Sprintf("%s %d", prefix, from+i),
			Timestamp:  now,
			ReceivedAt: now,
		}
	}
	return out
}

func count(ls *storage.LogStore) int64 {
	n, _, _ := ls.Span()
	return n
}

// What the sink lacks is added; what it holds already stays, counted as
// read but not added.
func TestCopy_MergesWhatTheSinkLacks(t *testing.T) {
	src, dst := store(t), store(t)
	if err := src.InsertMessages(messages("m", 0, 250)); err != nil {
		t.Fatal(err)
	}
	if err := dst.InsertMessages(append(messages("m", 50, 50), messages("own", 0, 25)...)); err != nil {
		t.Fatal(err)
	}
	reports := 0
	p, err := Copy(context.Background(), src, dst, Progress{}, func(Progress) { reports++ })
	if err != nil {
		t.Fatal(err)
	}
	if p.Read != 250 || p.Added != 200 {
		t.Fatalf("read %d, added %d; want 250 and 200", p.Read, p.Added)
	}
	if reports != 3 {
		t.Fatalf("%d reports for 250 messages in batches of %d", reports, batch)
	}
	if n := count(dst); n != 275 {
		t.Fatalf("the sink holds %d messages, want 275", n)
	}

	// Again: nothing to add.
	p, err = Copy(context.Background(), src, dst, Progress{}, nil)
	if err != nil || p.Read != 250 || p.Added != 0 {
		t.Fatalf("a second copy: %+v, %v", p, err)
	}
}

// failingSink stops storing after a number of batches, as a service that
// went away would.
type failingSink struct {
	Sink
	left int
}

func (s *failingSink) MergeMessages(msgs []models.SyslogMessage) (int, error) {
	if s.left == 0 {
		return 0, errors.New("the service went away")
	}
	s.left--
	return s.Sink.MergeMessages(msgs)
}

// A copy that stopped is taken up where it stopped, its counts carried on.
func TestCopy_TakesUpWhereItStopped(t *testing.T) {
	src, dst := store(t), store(t)
	if err := src.InsertMessages(messages("m", 0, 350)); err != nil {
		t.Fatal(err)
	}
	p, err := Copy(context.Background(), src, &failingSink{Sink: dst, left: 2}, Progress{}, nil)
	if err == nil {
		t.Fatal("a copy into a sink that failed reported no error")
	}
	if p.Read != int64(2*batch) || p.Added != int64(2*batch) || p.Cursor == 0 {
		t.Fatalf("stopped at %+v", p)
	}
	p, err = Copy(context.Background(), src, dst, p, nil)
	if err != nil {
		t.Fatal(err)
	}
	if p.Read != 350 || p.Added != 350 {
		t.Fatalf("taken up: read %d, added %d; want 350 both", p.Read, p.Added)
	}
	if n := count(dst); n != 350 {
		t.Fatalf("the sink holds %d messages, want 350", n)
	}
}

// writingSource writes to the source while it is read: a service receiving
// while its history is copied.
type writingSource struct {
	*storage.LogStore
	t     *testing.T
	wrote bool
}

func (s *writingSource) MessagesAfter(after int64, limit int) ([]models.SyslogMessage, int64, error) {
	if !s.wrote {
		s.wrote = true
		if err := s.LogStore.InsertMessages(messages("meanwhile", 0, 30)); err != nil {
			s.t.Fatal(err)
		}
	}
	return s.LogStore.MessagesAfter(after, limit)
}

// What the source receives during the copy is copied too.
func TestCopy_IncludesWhatArrivesMeanwhile(t *testing.T) {
	src, dst := store(t), store(t)
	if err := src.InsertMessages(messages("m", 0, 150)); err != nil {
		t.Fatal(err)
	}
	p, err := Copy(context.Background(), &writingSource{LogStore: src, t: t}, dst, Progress{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if p.Read != 180 || count(dst) != 180 {
		t.Fatalf("read %d, the sink holds %d; want 180", p.Read, count(dst))
	}
}

// A copy stops when it is told to, saying how far it got.
func TestCopy_StopsWhenCancelled(t *testing.T) {
	src, dst := store(t), store(t)
	if err := src.InsertMessages(messages("m", 0, 250)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	p, err := Copy(ctx, src, dst, Progress{}, func(Progress) { cancel() })
	if !errors.Is(err, context.Canceled) || p.Read != int64(batch) {
		t.Fatalf("cancelled after a batch: %+v, %v", p, err)
	}
}
