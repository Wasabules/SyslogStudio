package backup

import (
	"bufio"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	ftpserver "github.com/fclairamb/ftpserverlib"
	"golang.org/x/crypto/ssh"

	"SyslogStudio/internal/models"
)

// How fast a copy goes to a server and comes back, on servers in this
// process — the transport's own cost, without a network's. Not part of the
// suite:
//
//	SYSLOGSTUDIO_BIGUPLOAD=700 go test -run TestBigUpload -v ./internal/backup
func TestBigUpload(t *testing.T) {
	mb, _ := strconv.Atoi(os.Getenv("SYSLOGSTUDIO_BIGUPLOAD"))
	if mb == 0 {
		t.Skip("set SYSLOGSTUDIO_BIGUPLOAD to a size in MB")
	}
	src := filepath.Join(t.TempDir(), "copy")
	f, err := os.Create(src)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.CopyN(f, rand.Reader, int64(mb)<<20); err != nil {
		t.Fatal(err)
	}
	f.Close()

	srv := startSFTP(t, nil)
	host, port := hostAndPort(t, srv.addr)
	sftpDest := models.BackupDestination{Kind: models.BackupToSFTP, Host: host, Port: port, User: serverUser,
		Auth: models.SFTPPassword, HostKey: ssh.FingerprintSHA256(srv.hostKey), Path: "b"}
	ftpsAddr, leaf, _ := startFTP(t, ftpserver.MandatoryEncryption, true)
	h2, p2 := hostAndPort(t, ftpsAddr)
	ftpsDest := models.BackupDestination{Kind: models.BackupToFTPS, Host: h2, Port: p2, User: serverUser,
		TLS: models.FTPSExplicit, CertPin: CertFingerprint(leaf), Path: "b"}
	ftpAddr, _, _ := startFTP(t, ftpserver.ClearOrEncrypted, false)
	h3, p3 := hostAndPort(t, ftpAddr)
	ftpDest := models.BackupDestination{Kind: models.BackupToFTP, Host: h3, Port: p3, User: serverUser, Cleartext: true, Path: "b"}

	for _, d := range []models.BackupDestination{sftpDest, ftpsDest, ftpDest} {
		a := models.BackupAccess{Password: serverPassword}
		tg, err := Connect(context.Background(), d, a)
		if err != nil {
			t.Fatal(err)
		}
		name := Name(time.Now(), false, true)
		start := time.Now()
		if err := Upload(tg, src, name, nil); err != nil {
			t.Fatal(err)
		}
		up := time.Since(start)
		tg.Close()
		start = time.Now()
		r, _, err := Fetch(context.Background(), d, a, name)
		if err != nil {
			t.Fatal(err)
		}
		// As a copy is read to be opened: through Unseal's large buffer.
		n, err := io.CopyBuffer(io.Discard, struct{ io.Reader }{bufio.NewReaderSize(r, 1<<20)}, make([]byte, 1<<20))
		r.Close()
		if err != nil || n != int64(mb)<<20 {
			t.Fatalf("%s: read back %d bytes (%v)", d.Kind, n, err)
		}
		down := time.Since(start)
		fmt.Printf("%-5s %d MB: up %s (%.0f MB/s), down %s (%.0f MB/s)\n", d.Kind, mb,
			up.Round(time.Millisecond), float64(mb)/up.Seconds(), down.Round(time.Millisecond), float64(mb)/down.Seconds())
	}
}
