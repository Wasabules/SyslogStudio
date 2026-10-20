package storage

import (
	"os"
	"testing"

	"SyslogStudio/internal/testenv"
)

// TestMain keeps the tests away from the user's own files (see testenv).
func TestMain(m *testing.M) { os.Exit(testenv.Run(m)) }
