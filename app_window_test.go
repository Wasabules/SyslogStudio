package main

import (
	"testing"

	"SyslogStudio/internal/models"
	"SyslogStudio/internal/storage"
)

// Closing to the tray swallows the window's close, and a plain runtime Quit
// goes through that same interception. The quit the updater is given must not:
// an update that leaves the application running cannot replace its executable.
func TestQuitApplication_IsNotInterceptedByCloseToTray(t *testing.T) {
	t.Cleanup(func() {
		window.mu.Lock()
		window.quitting = false
		window.mu.Unlock()
	})
	a := newAppIn(storage.NewConfigStoreAt(t.TempDir()))

	for _, action := range []models.CloseAction{models.CloseBackground, models.CloseAsk} {
		a.prefs.SaveCloseAction(action)
		if !a.beforeClose() {
			t.Fatalf("with %q, closing the window was not intercepted", action)
		}
	}

	a.QuitApplication()
	if a.beforeClose() {
		t.Fatal("the quit an update relies on was intercepted")
	}
}
