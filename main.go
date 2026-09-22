package main

import (
	"context"
	"embed"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	goruntime "runtime"

	// Embeds the IANA time zone database. Without it, time.LoadLocation depends
	// on zone files being present on the host — which they are not on Windows,
	// so a user picking "Asia/Tokyo" for exports would silently get UTC. 450 KB
	// for a setting that is otherwise broken on the platform most users run.
	_ "time/tzdata"

	"SyslogStudio/internal/tray"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/windows"
)

// The tray icon. Windows wants an .ico; everything else takes the PNG.
//
//go:embed build/windows/icon.ico
var trayIconWindows []byte

//go:embed build/appicon.png
var trayIconOther []byte

func trayIcon() []byte {
	if goruntime.GOOS == "windows" {
		return trayIconWindows
	}
	return trayIconOther
}

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	distFS, err := fs.Sub(assets, "frontend/dist")
	if err != nil {
		log.Fatal("Failed to create sub FS:", err)
	}

	// Store WebView2 data (localStorage: theme, locale) under a stable per-user
	// directory rather than the temp dir, which OS temp cleaners (Disk Cleanup,
	// Storage Sense) periodically wipe — silently resetting the user's prefs.
	webviewDataPath := filepath.Join(os.TempDir(), "SyslogStudio")
	if cacheDir, cerr := os.UserCacheDir(); cerr == nil {
		webviewDataPath = filepath.Join(cacheDir, "SyslogStudio", "WebView2")
	}

	app := NewApp()

	err = wails.Run(&options.App{
		Title:     "SyslogStudio",
		Width:     1280,
		Height:    800,
		MinWidth:  900,
		MinHeight: 600,
		AssetServer: &assetserver.Options{
			Assets: distFS,
		},
		BackgroundColour: &options.RGBA{R: 27, G: 38, B: 54, A: 1},
		Windows: &windows.Options{
			WebviewUserDataPath: webviewDataPath,
		},
		OnStartup: func(ctx context.Context) {
			app.startup(ctx)

			// Started after startup so the callbacks have a context to act on,
			// and so a desktop with no tray host delays nothing the user can
			// see: Start gives up after its own timeout and reports that no
			// icon appeared.
			ctrl, ok := tray.Start(tray.Options{
				Icon:    trayIcon(),
				Tooltip: "SyslogStudio",
				Labels:  tray.DefaultLabels(),
				OnShow:  app.RevealWindow,
				OnQuit:  app.QuitApplication,
			})
			setTray(ctrl, ok)
			app.refreshTrayStatus()
		},
		OnShutdown: func(ctx context.Context) {
			// Before the application's own shutdown, so the icon goes away
			// promptly rather than lingering while the database is flushed.
			trayController().Stop()
			app.shutdown(ctx)
		},
		// HideWindowOnClose is deliberately NOT set. It is fixed here, before
		// we know whether a tray icon actually appeared, and an application
		// that refuses to close with no tray to quit from is one you escape
		// with the task manager. beforeClose makes the same decision later,
		// when the answer is known — and asks the user rather than assuming.
		OnBeforeClose: func(context.Context) bool {
			return app.beforeClose()
		},
		SingleInstanceLock: &options.SingleInstanceLock{
			UniqueId: "com.wasabules.syslogstudio",
			// Relaunching is the second way back to a hidden window, and it is
			// the one that still works on a desktop with no usable tray. It
			// also stops a second instance fighting the first for port 514.
			OnSecondInstanceLaunch: func(options.SecondInstanceData) {
				app.RevealWindow()
			},
		},
		Bind: []interface{}{
			app,
		},
	})

	if err != nil {
		log.Fatal("Error:", err)
	}
}
