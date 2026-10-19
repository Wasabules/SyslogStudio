package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"SyslogStudio/internal/autostart"
	"SyslogStudio/internal/headless"
	"SyslogStudio/internal/storage"
	"SyslogStudio/internal/updater"
	"SyslogStudio/internal/winsvc"
)

// The executable is three programs, chosen by how it is started:
//
//	SyslogStudio                       the desktop application
//	SyslogStudio --background          the same, starting hidden in the tray
//	SyslogStudio --headless            the engine alone, in the foreground
//	SyslogStudio service <command>     the Windows service, and managing it
//
// One binary rather than three because they must always be the same version:
// the service reads the configuration the window wrote.

const usageText = `SyslogStudio %s

Usage:
  SyslogStudio                       open the application
  SyslogStudio --background          open it hidden in the system tray
  SyslogStudio --headless [--data-dir DIR]
                                     receive with no window, in the foreground,
                                     until interrupted (for systemd, launchd,
                                     or a terminal); DIR defaults to the
                                     desktop application's own directory
  SyslogStudio service status        show the Windows service's state
  SyslogStudio service install --bundle FILE
  SyslogStudio service uninstall [--purge]
  SyslogStudio service start | stop  manage it (as an administrator)

The service is normally installed from Settings > Background, which prepares
the bundle and asks for administrator rights itself.
`

// runCommandLine handles every way of starting the executable except the
// desktop application. handled is false when the desktop application should
// start.
func runCommandLine(args []string) (handled bool, code int) {
	// Started by the service manager: nothing else applies.
	if winsvc.IsService() {
		if err := winsvc.Run(updater.GetAppVersion()); err != nil {
			return true, 1
		}
		return true, 0
	}
	if len(args) == 0 {
		return false, 0
	}
	switch args[0] {
	case "service":
		return true, serviceCommand(args[1:])
	case "--headless", "headless":
		return true, headlessCommand(args[1:])
	case "--help", "-h", "help", "/?":
		winsvc.AttachConsole()
		fmt.Fprintf(os.Stdout, usageText, updater.GetAppVersion())
		return true, 0
	}
	return false, 0
}

// hasArg reports whether a flag was given, for the ones the desktop
// application reads itself.
func hasArg(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}

func serviceCommand(args []string) int {
	if len(args) == 0 {
		winsvc.AttachConsole()
		fmt.Fprintf(os.Stderr, usageText, updater.GetAppVersion())
		return 2
	}
	cmd := args[0]
	fs := flag.NewFlagSet("service "+cmd, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	bundle := fs.String("bundle", "", "configuration bundle to install")
	result := fs.String("result", "", "where to record the outcome")
	purge := fs.Bool("purge", false, "also delete the service's data")
	if err := fs.Parse(args[1:]); err != nil {
		winsvc.AttachConsole()
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	// An elevated helper started by the window reports through --result; one
	// typed in a terminal reports on the terminal.
	finish := func(err error) int {
		winsvc.WriteResult(*result, err)
		if *result == "" {
			winsvc.AttachConsole()
			if err != nil {
				fmt.Fprintln(os.Stderr, "Error:", err)
			} else {
				fmt.Fprintln(os.Stdout, "Done.")
			}
		}
		if err != nil {
			return 1
		}
		return 0
	}

	switch cmd {
	case "run":
		// Only meaningful under the service manager, which was handled above.
		winsvc.AttachConsole()
		fmt.Fprintln(os.Stderr, "`service run` is what the service manager starts; to receive in a terminal, use --headless.")
		return 2
	case "install":
		if *bundle == "" {
			return finish(fmt.Errorf("--bundle is required; install the service from Settings > Background"))
		}
		exe, err := autostart.Executable()
		if err != nil {
			return finish(err)
		}
		return finish(winsvc.Install(exe, *bundle))
	case "uninstall":
		return finish(winsvc.Uninstall(*purge))
	case "start":
		return finish(winsvc.Start())
	case "stop":
		return finish(winsvc.Stop())
	case "status":
		winsvc.AttachConsole()
		printServiceStatus(os.Stdout)
		return 0
	}
	winsvc.AttachConsole()
	fmt.Fprintf(os.Stderr, "unknown service command %q\n\n", cmd)
	fmt.Fprintf(os.Stderr, usageText, updater.GetAppVersion())
	return 2
}

func printServiceStatus(w io.Writer) {
	if !winsvc.Supported() {
		fmt.Fprintln(w, winsvc.ErrUnsupported)
		return
	}
	info, err := winsvc.Query()
	if err != nil {
		fmt.Fprintln(w, "Cannot query the service manager:", err)
		return
	}
	if !info.Installed {
		fmt.Fprintln(w, "The SyslogStudio service is not installed.")
		return
	}
	fmt.Fprintf(w, "Service:     %s (%s)\n", winsvc.Name, info.State)
	fmt.Fprintf(w, "Executable:  %s\n", info.Executable)
	fmt.Fprintf(w, "Account:     %s\n", info.Account)
	if dir, err := winsvc.DataDir(); err == nil {
		fmt.Fprintf(w, "Data:        %s\n", dir)
	}
	dir, _ := winsvc.StatusDir()
	st, ok := headless.ReadStatus(dir)
	if !ok {
		fmt.Fprintln(w, "The service has not published a status yet.")
		return
	}
	fmt.Fprintf(w, "Reported:    %s at %s (version %s, pid %d)\n",
		st.State, st.UpdatedAt.Local().Format("2006-01-02 15:04:05"), st.Version, st.PID)
	for _, l := range st.Listeners {
		state := "not running"
		if l.Running {
			state = "listening"
		}
		fmt.Fprintf(w, "  %-4s %5d  %s\n", strings.ToUpper(l.Protocol), l.Port, state)
	}
	fmt.Fprintf(w, "Received:    %d messages since start\n", st.Messages)
	if st.Error != "" {
		fmt.Fprintf(w, "Last error:  %s\n", st.Error)
	}
}

func headlessCommand(args []string) int {
	winsvc.AttachConsole()
	fs := flag.NewFlagSet("headless", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	dataDir := fs.String("data-dir", "", "configuration and database directory")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *dataDir == "" {
		*dataDir = storage.NewConfigStore().Dir()
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	slog.SetDefault(log)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	host, err := headless.Start(headless.Options{
		DataDir: *dataDir,
		Version: updater.GetAppVersion(),
		Logger:  log,
	})
	if err != nil {
		return 1
	}
	<-ctx.Done()
	host.Stop()
	return 0
}
