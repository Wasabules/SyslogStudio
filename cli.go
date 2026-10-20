package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"SyslogStudio/internal/autostart"
	"SyslogStudio/internal/headless"
	"SyslogStudio/internal/storage"
	"SyslogStudio/internal/sysvc"
	"SyslogStudio/internal/updater"
)

// The executable is three programs, chosen by how it is started:
//
//	SyslogStudio                       the desktop application
//	SyslogStudio --background          the same, starting hidden in the tray
//	SyslogStudio --headless            the engine alone, in the foreground
//	SyslogStudio service <command>     the system service, and managing it
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
  SyslogStudio service status        show the system service's state (a
                                     Windows service, or a systemd unit)
  SyslogStudio service install --bundle FILE [--operator ID]
  SyslogStudio service allow --operator ID
                                     let an account drive the service from
                                     its window; ID is its SID on Windows,
                                     its uid on Linux
  SyslogStudio service uninstall [--purge]
  SyslogStudio service start | stop  manage it (as an administrator, or root)

The service is normally installed from Settings > Background, which prepares
the bundle and asks for administrator rights itself. Once it runs, the window
of an allowed account drives it: its settings, its messages, its rules.
`

// runCommandLine handles every way of starting the executable except the
// desktop application. handled is false when the desktop application should
// start.
func runCommandLine(args []string) (handled bool, code int) {
	// Started by the service manager: nothing else applies.
	if sysvc.IsService() {
		if err := sysvc.Run(updater.GetAppVersion()); err != nil {
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
		sysvc.AttachConsole()
		fmt.Fprintf(os.Stdout, usageText, updater.GetAppVersion())
		return true, 0
	}
	return false, 0
}

// waitAfterUpdate holds a copy started by an update until the copy it
// replaces has exited: that one keeps the single-instance lock until then,
// and a second instance that finds the lock held exits at once.
func waitAfterUpdate(args []string) {
	if pid, ok := afterUpdatePID(args); ok {
		updater.WaitForExit(pid, 30*time.Second)
	}
}

// afterUpdatePID returns the process given with --after-update.
func afterUpdatePID(args []string) (int, bool) {
	for i, a := range args {
		if a == updater.AfterUpdateFlag && i+1 < len(args) {
			pid, err := strconv.Atoi(args[i+1])
			return pid, err == nil && pid > 0
		}
	}
	return 0, false
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
		sysvc.AttachConsole()
		fmt.Fprintf(os.Stderr, usageText, updater.GetAppVersion())
		return 2
	}
	cmd := args[0]
	fs := flag.NewFlagSet("service "+cmd, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	bundle := fs.String("bundle", "", "configuration bundle to install")
	result := fs.String("result", "", "where to record the outcome")
	purge := fs.Bool("purge", false, "also delete the service's data")
	operator := fs.String("operator", "", "account allowed to drive the service: SID on Windows, uid on Linux")
	if err := fs.Parse(args[1:]); err != nil {
		sysvc.AttachConsole()
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	// An elevated helper started by the window reports through --result; one
	// typed in a terminal reports on the terminal.
	finish := func(err error) int {
		sysvc.WriteResult(*result, err)
		if *result == "" {
			sysvc.AttachConsole()
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
		// systemd starts the Linux service this way. Windows' service manager
		// was handled above, and anywhere else this is a mistake.
		if runtime.GOOS == "linux" {
			if err := sysvc.Run(updater.GetAppVersion()); err != nil {
				fmt.Fprintln(os.Stderr, err)
				return 1
			}
			return 0
		}
		sysvc.AttachConsole()
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
		return finish(sysvc.Install(exe, *bundle, *operator))
	case "allow":
		if *operator == "" {
			return finish(fmt.Errorf("--operator is required: the account to allow (its SID on Windows, its uid on Linux)"))
		}
		return finish(sysvc.Allow(*operator))
	case "uninstall":
		return finish(sysvc.Uninstall(*purge))
	case "start":
		return finish(sysvc.Start())
	case "stop":
		return finish(sysvc.Stop())
	case "status":
		sysvc.AttachConsole()
		printServiceStatus(os.Stdout)
		return 0
	}
	sysvc.AttachConsole()
	fmt.Fprintf(os.Stderr, "unknown service command %q\n\n", cmd)
	fmt.Fprintf(os.Stderr, usageText, updater.GetAppVersion())
	return 2
}

func printServiceStatus(w io.Writer) {
	if !sysvc.Supported() {
		fmt.Fprintln(w, sysvc.ErrUnsupported)
		return
	}
	info, err := sysvc.Query()
	if err != nil {
		fmt.Fprintln(w, "Cannot query the service manager:", err)
		return
	}
	if !info.Installed {
		fmt.Fprintln(w, "The SyslogStudio service is not installed.")
		return
	}
	fmt.Fprintf(w, "Service:     %s (%s)\n", sysvc.Name, info.State)
	fmt.Fprintf(w, "Executable:  %s\n", info.Executable)
	fmt.Fprintf(w, "Account:     %s\n", info.Account)
	if dir, err := sysvc.DataDir(); err == nil {
		fmt.Fprintf(w, "Data:        %s\n", dir)
	}
	dir, _ := sysvc.StatusDir()
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
	onStart := "starts the listeners"
	if !st.ListenOnStart {
		onStart = "leaves the listeners for a window to start"
	}
	fmt.Fprintf(w, "On start:    %s\n", onStart)
	if ib := st.Inbox; ib != nil {
		state := "no longer sealing; batches left to collect"
		if ib.Sealed {
			state = "sealed for key " + ib.KeyID
		}
		fmt.Fprintf(w, "Inbox:       %s, %d batches waiting (%d of %d MB)\n", state, ib.Batches, ib.Bytes>>20, ib.Quota>>20)
		if ib.Dropped > 0 {
			fmt.Fprintf(w, "             %d messages dropped since start: %s\n", ib.Dropped, ib.Error)
		}
	}
	fmt.Fprintf(w, "Received:    %d messages since start\n", st.Messages)
	fmt.Fprintf(w, "Windows:     %d connected\n", st.Windows)
	if ops, err := sysvc.Operators(); err == nil {
		names := make([]string, 0, len(ops))
		for _, op := range ops {
			if op.Name != "" {
				names = append(names, op.Name)
			} else {
				names = append(names, op.SID)
			}
		}
		if len(names) > 0 {
			fmt.Fprintf(w, "Operators:   %s\n", strings.Join(names, ", "))
		}
	}
	if st.Error != "" {
		fmt.Fprintf(w, "Last error:  %s\n", st.Error)
	}
}

func headlessCommand(args []string) int {
	sysvc.AttachConsole()
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
