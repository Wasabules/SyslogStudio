//go:build windows

package winsvc

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"SyslogStudio/internal/headless"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
)

// Event identifiers in the Application log.
const (
	eventStarted = 1
	eventStopped = 2
	eventFailed  = 3
)

// IsService reports whether this process was started by the service manager.
func IsService() bool {
	ok, err := svc.IsWindowsService()
	return err == nil && ok
}

// Run is the service's main: it hands control to the service manager and
// returns when the service has stopped.
func Run(version string) error {
	return svc.Run(Name, &handler{version: version})
}

type handler struct {
	version string
}

func (h *handler) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}

	elog, _ := eventlog.Open(Name)
	if elog != nil {
		defer elog.Close()
	}
	report := func(id uint32, isError bool, msg string) {
		if elog == nil {
			return
		}
		if isError {
			_ = elog.Error(id, msg)
		} else {
			_ = elog.Info(id, msg)
		}
	}

	logger, closeLog := serviceLogger()
	defer closeLog()
	slog.SetDefault(logger)

	dataDir, err := DataDir()
	if err != nil {
		report(eventFailed, true, "SyslogStudio could not find its data directory: "+err.Error())
		return true, 1
	}
	statusDir, _ := StatusDir()

	// Without its pipe the service still receives; windows just cannot
	// reach it, and the event log says why.
	control, err := ListenControl()
	if err != nil {
		logger.Error("windows cannot connect", "error", err)
		report(eventFailed, true, "SyslogStudio receives, but windows cannot connect to it: "+err.Error())
		control = nil
	}

	host, err := headless.Start(headless.Options{
		DataDir:   dataDir,
		StatusDir: statusDir,
		Sealer:    MachineSealer{},
		Version:   h.version,
		Logger:    logger,
		Control:   control,
	})
	if err != nil {
		// The service manager restarts us after a failure; the event log and
		// the published status say why, so the retries are not silent.
		report(eventFailed, true, "SyslogStudio could not start: "+err.Error())
		return true, 1
	}
	report(eventStarted, false, "SyslogStudio started: "+describe(host))

	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for req := range requests {
		switch req.Cmd {
		case svc.Interrogate:
			status <- req.CurrentStatus
		case svc.Stop, svc.Shutdown:
			status <- svc.Status{State: svc.StopPending}
			host.Stop()
			report(eventStopped, false, "SyslogStudio stopped.")
			return false, 0
		}
	}
	host.Stop()
	return false, 0
}

func describe(h *headless.Host) string {
	var parts []string
	for _, l := range h.Status().Listeners {
		if l.Running {
			parts = append(parts, fmt.Sprintf("%s/%d", strings.ToUpper(l.Protocol), l.Port))
		}
	}
	if len(parts) == 0 {
		return "no listener is running."
	}
	return "listening on " + strings.Join(parts, ", ") + "."
}

// serviceLogger writes to the service's own log file, rotated at 5 MB. When
// the file cannot be opened the log goes nowhere rather than stopping the
// service: receiving matters more than its diary.
func serviceLogger() (*slog.Logger, func()) {
	path, err := LogPath()
	var w io.Writer = io.Discard
	closeFn := func() {}
	if err == nil {
		if f, ferr := headless.OpenLogFile(path, 5<<20, 3); ferr == nil {
			w = f
			closeFn = func() { f.Close() }
		} else {
			fmt.Fprintln(os.Stderr, "cannot open the service log:", ferr)
		}
	}
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: slog.LevelInfo})), closeFn
}
