//go:build linux

package sysvc

import (
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"SyslogStudio/internal/headless"
)

// Run is the service's main under systemd, which starts it as `service run`:
// it receives until told to stop. What it logs goes to the journal
// (journalctl -u syslogstudio).
func Run(version string) error {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	data, err := DataDir()
	if err != nil {
		return err
	}
	status, err := StatusDir()
	if err != nil {
		return err
	}
	control, err := ListenControl()
	if err != nil {
		// Receiving matters more than being reachable from a window.
		logger.Error("windows cannot connect to the service", "error", err)
		control = nil
	}

	h, err := headless.Start(headless.Options{
		DataDir:   data,
		StatusDir: status,
		Version:   version,
		Logger:    logger,
		Control:   control,
		Warn:      func(msg string) { logger.Warn(msg) },
	})
	if err != nil {
		return fmt.Errorf("SyslogStudio could not start: %w", err)
	}
	logger.Info("SyslogStudio started: " + describe(h))

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	<-stop
	h.Stop()
	logger.Info("SyslogStudio stopped.")
	return nil
}

func describe(h *headless.Host) string {
	var parts []string
	for _, l := range h.Status().Listeners {
		if l.Running {
			parts = append(parts, fmt.Sprintf("%s/%d", strings.ToUpper(l.Protocol), l.Port))
		}
	}
	s := "listening on " + strings.Join(parts, ", ") + "."
	if len(parts) == 0 {
		s = "no listener is running."
		if !h.Status().ListenOnStart {
			s = "not receiving: listening on start is off, so the listeners wait for a window to start them."
		}
	}
	if ib := h.Status().Inbox; ib != nil && ib.Sealed {
		s += " What it receives is sealed for the window that installed it, and stored nowhere in the clear."
	}
	return s
}
