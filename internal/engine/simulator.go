package engine

// The built-in traffic generator.

import (
	"fmt"

	"SyslogStudio/internal/models"
	"SyslogStudio/internal/simulator"
)

// StartSimulator begins a traffic run. Progress arrives on the frontend through
// syslog:simulatorStatus events rather than by polling.
func (e *Engine) StartSimulator(cfg models.SimulatorConfig) error {
	if e.simulator == nil {
		return fmt.Errorf("simulator not initialized")
	}
	if err := e.simulator.Start(cfg); err != nil {
		return err
	}
	e.configStore.SaveSimulator(cfg)
	return nil
}

// StopSimulator ends the current run. It returns once the run has unwound.
func (e *Engine) StopSimulator() error {
	if e.simulator == nil {
		return nil
	}
	return e.simulator.Stop()
}

// GetSimulatorStatus returns the live state of the run, for the initial render
// before the first event arrives.
func (e *Engine) GetSimulatorStatus() models.SimulatorStatus {
	if e.simulator == nil {
		return models.SimulatorStatus{}
	}
	return e.simulator.Status()
}

// GetSimulatorConfig returns the last saved run configuration, or a runnable
// default aimed at this app's own UDP port.
func (e *Engine) GetSimulatorConfig() models.SimulatorConfig {
	return e.configStore.LoadSimulator()
}

// SaveSimulatorConfig persists the configuration without starting a run, so a
// destination list survives a restart.
func (e *Engine) SaveSimulatorConfig(cfg models.SimulatorConfig) {
	e.configStore.SaveSimulator(cfg)
}

// GetScenarioDurationSeconds is how long a full scenario run lasts, so the UI
// can show real progress instead of an open-ended spinner.
func (e *Engine) GetScenarioDurationSeconds() int {
	return int(simulator.ScenarioDuration().Seconds())
}
