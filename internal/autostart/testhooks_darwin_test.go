//go:build darwin

package autostart

import "testing"

// useAgentDir points the LaunchAgents directory at a scratch one.
func useAgentDir(t *testing.T, dir string) string {
	t.Helper()
	old := agentDir
	agentDir = func() (string, error) { return dir, nil }
	t.Cleanup(func() { agentDir = old })
	return dir
}
