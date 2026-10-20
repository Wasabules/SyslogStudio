package remote

import "sync"

// Switch is a Backend that forwards to another, which can be replaced while
// calls are made: the window drives its own engine, then the service once it
// runs, then its own again when the service stops. The methods in
// switch_gen.go each forward one call to whichever is current.
type Switch struct {
	mu  sync.RWMutex
	cur Backend
}

// NewSwitch starts on b.
func NewSwitch(b Backend) *Switch { return &Switch{cur: b} }

// Current is the backend calls go to now.
func (s *Switch) Current() Backend {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cur
}

// Set makes later calls go to b. Calls already under way finish where they
// started.
func (s *Switch) Set(b Backend) {
	s.mu.Lock()
	s.cur = b
	s.mu.Unlock()
}
