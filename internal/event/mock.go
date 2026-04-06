package event

import "sync"

// MockEvent records a single emission.
type MockEvent struct {
	Name string
	Data []interface{}
}

// MockEventEmitter records all emitted events for test verification.
type MockEventEmitter struct {
	mu     sync.Mutex
	events []MockEvent
}

// NewMockEventEmitter creates a new mock emitter.
func NewMockEventEmitter() *MockEventEmitter {
	return &MockEventEmitter{}
}

// Emit records the event.
func (m *MockEventEmitter) Emit(eventName string, data ...interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, MockEvent{Name: eventName, Data: data})
}

// GetEvents returns a copy of all recorded events.
func (m *MockEventEmitter) GetEvents() []MockEvent {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]MockEvent, len(m.events))
	copy(cp, m.events)
	return cp
}

// Clear removes all recorded events.
func (m *MockEventEmitter) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = nil
}
