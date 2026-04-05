package main

import (
	"context"

	wailsRuntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// EventEmitter abstracts event emission for testability.
type EventEmitter interface {
	Emit(eventName string, data ...interface{})
}

// WailsEventEmitter emits events through the Wails runtime.
type WailsEventEmitter struct {
	ctx context.Context
}

// NewWailsEventEmitter creates an emitter bound to a Wails app context.
func NewWailsEventEmitter(ctx context.Context) *WailsEventEmitter {
	return &WailsEventEmitter{ctx: ctx}
}

// Emit sends an event to the frontend via Wails.
func (e *WailsEventEmitter) Emit(eventName string, data ...interface{}) {
	wailsRuntime.EventsEmit(e.ctx, eventName, data...)
}
