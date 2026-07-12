package main

import (
	"testing"
	"time"
)

func TestLockoutBackoff(t *testing.T) {
	tests := []struct {
		attempts int
		want     time.Duration
	}{
		{0, 0},
		{1, 0},
		{4, 0},
		{5, baseLockoutBackoff},     // first backoff step
		{6, baseLockoutBackoff * 2}, // doubles
		{7, baseLockoutBackoff * 4}, // doubles again
		{8, baseLockoutBackoff * 8}, // 30s -> 4m
		{100, maxLockoutBackoff},    // capped, no overflow
		{1000, maxLockoutBackoff},   // still capped
	}

	for _, tt := range tests {
		got := lockoutBackoff(tt.attempts)
		if got != tt.want {
			t.Errorf("lockoutBackoff(%d) = %v, want %v", tt.attempts, got, tt.want)
		}
	}
}

func TestLockoutBackoff_NeverExceedsCap(t *testing.T) {
	// Guard against left-shift overflow producing a negative duration.
	for a := unlockAttemptsBeforeBackoff; a < 200; a++ {
		if d := lockoutBackoff(a); d < 0 || d > maxLockoutBackoff {
			t.Fatalf("lockoutBackoff(%d) = %v, out of range (0, %v]", a, d, maxLockoutBackoff)
		}
	}
}
