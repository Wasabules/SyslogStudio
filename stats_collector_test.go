package main

import (
	"sync"
	"testing"
)

func TestNewStatsCollector(t *testing.T) {
	sc := NewStatsCollector()
	if sc == nil {
		t.Fatal("NewStatsCollector returned nil")
	}
	if sc.totalMessages != 0 {
		t.Errorf("expected totalMessages 0, got %d", sc.totalMessages)
	}
	if sc.messagesByLevel == nil {
		t.Fatal("expected non-nil messagesByLevel map")
	}
	if sc.sourceCounts == nil {
		t.Fatal("expected non-nil sourceCounts map")
	}
}

func TestRecordMessage_IncrementsCounters(t *testing.T) {
	sc := NewStatsCollector()

	msg1 := SyslogMessage{
		SeverityLabel: "Error",
		Hostname:      "host1",
		SourceIP:      "10.0.0.1",
	}
	msg2 := SyslogMessage{
		SeverityLabel: "Warning",
		Hostname:      "host2",
		SourceIP:      "10.0.0.2",
	}
	msg3 := SyslogMessage{
		SeverityLabel: "Error",
		Hostname:      "host1",
		SourceIP:      "10.0.0.1",
	}

	sc.RecordMessage(msg1)
	sc.RecordMessage(msg2)
	sc.RecordMessage(msg3)

	if sc.totalMessages != 3 {
		t.Errorf("expected totalMessages 3, got %d", sc.totalMessages)
	}

	if sc.messagesByLevel["Error"] != 2 {
		t.Errorf("expected Error count 2, got %d", sc.messagesByLevel["Error"])
	}
	if sc.messagesByLevel["Warning"] != 1 {
		t.Errorf("expected Warning count 1, got %d", sc.messagesByLevel["Warning"])
	}

	if sc.sourceCounts["host1"] != 2 {
		t.Errorf("expected host1 count 2, got %d", sc.sourceCounts["host1"])
	}
	if sc.sourceCounts["host2"] != 1 {
		t.Errorf("expected host2 count 1, got %d", sc.sourceCounts["host2"])
	}
}

func TestRecordMessage_UsesSourceIPWhenHostnameEmpty(t *testing.T) {
	sc := NewStatsCollector()

	msg := SyslogMessage{
		SeverityLabel: "Info",
		Hostname:      "",
		SourceIP:      "192.168.1.100",
	}

	sc.RecordMessage(msg)

	if sc.sourceCounts["192.168.1.100"] != 1 {
		t.Errorf("expected sourceIP count 1, got %d", sc.sourceCounts["192.168.1.100"])
	}
	if _, exists := sc.sourceCounts[""]; exists {
		t.Error("should not have empty string key in sourceCounts")
	}
}

func TestRecordMessage_IncrementsRateBucket(t *testing.T) {
	sc := NewStatsCollector()

	msg := SyslogMessage{
		SeverityLabel: "Info",
		Hostname:      "host",
	}

	sc.RecordMessage(msg)
	sc.RecordMessage(msg)
	sc.RecordMessage(msg)

	if sc.rateBuckets[0] != 3 {
		t.Errorf("expected rateBuckets[0] = 3, got %d", sc.rateBuckets[0])
	}
}

func TestGetStats_ReturnsCorrectSnapshot(t *testing.T) {
	sc := NewStatsCollector()

	msgs := []SyslogMessage{
		{SeverityLabel: "Error", Hostname: "host-a"},
		{SeverityLabel: "Error", Hostname: "host-a"},
		{SeverityLabel: "Warning", Hostname: "host-b"},
		{SeverityLabel: "Info", Hostname: "host-c"},
		{SeverityLabel: "Info", Hostname: "host-c"},
		{SeverityLabel: "Info", Hostname: "host-c"},
	}

	for _, m := range msgs {
		sc.RecordMessage(m)
	}

	stats := sc.GetStats(50, 10000)

	if stats.TotalMessages != 6 {
		t.Errorf("expected TotalMessages 6, got %d", stats.TotalMessages)
	}
	if stats.MessagesByLevel["Error"] != 2 {
		t.Errorf("expected Error=2, got %d", stats.MessagesByLevel["Error"])
	}
	if stats.MessagesByLevel["Warning"] != 1 {
		t.Errorf("expected Warning=1, got %d", stats.MessagesByLevel["Warning"])
	}
	if stats.MessagesByLevel["Info"] != 3 {
		t.Errorf("expected Info=3, got %d", stats.MessagesByLevel["Info"])
	}
	if stats.BufferUsed != 50 {
		t.Errorf("expected BufferUsed 50, got %d", stats.BufferUsed)
	}
	if stats.BufferMax != 10000 {
		t.Errorf("expected BufferMax 10000, got %d", stats.BufferMax)
	}

	// TopSources should be sorted by count descending
	if len(stats.TopSources) != 3 {
		t.Fatalf("expected 3 top sources, got %d", len(stats.TopSources))
	}
	if stats.TopSources[0].Hostname != "host-c" || stats.TopSources[0].Count != 3 {
		t.Errorf("expected top source host-c with count 3, got %q with count %d",
			stats.TopSources[0].Hostname, stats.TopSources[0].Count)
	}
}

func TestGetStats_TopSourcesLimitedTo10(t *testing.T) {
	sc := NewStatsCollector()

	// Add messages from 15 different hosts
	for i := 0; i < 15; i++ {
		msg := SyslogMessage{
			SeverityLabel: "Info",
			Hostname:      "host-" + string(rune('A'+i)),
		}
		sc.RecordMessage(msg)
	}

	stats := sc.GetStats(15, 10000)

	if len(stats.TopSources) > 10 {
		t.Errorf("expected at most 10 top sources, got %d", len(stats.TopSources))
	}
}

func TestGetStats_MessagesByLevelIsCopy(t *testing.T) {
	sc := NewStatsCollector()

	sc.RecordMessage(SyslogMessage{SeverityLabel: "Error", Hostname: "h"})
	stats := sc.GetStats(1, 100)

	// Modify the returned map
	stats.MessagesByLevel["Error"] = 999

	// Original should be unchanged
	sc.mu.Lock()
	original := sc.messagesByLevel["Error"]
	sc.mu.Unlock()

	if original != 1 {
		t.Errorf("modifying returned map should not affect collector, got %d", original)
	}
}

func TestGetStats_MessagesPerSec(t *testing.T) {
	sc := NewStatsCollector()

	// Record some messages (they go to rateBuckets[0])
	for i := 0; i < 20; i++ {
		sc.RecordMessage(SyslogMessage{SeverityLabel: "Info", Hostname: "h"})
	}

	stats := sc.GetStats(20, 10000)

	// All 20 in bucket[0], 0 in the other 9 buckets => average = 20 / 10 = 2.0
	expectedRate := 2.0
	if stats.MessagesPerSec != expectedRate {
		t.Errorf("expected MessagesPerSec %.1f, got %.1f", expectedRate, stats.MessagesPerSec)
	}
}

func TestRotateRateBucket(t *testing.T) {
	sc := NewStatsCollector()

	// Record messages in bucket 0
	for i := 0; i < 5; i++ {
		sc.RecordMessage(SyslogMessage{SeverityLabel: "Info", Hostname: "h"})
	}
	if sc.rateBuckets[0] != 5 {
		t.Fatalf("expected rateBuckets[0]=5, got %d", sc.rateBuckets[0])
	}

	// Rotate: rateIndex moves to 1, and bucket[1] is cleared
	sc.RotateRateBucket()
	if sc.rateIndex != 1 {
		t.Errorf("expected rateIndex 1 after rotation, got %d", sc.rateIndex)
	}
	if sc.rateBuckets[1] != 0 {
		t.Errorf("expected rateBuckets[1]=0 after rotation, got %d", sc.rateBuckets[1])
	}
	// Bucket 0 should still have its messages
	if sc.rateBuckets[0] != 5 {
		t.Errorf("expected rateBuckets[0]=5 preserved, got %d", sc.rateBuckets[0])
	}

	// Record in new bucket
	for i := 0; i < 3; i++ {
		sc.RecordMessage(SyslogMessage{SeverityLabel: "Info", Hostname: "h"})
	}
	if sc.rateBuckets[1] != 3 {
		t.Errorf("expected rateBuckets[1]=3, got %d", sc.rateBuckets[1])
	}
}

func TestRotateRateBucket_WrapsAround(t *testing.T) {
	sc := NewStatsCollector()

	// Rotate 10 times (full cycle for 10-slot array)
	for i := 0; i < 10; i++ {
		sc.RotateRateBucket()
	}
	if sc.rateIndex != 0 {
		t.Errorf("expected rateIndex 0 after full rotation, got %d", sc.rateIndex)
	}

	// One more rotation
	sc.RotateRateBucket()
	if sc.rateIndex != 1 {
		t.Errorf("expected rateIndex 1, got %d", sc.rateIndex)
	}
}

func TestRotateRateBucket_ClearsCurrentBucket(t *testing.T) {
	sc := NewStatsCollector()

	// Fill all buckets manually
	for i := range sc.rateBuckets {
		sc.rateBuckets[i] = int64(i + 1)
	}

	// Rotate should clear the bucket it advances to
	sc.RotateRateBucket()
	if sc.rateBuckets[1] != 0 {
		t.Errorf("expected rateBuckets[1]=0 after rotation cleared it, got %d", sc.rateBuckets[1])
	}
	// Bucket 0 should be untouched
	if sc.rateBuckets[0] != 1 {
		t.Errorf("expected rateBuckets[0]=1, got %d", sc.rateBuckets[0])
	}
}

func TestClear_ResetsEverything(t *testing.T) {
	sc := NewStatsCollector()

	// Add some data
	for i := 0; i < 10; i++ {
		sc.RecordMessage(SyslogMessage{SeverityLabel: "Error", Hostname: "host"})
	}
	sc.RotateRateBucket()
	sc.RecordMessage(SyslogMessage{SeverityLabel: "Warning", Hostname: "host2"})

	// Verify we have data
	if sc.totalMessages == 0 {
		t.Fatal("expected non-zero totalMessages before clear")
	}

	sc.Clear()

	if sc.totalMessages != 0 {
		t.Errorf("expected totalMessages 0 after clear, got %d", sc.totalMessages)
	}
	if len(sc.messagesByLevel) != 0 {
		t.Errorf("expected empty messagesByLevel after clear, got %d entries", len(sc.messagesByLevel))
	}
	if len(sc.sourceCounts) != 0 {
		t.Errorf("expected empty sourceCounts after clear, got %d entries", len(sc.sourceCounts))
	}
	for i, b := range sc.rateBuckets {
		if b != 0 {
			t.Errorf("expected rateBuckets[%d]=0 after clear, got %d", i, b)
		}
	}
}

func TestClear_ThenRecordWorks(t *testing.T) {
	sc := NewStatsCollector()

	sc.RecordMessage(SyslogMessage{SeverityLabel: "Error", Hostname: "h"})
	sc.Clear()
	sc.RecordMessage(SyslogMessage{SeverityLabel: "Warning", Hostname: "h2"})

	if sc.totalMessages != 1 {
		t.Errorf("expected totalMessages 1 after clear+record, got %d", sc.totalMessages)
	}
	if sc.messagesByLevel["Warning"] != 1 {
		t.Errorf("expected Warning=1, got %d", sc.messagesByLevel["Warning"])
	}
	if sc.messagesByLevel["Error"] != 0 {
		t.Errorf("expected Error=0 after clear, got %d", sc.messagesByLevel["Error"])
	}
}

// --- Concurrent Access Tests ---

func TestStatsCollector_ConcurrentRecordMessage(t *testing.T) {
	sc := NewStatsCollector()
	var wg sync.WaitGroup

	numGoroutines := 100
	messagesPerGoroutine := 100

	wg.Add(numGoroutines)
	for g := 0; g < numGoroutines; g++ {
		go func(id int) {
			defer wg.Done()
			for i := 0; i < messagesPerGoroutine; i++ {
				msg := SyslogMessage{
					SeverityLabel: "Info",
					Hostname:      "host",
				}
				sc.RecordMessage(msg)
			}
		}(g)
	}

	wg.Wait()

	expected := int64(numGoroutines * messagesPerGoroutine)
	if sc.totalMessages != expected {
		t.Errorf("expected totalMessages %d, got %d", expected, sc.totalMessages)
	}
}

func TestStatsCollector_ConcurrentRecordAndRotate(t *testing.T) {
	sc := NewStatsCollector()
	var wg sync.WaitGroup

	// Concurrent records
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			sc.RecordMessage(SyslogMessage{SeverityLabel: "Info", Hostname: "h"})
		}
	}()

	// Concurrent rotations
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			sc.RotateRateBucket()
		}
	}()

	// Concurrent GetStats
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			_ = sc.GetStats(0, 10000)
		}
	}()

	// Concurrent Clear
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 10; i++ {
			sc.Clear()
		}
	}()

	wg.Wait()

	// Just verify no panics or data races occurred (run with -race flag)
	// The exact counts are nondeterministic due to clears
}

func TestStatsCollector_ConcurrentGetStats(t *testing.T) {
	sc := NewStatsCollector()

	// Pre-populate with data
	for i := 0; i < 100; i++ {
		sc.RecordMessage(SyslogMessage{SeverityLabel: "Error", Hostname: "host"})
	}

	var wg sync.WaitGroup
	numReaders := 50

	wg.Add(numReaders)
	for i := 0; i < numReaders; i++ {
		go func() {
			defer wg.Done()
			stats := sc.GetStats(100, 10000)
			if stats.TotalMessages != 100 {
				t.Errorf("expected 100 total messages, got %d", stats.TotalMessages)
			}
		}()
	}

	wg.Wait()
}

// --- computeTopSources Tests ---

func TestComputeTopSources_SortOrder(t *testing.T) {
	sc := NewStatsCollector()

	// Add messages with different frequencies
	for i := 0; i < 5; i++ {
		sc.RecordMessage(SyslogMessage{SeverityLabel: "Info", Hostname: "low"})
	}
	for i := 0; i < 15; i++ {
		sc.RecordMessage(SyslogMessage{SeverityLabel: "Info", Hostname: "high"})
	}
	for i := 0; i < 10; i++ {
		sc.RecordMessage(SyslogMessage{SeverityLabel: "Info", Hostname: "medium"})
	}

	stats := sc.GetStats(30, 10000)

	if len(stats.TopSources) != 3 {
		t.Fatalf("expected 3 sources, got %d", len(stats.TopSources))
	}
	if stats.TopSources[0].Hostname != "high" {
		t.Errorf("expected top source 'high', got %q", stats.TopSources[0].Hostname)
	}
	if stats.TopSources[1].Hostname != "medium" {
		t.Errorf("expected second source 'medium', got %q", stats.TopSources[1].Hostname)
	}
	if stats.TopSources[2].Hostname != "low" {
		t.Errorf("expected third source 'low', got %q", stats.TopSources[2].Hostname)
	}
}
