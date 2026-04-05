package main

import (
	"sort"
	"sync"
)

// StatsCollector tracks syslog message statistics independently of the server.
type StatsCollector struct {
	mu              sync.Mutex
	totalMessages   int64
	messagesByLevel map[string]int64
	sourceCounts    map[string]int64
	rateBuckets     [10]int64
	rateIndex       int
}

// NewStatsCollector creates a new StatsCollector.
func NewStatsCollector() *StatsCollector {
	return &StatsCollector{
		messagesByLevel: make(map[string]int64),
		sourceCounts:    make(map[string]int64),
	}
}

// RecordMessage updates statistics for a received message.
func (sc *StatsCollector) RecordMessage(msg SyslogMessage) {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	sc.totalMessages++
	sc.messagesByLevel[msg.SeverityLabel]++

	hostname := msg.Hostname
	if hostname == "" {
		hostname = msg.SourceIP
	}
	sc.sourceCounts[hostname]++
	sc.rateBuckets[sc.rateIndex]++
}

// GetStats returns a snapshot of current statistics.
func (sc *StatsCollector) GetStats(bufferUsed, bufferMax int) ServerStats {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	levelsCopy := make(map[string]int64)
	for k, v := range sc.messagesByLevel {
		levelsCopy[k] = v
	}

	topSources := sc.computeTopSources(10)

	var totalRate int64
	for _, b := range sc.rateBuckets {
		totalRate += b
	}
	msgsPerSec := float64(totalRate) / float64(len(sc.rateBuckets))

	return ServerStats{
		TotalMessages:   sc.totalMessages,
		MessagesByLevel: levelsCopy,
		TopSources:      topSources,
		MessagesPerSec:  msgsPerSec,
		BufferUsed:      bufferUsed,
		BufferMax:       bufferMax,
	}
}

// RotateRateBucket advances the rate-tracking window by one slot.
func (sc *StatsCollector) RotateRateBucket() {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.rateIndex = (sc.rateIndex + 1) % len(sc.rateBuckets)
	sc.rateBuckets[sc.rateIndex] = 0
}

// Clear resets all statistics.
func (sc *StatsCollector) Clear() {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.totalMessages = 0
	sc.messagesByLevel = make(map[string]int64)
	sc.sourceCounts = make(map[string]int64)
	sc.rateBuckets = [10]int64{}
}

func (sc *StatsCollector) computeTopSources(n int) []SourceCount {
	sources := make([]SourceCount, 0, len(sc.sourceCounts))
	for hostname, count := range sc.sourceCounts {
		sources = append(sources, SourceCount{Hostname: hostname, Count: count})
	}
	sort.Slice(sources, func(i, j int) bool {
		return sources[i].Count > sources[j].Count
	})
	if len(sources) > n {
		sources = sources[:n]
	}
	return sources
}
