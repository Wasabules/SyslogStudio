package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	maxPendingBatch  = 5000
	udpReadBufSize   = 65535
	tcpScanBufSize   = 65535
	batchInterval    = 100 * time.Millisecond
	statsInterval    = 1 * time.Second
	udpReadTimeout   = 1 * time.Second
	tcpAcceptTimeout = 1 * time.Second
	tcpReadTimeout   = 5 * time.Minute
	maxWorkers       = 256
)

// SyslogServer manages UDP, TCP, and TLS syslog listeners.
type SyslogServer struct {
	config       ServerConfig
	emitter      EventEmitter
	stats        *StatsCollector
	alertManager *AlertManager
	logStore     *LogStore

	mu       sync.RWMutex
	messages []SyslogMessage // Ring buffer
	head     int             // Next write position
	count    int             // Current number of messages

	// Pending batch for emission
	pendingBatch []SyslogMessage

	// Listener handles
	udpConn     *net.UDPConn
	tcpListener net.Listener
	tlsListener net.Listener

	// Cancellation
	cancel  context.CancelFunc
	running bool
	wg      sync.WaitGroup

	// Worker pool
	workCh chan func()

	tlsManager *TLSManager
	tlsConfig  *tls.Config
}

// NewSyslogServer creates a server with default config.
// If tlsMgr is nil, a new TLSManager is created.
func NewSyslogServer(emitter EventEmitter, tlsMgr *TLSManager) *SyslogServer {
	if tlsMgr == nil {
		tlsMgr = NewTLSManager()
	}
	config := DefaultServerConfig()
	return &SyslogServer{
		emitter:      emitter,
		config:       config,
		messages:     make([]SyslogMessage, config.MaxBuffer),
		stats:        NewStatsCollector(),
		alertManager: NewAlertManager(emitter),
		tlsManager:   tlsMgr,
	}
}

// Start begins listening on enabled protocols.
func (s *SyslogServer) Start(config ServerConfig) error {
	if err := ValidateServerConfig(config); err != nil {
		return err
	}

	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return fmt.Errorf("server is already running")
	}

	s.config = config
	if config.MaxBuffer <= 0 {
		config.MaxBuffer = 10000
	}

	// Reinitialize buffer if size changed
	if len(s.messages) != config.MaxBuffer {
		s.messages = make([]SyslogMessage, config.MaxBuffer)
		s.head = 0
		s.count = 0
	}

	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	s.running = true
	s.workCh = make(chan func(), maxWorkers*4)
	s.mu.Unlock()

	// Start worker pool
	for i := 0; i < maxWorkers; i++ {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			for fn := range s.workCh {
				fn()
			}
		}()
	}

	slog.Info("starting syslog server", "udp", config.UDPEnabled, "tcp", config.TCPEnabled, "tls", config.TLSEnabled)

	var startErrors []string

	if config.UDPEnabled {
		if err := s.startUDPListener(ctx, config.UDPPort); err != nil {
			slog.Error("failed to start UDP listener", "port", config.UDPPort, "error", err)
			startErrors = append(startErrors, err.Error())
		} else {
			slog.Info("UDP listener started", "port", config.UDPPort)
		}
	}

	if config.TCPEnabled {
		if err := s.startTCPListener(ctx, config.TCPPort); err != nil {
			slog.Error("failed to start TCP listener", "port", config.TCPPort, "error", err)
			startErrors = append(startErrors, err.Error())
		} else {
			slog.Info("TCP listener started", "port", config.TCPPort)
		}
	}

	if config.TLSEnabled {
		if err := s.startTLSListener(ctx, config); err != nil {
			slog.Error("failed to start TLS listener", "port", config.TLSPort, "error", err)
			startErrors = append(startErrors, err.Error())
		} else {
			slog.Info("TLS listener started", "port", config.TLSPort)
		}
	}

	// Start batch emitter and stats emitter
	s.wg.Add(2)
	go s.runBatchEmitter(ctx)
	go s.runStatsEmitter(ctx)

	// Emit status
	s.emitStatus()

	if len(startErrors) > 0 {
		return fmt.Errorf("%s", strings.Join(startErrors, "; "))
	}
	return nil
}

func (s *SyslogServer) startUDPListener(ctx context.Context, port int) error {
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", port))
	if err != nil {
		return fmt.Errorf("UDP resolve: %v", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("UDP listen on port %d: %v", port, err)
	}
	s.mu.Lock()
	s.udpConn = conn
	s.mu.Unlock()
	s.wg.Add(1)
	go s.listenUDP(ctx)
	return nil
}

func (s *SyslogServer) startTCPListener(ctx context.Context, port int) error {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return fmt.Errorf("TCP listen on port %d: %v", port, err)
	}
	s.mu.Lock()
	s.tcpListener = listener
	s.mu.Unlock()
	s.wg.Add(1)
	go s.listenTCP(ctx)
	return nil
}

func (s *SyslogServer) startTLSListener(ctx context.Context, config ServerConfig) error {
	tlsCfg, err := s.tlsManager.GetTLSConfig(config)
	if err != nil {
		return fmt.Errorf("TLS config: %v", err)
	}
	s.mu.Lock()
	s.tlsConfig = tlsCfg
	s.mu.Unlock()

	listener, err := tls.Listen("tcp", fmt.Sprintf(":%d", config.TLSPort), tlsCfg)
	if err != nil {
		return fmt.Errorf("TLS listen on port %d: %v", config.TLSPort, err)
	}
	s.mu.Lock()
	s.tlsListener = listener
	s.mu.Unlock()
	s.wg.Add(1)
	go s.listenTLS(ctx)
	return nil
}

// Stop gracefully shuts down all listeners.
func (s *SyslogServer) Stop() error {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return nil
	}

	s.running = false
	s.cancel()

	if s.udpConn != nil {
		s.udpConn.Close()
		s.udpConn = nil
	}
	if s.tcpListener != nil {
		s.tcpListener.Close()
		s.tcpListener = nil
	}
	if s.tlsListener != nil {
		s.tlsListener.Close()
		s.tlsListener = nil
	}
	workCh := s.workCh
	s.workCh = nil
	s.mu.Unlock()

	if workCh != nil {
		close(workCh)
	}

	s.wg.Wait()
	slog.Info("syslog server stopped")
	s.emitStatus()
	return nil
}

// GetStatus returns the current server status.
func (s *SyslogServer) GetStatus() ServerStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return ServerStatus{
		Running:    s.running,
		UDPRunning: s.running && s.udpConn != nil,
		TCPRunning: s.running && s.tcpListener != nil,
		TLSRunning: s.running && s.tlsListener != nil,
		Config:     s.config,
	}
}

// GetStats returns the current statistics.
func (s *SyslogServer) GetStats() ServerStats {
	s.mu.RLock()
	bufferUsed := s.count
	bufferMax := len(s.messages)
	s.mu.RUnlock()

	return s.stats.GetStats(bufferUsed, bufferMax)
}

// GetMessages returns buffered messages matching the filter.
func (s *SyslogServer) GetMessages(filter FilterCriteria) []SyslogMessage {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]SyslogMessage, 0, s.count)

	// Read from oldest to newest
	for i := 0; i < s.count; i++ {
		idx := (s.head - s.count + i + len(s.messages)) % len(s.messages)
		msg := s.messages[idx]
		if matchesFilter(msg, filter) {
			result = append(result, msg)
		}
	}

	return result
}

// ClearMessages empties the buffer and resets stats.
func (s *SyslogServer) ClearMessages() {
	s.mu.Lock()
	s.head = 0
	s.count = 0
	s.pendingBatch = nil
	for i := range s.messages {
		s.messages[i] = SyslogMessage{}
	}
	s.mu.Unlock()

	s.stats.Clear()
}

// --- Internal listeners ---

func (s *SyslogServer) listenUDP(ctx context.Context) {
	defer s.wg.Done()
	buf := make([]byte, udpReadBufSize)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		s.mu.RLock()
		conn := s.udpConn
		s.mu.RUnlock()
		if conn == nil {
			return
		}

		conn.SetReadDeadline(time.Now().Add(udpReadTimeout))
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			select {
			case <-ctx.Done():
				return
			default:
				slog.Debug("UDP read error", "error", err)
				continue
			}
		}

		raw := make([]byte, n)
		copy(raw, buf[:n])
		sourceIP := addr.IP.String()

		s.submitWork(func() {
			s.processMessage(raw, sourceIP, "UDP")
		})
	}
}

func (s *SyslogServer) listenTCP(ctx context.Context) {
	defer s.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		s.mu.RLock()
		listener := s.tcpListener
		s.mu.RUnlock()
		if listener == nil {
			return
		}

		if tcpListener, ok := listener.(*net.TCPListener); ok {
			tcpListener.SetDeadline(time.Now().Add(tcpAcceptTimeout))
		}

		conn, err := listener.Accept()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			select {
			case <-ctx.Done():
				return
			default:
				slog.Debug("TCP accept error", "error", err)
				continue
			}
		}

		slog.Debug("TCP connection accepted", "remote", conn.RemoteAddr())
		s.wg.Add(1)
		go s.handleTCPConnection(ctx, conn, "TCP")
	}
}

func (s *SyslogServer) listenTLS(ctx context.Context) {
	defer s.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		s.mu.RLock()
		listener := s.tlsListener
		s.mu.RUnlock()
		if listener == nil {
			return
		}

		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				slog.Debug("TLS accept error", "error", err)
				continue
			}
		}

		slog.Debug("TLS connection accepted", "remote", conn.RemoteAddr())
		s.wg.Add(1)
		go s.handleTCPConnection(ctx, conn, "TLS")
	}
}

func (s *SyslogServer) handleTCPConnection(ctx context.Context, conn net.Conn, protocol string) {
	defer s.wg.Done()
	defer conn.Close()

	var sourceIP string
	if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		sourceIP = tcpAddr.IP.String()
	} else {
		sourceIP = conn.RemoteAddr().String()
	}

	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 0, tcpScanBufSize), tcpScanBufSize)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		conn.SetReadDeadline(time.Now().Add(tcpReadTimeout))
		if !scanner.Scan() {
			return
		}

		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		raw := make([]byte, len(line))
		copy(raw, line)

		s.submitWork(func() {
			s.processMessage(raw, sourceIP, protocol)
		})
	}
}

// submitWork sends a task to the worker pool, falling back to inline execution if the pool is full.
func (s *SyslogServer) submitWork(fn func()) {
	s.mu.RLock()
	ch := s.workCh
	s.mu.RUnlock()
	if ch == nil {
		return
	}
	select {
	case ch <- fn:
	default:
		// Pool saturated — execute inline to avoid dropping messages
		fn()
	}
}

func (s *SyslogServer) processMessage(raw []byte, sourceIP string, protocol string) {
	msg := Parse(raw, sourceIP, protocol)
	s.addMessage(msg)
}

func (s *SyslogServer) addMessage(msg SyslogMessage) {
	s.mu.Lock()
	s.messages[s.head] = msg
	s.head = (s.head + 1) % len(s.messages)
	if s.count < len(s.messages) {
		s.count++
	}
	if len(s.pendingBatch) < maxPendingBatch {
		s.pendingBatch = append(s.pendingBatch, msg)
	}
	s.mu.Unlock()

	s.stats.RecordMessage(msg)

	// Persist to SQLite
	if s.logStore != nil {
		s.logStore.BufferMessage(msg)
	}

	// Check alert rules
	if events := s.alertManager.CheckMessage(msg); len(events) > 0 {
		s.emitter.Emit("syslog:alerts", events)
	}
}

// --- Emitters ---

func (s *SyslogServer) runBatchEmitter(ctx context.Context) {
	defer s.wg.Done()
	ticker := time.NewTicker(batchInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.mu.Lock()
			if len(s.pendingBatch) > 0 {
				batch := make([]SyslogMessage, len(s.pendingBatch))
				copy(batch, s.pendingBatch)
				s.pendingBatch = s.pendingBatch[:0] // reuse capacity
				s.mu.Unlock()
				s.emitter.Emit("syslog:messages", batch)
			} else {
				s.mu.Unlock()
			}
		}
	}
}

func (s *SyslogServer) runStatsEmitter(ctx context.Context) {
	defer s.wg.Done()
	ticker := time.NewTicker(statsInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.stats.RotateRateBucket()
			stats := s.GetStats()
			s.emitter.Emit("syslog:stats", stats)
		}
	}
}

func (s *SyslogServer) emitStatus() {
	status := s.GetStatus()
	s.emitter.Emit("syslog:status", status)
}

const maxRegexLen = 200

// safeCompileRegex compiles a user-supplied regex with length limit to prevent ReDoS.
func safeCompileRegex(pattern string) (*regexp.Regexp, error) {
	if len(pattern) > maxRegexLen {
		return nil, fmt.Errorf("regex pattern too long (max %d characters)", maxRegexLen)
	}
	return regexp.Compile("(?i)" + pattern)
}

// parseFilterDate parses a date string in RFC 3339 or "YYYY-MM-DD" format.
func parseFilterDate(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, s)
	if err == nil {
		return t, true
	}
	t, err = time.Parse("2006-01-02", s)
	if err == nil {
		return t, true
	}
	t, err = time.Parse("2006-01-02T15:04", s)
	if err == nil {
		return t, true
	}
	return time.Time{}, false
}

// matchesFilter checks if a message matches the given filter criteria.
func matchesFilter(msg SyslogMessage, filter FilterCriteria) bool {
	if len(filter.Severities) > 0 {
		found := false
		for _, sev := range filter.Severities {
			if int(msg.Severity) == sev {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	if len(filter.Facilities) > 0 {
		found := false
		for _, fac := range filter.Facilities {
			if int(msg.Facility) == fac {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	if filter.Hostname != "" {
		if !strings.Contains(strings.ToLower(msg.Hostname), strings.ToLower(filter.Hostname)) {
			return false
		}
	}

	if filter.AppName != "" {
		if !strings.Contains(strings.ToLower(msg.AppName), strings.ToLower(filter.AppName)) {
			return false
		}
	}

	if filter.SourceIP != "" {
		if !strings.Contains(strings.ToLower(msg.SourceIP), strings.ToLower(filter.SourceIP)) {
			return false
		}
	}

	// Date range filter
	if from, ok := parseFilterDate(filter.DateFrom); ok {
		if msg.Timestamp.Before(from) {
			return false
		}
	}
	if to, ok := parseFilterDate(filter.DateTo); ok {
		// If only date is given (no time part), include the whole day
		if to.Hour() == 0 && to.Minute() == 0 && to.Second() == 0 {
			to = to.Add(24*time.Hour - time.Nanosecond)
		}
		if msg.Timestamp.After(to) {
			return false
		}
	}

	// Search
	if filter.Search != "" {
		if filter.SearchMode == "regex" {
			re, err := safeCompileRegex(filter.Search)
			if err != nil {
				return matchPlainSearch(msg, filter.Search)
			}
			if !re.MatchString(msg.Message) && !re.MatchString(msg.RawMessage) {
				return false
			}
		} else {
			if !matchPlainSearch(msg, filter.Search) {
				return false
			}
		}
	}

	return true
}

func matchPlainSearch(msg SyslogMessage, search string) bool {
	s := strings.ToLower(search)
	return strings.Contains(strings.ToLower(msg.Message), s) ||
		strings.Contains(strings.ToLower(msg.RawMessage), s)
}
