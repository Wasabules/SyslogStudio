package notify

import (
	"hash/fnv"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Relaying is the one routing feature that can feed itself. A destination
// pointing back at this app's own listener turns one message into an endless
// stream, and each rule multiplies it: the receiver stores every copy, the
// disk fills, and the network carries the rest. A collector that relays back
// to us does the same without either side being misconfigured on its own.
//
// Two defences, because neither is sufficient alone:
//
//   - A destination that resolves to one of our own listeners is refused
//     outright. Certain, no false positives, and it catches the mistake that
//     is easiest to make.
//   - A message that was already relayed in the recent past is not relayed
//     again. This catches loops through other hosts, which no amount of
//     local configuration checking can see.
//
// The second is deliberately conservative: suppression stops the message being
// FORWARDED, never received. It is still parsed, counted, stored in the
// database and shown in the log viewer. So the cost of a false positive is one
// duplicate line not reaching a second collector, not a lost log.

const (
	// loopWindow is how long a relayed message is remembered. A loop closes in
	// milliseconds; this is generous, while staying far short of the interval
	// at which a device would legitimately repeat a line with an identical
	// timestamp to the millisecond.
	loopWindow = 30 * time.Second
	// maxLoopEntries bounds the memory the guard can take. Reaching it rotates
	// early, which shortens the effective window rather than growing without
	// limit — the hot path must not be the thing that exhausts memory.
	maxLoopEntries = 20000
)

// fingerprint identifies a message by what survives a relay.
//
// The timestamp is truncated to milliseconds because that is the precision an
// RFC 5424 frame carries: a message that comes back has lost anything finer,
// so a nanosecond-accurate fingerprint would never match its own echo.
//
// An empty PROCID or MSGID travels as "-" and returns as "-", so both forms
// are folded together.
func fingerprint(msg messageFields) uint64 {
	h := fnv.New64a()
	write := func(s string) {
		h.Write([]byte(s))
		h.Write([]byte{0x1f}) // a separator, so "ab"+"c" and "a"+"bc" differ
	}
	write(strconv.FormatInt(msg.timestamp.UTC().Truncate(time.Millisecond).UnixMilli(), 10))
	write(foldDash(msg.hostname))
	write(foldDash(msg.appName))
	write(foldDash(msg.procID))
	write(foldDash(msg.msgID))
	write(msg.message)
	return h.Sum64()
}

func foldDash(s string) string {
	if s == "-" {
		return ""
	}
	return s
}

// messageFields is the part of a syslog message the fingerprint is built from.
// A small struct rather than models.SyslogMessage so the guard can be tested
// without constructing a whole message.
type messageFields struct {
	timestamp time.Time
	hostname  string
	appName   string
	procID    string
	msgID     string
	message   string
}

// loopGuard remembers which messages were relayed recently.
//
// Two generations rather than a timestamp per entry: when the window elapses or
// the current generation fills, it becomes the previous one and a fresh map
// starts. Lookups check both, so the effective memory is between one and two
// windows, with no per-entry bookkeeping and a hard bound on size.
type loopGuard struct {
	mu        sync.Mutex
	cur       map[uint64]struct{}
	prev      map[uint64]struct{}
	rotatedAt time.Time
	window    time.Duration
	max       int
}

func newLoopGuard(window time.Duration, max int) *loopGuard {
	return &loopGuard{
		cur:       make(map[uint64]struct{}),
		prev:      make(map[uint64]struct{}),
		rotatedAt: time.Now(),
		window:    window,
		max:       max,
	}
}

// seen records a fingerprint and reports whether it was already there, which
// means the message has come round again.
func (g *loopGuard) seen(fp uint64, now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()

	if now.Sub(g.rotatedAt) >= g.window || len(g.cur) >= g.max {
		g.prev = g.cur
		g.cur = make(map[uint64]struct{})
		g.rotatedAt = now
	}
	if _, ok := g.cur[fp]; ok {
		return true
	}
	if _, ok := g.prev[fp]; ok {
		return true
	}
	g.cur[fp] = struct{}{}
	return false
}

// reset forgets everything. Used when the routing configuration changes, so a
// message suppressed under the old set is not held against the new one.
func (g *loopGuard) reset() {
	g.mu.Lock()
	g.cur = make(map[uint64]struct{})
	g.prev = make(map[uint64]struct{})
	g.rotatedAt = time.Now()
	g.mu.Unlock()
}

// LocalEndpoints describes where this app is listening, so a destination
// aiming back at it can be recognised.
type LocalEndpoints struct {
	// Ports this app has listeners on.
	Ports map[int]bool
	// IPs of this machine's interfaces, as strings.
	IPs map[string]bool
}

// IsSelfDestination reports whether a syslog destination points back at one of
// this app's own listeners.
//
// Both halves must match: the same port AND an address that is this machine.
// Sending to port 1514 on another host is a perfectly ordinary relay, and so
// is sending to a different port on this one.
//
// A hostname that is not an IP literal is resolved, because "localhost" and
// the machine's own name are exactly how this mistake gets typed. Resolution
// failure is not a loop — an unresolvable name cannot be reached at all.
func IsSelfDestination(address string, local LocalEndpoints) bool {
	host, portStr, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil {
		return false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || !local.Ports[port] {
		return false
	}

	// An unspecified address means "every interface on this machine", so a
	// destination of 0.0.0.0:<our port> is us by definition.
	if ip := net.ParseIP(host); ip != nil {
		return isLocalIP(ip, local.IPs)
	}

	if strings.EqualFold(host, "localhost") {
		return true
	}
	resolved, err := net.LookupIP(host)
	if err != nil {
		return false
	}
	for _, ip := range resolved {
		if isLocalIP(ip, local.IPs) {
			return true
		}
	}
	return false
}

func isLocalIP(ip net.IP, localIPs map[string]bool) bool {
	if ip.IsLoopback() || ip.IsUnspecified() {
		return true
	}
	return localIPs[ip.String()]
}
