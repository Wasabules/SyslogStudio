// Package simulator generates and sends syslog traffic, so a collector can be
// exercised without waiting for real devices to misbehave.
//
// The message catalogue and severity profiles are ported from
// tools/syslog_generator.py, which stays in the repository for command-line and
// CI use. Keeping the wording identical means a scenario run looks the same
// whether it came from the script or from the app.
package simulator

import (
	"fmt"
	"math/rand/v2"
	"strings"
	"time"

	"SyslogStudio/internal/models"
)

var hostnames = []string{
	"web-server-01", "web-server-02", "db-master", "db-replica-01",
	"api-gateway", "auth-service", "cache-01", "proxy-lb",
	"monitoring-01", "backup-srv", "mail-relay", "dns-primary",
	"k8s-node-01", "k8s-node-02", "storage-nfs", "vpn-gateway",
}

var appNames = []string{
	"nginx", "apache2", "sshd", "postgres", "mysql", "redis",
	"docker", "kubelet", "systemd", "cron", "postfix", "named",
	"haproxy", "keepalived", "firewalld", "sudo", "kernel",
	"node-app", "python-api", "java-svc",
}

// messagesBySeverity holds realistic lines per severity, with {placeholders}
// filled at generation time.
var messagesBySeverity = map[models.Severity][]string{
	models.SevEmergency: {
		"System is going down for emergency shutdown NOW!",
		"KERNEL PANIC - not syncing: Fatal exception in interrupt",
		"CRITICAL HARDWARE FAILURE: RAID controller unresponsive",
	},
	models.SevAlert: {
		"File system /dev/sda1 has reached 99% capacity",
		"Database replication lag exceeded 300 seconds",
		"SSL certificate expires in 24 hours: *.example.com",
	},
	models.SevCritical: {
		"Out of memory: Kill process {pid} ({app}) score {score}",
		"Connection pool exhausted: 0/{max} available connections",
		"Disk I/O error on /dev/sdb: read-only filesystem",
	},
	models.SevError: {
		"Connection refused to upstream server {host}:{port}",
		"Failed to authenticate user '{user}': invalid credentials",
		"Query timeout after 30000ms: SELECT * FROM {table}",
		"Cannot bind to port {port}: address already in use",
		"TLS handshake failed: certificate verify failed (depth 0)",
		"Failed to write to /var/log/{app}.log: No space left on device",
	},
	models.SevWarning: {
		"High CPU usage detected: {percent}% (threshold: 80%)",
		"Connection pool utilization at {percent}%: {used}/{max} connections",
		"Slow query detected ({ms}ms): SELECT * FROM {table} WHERE id = {id}",
		"Retry attempt {n}/3 for upstream {host}",
		"Deprecated API endpoint called: GET /api/v1/{endpoint}",
		"Memory usage at {percent}%: {used}MB / {max}MB",
	},
	models.SevNotice: {
		"Server started on port {port}",
		"Configuration reloaded successfully",
		"User '{user}' logged in from {ip}",
		"Backup completed: {size}GB in {duration}s",
		"Certificate renewed for {domain}, expires {date}",
		"New worker process spawned (PID {pid})",
	},
	models.SevInformational: {
		"GET /api/v2/{endpoint} 200 {ms}ms",
		"POST /api/v2/{endpoint} 201 {ms}ms",
		"Processing job {job_id} from queue '{queue}'",
		"Health check passed: all {count} services healthy",
		"Cache hit ratio: {percent}% ({hits}/{total} requests)",
		"Accepted connection from {ip}:{port}",
		"Request completed: {method} {path} [{status}] {ms}ms",
	},
	models.SevDebug: {
		"SQL: SELECT * FROM {table} WHERE id = {id} [{ms}ms]",
		"HTTP request headers: Host={host}, User-Agent={ua}",
		"Session {session_id} validated, TTL={ttl}s",
		"Cache lookup: key='{key}' result={result}",
		"DNS resolved {domain} -> {ip} in {ms}ms",
		"GC pause: {ms}ms, heap: {heap}MB",
	},
}

var (
	endpoints  = []string{"users", "orders", "products", "auth/login", "health", "metrics", "config", "search"}
	tables     = []string{"users", "orders", "sessions", "products", "audit_log", "metrics"}
	users      = []string{"admin", "deployer", "jdoe", "backup-agent", "monitoring", "root", "www-data"}
	domains    = []string{"example.com", "api.internal", "db.cluster.local", "cdn.example.com"}
	userAgents = []string{"curl/7.88", "Mozilla/5.0", "Go-http-client/2.0", "python-requests/2.28"}
	queues     = []string{"default", "critical", "email", "reports", "notifications"}
	methods    = []string{"GET", "POST", "PUT", "DELETE"}
	outcomes   = []string{"success", "failure", "timeout"}
	ports      = []int{80, 443, 3306, 5432, 6379, 8080, 8443, 9200}
	statuses   = []int{200, 201, 204, 301, 400, 401, 403, 404, 500, 502, 503}
	poolSizes  = []int{50, 100, 200, 500, 1000}
	ttls       = []int{300, 900, 1800, 3600}
)

// severityWeights is the severity mix per profile. The weights come from the
// Python generator and are what make a "quiet" run look like an idle server
// rather than an even spread across all eight severities, which no real system
// ever produces.
var severityWeights = map[models.SimulatorProfile]map[models.Severity]int{
	models.SimProfileQuiet: {
		models.SevEmergency: 0, models.SevAlert: 0, models.SevCritical: 1,
		models.SevError: 2, models.SevWarning: 5, models.SevNotice: 15,
		models.SevInformational: 50, models.SevDebug: 27,
	},
	models.SimProfileNormal: {
		models.SevEmergency: 0, models.SevAlert: 1, models.SevCritical: 2,
		models.SevError: 7, models.SevWarning: 15, models.SevNotice: 20,
		models.SevInformational: 40, models.SevDebug: 15,
	},
	models.SimProfileStressed: {
		models.SevEmergency: 1, models.SevAlert: 3, models.SevCritical: 8,
		models.SevError: 20, models.SevWarning: 30, models.SevNotice: 15,
		models.SevInformational: 18, models.SevDebug: 5,
	},
	models.SimProfileCritical: {
		models.SevEmergency: 5, models.SevAlert: 12, models.SevCritical: 25,
		models.SevError: 30, models.SevWarning: 18, models.SevNotice: 5,
		models.SevInformational: 4, models.SevDebug: 1,
	},
}

func pick[T any](s []T) T { return s[rand.IntN(len(s))] }

// weightedSeverity draws a severity from the profile's distribution.
func weightedSeverity(profile models.SimulatorProfile) models.Severity {
	weights, ok := severityWeights[profile]
	if !ok {
		weights = severityWeights[models.SimProfileNormal]
	}
	total := 0
	for _, w := range weights {
		total += w
	}
	if total <= 0 {
		return models.SevInformational
	}
	n := rand.IntN(total)
	// Iterated in severity order rather than over the map, so the same seed
	// yields the same draw regardless of Go's map ordering.
	for sev := models.SevEmergency; sev <= models.SevDebug; sev++ {
		n -= weights[sev]
		if n < 0 {
			return sev
		}
	}
	return models.SevInformational
}

// fillTemplate substitutes the {placeholders} in a message line.
func fillTemplate(tpl string) string {
	if !strings.ContainsRune(tpl, '{') {
		return tpl
	}
	r := strings.NewReplacer(
		"{pid}", itoa(rand.IntN(64536)+1000),
		"{app}", pick(appNames),
		"{score}", itoa(rand.IntN(900)+100),
		"{max}", itoa(pick(poolSizes)),
		"{host}", fmt.Sprintf("10.0.%d.%d", rand.IntN(10)+1, rand.IntN(254)+1),
		"{port}", itoa(pick(ports)),
		"{user}", pick(users),
		"{table}", pick(tables),
		"{percent}", itoa(rand.IntN(25)+75),
		"{used}", itoa(rand.IntN(800)+100),
		"{ms}", itoa(rand.IntN(5000)+1),
		"{n}", itoa(rand.IntN(3)+1),
		"{endpoint}", pick(endpoints),
		"{ip}", fmt.Sprintf("192.168.%d.%d", rand.IntN(10)+1, rand.IntN(254)+1),
		"{size}", itoa(rand.IntN(500)+1),
		"{duration}", itoa(rand.IntN(3590)+10),
		"{date}", time.Now().AddDate(0, 0, rand.IntN(335)+30).Format("2006-01-02"),
		"{domain}", pick(domains),
		"{job_id}", randHex(8),
		"{queue}", pick(queues),
		"{count}", itoa(rand.IntN(18)+3),
		"{hits}", itoa(rand.IntN(2000)+8000),
		"{total}", "10000",
		"{method}", pick(methods),
		"{path}", "/api/v2/"+pick(endpoints),
		"{status}", itoa(pick(statuses)),
		"{id}", itoa(rand.IntN(1000000)+1),
		"{session_id}", randHex(12),
		"{ttl}", itoa(pick(ttls)),
		"{key}", fmt.Sprintf("user:%d:profile", rand.IntN(9999)+1),
		"{result}", pick([]string{"HIT", "MISS"}),
		"{ua}", pick(userAgents),
		"{heap}", itoa(rand.IntN(1985)+64),
		"{event_id}", itoa(rand.IntN(9000)+1000),
		"{source}", pick(appNames),
		"{outcome}", pick(outcomes),
		"{seq}", itoa(rand.IntN(999999)+1),
		"{uptime}", itoa(rand.IntN(9999000)+1000),
	)
	return r.Replace(tpl)
}

// alertTestCases are messages shaped to match the kind of rule people actually
// write — a severity threshold, a hostname, "Failed password", "Out of memory".
// Fixed rather than generated, so a rule that should fire fires every run.
var alertTestCases = []struct {
	Severity models.Severity
	Facility models.Facility
	Hostname string
	AppName  string
	Message  string
}{
	{models.SevEmergency, models.FacKern, "db-master", "kernel", "KERNEL PANIC - not syncing: Fatal exception"},
	{models.SevAlert, models.FacDaemon, "web-server-01", "nginx", "SSL certificate expires in 1 hour"},
	{models.SevCritical, models.FacDaemon, "api-gateway", "haproxy", "Out of memory: Kill process 12345 (java-svc)"},
	{models.SevError, models.FacAuth, "vpn-gateway", "sshd", "Failed to authenticate user 'root': invalid credentials"},
	{models.SevError, models.FacAuth, "web-server-01", "sshd", "Failed password for admin from 203.0.113.7 port 22 ssh2"},
	{models.SevError, models.FacDaemon, "db-master", "postgres", "FATAL: too many connections for role 'webapp'"},
	{models.SevWarning, models.FacDaemon, "web-server-02", "nginx", "upstream timed out (110: Connection timed out)"},
	{models.SevWarning, models.FacKern, "k8s-node-01", "kubelet", "OOMKiller invoked for container python-api"},
	{models.SevCritical, models.FacDaemon, "storage-nfs", "kernel", "Disk I/O error on /dev/sdb: read-only filesystem"},
}

// scenarioPhases is an incident timeline: quiet, ramp up, crisis, recovery. It
// exists so a dashboard, an alert rule and a retention setting can be watched
// through a realistic arc instead of a flat stream.
var scenarioPhases = []struct {
	Name     string
	Profile  models.SimulatorProfile
	Rate     float64
	Duration time.Duration
}{
	{"Normal operations", models.SimProfileQuiet, 2, 30 * time.Second},
	{"Traffic increasing", models.SimProfileNormal, 5, 20 * time.Second},
	{"High load detected", models.SimProfileStressed, 10, 20 * time.Second},
	{"System critical", models.SimProfileCritical, 20, 15 * time.Second},
	{"Recovery in progress", models.SimProfileStressed, 8, 15 * time.Second},
	{"Back to normal", models.SimProfileNormal, 3, 20 * time.Second},
	{"Quiet period", models.SimProfileQuiet, 1, 15 * time.Second},
}

// ScenarioDuration is how long a full scenario run takes, so the UI can show
// progress rather than an open-ended spinner.
func ScenarioDuration() time.Duration {
	var total time.Duration
	for _, p := range scenarioPhases {
		total += p.Duration
	}
	return total
}
