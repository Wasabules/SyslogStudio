#!/usr/bin/env python3
"""
SyslogStudio Test Generator

A comprehensive syslog message generator for testing SyslogStudio.
Supports UDP, TCP, and TLS. Generates realistic RFC 5424 and RFC 3164 messages
with configurable rates, severities, and patterns.

Usage:
    python syslog_generator.py                          # Quick start: 1 msg/s UDP to localhost:514
    python syslog_generator.py --rate 100               # 100 messages per second
    python syslog_generator.py --protocol tcp            # Send via TCP
    python syslog_generator.py --protocol tls --ca-cert ca-cert.pem  # Send via TLS
    python syslog_generator.py --mode burst --count 5000 # Send 5000 messages as fast as possible
    python syslog_generator.py --mode scenario           # Run a realistic scenario
    python syslog_generator.py --mode alert-test         # Trigger alert-worthy messages
"""

import argparse
import datetime
import json
import logging
import os
import random
import socket
import ssl
import string
import sys
import time
import uuid
from dataclasses import dataclass
from typing import Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

FACILITIES = {
    "kern": 0, "user": 1, "mail": 2, "daemon": 3, "auth": 4,
    "syslog": 5, "lpr": 6, "news": 7, "uucp": 8, "cron": 9,
    "authpriv": 10, "ftp": 11, "ntp": 12, "audit": 13, "alert": 14,
    "clock": 15, "local0": 16, "local1": 17, "local2": 18, "local3": 19,
    "local4": 20, "local5": 21, "local6": 22, "local7": 23,
}

SEVERITIES = {
    "emergency": 0, "alert": 1, "critical": 2, "error": 3,
    "warning": 4, "notice": 5, "info": 6, "debug": 7,
}

HOSTNAMES = [
    "web-server-01", "web-server-02", "db-master", "db-replica-01",
    "api-gateway", "auth-service", "cache-01", "proxy-lb",
    "monitoring-01", "backup-srv", "mail-relay", "dns-primary",
    "k8s-node-01", "k8s-node-02", "storage-nfs", "vpn-gateway",
]

APP_NAMES = [
    "nginx", "apache2", "sshd", "postgres", "mysql", "redis",
    "docker", "kubelet", "systemd", "cron", "postfix", "named",
    "haproxy", "keepalived", "firewalld", "sudo", "kernel",
    "node-app", "python-api", "java-svc",
]

# Realistic message templates per severity
MESSAGES = {
    0: [  # Emergency
        "System is going down for emergency shutdown NOW!",
        "KERNEL PANIC - not syncing: Fatal exception in interrupt",
        "CRITICAL HARDWARE FAILURE: RAID controller unresponsive",
    ],
    1: [  # Alert
        "File system /dev/sda1 has reached 99% capacity",
        "Database replication lag exceeded 300 seconds",
        "SSL certificate expires in 24 hours: *.example.com",
    ],
    2: [  # Critical
        "Out of memory: Kill process {pid} ({app}) score {score}",
        "Connection pool exhausted: 0/{max} available connections",
        "Disk I/O error on /dev/sdb: read-only filesystem",
    ],
    3: [  # Error
        "Connection refused to upstream server {host}:{port}",
        "Failed to authenticate user '{user}': invalid credentials",
        "Query timeout after 30000ms: SELECT * FROM {table}",
        "Cannot bind to port {port}: address already in use",
        "TLS handshake failed: certificate verify failed (depth 0)",
        "Failed to write to /var/log/{app}.log: No space left on device",
    ],
    4: [  # Warning
        "High CPU usage detected: {percent}% (threshold: 80%)",
        "Connection pool utilization at {percent}%: {used}/{max} connections",
        "Slow query detected ({ms}ms): SELECT * FROM {table} WHERE id = {id}",
        "Retry attempt {n}/3 for upstream {host}",
        "Deprecated API endpoint called: GET /api/v1/{endpoint}",
        "Memory usage at {percent}%: {used}MB / {max}MB",
    ],
    5: [  # Notice
        "Server started on port {port}",
        "Configuration reloaded successfully",
        "User '{user}' logged in from {ip}",
        "Backup completed: {size}GB in {duration}s",
        "Certificate renewed for {domain}, expires {date}",
        "New worker process spawned (PID {pid})",
    ],
    6: [  # Info
        "GET /api/v2/{endpoint} 200 {ms}ms",
        "POST /api/v2/{endpoint} 201 {ms}ms",
        "Processing job {job_id} from queue '{queue}'",
        "Health check passed: all {count} services healthy",
        "Cache hit ratio: {percent}% ({hits}/{total} requests)",
        "Accepted connection from {ip}:{port}",
        "Request completed: {method} {path} [{status}] {ms}ms",
    ],
    7: [  # Debug
        "SQL: SELECT * FROM {table} WHERE id = {id} [{ms}ms]",
        "HTTP request headers: Host={host}, User-Agent={ua}",
        "Session {session_id} validated, TTL={ttl}s",
        "Cache lookup: key='{key}' result={result}",
        "DNS resolved {domain} -> {ip} in {ms}ms",
        "GC pause: {ms}ms, heap: {heap}MB",
    ],
}

ENDPOINTS = ["users", "orders", "products", "auth/login", "health", "metrics", "config", "search"]
TABLES = ["users", "orders", "sessions", "products", "audit_log", "metrics"]
USERS = ["admin", "deployer", "jdoe", "backup-agent", "monitoring", "root", "www-data"]
DOMAINS = ["example.com", "api.internal", "db.cluster.local", "cdn.example.com"]
USER_AGENTS = ["curl/7.88", "Mozilla/5.0", "Go-http-client/2.0", "python-requests/2.28"]
QUEUES = ["default", "critical", "email", "reports", "notifications"]

# ---------------------------------------------------------------------------
# Structured Data examples (RFC 5424)
# ---------------------------------------------------------------------------

STRUCTURED_DATA_TEMPLATES = [
    '[origin ip="{ip}" software="SyslogStudio-Generator" swVersion="1.0"]',
    '[meta sequenceId="{seq}" sysUpTime="{uptime}"]',
    '[event id="{event_id}" source="{source}" outcome="{outcome}"]',
    '[origin ip="{ip}"][meta sequenceId="{seq}"]',
]

# ---------------------------------------------------------------------------
# Message formatting
# ---------------------------------------------------------------------------

def fill_template(template: str) -> str:
    """Fill a message template with random realistic values."""
    replacements = {
        "{pid}": str(random.randint(1000, 65535)),
        "{app}": random.choice(APP_NAMES),
        "{score}": str(random.randint(100, 999)),
        "{max}": str(random.choice([50, 100, 200, 500, 1000])),
        "{host}": f"10.0.{random.randint(1,10)}.{random.randint(1,254)}",
        "{port}": str(random.choice([80, 443, 3306, 5432, 6379, 8080, 8443, 9200])),
        "{user}": random.choice(USERS),
        "{table}": random.choice(TABLES),
        "{percent}": str(random.randint(75, 99)),
        "{used}": str(random.randint(100, 900)),
        "{ms}": str(random.randint(1, 5000)),
        "{n}": str(random.randint(1, 3)),
        "{endpoint}": random.choice(ENDPOINTS),
        "{ip}": f"192.168.{random.randint(1,10)}.{random.randint(1,254)}",
        "{size}": str(random.randint(1, 500)),
        "{duration}": str(random.randint(10, 3600)),
        "{date}": (datetime.datetime.now() + datetime.timedelta(days=random.randint(30, 365))).strftime("%Y-%m-%d"),
        "{domain}": random.choice(DOMAINS),
        "{job_id}": uuid.uuid4().hex[:8],
        "{queue}": random.choice(QUEUES),
        "{count}": str(random.randint(3, 20)),
        "{hits}": str(random.randint(8000, 9999)),
        "{total}": str(10000),
        "{method}": random.choice(["GET", "POST", "PUT", "DELETE"]),
        "{path}": f"/api/v2/{random.choice(ENDPOINTS)}",
        "{status}": str(random.choice([200, 201, 204, 301, 400, 401, 403, 404, 500, 502, 503])),
        "{id}": str(random.randint(1, 1000000)),
        "{session_id}": uuid.uuid4().hex[:12],
        "{ttl}": str(random.choice([300, 900, 1800, 3600])),
        "{key}": f"user:{random.randint(1,9999)}:profile",
        "{result}": random.choice(["HIT", "MISS"]),
        "{ua}": random.choice(USER_AGENTS),
        "{heap}": str(random.randint(64, 2048)),
        "{event_id}": str(random.randint(1000, 9999)),
        "{source}": random.choice(APP_NAMES),
        "{outcome}": random.choice(["success", "failure", "timeout"]),
        "{seq}": str(random.randint(1, 999999)),
        "{uptime}": str(random.randint(1000, 9999999)),
    }
    result = template
    for k, v in replacements.items():
        result = result.replace(k, v)
    return result


def generate_rfc5424(severity: int, facility: int, hostname: str, app_name: str,
                     message: str, structured_data: Optional[str] = None) -> str:
    """Generate an RFC 5424 syslog message."""
    pri = facility * 8 + severity
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    pid = str(random.randint(1000, 65535))
    msg_id = str(random.randint(1000, 9999))
    sd = structured_data or "-"
    return f"<{pri}>1 {ts} {hostname} {app_name} {pid} {msg_id} {sd} {message}"


def generate_rfc3164(severity: int, facility: int, hostname: str, app_name: str,
                     message: str) -> str:
    """Generate an RFC 3164 (BSD) syslog message."""
    pri = facility * 8 + severity
    ts = datetime.datetime.now().strftime("%b %d %H:%M:%S")
    # Pad single-digit day with space (BSD format)
    if ts[4] == "0":
        ts = ts[:4] + " " + ts[5:]
    pid = random.randint(1000, 65535)
    return f"<{pri}>{ts} {hostname} {app_name}[{pid}]: {message}"


def random_message(severity: int) -> str:
    """Pick and fill a random message template for a given severity."""
    templates = MESSAGES.get(severity, MESSAGES[6])
    return fill_template(random.choice(templates))


def random_structured_data() -> Optional[str]:
    """Randomly generate structured data (30% chance)."""
    if random.random() < 0.3:
        return fill_template(random.choice(STRUCTURED_DATA_TEMPLATES))
    return None


# ---------------------------------------------------------------------------
# Severity distribution profiles
# ---------------------------------------------------------------------------

PROFILES = {
    "normal": {7: 30, 6: 40, 5: 15, 4: 10, 3: 4, 2: 0.5, 1: 0.3, 0: 0.2},
    "stressed": {7: 10, 6: 20, 5: 10, 4: 25, 3: 25, 2: 5, 1: 3, 0: 2},
    "critical": {7: 5, 6: 10, 5: 5, 4: 15, 3: 30, 2: 20, 1: 10, 0: 5},
    "quiet": {7: 5, 6: 70, 5: 20, 4: 4, 3: 1, 2: 0, 1: 0, 0: 0},
}


def weighted_severity(profile: str = "normal") -> int:
    """Pick a random severity based on the distribution profile."""
    weights = PROFILES.get(profile, PROFILES["normal"])
    severities = list(weights.keys())
    probs = list(weights.values())
    return random.choices(severities, weights=probs, k=1)[0]


# ---------------------------------------------------------------------------
# Transport
# ---------------------------------------------------------------------------

class SyslogSender:
    """Sends syslog messages via UDP, TCP, or TLS."""

    def __init__(self, host: str, port: int, protocol: str,
                 ca_cert: Optional[str] = None, client_cert: Optional[str] = None,
                 client_key: Optional[str] = None):
        self.host = host
        self.port = port
        self.protocol = protocol.lower()
        self.ca_cert = ca_cert
        self.client_cert = client_cert
        self.client_key = client_key
        self._sock: Optional[socket.socket] = None

    def connect(self):
        """Establish connection (TCP/TLS only)."""
        if self.protocol == "udp":
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        elif self.protocol == "tcp":
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.settimeout(10)
            self._sock.connect((self.host, self.port))
        elif self.protocol == "tls":
            ctx = ssl.create_default_context()
            if self.ca_cert:
                ctx.load_verify_locations(self.ca_cert)
            else:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            if self.client_cert and self.client_key:
                ctx.load_cert_chain(self.client_cert, self.client_key)
            raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw.settimeout(10)
            self._sock = ctx.wrap_socket(raw, server_hostname=self.host)
            self._sock.connect((self.host, self.port))
        logging.info(f"Connected via {self.protocol.upper()} to {self.host}:{self.port}")

    def send(self, message: str):
        """Send a single syslog message."""
        data = message.encode("utf-8")
        if self.protocol == "udp":
            self._sock.sendto(data, (self.host, self.port))
        else:
            self._sock.sendall(data + b"\n")

    def close(self):
        """Close the connection."""
        if self._sock:
            self._sock.close()
            self._sock = None


# ---------------------------------------------------------------------------
# Generator modes
# ---------------------------------------------------------------------------

def generate_one(profile: str = "normal", fmt: str = "rfc5424") -> str:
    """Generate a single random syslog message."""
    sev = weighted_severity(profile)
    fac_name = random.choice(list(FACILITIES.keys()))
    fac = FACILITIES[fac_name]
    hostname = random.choice(HOSTNAMES)
    app = random.choice(APP_NAMES)
    msg = random_message(sev)

    if fmt == "rfc3164":
        return generate_rfc3164(sev, fac, hostname, app, msg)
    else:
        sd = random_structured_data()
        return generate_rfc5424(sev, fac, hostname, app, msg, sd)


def mode_continuous(sender: SyslogSender, rate: float, profile: str, fmt: str):
    """Continuous mode: send messages at a fixed rate until interrupted."""
    interval = 1.0 / rate if rate > 0 else 0
    count = 0
    print(f"Sending {rate} msg/s ({profile} profile, {fmt}) — Ctrl+C to stop")
    try:
        while True:
            msg = generate_one(profile, fmt)
            sender.send(msg)
            count += 1
            if count % 100 == 0:
                print(f"\r  Sent: {count} messages", end="", flush=True)
            if interval > 0:
                time.sleep(interval)
    except KeyboardInterrupt:
        print(f"\n  Total sent: {count}")


def mode_burst(sender: SyslogSender, count: int, profile: str, fmt: str):
    """Burst mode: send N messages as fast as possible."""
    print(f"Sending {count} messages in burst mode...")
    start = time.time()
    for i in range(count):
        msg = generate_one(profile, fmt)
        sender.send(msg)
        if (i + 1) % 500 == 0:
            print(f"\r  Sent: {i + 1}/{count}", end="", flush=True)
    elapsed = time.time() - start
    rate = count / elapsed if elapsed > 0 else 0
    print(f"\n  Done: {count} messages in {elapsed:.2f}s ({rate:.0f} msg/s)")


def mode_scenario(sender: SyslogSender, fmt: str):
    """Scenario mode: simulate a realistic server incident timeline."""
    scenarios = [
        ("Normal operations", "quiet", 2.0, 30),
        ("Traffic increasing", "normal", 5.0, 20),
        ("High load detected", "stressed", 10.0, 20),
        ("System critical!", "critical", 20.0, 15),
        ("Recovery in progress", "stressed", 8.0, 15),
        ("Back to normal", "normal", 3.0, 20),
        ("Quiet period", "quiet", 1.0, 15),
    ]
    print("Running incident scenario timeline...")
    total = 0
    for phase_name, profile, rate, duration in scenarios:
        print(f"\n  [{phase_name}] — {rate} msg/s for {duration}s ({profile})")
        interval = 1.0 / rate
        end_time = time.time() + duration
        phase_count = 0
        while time.time() < end_time:
            msg = generate_one(profile, fmt)
            sender.send(msg)
            phase_count += 1
            total += 1
            time.sleep(interval)
        print(f"    Sent {phase_count} messages")
    print(f"\n  Scenario complete: {total} total messages")


def mode_alert_test(sender: SyslogSender, fmt: str):
    """Alert test mode: send specific messages designed to trigger alert rules."""
    print("Sending alert-trigger test messages...")
    test_cases = [
        # (severity, facility, hostname, app, message)
        (0, "kern", "db-master", "kernel", "KERNEL PANIC - not syncing: Fatal exception"),
        (1, "daemon", "web-server-01", "nginx", "SSL certificate expires in 1 hour"),
        (2, "daemon", "api-gateway", "haproxy", "Out of memory: Kill process 12345 (java-svc)"),
        (3, "auth", "vpn-gateway", "sshd", "Failed to authenticate user 'root': invalid credentials"),
        (3, "auth", "web-server-01", "sshd", "Failed to authenticate user 'admin': brute force detected"),
        (3, "daemon", "db-master", "postgres", "FATAL: too many connections for role 'webapp'"),
        (4, "daemon", "web-server-02", "nginx", "upstream timed out (110: Connection timed out)"),
        (4, "kern", "k8s-node-01", "kubelet", "OOMKiller invoked for container python-api"),
        (2, "daemon", "storage-nfs", "kernel", "Disk I/O error on /dev/sdb: read-only filesystem"),
        (3, "mail", "mail-relay", "postfix", "warning: connect to smtp.relay.local: Connection refused"),
        (1, "auth", "auth-service", "sudo", "3 failed sudo attempts by user jdoe on auth-service"),
        (4, "local0", "monitoring-01", "prometheus", "Target web-server-01:9090 is DOWN"),
        (3, "daemon", "cache-01", "redis", "ERROR: MISCONF write commands disabled due to BGSAVE error"),
        (0, "kern", "k8s-node-02", "kernel", "BUG: unable to handle kernel paging request"),
        (5, "auth", "web-server-01", "sshd", "Accepted publickey for deployer from 10.0.1.50"),
        (6, "local1", "api-gateway", "node-app", "GET /api/v2/health 200 2ms"),
        (7, "daemon", "db-replica-01", "postgres", "checkpoint starting: time"),
    ]

    for sev, fac_name, hostname, app, message in test_cases:
        fac = FACILITIES[fac_name]
        if fmt == "rfc3164":
            msg = generate_rfc3164(sev, fac, hostname, app, message)
        else:
            msg = generate_rfc5424(sev, fac, hostname, app, message)
        sender.send(msg)
        sev_name = [k for k, v in SEVERITIES.items() if v == sev][0]
        print(f"  [{sev_name.upper():>9}] {hostname}/{app}: {message[:70]}")
        time.sleep(0.3)

    print(f"\n  Sent {len(test_cases)} test messages")


def mode_stress(sender: SyslogSender, fmt: str):
    """Stress test: send messages as fast as possible to test limits."""
    print("Stress test: sending as fast as possible for 30 seconds...")
    count = 0
    start = time.time()
    end_time = start + 30
    while time.time() < end_time:
        for _ in range(100):
            msg = generate_one("normal", fmt)
            sender.send(msg)
            count += 1
    elapsed = time.time() - start
    rate = count / elapsed
    print(f"  Sent {count} messages in {elapsed:.1f}s ({rate:.0f} msg/s)")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="SyslogStudio Test Generator — generate realistic syslog messages",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes:
  continuous   Send at a fixed rate until Ctrl+C (default)
  burst        Send N messages as fast as possible
  scenario     Simulate a realistic server incident timeline
  alert-test   Send specific messages to test alert rules
  stress       Maximum throughput for 30 seconds

Profiles (severity distribution):
  quiet        Mostly info/notice, very few errors
  normal       Realistic production mix (default)
  stressed     More warnings and errors
  critical     Many critical/error messages

Examples:
  %(prog)s                                    # 1 msg/s UDP to localhost:514
  %(prog)s --rate 50 --profile stressed       # 50 msg/s with more errors
  %(prog)s --protocol tcp --port 514          # TCP mode
  %(prog)s --protocol tls --port 6514 --ca-cert ca-cert.pem
  %(prog)s --mode burst --count 10000         # Burst 10k messages
  %(prog)s --mode scenario                    # Run incident simulation
  %(prog)s --mode alert-test                  # Test alert rules
  %(prog)s --mode stress                      # Stress test
        """,
    )
    parser.add_argument("--host", default="127.0.0.1", help="Target host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=514, help="Target port (default: 514)")
    parser.add_argument("--protocol", choices=["udp", "tcp", "tls"], default="udp", help="Transport protocol")
    parser.add_argument("--rate", type=float, default=1.0, help="Messages per second (continuous mode)")
    parser.add_argument("--mode", choices=["continuous", "burst", "scenario", "alert-test", "stress"],
                        default="continuous", help="Generation mode")
    parser.add_argument("--count", type=int, default=1000, help="Number of messages (burst mode)")
    parser.add_argument("--profile", choices=["quiet", "normal", "stressed", "critical"],
                        default="normal", help="Severity distribution profile")
    parser.add_argument("--format", choices=["rfc5424", "rfc3164"], default="rfc5424",
                        help="Message format (default: rfc5424)")
    parser.add_argument("--ca-cert", help="CA certificate file for TLS verification")
    parser.add_argument("--client-cert", help="Client certificate for mutual TLS")
    parser.add_argument("--client-key", help="Client private key for mutual TLS")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")

    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(message)s")

    # Auto-select port for TLS if not explicitly set
    if args.protocol == "tls" and args.port == 514:
        args.port = 6514

    sender = SyslogSender(
        host=args.host, port=args.port, protocol=args.protocol,
        ca_cert=args.ca_cert, client_cert=args.client_cert, client_key=args.client_key,
    )

    print(f"SyslogStudio Test Generator")
    print(f"  Target: {args.protocol.upper()}://{args.host}:{args.port}")
    print(f"  Format: {args.format.upper()}")
    print()

    try:
        sender.connect()
        if args.mode == "continuous":
            mode_continuous(sender, args.rate, args.profile, args.format)
        elif args.mode == "burst":
            mode_burst(sender, args.count, args.profile, args.format)
        elif args.mode == "scenario":
            mode_scenario(sender, args.format)
        elif args.mode == "alert-test":
            mode_alert_test(sender, args.format)
        elif args.mode == "stress":
            mode_stress(sender, args.format)
    except ConnectionRefusedError:
        print(f"ERROR: Connection refused to {args.host}:{args.port}")
        print(f"  Make sure SyslogStudio is running with {args.protocol.upper()} enabled on port {args.port}")
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: {e}")
        sys.exit(1)
    finally:
        sender.close()


if __name__ == "__main__":
    main()
