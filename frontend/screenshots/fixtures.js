/**
 * The demo's world: one small network, one evening.
 *
 * Written rather than recorded, and written to be READ. A screenshot of random
 * bytes proves the grid renders; it does not show anyone what the product is
 * for. So this is a night where a VPN concentrator starts failing, a switch
 * port flaps, someone brute-forces SSH against a jump host, and a backup runs
 * long — the kinds of things an operator opens a syslog viewer to find.
 *
 * Everything is derived from a fixed instant and a fixed sequence, so two runs
 * produce identical pixels. A clock-dependent fixture makes every screenshot a
 * diff.
 */

// The evening this all happens.
//
// Fixed for the screenshots: the images have to be reproducible, and a
// clock-relative timestamp would redraw every field that shows one, making
// every run a diff.
//
// The demo has the opposite need. A visitor arriving at a log viewer whose
// newest line is six months old reads it as broken, so there the same story is
// told as the hour that has just passed. The offsets are identical either way —
// only where the story is anchored changes.
const FIXED_EVENING = new Date('2026-03-17T21:42:10.000Z');

export const NOW = (typeof window !== 'undefined' && window.__SYSLOGSTUDIO_DEMO__)
  ? new Date()
  : FIXED_EVENING;

export const SEVERITY = {
  EMERGENCY: 0, ALERT: 1, CRITICAL: 2, ERROR: 3,
  WARNING: 4, NOTICE: 5, INFO: 6, DEBUG: 7,
};

const SEVERITY_LABELS = {
  0: 'Emergency', 1: 'Alert', 2: 'Critical', 3: 'Error',
  4: 'Warning', 5: 'Notice', 6: 'Info', 7: 'Debug',
};

const FACILITY_LABELS = {
  0: 'kernel', 1: 'user', 2: 'mail', 3: 'daemon', 4: 'auth', 5: 'syslog',
  6: 'lpr', 7: 'news', 8: 'uucp', 9: 'cron', 10: 'authpriv', 11: 'ftp',
  16: 'local0', 17: 'local1', 18: 'local2', 19: 'local3',
  20: 'local4', 21: 'local5', 22: 'local6', 23: 'local7',
};

/** The devices. A plausible small site, not a list of hostnames. */
export const HOSTS = [
  { host: 'fw-edge-01', ip: '10.10.0.1', role: 'perimeter firewall' },
  { host: 'sw-core-01', ip: '10.10.0.2', role: 'core switch' },
  { host: 'sw-access-03', ip: '10.10.0.23', role: 'access switch' },
  { host: 'vpn-gw-01', ip: '10.10.0.7', role: 'VPN concentrator' },
  { host: 'jump-01', ip: '10.10.1.15', role: 'bastion' },
  { host: 'app-prod-02', ip: '10.10.2.32', role: 'application server' },
  { host: 'db-prod-01', ip: '10.10.2.10', role: 'database' },
  { host: 'backup-01', ip: '10.10.3.4', role: 'backup server' },
];

/**
 * The evening, as a script.
 *
 * `at` is seconds before NOW, so the story reads in order here and arrives
 * newest-first in the viewer, which is how it is actually read.
 */
const SCRIPT = [
  // --- the quiet background any real feed has -----------------------------
  { at: 3600, host: 'sw-core-01', app: 'snmpd', sev: 6, fac: 3, msg: 'Connection from UDP: [10.10.9.5]:57221->[10.10.0.2]:161' },
  { at: 3540, host: 'app-prod-02', app: 'nginx', sev: 6, fac: 16, msg: '10.10.9.41 - - "GET /api/v2/health HTTP/1.1" 200 21 "-" "kube-probe/1.29"' },
  { at: 3480, host: 'db-prod-01', app: 'postgres', sev: 6, fac: 16, pid: '1284', msg: 'checkpoint complete: wrote 1842 buffers (1.4%); sync files=27, longest=0.019 s' },
  { at: 3420, host: 'jump-01', app: 'sshd', sev: 6, fac: 4, pid: '2291', msg: 'Accepted publickey for lmartin from 10.10.9.18 port 51422 ssh2: ED25519 SHA256:1sT0…' },
  { at: 3360, host: 'fw-edge-01', app: 'pf', sev: 5, fac: 16, msg: 'block in on igb0: 198.51.100.77.54021 > 10.10.0.1.23: Flags [S]' },

  // --- a port starts flapping --------------------------------------------
  { at: 3000, host: 'sw-access-03', app: 'mgmtd', sev: 4, fac: 23, msg: 'Interface GigabitEthernet1/0/14 changed state to down' },
  { at: 2988, host: 'sw-access-03', app: 'mgmtd', sev: 5, fac: 23, msg: 'Interface GigabitEthernet1/0/14 changed state to up' },
  { at: 2880, host: 'sw-access-03', app: 'mgmtd', sev: 4, fac: 23, msg: 'Interface GigabitEthernet1/0/14 changed state to down' },
  { at: 2868, host: 'sw-access-03', app: 'mgmtd', sev: 5, fac: 23, msg: 'Interface GigabitEthernet1/0/14 changed state to up' },
  { at: 2760, host: 'sw-access-03', app: 'mgmtd', sev: 3, fac: 23, msg: 'Port GigabitEthernet1/0/14 error-disabled: link-flap detected (7 transitions in 120 s)' },
  { at: 2745, host: 'sw-core-01', app: 'stpd', sev: 4, fac: 23, msg: 'Topology change received on VLAN 40 from port 1/0/2' },

  // --- someone knocking on SSH -------------------------------------------
  { at: 2400, host: 'jump-01', app: 'sshd', sev: 4, fac: 4, pid: '3310', msg: 'Failed password for invalid user admin from 203.0.113.44 port 40122 ssh2' },
  { at: 2394, host: 'jump-01', app: 'sshd', sev: 4, fac: 4, pid: '3311', msg: 'Failed password for invalid user oracle from 203.0.113.44 port 40188 ssh2' },
  { at: 2388, host: 'jump-01', app: 'sshd', sev: 4, fac: 4, pid: '3312', msg: 'Failed password for invalid user postgres from 203.0.113.44 port 40244 ssh2' },
  { at: 2382, host: 'jump-01', app: 'sshd', sev: 4, fac: 4, pid: '3313', msg: 'Failed password for root from 203.0.113.44 port 40301 ssh2' },
  { at: 2376, host: 'jump-01', app: 'sshd', sev: 4, fac: 4, pid: '3314', msg: 'Failed password for root from 203.0.113.44 port 40355 ssh2' },
  { at: 2370, host: 'jump-01', app: 'fail2ban', sev: 5, fac: 4, msg: 'NOTICE [sshd] Ban 203.0.113.44' },
  { at: 2364, host: 'fw-edge-01', app: 'pf', sev: 5, fac: 16, msg: 'block in on igb0: 203.0.113.44.40412 > 10.10.1.15.22: Flags [S]' },

  // --- the backup runs long ----------------------------------------------
  { at: 2100, host: 'backup-01', app: 'bacula-fd', sev: 6, fac: 16, msg: 'Start Backup JobId 4471, Job=Nightly.2026-03-17_20.00.00_14' },
  { at: 1800, host: 'backup-01', app: 'bacula-fd', sev: 4, fac: 16, msg: 'JobId 4471 running 30 min, 41% complete — slower than the 7-day average' },
  { at: 1500, host: 'db-prod-01', app: 'postgres', sev: 4, fac: 16, pid: '1284', msg: 'checkpoints are occurring too frequently (18 seconds apart)' },

  // --- the VPN concentrator degrades -------------------------------------
  { at: 1200, host: 'vpn-gw-01', app: 'ipsec', sev: 4, fac: 16, msg: 'IKE_SA rekeying failed for peer 198.51.100.12, retrying in 30 s' },
  { at: 1140, host: 'vpn-gw-01', app: 'ipsec', sev: 3, fac: 16, msg: 'IKE_SA rekeying failed for peer 198.51.100.12, retrying in 60 s' },
  { at: 1080, host: 'vpn-gw-01', app: 'ipsec', sev: 3, fac: 16, msg: 'tunnel to 198.51.100.12 torn down after 3 failed rekeys' },
  { at: 1020, host: 'vpn-gw-01', app: 'kernel', sev: 3, fac: 0, msg: 'crypto engine queue full, dropping 214 packets' },
  { at: 960, host: 'vpn-gw-01', app: 'kernel', sev: 2, fac: 0, msg: 'crypto engine reset: hardware acceleration disabled, falling back to software' },
  { at: 900, host: 'vpn-gw-01', app: 'ipsec', sev: 2, fac: 16, msg: 'CPU saturated: 41 tunnels renegotiating in software' },
  { at: 840, host: 'fw-edge-01', app: 'pf', sev: 4, fac: 16, msg: 'state table 78% full (78432/100000)' },

  // --- it gets worse ------------------------------------------------------
  { at: 600, host: 'vpn-gw-01', app: 'kernel', sev: 1, fac: 0, msg: 'Out of memory: Killed process 8821 (charon) total-vm:2841088kB' },
  { at: 588, host: 'vpn-gw-01', app: 'systemd', sev: 3, fac: 3, msg: 'strongswan.service: Main process exited, code=killed, status=9/KILL' },
  { at: 576, host: 'vpn-gw-01', app: 'systemd', sev: 5, fac: 3, msg: 'strongswan.service: Scheduled restart job, restart counter is at 1' },
  { at: 540, host: 'app-prod-02', app: 'nginx', sev: 3, fac: 16, msg: 'upstream timed out (110: Connection timed out) while reading response header from upstream' },
  { at: 528, host: 'app-prod-02', app: 'nginx', sev: 3, fac: 16, msg: '10.10.9.41 - - "POST /api/v2/orders HTTP/1.1" 504 167 "-" "checkout-svc/2.3"' },
  { at: 480, host: 'db-prod-01', app: 'postgres', sev: 4, fac: 16, pid: '1284', msg: 'FATAL: sorry, too many clients already' },

  // --- and then recovers --------------------------------------------------
  { at: 360, host: 'vpn-gw-01', app: 'ipsec', sev: 5, fac: 16, msg: 'charon started, 41 connections loaded' },
  { at: 300, host: 'vpn-gw-01', app: 'ipsec', sev: 6, fac: 16, msg: 'IKE_SA established with peer 198.51.100.12' },
  { at: 240, host: 'app-prod-02', app: 'nginx', sev: 6, fac: 16, msg: '10.10.9.41 - - "POST /api/v2/orders HTTP/1.1" 201 512 "-" "checkout-svc/2.3"' },
  { at: 180, host: 'sw-access-03', app: 'mgmtd', sev: 5, fac: 23, msg: 'Port GigabitEthernet1/0/14 recovered from error-disabled state' },
  { at: 120, host: 'backup-01', app: 'bacula-fd', sev: 6, fac: 16, msg: 'End Backup JobId 4471, Elapsed time=1:47:12, Files=284,119, Bytes=411,204,883,001' },
  { at: 60, host: 'db-prod-01', app: 'postgres', sev: 6, fac: 16, pid: '1284', msg: 'checkpoint complete: wrote 904 buffers (0.7%); sync files=14, longest=0.008 s' },
  { at: 20, host: 'jump-01', app: 'sshd', sev: 6, fac: 4, pid: '4102', msg: 'Accepted publickey for gkovacs from 10.10.9.22 port 52880 ssh2: ED25519 SHA256:9kQx…' },
];

const hostIP = (name) => (HOSTS.find((h) => h.host === name) || {}).ip || '10.10.0.99';

const pad = (n, w) => String(n).padStart(w, '0');

function rfc5424(msg) {
  const t = msg.timestamp.replace('Z', '.000Z');
  return `<${msg.facility * 8 + msg.severity}>1 ${t} ${msg.hostname} ${msg.appName} ` +
    `${msg.procID || '-'} - - ${msg.message}`;
}

/**
 * The messages, newest last — which is the order the application's own ring
 * buffer holds them in, so the demo feeds the store exactly what the backend
 * would.
 */
export const MESSAGES = SCRIPT
  .slice()
  .sort((a, b) => b.at - a.at)
  .map((e, i) => {
    const when = new Date(NOW.getTime() - e.at * 1000);
    const m = {
      id: `demo-${pad(i + 1, 4)}`,
      timestamp: when.toISOString().replace('.000Z', 'Z'),
      receivedAt: when.toISOString().replace('.000Z', 'Z'),
      severity: e.sev,
      severityLabel: SEVERITY_LABELS[e.sev],
      facility: e.fac,
      facilityLabel: FACILITY_LABELS[e.fac] || `local${e.fac - 16}`,
      hostname: e.host,
      appName: e.app,
      procID: e.pid || '',
      msgID: '',
      message: e.msg,
      sourceIP: hostIP(e.host),
      protocol: e.host === 'fw-edge-01' || e.host === 'vpn-gw-01' ? 'TCP' : 'UDP',
      structuredData: '',
    };
    m.rawMessage = rfc5424(m);
    return m;
  });

/**
 * Message counts by severity LABEL, which is the shape ServerStats uses —
 * counted from the messages rather than asserted, so the dashboard can never
 * disagree with the list underneath it.
 */
export function messagesByLevel(messages = MESSAGES) {
  const counts = {};
  for (const m of messages) counts[m.severityLabel] = (counts[m.severityLabel] || 0) + 1;
  return counts;
}

/** Top sources, in the {hostname, count} shape the dashboard expects. */
export function topSources(messages = MESSAGES) {
  const byHost = new Map();
  for (const m of messages) byHost.set(m.hostname, (byHost.get(m.hostname) || 0) + 1);
  return [...byHost.entries()]
    .map(([hostname, count]) => ({ hostname, count }))
    .sort((a, b) => b.count - a.count || a.hostname.localeCompare(b.hostname))
    .slice(0, 8);
}

export const STATS = {
  totalMessages: MESSAGES.length,
  messagesByLevel: messagesByLevel(),
  topSources: topSources(),
  messagesPerSec: 7.4,
  bufferUsed: MESSAGES.length,
  bufferMax: 10000,
};

export const SERVER_CONFIG = {
  udpEnabled: true,
  tcpEnabled: true,
  tlsEnabled: false,
  udpPort: 514,
  tcpPort: 601,
  tlsPort: 6514,
  bindAddress: '',
  allowedSources: [],
  maxBuffer: 10000,
  certFile: '',
  keyFile: '',
  useSelfSigned: true,
  certOptions: {},
  mutualTLS: false,
  caFile: '',
  maxConnsPerIP: 0,
};

export const SERVER_STATUS = {
  running: true,
  udpRunning: true,
  tcpRunning: true,
  tlsRunning: false,
  config: SERVER_CONFIG,
};

export const ALERT_RULES = [
  {
    id: 'rule-ssh-bruteforce', name: 'SSH brute force', enabled: true,
    pattern: 'Failed password', useRegex: false,
    minSeverity: SEVERITY.WARNING, hostname: '', appName: 'sshd', cooldown: 60,
  },
  {
    id: 'rule-critical', name: 'Critical and above', enabled: true,
    pattern: '', useRegex: false,
    minSeverity: SEVERITY.CRITICAL, hostname: '', appName: '', cooldown: 30,
  },
  {
    id: 'rule-linkflap', name: 'Port flapping', enabled: true,
    pattern: 'link-flap|error-disabled', useRegex: true,
    minSeverity: SEVERITY.ERROR, hostname: 'sw-access-03', appName: '', cooldown: 300,
  },
  {
    id: 'rule-oom', name: 'Out of memory', enabled: false,
    pattern: 'Out of memory', useRegex: false,
    minSeverity: SEVERITY.ALERT, hostname: '', appName: '', cooldown: 0,
  },
];

const alertAt = (secondsAgo) =>
  new Date(NOW.getTime() - secondsAgo * 1000).toISOString().replace('.000Z', 'Z');

export const ALERT_HISTORY = [
  {
    id: 'ev-1', ruleId: 'rule-critical', ruleName: 'Critical and above',
    message: 'Out of memory: Killed process 8821 (charon) total-vm:2841088kB',
    severity: 'Alert', hostname: 'vpn-gw-01', timestamp: alertAt(600),
  },
  {
    id: 'ev-2', ruleId: 'rule-critical', ruleName: 'Critical and above',
    message: 'crypto engine reset: hardware acceleration disabled, falling back to software',
    severity: 'Critical', hostname: 'vpn-gw-01', timestamp: alertAt(960),
  },
  {
    id: 'ev-3', ruleId: 'rule-ssh-bruteforce', ruleName: 'SSH brute force',
    message: 'Failed password for root from 203.0.113.44 port 40301 ssh2',
    severity: 'Warning', hostname: 'jump-01', timestamp: alertAt(2382),
  },
  {
    id: 'ev-4', ruleId: 'rule-linkflap', ruleName: 'Port flapping',
    message: 'Port GigabitEthernet1/0/14 error-disabled: link-flap detected (7 transitions in 120 s)',
    severity: 'Error', hostname: 'sw-access-03', timestamp: alertAt(2760),
  },
];

export const NOTIFY_SINKS = [
  {
    id: 'sink-siem',
    name: 'SIEM collector',
    kind: 'syslog',
    enabled: true,
    redact: false,
    hasSecret: false,
    maxRate: 0,
    syslog: {
      address: '10.10.4.20:6514', protocol: 'tls', facility: 16,
      hostname: '', appName: '', timeout: 0,
      preserveOrigin: true, preserveFacility: false,
      caFile: '/etc/ssl/siem-ca.pem', clientCertFile: '/etc/ssl/syslogstudio.pem',
      clientKeyFile: '/etc/ssl/syslogstudio.key', insecureSkipVerify: false,
    },
    webhook: { url: '', method: 'POST', headers: {}, timeout: 0, payloadMode: 'envelope' },
    email: { host: '', port: 587, username: '', from: '', to: [], encryption: 'starttls', format: 'text', timeout: 0 },
    template: { subject: '', body: '' },
  },
  {
    id: 'sink-chat',
    name: 'Ops channel',
    kind: 'webhook',
    enabled: true,
    redact: false,
    hasSecret: true,
    maxRate: 0,
    syslog: { address: '', protocol: 'udp', facility: 16, hostname: '', appName: '', timeout: 0, preserveOrigin: true, preserveFacility: false, caFile: '', clientCertFile: '', clientKeyFile: '', insecureSkipVerify: false },
    webhook: { url: 'https://chat.example.net/hooks/network-ops', method: 'POST', headers: {}, timeout: 0, payloadMode: 'envelope' },
    email: { host: '', port: 587, username: '', from: '', to: [], encryption: 'starttls', format: 'text', timeout: 0 },
    template: { subject: '', body: '' },
  },
  {
    id: 'sink-oncall',
    name: 'On-call e-mail',
    kind: 'email',
    enabled: true,
    redact: false,
    hasSecret: true,
    maxRate: 0,
    syslog: { address: '', protocol: 'udp', facility: 16, hostname: '', appName: '', timeout: 0, preserveOrigin: true, preserveFacility: false, caFile: '', clientCertFile: '', clientKeyFile: '', insecureSkipVerify: false },
    webhook: { url: '', method: 'POST', headers: {}, timeout: 0, payloadMode: 'envelope' },
    email: {
      host: 'smtp.example.net', port: 587, username: 'syslogstudio@example.net',
      from: 'syslogstudio@example.net', to: ['oncall@example.net'],
      encryption: 'starttls', format: 'text', timeout: 0,
    },
    template: { subject: '', body: '' },
  },
];

export const NOTIFY_ROUTES = [
  {
    id: 'route-siem',
    name: 'Everything to the SIEM',
    enabled: true,
    priority: 10,
    sinkIds: ['sink-siem'],
    stop: false,
    match: { facilities: [], hostnames: [], appNames: [], sources: [], pattern: '', useRegex: false },
  },
  {
    id: 'route-critical',
    name: 'Critical to the on-call',
    enabled: true,
    priority: 20,
    sinkIds: ['sink-oncall', 'sink-chat'],
    stop: false,
    match: { maxSeverity: SEVERITY.CRITICAL, facilities: [], hostnames: [], appNames: [], sources: [], pattern: '', useRegex: false },
  },
  {
    id: 'route-security',
    name: 'Authentication failures',
    enabled: true,
    priority: 30,
    sinkIds: ['sink-chat'],
    stop: false,
    match: { facilities: [], hostnames: [], appNames: ['sshd'], sources: [], pattern: 'Failed password', useRegex: false },
  },
];

const deliveredAt = (secondsAgo) => new Date(NOW.getTime() - secondsAgo * 1000).toISOString();

export const NOTIFY_LOG = [
  { time: deliveredAt(2382), sinkId: 'sink-chat', sinkName: 'Ops channel', target: 'webhook https://chat.example.net/hooks/network-ops', ok: true, attempts: 1, subject: '[Warning] jump-01 sshd' },
  { time: deliveredAt(2760), sinkId: 'sink-siem', sinkName: 'SIEM collector', target: 'syslog tls://10.10.4.20:6514', ok: true, attempts: 1, subject: '[Error] sw-access-03 mgmtd' },
  { time: deliveredAt(960), sinkId: 'sink-oncall', sinkName: 'On-call e-mail', target: 'email smtp.example.net:587 -> oncall@example.net', ok: true, attempts: 1, subject: '[Critical] vpn-gw-01 kernel' },
  { time: deliveredAt(603), sinkId: 'sink-oncall', sinkName: 'On-call e-mail', target: 'email smtp.example.net:587 -> oncall@example.net', ok: false, attempts: 2, error: 'dial tcp 10.10.4.11:587: i/o timeout', subject: '[Alert] vpn-gw-01 kernel' },
  { time: deliveredAt(600), sinkId: 'sink-oncall', sinkName: 'On-call e-mail', target: 'email smtp.example.net:587 -> oncall@example.net', ok: true, attempts: 3, subject: '[Alert] vpn-gw-01 kernel' },
  { time: deliveredAt(600), sinkId: 'sink-chat', sinkName: 'Ops channel', target: 'webhook https://chat.example.net/hooks/network-ops', ok: true, attempts: 1, subject: '[Alert] vpn-gw-01 kernel' },
];

export const NOTIFY_STATS = {
  matched: 47, delivered: 51, failed: 1, dropped: 0, looped: 0, blocked: 0, tripped: [], queued: 0,
};

export const STORAGE_CONFIG = {
  enabled: true,
  path: 'C:\\Users\\operator\\AppData\\Roaming\\SyslogStudio\\logs.db',
  retentionDays: 30,
  maxMessages: 5000000,
  maxSizeMB: 2048,
  encryptionEnabled: false,
};

export const STORAGE_STATS = {
  messageCount: 1284409,
  databaseSizeMB: 463.8,
  oldestTimestamp: new Date(NOW.getTime() - 29 * 86400 * 1000).toISOString(),
  droppedWrites: 0,
};

export const SIMULATOR_CONFIG = {
  mode: 'continuous',
  profile: 'mixed',
  ratePerSecond: 25,
  durationSeconds: 0,
  destinations: [
    { id: 'sim-1', name: 'This collector', host: '127.0.0.1', port: 514, protocol: 'udp', enabled: true },
    { id: 'sim-2', name: 'Lab collector', host: '10.10.4.20', port: 514, protocol: 'tcp', enabled: false },
  ],
};

export const SIMULATOR_STATUS = {
  running: false, mode: 'continuous', sent: 0, failed: 0,
  ratePerSec: 0, elapsedMs: 0, destinations: [],
};

export const NETWORK_INTERFACES = [
  { name: 'Ethernet', ip: '10.10.9.22' },
  { name: 'Wi-Fi', ip: '192.168.1.44' },
  { name: 'Loopback', ip: '127.0.0.1' },
];

export const CERT_INFO = {
  subject: 'CN=syslog.example.net, O=Example Networks',
  issuer: 'CN=Example Networks Internal CA',
  notBefore: new Date(NOW.getTime() - 60 * 86400 * 1000).toISOString(),
  notAfter: new Date(NOW.getTime() + 305 * 86400 * 1000).toISOString(),
  serialNumber: '4A:1F:88:C2:07:3D:91:E0',
  fingerprint: 'SHA256:2F:8C:11:AB:44:9D:0E:63:7A:B5:C9:12:E4:60:8D:31',
  algorithm: 'ECDSA P-256',
  dnsNames: ['syslog.example.net', 'syslog'],
  ipAddresses: ['10.10.9.22'],
  isCA: false,
};
