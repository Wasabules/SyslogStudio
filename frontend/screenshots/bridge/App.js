/**
 * The Go backend, stubbed.
 *
 * Every method the application can call, answered from the fixtures. Two things
 * make this worth the trouble over a hand-drawn mock-up:
 *
 *   - It is the REAL application. The same Svelte components, the same
 *     stylesheet, the same translations. A demo drawn separately drifts from
 *     the product the first time anything changes, and is then worse than no
 *     demo at all.
 *   - The screenshots on the site come from this same bundle, so they cannot
 *     show an interface the product does not actually produce.
 *
 * Two call paths have to be served. Most bindings are imported from
 * `wailsjs/go/main/App` and resolved to this module by the Vite plugin; the
 * alerts, storage and notification groups go through `window.go.main.App[name]`
 * instead. Both are wired below from one table, so neither can fall behind.
 *
 * DEMO_ONLY names the calls that ask the operating system for something a web
 * page does not have — writing a file, opening a dialog, installing an update.
 * In the demo they are refused with an explanation rather than answered "ok",
 * because a button that silently does nothing is worse than one that says why.
 */

import './runtime.js';
import { isDemo, override, delayed } from './scene.js';
import {
  MESSAGES, STATS, SERVER_CONFIG, SERVER_STATUS,
  ALERT_RULES, ALERT_HISTORY,
  NOTIFY_ROUTES, NOTIFY_SINKS, NOTIFY_LOG, NOTIFY_STATS,
  STORAGE_CONFIG, STORAGE_STATS,
  IMPORT_PREVIEW,
  SIMULATOR_CONFIG, SIMULATOR_STATUS,
  NETWORK_INTERFACES, CERT_INFO,
} from '../fixtures.js';

const clone = (v) => (v === undefined ? v : JSON.parse(JSON.stringify(v)));

/** Calls that need a real machine. Refused in the demo, said plainly. */
const DEMO_ONLY = {
  ExportLogs: 'Exporting writes a file, which a web page cannot do. The desktop application can.',
  ExportCertificate: 'Exporting writes a file, which a web page cannot do.',
  ExportCACertificate: 'Exporting writes a file, which a web page cannot do.',
  ExportServerCertificate: 'Exporting writes a file, which a web page cannot do.',
  SelectCertFile: 'Choosing a file needs a native dialog, which a web page does not have.',
  SelectKeyFile: 'Choosing a file needs a native dialog, which a web page does not have.',
  SelectCAFile: 'Choosing a file needs a native dialog, which a web page does not have.',
  SelectLogFile: 'Choosing a file needs a native dialog, which a web page does not have. The desktop application imports .log, .txt and .gz files from disk.',
  ImportLogFile: 'Importing reads a file off your disk, which the desktop application can do and a web page cannot.',
  DownloadAndApplyUpdate: 'Updating replaces the application on disk. Download it from the site instead.',
  CompactDatabase: 'There is no database behind the demo — this one runs entirely in your browser.',
  ClearDatabase: 'There is no database behind the demo — this one runs entirely in your browser.',
  StartSimulator: 'The simulator opens a network socket, which a web page cannot open.',
};

// --- mutable demo state ----------------------------------------------------
//
// The demo is used, not only looked at: adding a rule and seeing it in the list
// is most of what someone does in the first minute. Held in memory, so a reload
// starts the story again.

let messages = clone(MESSAGES);
let serverStatus = clone(SERVER_STATUS);
let alertRules = clone(ALERT_RULES);
let alertHistory = clone(ALERT_HISTORY);
let notifyRoutes = clone(NOTIFY_ROUTES);
let notifySinks = clone(NOTIFY_SINKS);
let notifyLog = clone(NOTIFY_LOG);
let storageConfig = clone(STORAGE_CONFIG);
let simulatorConfig = clone(SIMULATOR_CONFIG);
let updateConfig = { checkOnStartup: true, channel: 'stable', skippedVersion: '' };

const nextId = (prefix) => `${prefix}-${Math.random().toString(36).slice(2, 10)}`;

function refuse(name) {
  return Promise.reject(new Error(DEMO_ONLY[name]));
}

/** Filter the fixture the way the backend's FilterCriteria would. */
function applyFilter(list, criteria) {
  if (!criteria) return list;
  const text = (criteria.searchText || '').toLowerCase();
  return list.filter((m) => {
    if (criteria.minSeverity !== undefined && criteria.minSeverity !== null
      && m.severity > criteria.minSeverity) return false;
    if (criteria.hostname && !m.hostname.includes(criteria.hostname)) return false;
    if (criteria.appName && !m.appName.includes(criteria.appName)) return false;
    if (text) {
      const hay = `${m.message} ${m.hostname} ${m.appName} ${m.sourceIP}`.toLowerCase();
      if (!hay.includes(text)) return false;
    }
    return true;
  });
}

// --- the table -------------------------------------------------------------

const HANDLERS = {
  // server
  StartServer: (config) => {
    serverStatus = { ...serverStatus, running: true, config: { ...serverStatus.config, ...(config || {}) } };
    return Promise.resolve(null);
  },
  StopServer: () => {
    serverStatus = { ...serverStatus, running: false };
    return Promise.resolve(null);
  },
  GetServerStatus: () => Promise.resolve(clone(serverStatus)),
  GetDefaultConfig: () => Promise.resolve(clone(SERVER_CONFIG)),
  GetLocalIPs: () => Promise.resolve(NETWORK_INTERFACES.map((i) => i.ip)),
  GetNetworkInterfaces: () => Promise.resolve(clone(NETWORK_INTERFACES)),

  // messages
  GetMessages: (criteria) => Promise.resolve(clone(applyFilter(messages, criteria))),
  ClearMessages: () => { messages = []; return Promise.resolve(null); },
  GetStats: () => Promise.resolve(clone(STATS)),
  ExportLogs: () => refuse('ExportLogs'),

  // importing a log file (#46). Choosing and reading a file both need the
  // machine, so both are refused here and said plainly; the PREVIEW is
  // answered, because that is the part worth showing — how much of the result
  // was read from the file and how much was inferred from it.
  SelectLogFile: () => refuse('SelectLogFile'),
  // The format is ignored here because there is no file to apply it to: the
  // preview is a fixture. In the application this is where a declared format
  // is tried against the file's own lines.
  PreviewLogFile: () => Promise.resolve(clone(IMPORT_PREVIEW)),
  ImportLogFile: () => refuse('ImportLogFile'),
  GetImportFormat: () => Promise.resolve({
    mode: 'auto', joinContinuations: true, skipUnmatched: false,
  }),

  // history (the database view)
  QueryMessages: (opts) => {
    const all = applyFilter(messages, (opts && opts.filter) || {});
    const pageSize = (opts && opts.pageSize) || 100;
    const page = (opts && opts.page) || 1;
    const start = (page - 1) * pageSize;
    return Promise.resolve({
      messages: clone(all.slice(start, start + pageSize)),
      total: all.length,
      page,
      pageSize,
      totalPages: Math.max(1, Math.ceil(all.length / pageSize)),
    });
  },
  QueryMessageGroups: (opts) => {
    const by = (opts && opts.groupBy) || 'severity';
    const key = { severity: 'severityLabel', hostname: 'hostname', app: 'appName', sourceIP: 'sourceIP' }[by]
      || 'severityLabel';
    const counts = new Map();
    for (const m of messages) counts.set(m[key], (counts.get(m[key]) || 0) + 1);
    return Promise.resolve(
      [...counts.entries()]
        .map(([value, count]) => ({ value, count }))
        .sort((a, b) => b.count - a.count),
    );
  },

  // alerts
  GetAlertRules: () => Promise.resolve(clone(alertRules)),
  AddAlertRule: (rule) => {
    const added = { ...rule, id: rule.id || nextId('rule') };
    alertRules = [...alertRules, added];
    return Promise.resolve(clone(added));
  },
  UpdateAlertRule: (rule) => {
    alertRules = alertRules.map((r) => (r.id === rule.id ? { ...rule } : r));
    return Promise.resolve(true);
  },
  DeleteAlertRule: (id) => {
    alertRules = alertRules.filter((r) => r.id !== id);
    return Promise.resolve(true);
  },
  GetAlertHistory: () => Promise.resolve(clone(alertHistory)),
  ClearAlertHistory: () => { alertHistory = []; return Promise.resolve(null); },

  // routing and notifications
  GetNotifyRoutes: () => Promise.resolve(clone(notifyRoutes)),
  GetNotifySinks: () => Promise.resolve(clone(notifySinks)),
  SaveNotifyRoute: (route) => {
    const saved = { ...route, id: route.id || nextId('route') };
    notifyRoutes = notifyRoutes.some((r) => r.id === saved.id)
      ? notifyRoutes.map((r) => (r.id === saved.id ? saved : r))
      : [...notifyRoutes, saved];
    return Promise.resolve(null);
  },
  DeleteNotifyRoute: (id) => {
    notifyRoutes = notifyRoutes.filter((r) => r.id !== id);
    return Promise.resolve(null);
  },
  SaveNotifySink: (sink) => {
    // The credential is write-only in the product too: it is stored elsewhere
    // and never handed back, so the stub drops it exactly as the backend does.
    const { secret, ...rest } = sink;
    const saved = { ...rest, id: sink.id || nextId('sink'), hasSecret: Boolean(secret) || sink.hasSecret };
    notifySinks = notifySinks.some((s) => s.id === saved.id)
      ? notifySinks.map((s) => (s.id === saved.id ? saved : s))
      : [...notifySinks, saved];
    return Promise.resolve(null);
  },
  DeleteNotifySink: (id) => {
    notifySinks = notifySinks.filter((s) => s.id !== id);
    notifyRoutes = notifyRoutes.map((r) => ({
      ...r, sinkIds: (r.sinkIds || []).filter((x) => x !== id),
    }));
    return Promise.resolve(null);
  },
  TestNotifySink: (sink) => {
    if (isDemo()) {
      return Promise.reject(new Error(
        'A test message would leave your browser for a real server. The desktop application sends it.',
      ));
    }
    return delayed('TestNotifySink', null);
  },
  GetNotifyLog: () => Promise.resolve(clone(notifyLog)),
  ClearNotifyLog: () => { notifyLog = []; return Promise.resolve(null); },
  GetNotifyStats: () => Promise.resolve(clone(NOTIFY_STATS)),
  AreSinkCredentialsUnencrypted: () => Promise.resolve(false),

  // storage
  GetStorageConfig: () => Promise.resolve(clone(storageConfig)),
  SetStorageConfig: (cfg) => { storageConfig = { ...storageConfig, ...cfg }; return Promise.resolve(null); },
  GetStorageStats: () => Promise.resolve(clone(STORAGE_STATS)),
  IsStorageReady: () => Promise.resolve(true),
  CompactDatabase: () => refuse('CompactDatabase'),
  ClearDatabase: () => refuse('ClearDatabase'),

  // encryption
  IsEncryptionEnabled: () => Promise.resolve(false),
  IsEncryptionLocked: () => Promise.resolve(false),
  EnableEncryption: () => Promise.resolve(null),
  DisableEncryption: () => Promise.resolve(null),
  ChangeEncryptionPassword: () => Promise.resolve(null),
  UnlockDatabase: () => Promise.resolve(null),
  GetUnlockAttemptsRemaining: () => Promise.resolve(5),
  GetUnlockLockoutSeconds: () => Promise.resolve(0),

  // TLS
  GetDefaultCertOptions: () => Promise.resolve({
    commonName: 'syslog.example.net', organization: 'Example Networks',
    validDays: 365, keyType: 'ecdsa', keySize: 256,
    dnsNames: ['syslog.example.net'], ipAddresses: ['10.10.9.22'],
  }),
  GenerateCA: () => delayed('GenerateCA', clone({ ...CERT_INFO, isCA: true, subject: 'CN=Example Networks Internal CA' })),
  GenerateServerCert: () => delayed('GenerateServerCert', clone(CERT_INFO)),
  GenerateCertificate: () => delayed('GenerateCertificate', clone(CERT_INFO)),
  GetCACertInfo: () => Promise.resolve(clone({ ...CERT_INFO, isCA: true, subject: 'CN=Example Networks Internal CA' })),
  GetServerCertInfo: () => Promise.resolve(clone(CERT_INFO)),
  GetCertificateInfo: () => Promise.resolve(clone(CERT_INFO)),
  LoadPersistedCA: () => Promise.resolve(true),
  IsCAKeyUnencrypted: () => Promise.resolve(false),
  ExportCertificate: () => refuse('ExportCertificate'),
  ExportCACertificate: () => refuse('ExportCACertificate'),
  ExportServerCertificate: () => refuse('ExportServerCertificate'),
  SelectCertFile: () => refuse('SelectCertFile'),
  SelectKeyFile: () => refuse('SelectKeyFile'),
  SelectCAFile: () => refuse('SelectCAFile'),

  // simulator
  GetSimulatorConfig: () => Promise.resolve(clone(simulatorConfig)),
  SaveSimulatorConfig: (cfg) => { simulatorConfig = { ...simulatorConfig, ...cfg }; return Promise.resolve(null); },
  GetSimulatorStatus: () => Promise.resolve(clone(SIMULATOR_STATUS)),
  StartSimulator: () => refuse('StartSimulator'),
  StopSimulator: () => Promise.resolve(null),
  GetScenarioDurationSeconds: () => Promise.resolve(180),

  // updates and shell
  GetAppVersion: () => Promise.resolve('v1.4.0'),
  CheckForUpdate: () => Promise.resolve({
    available: false, currentVersion: 'v1.4.0', latestVersion: 'v1.4.0',
    releaseNotes: '', downloadURL: '', publishedAt: '',
  }),
  GetUpdateConfig: () => Promise.resolve(clone(updateConfig)),
  SetUpdateConfig: (cfg) => { updateConfig = { ...updateConfig, ...cfg }; return Promise.resolve(null); },
  SkipUpdateVersion: (v) => { updateConfig = { ...updateConfig, skippedVersion: v }; return Promise.resolve(null); },
  DownloadAndApplyUpdate: () => refuse('DownloadAndApplyUpdate'),
  OpenURL: (url) => {
    try { window.open(url, '_blank', 'noopener'); } catch { /* popup blocked */ }
    return Promise.resolve(null);
  },
};

/**
 * A scene may answer any binding itself; otherwise the fixture answers. This is
 * what keeps each scene short — it states only what makes it different.
 */
function dispatch(name, args) {
  const scripted = override(name);
  if (scripted !== undefined) return delayed(name, clone(scripted));

  const fn = HANDLERS[name];
  if (!fn) return Promise.reject(new Error(`No fixture for ${name}.`));
  if (isDemo() && DEMO_ONLY[name]) return refuse(name);
  return Promise.resolve(fn(...args));
}

const API = {};
for (const name of Object.keys(HANDLERS)) {
  API[name] = (...args) => dispatch(name, args);
}

// The application reaches for these two ways, so both are wired from one table.
if (typeof window !== 'undefined') {
  window.go = { ...(window.go || {}), main: { ...((window.go || {}).main || {}), App: API } };
}

export const {
  StartServer, StopServer, GetServerStatus, GetDefaultConfig, GetLocalIPs, GetNetworkInterfaces,
  GetMessages, ClearMessages, GetStats, ExportLogs, QueryMessages, QueryMessageGroups,
  SelectLogFile, PreviewLogFile, ImportLogFile, GetImportFormat,
  GetAlertRules, AddAlertRule, UpdateAlertRule, DeleteAlertRule, GetAlertHistory, ClearAlertHistory,
  GetNotifyRoutes, GetNotifySinks, SaveNotifyRoute, DeleteNotifyRoute, SaveNotifySink,
  DeleteNotifySink, TestNotifySink, GetNotifyLog, ClearNotifyLog, GetNotifyStats,
  AreSinkCredentialsUnencrypted,
  GetStorageConfig, SetStorageConfig, GetStorageStats, IsStorageReady, CompactDatabase, ClearDatabase,
  IsEncryptionEnabled, IsEncryptionLocked, EnableEncryption, DisableEncryption,
  ChangeEncryptionPassword, UnlockDatabase, GetUnlockAttemptsRemaining, GetUnlockLockoutSeconds,
  GetDefaultCertOptions, GenerateCA, GenerateServerCert, GenerateCertificate,
  GetCACertInfo, GetServerCertInfo, GetCertificateInfo, LoadPersistedCA, IsCAKeyUnencrypted,
  ExportCertificate, ExportCACertificate, ExportServerCertificate,
  SelectCertFile, SelectKeyFile, SelectCAFile,
  GetSimulatorConfig, SaveSimulatorConfig, GetSimulatorStatus, StartSimulator, StopSimulator,
  GetScenarioDurationSeconds,
  GetAppVersion, CheckForUpdate, GetUpdateConfig, SetUpdateConfig, SkipUpdateVersion,
  DownloadAndApplyUpdate, OpenURL,
} = API;
