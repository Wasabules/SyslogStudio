/**
 * Service layer wrapping Wails-generated Go bindings.
 * All components should import from here instead of from wailsjs directly.
 */
import type { ServerConfig, FilterCriteria, CertOptions, CertInfo, ServerStatus, ServerStats, SyslogMessage, AlertRule, AlertEvent, StorageConfig, StorageStats, PagedResult, GroupSummary } from './stores';

// Re-export all Wails bindings through a typed service layer
import {
    StartServer as _StartServer,
    StopServer as _StopServer,
    GetServerStatus as _GetServerStatus,
    GetDefaultConfig as _GetDefaultConfig,
    GetMessages as _GetMessages,
    ClearMessages as _ClearMessages,
    GetStats as _GetStats,
    GenerateCA as _GenerateCA,
    GenerateServerCert as _GenerateServerCert,
    GenerateCertificate as _GenerateCertificate,
    GetCACertInfo as _GetCACertInfo,
    GetServerCertInfo as _GetServerCertInfo,
    GetCertificateInfo as _GetCertificateInfo,
    GetDefaultCertOptions as _GetDefaultCertOptions,
    ExportCACertificate as _ExportCACertificate,
    ExportServerCertificate as _ExportServerCertificate,
    ExportCertificate as _ExportCertificate,
    ExportLogs as _ExportLogs,
    GetLocalIPs as _GetLocalIPs,
    SelectCertFile as _SelectCertFile,
    SelectKeyFile as _SelectKeyFile,
    SelectCAFile as _SelectCAFile,
} from '../../wailsjs/go/main/App';

// --- Server Control ---
export const startServer = (config: ServerConfig): Promise<void> => _StartServer(config as any);
export const stopServer = (): Promise<void> => _StopServer();
export const getServerStatus = (): Promise<ServerStatus> => _GetServerStatus();
export const getDefaultConfig = (): Promise<ServerConfig> => _GetDefaultConfig();
// Persist the server configuration without starting anything. Saving is not
// starting: a configuration halfway through being made is exactly what needs to
// survive, so this is not validated — StartServer is the gate.
export const saveServerConfig = (c: ServerConfig): Promise<void> => callGo('SaveServerConfig', c);

// --- Logs ---
export const getMessages = (filter: FilterCriteria): Promise<SyslogMessage[]> => _GetMessages(filter as any);
export const clearMessages = (): Promise<void> => _ClearMessages();
export const getStats = (): Promise<ServerStats> => _GetStats();
export const exportLogs = (filter: FilterCriteria, format: string, timezone: string): Promise<string> => _ExportLogs(filter as any, format, timezone);

// --- PKI / Certificates ---
export const generateCA = (opts: CertOptions): Promise<CertInfo> => _GenerateCA(opts as any);
export const generateServerCert = (opts: CertOptions): Promise<CertInfo> => _GenerateServerCert(opts as any);
export const generateCertificate = (opts: CertOptions): Promise<CertInfo> => _GenerateCertificate(opts as any);
export const getCACertInfo = (): Promise<CertInfo> => _GetCACertInfo();
export const getServerCertInfo = (): Promise<CertInfo> => _GetServerCertInfo();
export const getCertificateInfo = (config: ServerConfig): Promise<CertInfo> => _GetCertificateInfo(config as any);
export const getDefaultCertOptions = (): Promise<CertOptions> => _GetDefaultCertOptions();
export const exportCACertificate = (): Promise<string> => _ExportCACertificate();
export const exportServerCertificate = (): Promise<string> => _ExportServerCertificate();
export const exportCertificate = (): Promise<string> => _ExportCertificate();
export const isCAKeyUnencrypted = (): Promise<boolean> => callGo('IsCAKeyUnencrypted');

// --- Alerts ---
// These use window.go directly since bindings are generated at build time
function callGo(method: string, ...args: any[]): Promise<any> {
    return (window as any)['go']?.['main']?.['App']?.[method]?.(...args) ?? Promise.reject('Wails not available');
}
export const getAlertRules = (): Promise<AlertRule[]> => callGo('GetAlertRules');
export const addAlertRule = (rule: AlertRule): Promise<AlertRule> => callGo('AddAlertRule', rule);
export const updateAlertRule = (rule: AlertRule): Promise<boolean> => callGo('UpdateAlertRule', rule);
export const deleteAlertRule = (id: string): Promise<boolean> => callGo('DeleteAlertRule', id);
export const getAlertHistory = (): Promise<AlertEvent[]> => callGo('GetAlertHistory');
export const clearAlertHistory = (): Promise<void> => callGo('ClearAlertHistory');

// --- Storage ---
export const getStorageConfig = (): Promise<StorageConfig> => callGo('GetStorageConfig');
export const setStorageConfig = (cfg: StorageConfig): Promise<void> => callGo('SetStorageConfig', cfg);
export const getStorageStats = (): Promise<StorageStats> => callGo('GetStorageStats');
export const queryMessages = (filter: FilterCriteria, page: number, pageSize: number, sortField: string = '', sortDir: string = 'desc'): Promise<PagedResult> =>
    callGo('QueryMessages', { filter, page, pageSize, sortField, sortDir, groupBy: '' });
export const queryMessageGroups = (filter: FilterCriteria, groupField: string): Promise<GroupSummary[]> =>
    callGo('QueryMessageGroups', filter, groupField);
export const compactDatabase = (): Promise<void> => callGo('CompactDatabase');
export const clearDatabase = (): Promise<void> => callGo('ClearDatabase');

// --- Encryption ---
export const isEncryptionEnabled = (): Promise<boolean> => callGo('IsEncryptionEnabled');
export const isEncryptionLocked = (): Promise<boolean> => callGo('IsEncryptionLocked');
export const unlockDatabase = (password: string): Promise<void> => callGo('UnlockDatabase', password);
export const getUnlockLockoutSeconds = (): Promise<number> => callGo('GetUnlockLockoutSeconds');
export const enableEncryption = (password: string): Promise<void> => callGo('EnableEncryption', password);
export const disableEncryption = (password: string): Promise<void> => callGo('DisableEncryption', password);
export const changeEncryptionPassword = (oldPw: string, newPw: string): Promise<void> => callGo('ChangeEncryptionPassword', oldPw, newPw);

// --- Update ---
export interface UpdateInfo {
    currentVersion: string;
    latestVersion: string;
    updateUrl: string;
    hasUpdate: boolean;
    releaseNotes: string;
    releaseUrl: string;
    publishedAt: string;
    assetName: string;
    assetUrl: string;
    canSelfApply: boolean;
}
export interface UpdateConfig {
    autoCheck: boolean;
    intervalHours: number;
    skipVersion: string;
    lastCheckUnix: number;
}
export const checkForUpdate = (): Promise<UpdateInfo> => callGo('CheckForUpdate');
export const downloadAndApplyUpdate = (): Promise<void> => callGo('DownloadAndApplyUpdate');
export const getAppVersion = (): Promise<string> => callGo('GetAppVersion');
export const openUrl = (url: string): Promise<void> => callGo('OpenURL', url);
export const getUpdateConfig = (): Promise<UpdateConfig> => callGo('GetUpdateConfig');
export const setUpdateConfig = (cfg: UpdateConfig): Promise<void> => callGo('SetUpdateConfig', cfg);
export const skipUpdateVersion = (version: string): Promise<void> => callGo('SkipUpdateVersion', version);

// --- Utilities ---
export interface NetworkInterface { name: string; ip: string; }
export const getLocalIPs = (): Promise<string[]> => _GetLocalIPs();
export const getNetworkInterfaces = (): Promise<NetworkInterface[]> => callGo('GetNetworkInterfaces');
export const selectCertFile = (): Promise<string> => _SelectCertFile();
export const selectKeyFile = (): Promise<string> => _SelectKeyFile();
export const selectCAFile = (): Promise<string> => _SelectCAFile();

// --- Simulator ---
export interface SimulatorDestination {
    id: string;
    name: string;
    host: string;
    port: number;
    protocol: string;
    enabled: boolean;
    insecureSkipVerify: boolean;
}
export interface SimulatorConfig {
    destinations: SimulatorDestination[];
    mode: string;
    profile: string;
    format: string;
    rate: number;
    count: number;
    durationSeconds: number;
    customMessage: string;
    hostname: string;
    appName: string;
}
export interface SimulatorDestinationStatus {
    id: string;
    name: string;
    sent: number;
    failed: number;
    connected: boolean;
    lastError?: string;
}
export interface SimulatorStatus {
    running: boolean;
    mode: string;
    sent: number;
    failed: number;
    ratePerSec: number;
    elapsedMs: number;
    phase?: string;
    destinations: SimulatorDestinationStatus[];
}
export const startSimulator = (cfg: SimulatorConfig): Promise<void> => callGo('StartSimulator', cfg);
export const stopSimulator = (): Promise<void> => callGo('StopSimulator');
export const getSimulatorStatus = (): Promise<SimulatorStatus> => callGo('GetSimulatorStatus');
export const getSimulatorConfig = (): Promise<SimulatorConfig> => callGo('GetSimulatorConfig');
export const saveSimulatorConfig = (cfg: SimulatorConfig): Promise<void> => callGo('SaveSimulatorConfig', cfg);
export const getScenarioDurationSeconds = (): Promise<number> => callGo('GetScenarioDurationSeconds');

// --- Notification routing ---
export interface MessageTemplate { subject?: string; body?: string; }
// Certificate material for a sink that speaks TLS. Paths, not contents: the
// files are read at delivery time and a private key must not land in the
// configuration file.
export interface NotifyTLSFiles {
    caFile?: string;
    clientCertFile?: string;
    clientKeyFile?: string;
    insecureSkipVerify?: boolean;
}
export interface NotifySink {
    id: string;
    name: string;
    kind: string;
    enabled: boolean;
    redact: boolean;
    // Write-only: set to send a new credential, always blank when read back.
    secret?: string;
    hasSecret: boolean;
    template: MessageTemplate;
    // Ceiling in messages per second; 0 takes the default, negative turns the
    // rate breaker off for this destination.
    maxRate?: number;
    syslog: {
        address: string; protocol: string; facility: number; hostname: string;
        appName: string; timeout: number; preserveOrigin?: boolean;
        preserveFacility?: boolean; caFile?: string; clientCertFile?: string;
        clientKeyFile?: string; insecureSkipVerify?: boolean;
    };
    webhook: {
        url: string; method: string; headers: Record<string, string>;
        timeout: number; payloadMode?: string;
    };
    email: {
        host: string; port: number; username: string; from: string; to: string[];
        encryption: string; format?: string; timeout: number;
        tls: NotifyTLSFiles;
    };
}
export interface NotifyRouteMatch {
    minSeverity?: number;
    maxSeverity?: number;
    facilities?: number[];
    hostnames?: string[];
    appNames?: string[];
    sources?: string[];
    pattern?: string;
    useRegex?: boolean;
    window?: { start: string; end: string; days?: number[] };
}
export interface NotifyRoute {
    id: string;
    name: string;
    enabled: boolean;
    priority: number;
    match: NotifyRouteMatch;
    sinkIds: string[];
    stop: boolean;
}
export interface DeliveryEntry {
    time: string; sinkId: string; sinkName: string; target: string;
    ok: boolean; attempts: number; error?: string; subject?: string;
}
export interface NotifyStats {
    matched: number; delivered: number; failed: number; dropped: number; queued: number;
    // Non-zero means a relay loop was cut: a message came back, or a
    // destination pointed at this app's own listener.
    looped: number;
    // Messages not sent because their destination was cut off by the breaker.
    blocked: number;
    // Destinations currently cut off.
    tripped?: string[];
}
export const getNotifyRoutes = (): Promise<NotifyRoute[]> => callGo('GetNotifyRoutes');
export const getNotifySinks = (): Promise<NotifySink[]> => callGo('GetNotifySinks');
export const saveNotifyRoute = (r: NotifyRoute): Promise<void> => callGo('SaveNotifyRoute', r);
export const deleteNotifyRoute = (id: string): Promise<void> => callGo('DeleteNotifyRoute', id);
export const saveNotifySink = (s: NotifySink): Promise<void> => callGo('SaveNotifySink', s);
export const deleteNotifySink = (id: string): Promise<void> => callGo('DeleteNotifySink', id);
export const testNotifySink = (s: NotifySink): Promise<void> => callGo('TestNotifySink', s);
export const getNotifyLog = (): Promise<DeliveryEntry[]> => callGo('GetNotifyLog');
export const clearNotifyLog = (): Promise<void> => callGo('ClearNotifyLog');
export const getNotifyStats = (): Promise<NotifyStats> => callGo('GetNotifyStats');
export const areSinkCredentialsUnencrypted = (): Promise<boolean> => callGo('AreSinkCredentialsUnencrypted');

// --- Importing a log file ---
// What an import did, in the terms it can be checked by. The detected counts
// say how much of the result was INFERRED from plain text rather than read from
// a syslog priority, so the interface can show the difference.
export interface ImportResult {
    file: string;
    linesRead: number;
    imported: number;
    blank: number;
    truncated: number;
    syslog: number;
    timeDetected: number;
    levelDetected: number;
    // Lines whose host and application were read out of an RFC 3164 body.
    hostDetected: number;
    // What recognised each line, and what the file turned out to be. 'mixed'
    // when no single shape holds a clear majority; detectedMode is the format
    // to read it as, when the shape has one.
    byShape: Record<string, number>;
    detected: string;
    detectedMode: ImportMode | '';
    // Lines that did not fit the declared format, and continuation lines folded
    // into the record above them.
    unmatched: number;
    joined: number;
    stopped: boolean;
    bySeverity: Record<string, number>;
}
export interface ImportPreview {
    result: ImportResult;
    messages: SyslogMessage[];
}

// How a file should be read. 'auto' guesses and reports what it guessed; the
// others are declared, which is what makes JSON lines, access logs and stack
// traces readable — detection sees none of them.
export type ImportMode =
    | 'auto' | 'syslog' | 'json' | 'access' | 'logfmt' | 'custom'
    // Shapes automatic detection reads on its own, which can also be declared:
    // a name the dialog reports has to be a name the reader can choose.
    | 'bsd' | 'klog' | 'logcat' | 'apache' | 'epoch';
export interface ImportFormat {
    mode: ImportMode;
    // Field names for the json and logfmt modes. Empty means the usual
    // candidates are tried, which is why neither mode needs configuring.
    jsonTime?: string;
    jsonLevel?: string;
    jsonMessage?: string;
    jsonHost?: string;
    jsonApp?: string;
    // A Go regular expression with named groups: time, level, host, app, msg.
    pattern?: string;
    // A Go reference layout. Empty means the known shapes are tried.
    timeLayout?: string;
    // The year a BSD-shaped timestamp omits, and the zone one without a zone is
    // read in. Empty means this year and the machine's zone.
    year?: number;
    timezone?: string;
    joinContinuations: boolean;
    skipUnmatched: boolean;
}

export const selectLogFile = (): Promise<string> => callGo('SelectLogFile');
export const previewLogFile = (p: string, format: ImportFormat): Promise<ImportPreview> =>
    callGo('PreviewLogFile', p, format);
export const importLogFile = (p: string, persist: boolean, format: ImportFormat): Promise<ImportResult> =>
    callGo('ImportLogFile', p, persist, format);
export const getImportFormat = (): Promise<ImportFormat> => callGo('GetImportFormat');

// Exporting the lines that were picked out by hand, rather than everything a
// filter matched.
export const exportSelection = (ids: string[], format: string, timezone: string): Promise<string> =>
    callGo('ExportSelection', ids, format, timezone);

// Writing messages the interface hands over, as it has them — which is how an
// export can match a screen that is showing stand-ins.
export const exportMessages = (messages: SyslogMessage[], format: string, timezone: string): Promise<string> =>
    callGo('ExportMessages', messages, format, timezone);

// --- Window and tray ---
// What the close button does: 'ask' (the default), 'quit' or 'background'.
export type CloseAction = 'ask' | 'quit' | 'background';
export const quitApplication = (): Promise<void> => callGo('QuitApplication');
export const hideToBackground = (): Promise<void> => callGo('HideToBackground');
export const revealWindow = (): Promise<void> => callGo('RevealWindow');
export const cancelClose = (): Promise<void> => callGo('CancelClose');
export const isTrayAvailable = (): Promise<boolean> => callGo('IsTrayAvailable');
export const getCloseAction = (): Promise<CloseAction> => callGo('GetCloseAction');
export const setCloseAction = (a: CloseAction): Promise<void> => callGo('SetCloseAction', a);
export const setTrayLabels = (show: string, quit: string): Promise<void> =>
    callGo('SetTrayLabels', show, quit);

// --- Running in the background (#68) ---
// Two modes, kept apart: the desktop application started at sign-in, in the
// user's session; and a separate system service started at boot, Windows only.
export interface BackgroundSettings {
    launchAtLogin: boolean;
    launchAtLoginSupported: boolean;
    registeredElsewhere: string;
    autoStartListeners: boolean;
    launchedInBackground: boolean;
    trayAvailable: boolean;
}
export interface HostListener { protocol: string; port: number; running: boolean; }
export interface HostStatus {
    state: string;
    version: string;
    pid: number;
    dataDir: string;
    startedAt: string;
    updatedAt: string;
    listeners: HostListener[] | null;
    messages: number;
    windows: number;
    listenOnStart: boolean;
    inbox?: InboxStatus | null;
    error?: string;
}
// The service's sealed inbox: what it received for a window whose database is
// encrypted, waiting for that window to collect it.
export interface InboxStatus {
    sealed: boolean;
    keyId?: string;
    batches: number;
    bytes: number;
    quota: number;
    dropped: number;
    error?: string;
}
export interface SystemServiceInfo {
    supported: boolean;
    // "windows" or "linux": what installing involves, and how it is said.
    platform: string;
    installed: boolean;
    state: string;
    canInstall: boolean;
    cannotInstallReason: string;
    executableMatches: boolean;
    executable: string;
    account: string;
    dataDir: string;
    host?: HostStatus | null;
}
export const getBackgroundSettings = (): Promise<BackgroundSettings> => callGo('GetBackgroundSettings');
export const setLaunchAtLogin = (enabled: boolean): Promise<void> => callGo('SetLaunchAtLogin', enabled);
export const setAutoStartListeners = (enabled: boolean): Promise<void> => callGo('SetAutoStartListeners', enabled);
// Why receiving could not start on launch, once; empty when it did.
export const getAutoStartError = (): Promise<string> => callGo('GetAutoStartError');
// Why this window cannot use its data directory, or empty.
export const getDataDirConflict = (): Promise<string> => callGo('GetDataDirConflict');
export const getSystemService = (): Promise<SystemServiceInfo> => callGo('GetSystemService');
// These four ask for administrator rights through the Windows prompt.
// sealed keeps an encrypted database encrypted: the service seals what it
// receives for this window instead of storing it in the clear.
export const installSystemService = (sealed: boolean): Promise<void> => callGo('InstallSystemService', sealed);
export const uninstallSystemService = (purge: boolean): Promise<void> => callGo('UninstallSystemService', purge);
export const startSystemService = (): Promise<void> => callGo('StartSystemService');
export const stopSystemService = (): Promise<void> => callGo('StopSystemService');
// Whether the service starts its listeners when it starts, or leaves them for
// a window to start. Read and written on the engine this window drives: the
// service's, while it drives it.
export const getListenOnStart = (): Promise<boolean> => callGo('GetListenOnStart');
export const setListenOnStart = (enabled: boolean): Promise<void> => callGo('SetListenOnStart', enabled);

// Which engine this window drives: its own, or the system service's while it
// runs. reason says why it drives its own although the service is installed:
// stopped, denied, version (detail names the service's), notService, or
// unreachable.
export interface ServiceLink {
    mode: 'local' | 'service';
    installed: boolean;
    state: string;
    reason?: '' | 'stopped' | 'denied' | 'version' | 'notService' | 'unreachable';
    detail?: string;
    serviceVersion?: string;
    // The service seals what it receives; the history is this window's own
    // encrypted database, which collects it. collectError says why that fails.
    sealed?: boolean;
    collectError?: string;
}
export const getServiceLink = (): Promise<ServiceLink> => callGo('GetServiceLink');
// Lets this window's account drive the service; asks for administrator rights.
export const allowServiceAccess = (): Promise<void> => callGo('AllowServiceAccess');
