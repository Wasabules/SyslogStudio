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

// --- Logs ---
export const getMessages = (filter: FilterCriteria): Promise<SyslogMessage[]> => _GetMessages(filter as any);
export const clearMessages = (): Promise<void> => _ClearMessages();
export const getStats = (): Promise<ServerStats> => _GetStats();
export const exportLogs = (filter: FilterCriteria, format: string): Promise<string> => _ExportLogs(filter as any, format);

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

// --- Update Check ---
export interface UpdateInfo {
    currentVersion: string;
    latestVersion: string;
    updateUrl: string;
    hasUpdate: boolean;
}
export const checkForUpdate = (): Promise<UpdateInfo> => callGo('CheckForUpdate');
export const getAppVersion = (): Promise<string> => callGo('GetAppVersion');

// --- Utilities ---
export const getLocalIPs = (): Promise<string[]> => _GetLocalIPs();
export const selectCertFile = (): Promise<string> => _SelectCertFile();
export const selectKeyFile = (): Promise<string> => _SelectKeyFile();
export const selectCAFile = (): Promise<string> => _SelectCAFile();
