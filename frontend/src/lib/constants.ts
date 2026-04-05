export const SEVERITY_LABELS: Record<number, string> = {
    0: 'Emergency',
    1: 'Alert',
    2: 'Critical',
    3: 'Error',
    4: 'Warning',
    5: 'Notice',
    6: 'Info',
    7: 'Debug',
};

export const SEVERITY_COLORS: Record<number, string> = {
    0: '#ff0040',
    1: '#ff4444',
    2: '#ff6644',
    3: '#ff8800',
    4: '#ffcc00',
    5: '#44aaff',
    6: '#66dd66',
    7: '#888888',
};

export const FACILITY_LABELS: Record<number, string> = {
    0: 'kern',
    1: 'user',
    2: 'mail',
    3: 'daemon',
    4: 'auth',
    5: 'syslog',
    6: 'lpr',
    7: 'news',
    8: 'uucp',
    9: 'cron',
    10: 'authpriv',
    11: 'ftp',
    12: 'ntp',
    13: 'audit',
    14: 'alert',
    15: 'clock',
    16: 'local0',
    17: 'local1',
    18: 'local2',
    19: 'local3',
    20: 'local4',
    21: 'local5',
    22: 'local6',
    23: 'local7',
};

export function formatTimestamp(isoString: string): string {
    if (!isoString) return '';
    const d = new Date(isoString);
    const pad = (n: number) => n.toString().padStart(2, '0');
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}
