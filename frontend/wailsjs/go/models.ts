export namespace importer {
	
	export class Result {
	    file: string;
	    linesRead: number;
	    imported: number;
	    blank: number;
	    truncated: number;
	    syslog: number;
	    timeDetected: number;
	    levelDetected: number;
	    unmatched: number;
	    joined: number;
	    stopped: boolean;
	    bySeverity: Record<string, number>;
	
	    static createFrom(source: any = {}) {
	        return new Result(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.file = source["file"];
	        this.linesRead = source["linesRead"];
	        this.imported = source["imported"];
	        this.blank = source["blank"];
	        this.truncated = source["truncated"];
	        this.syslog = source["syslog"];
	        this.timeDetected = source["timeDetected"];
	        this.levelDetected = source["levelDetected"];
	        this.unmatched = source["unmatched"];
	        this.joined = source["joined"];
	        this.stopped = source["stopped"];
	        this.bySeverity = source["bySeverity"];
	    }
	}
	export class Preview {
	    result: Result;
	    messages: models.SyslogMessage[];
	
	    static createFrom(source: any = {}) {
	        return new Preview(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.result = this.convertValues(source["result"], Result);
	        this.messages = this.convertValues(source["messages"], models.SyslogMessage);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace models {
	
	export class AlertEvent {
	    id: string;
	    ruleId: string;
	    ruleName: string;
	    message: string;
	    severity: string;
	    hostname: string;
	    // Go type: time
	    timestamp: any;
	
	    static createFrom(source: any = {}) {
	        return new AlertEvent(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.ruleId = source["ruleId"];
	        this.ruleName = source["ruleName"];
	        this.message = source["message"];
	        this.severity = source["severity"];
	        this.hostname = source["hostname"];
	        this.timestamp = this.convertValues(source["timestamp"], null);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class AlertRule {
	    id: string;
	    name: string;
	    enabled: boolean;
	    pattern: string;
	    useRegex: boolean;
	    minSeverity: number;
	    hostname: string;
	    appName: string;
	    cooldown: number;
	
	    static createFrom(source: any = {}) {
	        return new AlertRule(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.name = source["name"];
	        this.enabled = source["enabled"];
	        this.pattern = source["pattern"];
	        this.useRegex = source["useRegex"];
	        this.minSeverity = source["minSeverity"];
	        this.hostname = source["hostname"];
	        this.appName = source["appName"];
	        this.cooldown = source["cooldown"];
	    }
	}
	export class CertInfo {
	    subject: string;
	    issuer: string;
	    notBefore: string;
	    notAfter: string;
	    serialNumber: string;
	    sha256Fingerprint: string;
	    algorithm: string;
	    keySize: string;
	    dnsNames: string[];
	    ipAddresses: string[];
	    isSelfSigned: boolean;
	    isExpired: boolean;
	    isValid: boolean;
	
	    static createFrom(source: any = {}) {
	        return new CertInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.subject = source["subject"];
	        this.issuer = source["issuer"];
	        this.notBefore = source["notBefore"];
	        this.notAfter = source["notAfter"];
	        this.serialNumber = source["serialNumber"];
	        this.sha256Fingerprint = source["sha256Fingerprint"];
	        this.algorithm = source["algorithm"];
	        this.keySize = source["keySize"];
	        this.dnsNames = source["dnsNames"];
	        this.ipAddresses = source["ipAddresses"];
	        this.isSelfSigned = source["isSelfSigned"];
	        this.isExpired = source["isExpired"];
	        this.isValid = source["isValid"];
	    }
	}
	export class CertOptions {
	    algorithm: string;
	    validityDays: number;
	    commonName: string;
	    organization: string;
	    dnsNames: string[];
	    ipAddresses: string[];
	
	    static createFrom(source: any = {}) {
	        return new CertOptions(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.algorithm = source["algorithm"];
	        this.validityDays = source["validityDays"];
	        this.commonName = source["commonName"];
	        this.organization = source["organization"];
	        this.dnsNames = source["dnsNames"];
	        this.ipAddresses = source["ipAddresses"];
	    }
	}
	export class FilterCriteria {
	    severities?: number[];
	    facilities?: number[];
	    hostname?: string;
	    appName?: string;
	    sourceIP?: string;
	    search?: string;
	    searchMode?: string;
	    dateFrom?: string;
	    dateTo?: string;
	
	    static createFrom(source: any = {}) {
	        return new FilterCriteria(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.severities = source["severities"];
	        this.facilities = source["facilities"];
	        this.hostname = source["hostname"];
	        this.appName = source["appName"];
	        this.sourceIP = source["sourceIP"];
	        this.search = source["search"];
	        this.searchMode = source["searchMode"];
	        this.dateFrom = source["dateFrom"];
	        this.dateTo = source["dateTo"];
	    }
	}
	export class GroupSummary {
	    key: string;
	    count: number;
	
	    static createFrom(source: any = {}) {
	        return new GroupSummary(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.key = source["key"];
	        this.count = source["count"];
	    }
	}
	export class ImportFormat {
	    mode: string;
	    jsonTime?: string;
	    jsonLevel?: string;
	    jsonMessage?: string;
	    jsonHost?: string;
	    jsonApp?: string;
	    pattern?: string;
	    timeLayout?: string;
	    year?: number;
	    timezone?: string;
	    joinContinuations: boolean;
	    skipUnmatched: boolean;
	
	    static createFrom(source: any = {}) {
	        return new ImportFormat(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.mode = source["mode"];
	        this.jsonTime = source["jsonTime"];
	        this.jsonLevel = source["jsonLevel"];
	        this.jsonMessage = source["jsonMessage"];
	        this.jsonHost = source["jsonHost"];
	        this.jsonApp = source["jsonApp"];
	        this.pattern = source["pattern"];
	        this.timeLayout = source["timeLayout"];
	        this.year = source["year"];
	        this.timezone = source["timezone"];
	        this.joinContinuations = source["joinContinuations"];
	        this.skipUnmatched = source["skipUnmatched"];
	    }
	}
	export class NetworkInterface {
	    name: string;
	    ip: string;
	
	    static createFrom(source: any = {}) {
	        return new NetworkInterface(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.ip = source["ip"];
	    }
	}
	export class SyslogMessage {
	    id: string;
	    // Go type: time
	    timestamp: any;
	    // Go type: time
	    receivedAt: any;
	    severity: number;
	    severityLabel: string;
	    facility: number;
	    facilityLabel: string;
	    hostname: string;
	    appName: string;
	    procID: string;
	    msgID: string;
	    message: string;
	    rawMessage: string;
	    sourceIP: string;
	    protocol: string;
	    version: number;
	    structuredData: string;
	
	    static createFrom(source: any = {}) {
	        return new SyslogMessage(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.timestamp = this.convertValues(source["timestamp"], null);
	        this.receivedAt = this.convertValues(source["receivedAt"], null);
	        this.severity = source["severity"];
	        this.severityLabel = source["severityLabel"];
	        this.facility = source["facility"];
	        this.facilityLabel = source["facilityLabel"];
	        this.hostname = source["hostname"];
	        this.appName = source["appName"];
	        this.procID = source["procID"];
	        this.msgID = source["msgID"];
	        this.message = source["message"];
	        this.rawMessage = source["rawMessage"];
	        this.sourceIP = source["sourceIP"];
	        this.protocol = source["protocol"];
	        this.version = source["version"];
	        this.structuredData = source["structuredData"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class PagedResult {
	    messages: SyslogMessage[];
	    total: number;
	    page: number;
	    pageSize: number;
	
	    static createFrom(source: any = {}) {
	        return new PagedResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.messages = this.convertValues(source["messages"], SyslogMessage);
	        this.total = source["total"];
	        this.page = source["page"];
	        this.pageSize = source["pageSize"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class QueryOptions {
	    filter: FilterCriteria;
	    page: number;
	    pageSize: number;
	    sortField: string;
	    sortDir: string;
	    groupBy: string;
	
	    static createFrom(source: any = {}) {
	        return new QueryOptions(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.filter = this.convertValues(source["filter"], FilterCriteria);
	        this.page = source["page"];
	        this.pageSize = source["pageSize"];
	        this.sortField = source["sortField"];
	        this.sortDir = source["sortDir"];
	        this.groupBy = source["groupBy"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class ServerConfig {
	    udpEnabled: boolean;
	    tcpEnabled: boolean;
	    tlsEnabled: boolean;
	    udpPort: number;
	    tcpPort: number;
	    tlsPort: number;
	    bindAddress: string;
	    allowedSources: string[];
	    maxBuffer: number;
	    certFile: string;
	    keyFile: string;
	    useSelfSigned: boolean;
	    certOptions: CertOptions;
	    mutualTLS: boolean;
	    caFile: string;
	    maxConnsPerIP: number;
	
	    static createFrom(source: any = {}) {
	        return new ServerConfig(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.udpEnabled = source["udpEnabled"];
	        this.tcpEnabled = source["tcpEnabled"];
	        this.tlsEnabled = source["tlsEnabled"];
	        this.udpPort = source["udpPort"];
	        this.tcpPort = source["tcpPort"];
	        this.tlsPort = source["tlsPort"];
	        this.bindAddress = source["bindAddress"];
	        this.allowedSources = source["allowedSources"];
	        this.maxBuffer = source["maxBuffer"];
	        this.certFile = source["certFile"];
	        this.keyFile = source["keyFile"];
	        this.useSelfSigned = source["useSelfSigned"];
	        this.certOptions = this.convertValues(source["certOptions"], CertOptions);
	        this.mutualTLS = source["mutualTLS"];
	        this.caFile = source["caFile"];
	        this.maxConnsPerIP = source["maxConnsPerIP"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class SourceCount {
	    hostname: string;
	    count: number;
	
	    static createFrom(source: any = {}) {
	        return new SourceCount(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.hostname = source["hostname"];
	        this.count = source["count"];
	    }
	}
	export class ServerStats {
	    totalMessages: number;
	    messagesByLevel: Record<string, number>;
	    topSources: SourceCount[];
	    messagesPerSec: number;
	    bufferUsed: number;
	    bufferMax: number;
	
	    static createFrom(source: any = {}) {
	        return new ServerStats(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.totalMessages = source["totalMessages"];
	        this.messagesByLevel = source["messagesByLevel"];
	        this.topSources = this.convertValues(source["topSources"], SourceCount);
	        this.messagesPerSec = source["messagesPerSec"];
	        this.bufferUsed = source["bufferUsed"];
	        this.bufferMax = source["bufferMax"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class ServerStatus {
	    running: boolean;
	    udpRunning: boolean;
	    tcpRunning: boolean;
	    tlsRunning: boolean;
	    config: ServerConfig;
	    error?: string;
	
	    static createFrom(source: any = {}) {
	        return new ServerStatus(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.running = source["running"];
	        this.udpRunning = source["udpRunning"];
	        this.tcpRunning = source["tcpRunning"];
	        this.tlsRunning = source["tlsRunning"];
	        this.config = this.convertValues(source["config"], ServerConfig);
	        this.error = source["error"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class SimulatorDestination {
	    id: string;
	    name: string;
	    host: string;
	    port: number;
	    protocol: string;
	    enabled: boolean;
	    insecureSkipVerify: boolean;
	
	    static createFrom(source: any = {}) {
	        return new SimulatorDestination(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.name = source["name"];
	        this.host = source["host"];
	        this.port = source["port"];
	        this.protocol = source["protocol"];
	        this.enabled = source["enabled"];
	        this.insecureSkipVerify = source["insecureSkipVerify"];
	    }
	}
	export class SimulatorConfig {
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
	
	    static createFrom(source: any = {}) {
	        return new SimulatorConfig(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.destinations = this.convertValues(source["destinations"], SimulatorDestination);
	        this.mode = source["mode"];
	        this.profile = source["profile"];
	        this.format = source["format"];
	        this.rate = source["rate"];
	        this.count = source["count"];
	        this.durationSeconds = source["durationSeconds"];
	        this.customMessage = source["customMessage"];
	        this.hostname = source["hostname"];
	        this.appName = source["appName"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	export class SimulatorDestinationStatus {
	    id: string;
	    name: string;
	    sent: number;
	    failed: number;
	    connected: boolean;
	    lastError?: string;
	
	    static createFrom(source: any = {}) {
	        return new SimulatorDestinationStatus(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.name = source["name"];
	        this.sent = source["sent"];
	        this.failed = source["failed"];
	        this.connected = source["connected"];
	        this.lastError = source["lastError"];
	    }
	}
	export class SimulatorStatus {
	    running: boolean;
	    mode: string;
	    sent: number;
	    failed: number;
	    ratePerSec: number;
	    elapsedMs: number;
	    phase?: string;
	    destinations: SimulatorDestinationStatus[];
	
	    static createFrom(source: any = {}) {
	        return new SimulatorStatus(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.running = source["running"];
	        this.mode = source["mode"];
	        this.sent = source["sent"];
	        this.failed = source["failed"];
	        this.ratePerSec = source["ratePerSec"];
	        this.elapsedMs = source["elapsedMs"];
	        this.phase = source["phase"];
	        this.destinations = this.convertValues(source["destinations"], SimulatorDestinationStatus);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	export class StorageConfig {
	    enabled: boolean;
	    path: string;
	    retentionDays: number;
	    maxMessages: number;
	    maxSizeMB: number;
	    encryptionEnabled: boolean;
	
	    static createFrom(source: any = {}) {
	        return new StorageConfig(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.enabled = source["enabled"];
	        this.path = source["path"];
	        this.retentionDays = source["retentionDays"];
	        this.maxMessages = source["maxMessages"];
	        this.maxSizeMB = source["maxSizeMB"];
	        this.encryptionEnabled = source["encryptionEnabled"];
	    }
	}
	export class StorageStats {
	    messageCount: number;
	    databaseSizeMB: number;
	    oldestTimestamp: string;
	    droppedWrites: number;
	
	    static createFrom(source: any = {}) {
	        return new StorageStats(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.messageCount = source["messageCount"];
	        this.databaseSizeMB = source["databaseSizeMB"];
	        this.oldestTimestamp = source["oldestTimestamp"];
	        this.droppedWrites = source["droppedWrites"];
	    }
	}
	
	export class UpdateConfig {
	    autoCheck: boolean;
	    intervalHours: number;
	    skipVersion: string;
	    lastCheckUnix: number;
	
	    static createFrom(source: any = {}) {
	        return new UpdateConfig(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.autoCheck = source["autoCheck"];
	        this.intervalHours = source["intervalHours"];
	        this.skipVersion = source["skipVersion"];
	        this.lastCheckUnix = source["lastCheckUnix"];
	    }
	}
	export class UpdateInfo {
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
	
	    static createFrom(source: any = {}) {
	        return new UpdateInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.currentVersion = source["currentVersion"];
	        this.latestVersion = source["latestVersion"];
	        this.updateUrl = source["updateUrl"];
	        this.hasUpdate = source["hasUpdate"];
	        this.releaseNotes = source["releaseNotes"];
	        this.releaseUrl = source["releaseUrl"];
	        this.publishedAt = source["publishedAt"];
	        this.assetName = source["assetName"];
	        this.assetUrl = source["assetUrl"];
	        this.canSelfApply = source["canSelfApply"];
	    }
	}

}

export namespace notify {
	
	export class DeliveryEntry {
	    // Go type: time
	    time: any;
	    sinkId: string;
	    sinkName: string;
	    target: string;
	    ok: boolean;
	    attempts: number;
	    error?: string;
	    subject?: string;
	
	    static createFrom(source: any = {}) {
	        return new DeliveryEntry(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.time = this.convertValues(source["time"], null);
	        this.sinkId = source["sinkId"];
	        this.sinkName = source["sinkName"];
	        this.target = source["target"];
	        this.ok = source["ok"];
	        this.attempts = source["attempts"];
	        this.error = source["error"];
	        this.subject = source["subject"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class TLSFiles {
	    caFile?: string;
	    clientCertFile?: string;
	    clientKeyFile?: string;
	    insecureSkipVerify?: boolean;
	
	    static createFrom(source: any = {}) {
	        return new TLSFiles(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.caFile = source["caFile"];
	        this.clientCertFile = source["clientCertFile"];
	        this.clientKeyFile = source["clientKeyFile"];
	        this.insecureSkipVerify = source["insecureSkipVerify"];
	    }
	}
	export class EmailSinkConfig {
	    host: string;
	    port: number;
	    username: string;
	    from: string;
	    to: string[];
	    encryption: string;
	    format?: string;
	    timeout: number;
	    tls: TLSFiles;
	
	    static createFrom(source: any = {}) {
	        return new EmailSinkConfig(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.host = source["host"];
	        this.port = source["port"];
	        this.username = source["username"];
	        this.from = source["from"];
	        this.to = source["to"];
	        this.encryption = source["encryption"];
	        this.format = source["format"];
	        this.timeout = source["timeout"];
	        this.tls = this.convertValues(source["tls"], TLSFiles);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class MessageTemplate {
	    subject?: string;
	    body?: string;
	
	    static createFrom(source: any = {}) {
	        return new MessageTemplate(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.subject = source["subject"];
	        this.body = source["body"];
	    }
	}
	export class Window {
	    start: string;
	    end: string;
	    days?: number[];
	
	    static createFrom(source: any = {}) {
	        return new Window(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.start = source["start"];
	        this.end = source["end"];
	        this.days = source["days"];
	    }
	}
	export class RouteMatch {
	    minSeverity?: number;
	    maxSeverity?: number;
	    facilities?: number[];
	    hostnames?: string[];
	    appNames?: string[];
	    sources?: string[];
	    pattern?: string;
	    useRegex?: boolean;
	    window?: Window;
	
	    static createFrom(source: any = {}) {
	        return new RouteMatch(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.minSeverity = source["minSeverity"];
	        this.maxSeverity = source["maxSeverity"];
	        this.facilities = source["facilities"];
	        this.hostnames = source["hostnames"];
	        this.appNames = source["appNames"];
	        this.sources = source["sources"];
	        this.pattern = source["pattern"];
	        this.useRegex = source["useRegex"];
	        this.window = this.convertValues(source["window"], Window);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class Route {
	    id: string;
	    name: string;
	    enabled: boolean;
	    priority: number;
	    match: RouteMatch;
	    sinkIds: string[];
	    stop: boolean;
	
	    static createFrom(source: any = {}) {
	        return new Route(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.name = source["name"];
	        this.enabled = source["enabled"];
	        this.priority = source["priority"];
	        this.match = this.convertValues(source["match"], RouteMatch);
	        this.sinkIds = source["sinkIds"];
	        this.stop = source["stop"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	export class WebhookSinkConfig {
	    url: string;
	    method: string;
	    headers: Record<string, string>;
	    timeout: number;
	    payloadMode?: string;
	
	    static createFrom(source: any = {}) {
	        return new WebhookSinkConfig(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.url = source["url"];
	        this.method = source["method"];
	        this.headers = source["headers"];
	        this.timeout = source["timeout"];
	        this.payloadMode = source["payloadMode"];
	    }
	}
	export class SyslogSinkConfig {
	    address: string;
	    protocol: string;
	    facility: number;
	    hostname: string;
	    appName: string;
	    timeout: number;
	    preserveOrigin?: boolean;
	    preserveFacility?: boolean;
	    caFile?: string;
	    clientCertFile?: string;
	    clientKeyFile?: string;
	    insecureSkipVerify?: boolean;
	
	    static createFrom(source: any = {}) {
	        return new SyslogSinkConfig(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.address = source["address"];
	        this.protocol = source["protocol"];
	        this.facility = source["facility"];
	        this.hostname = source["hostname"];
	        this.appName = source["appName"];
	        this.timeout = source["timeout"];
	        this.preserveOrigin = source["preserveOrigin"];
	        this.preserveFacility = source["preserveFacility"];
	        this.caFile = source["caFile"];
	        this.clientCertFile = source["clientCertFile"];
	        this.clientKeyFile = source["clientKeyFile"];
	        this.insecureSkipVerify = source["insecureSkipVerify"];
	    }
	}
	export class SinkConfig {
	    id: string;
	    name: string;
	    kind: string;
	    enabled: boolean;
	    syslog: SyslogSinkConfig;
	    webhook: WebhookSinkConfig;
	    email: EmailSinkConfig;
	    template: MessageTemplate;
	    redact: boolean;
	    secret?: string;
	    hasSecret: boolean;
	    maxRate?: number;
	
	    static createFrom(source: any = {}) {
	        return new SinkConfig(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.name = source["name"];
	        this.kind = source["kind"];
	        this.enabled = source["enabled"];
	        this.syslog = this.convertValues(source["syslog"], SyslogSinkConfig);
	        this.webhook = this.convertValues(source["webhook"], WebhookSinkConfig);
	        this.email = this.convertValues(source["email"], EmailSinkConfig);
	        this.template = this.convertValues(source["template"], MessageTemplate);
	        this.redact = source["redact"];
	        this.secret = source["secret"];
	        this.hasSecret = source["hasSecret"];
	        this.maxRate = source["maxRate"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class Stats {
	    matched: number;
	    delivered: number;
	    failed: number;
	    dropped: number;
	    looped: number;
	    blocked: number;
	    tripped?: string[];
	    queued: number;
	
	    static createFrom(source: any = {}) {
	        return new Stats(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.matched = source["matched"];
	        this.delivered = source["delivered"];
	        this.failed = source["failed"];
	        this.dropped = source["dropped"];
	        this.looped = source["looped"];
	        this.blocked = source["blocked"];
	        this.tripped = source["tripped"];
	        this.queued = source["queued"];
	    }
	}
	
	
	

}

