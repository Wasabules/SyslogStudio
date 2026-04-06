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
	    maxBuffer: number;
	    certFile: string;
	    keyFile: string;
	    useSelfSigned: boolean;
	    certOptions: CertOptions;
	    mutualTLS: boolean;
	    caFile: string;
	
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
	        this.maxBuffer = source["maxBuffer"];
	        this.certFile = source["certFile"];
	        this.keyFile = source["keyFile"];
	        this.useSelfSigned = source["useSelfSigned"];
	        this.certOptions = this.convertValues(source["certOptions"], CertOptions);
	        this.mutualTLS = source["mutualTLS"];
	        this.caFile = source["caFile"];
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
	
	    static createFrom(source: any = {}) {
	        return new StorageStats(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.messageCount = source["messageCount"];
	        this.databaseSizeMB = source["databaseSizeMB"];
	        this.oldestTimestamp = source["oldestTimestamp"];
	    }
	}
	
	export class UpdateInfo {
	    currentVersion: string;
	    latestVersion: string;
	    updateUrl: string;
	    hasUpdate: boolean;
	
	    static createFrom(source: any = {}) {
	        return new UpdateInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.currentVersion = source["currentVersion"];
	        this.latestVersion = source["latestVersion"];
	        this.updateUrl = source["updateUrl"];
	        this.hasUpdate = source["hasUpdate"];
	    }
	}

}

