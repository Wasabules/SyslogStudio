package models

import (
	"fmt"
	"os"
	"regexp"
	"time"
)

// Severity represents syslog severity levels (RFC 5424 Section 6.2.1)
type Severity int

const (
	SevEmergency     Severity = 0
	SevAlert         Severity = 1
	SevCritical      Severity = 2
	SevError         Severity = 3
	SevWarning       Severity = 4
	SevNotice        Severity = 5
	SevInformational Severity = 6
	SevDebug         Severity = 7
)

// Facility represents syslog facility codes (RFC 5424 Section 6.2.1)
type Facility int

const (
	FacKern     Facility = 0
	FacUser     Facility = 1
	FacMail     Facility = 2
	FacDaemon   Facility = 3
	FacAuth     Facility = 4
	FacSyslog   Facility = 5
	FacLPR      Facility = 6
	FacNews     Facility = 7
	FacUUCP     Facility = 8
	FacCron     Facility = 9
	FacAuthPriv Facility = 10
	FacFTP      Facility = 11
	FacNTP      Facility = 12
	FacAudit    Facility = 13
	FacAlert    Facility = 14
	FacClock    Facility = 15
	FacLocal0   Facility = 16
	FacLocal1   Facility = 17
	FacLocal2   Facility = 18
	FacLocal3   Facility = 19
	FacLocal4   Facility = 20
	FacLocal5   Facility = 21
	FacLocal6   Facility = 22
	FacLocal7   Facility = 23
)

// SyslogMessage represents a single parsed syslog entry.
type SyslogMessage struct {
	ID             string    `json:"id"`
	Timestamp      time.Time `json:"timestamp"`
	ReceivedAt     time.Time `json:"receivedAt"`
	Severity       Severity  `json:"severity"`
	SeverityLabel  string    `json:"severityLabel"`
	Facility       Facility  `json:"facility"`
	FacilityLabel  string    `json:"facilityLabel"`
	Hostname       string    `json:"hostname"`
	AppName        string    `json:"appName"`
	ProcID         string    `json:"procID"`
	MsgID          string    `json:"msgID"`
	Message        string    `json:"message"`
	RawMessage     string    `json:"rawMessage"`
	SourceIP       string    `json:"sourceIP"`
	Protocol       string    `json:"protocol"`
	Version        int       `json:"version"`
	StructuredData string    `json:"structuredData"`
}

// CertOptions holds parameters for certificate generation.
type CertOptions struct {
	Algorithm    string   `json:"algorithm"`
	ValidityDays int      `json:"validityDays"`
	CommonName   string   `json:"commonName"`
	Organization string   `json:"organization"`
	DNSNames     []string `json:"dnsNames"`
	IPAddresses  []string `json:"ipAddresses"`
}

// DefaultCertOptions returns sensible defaults for certificate generation.
func DefaultCertOptions() CertOptions {
	return CertOptions{
		Algorithm:    "ECDSA-P256",
		ValidityDays: 365,
		CommonName:   "SyslogStudio",
		Organization: "SyslogStudio",
		DNSNames:     []string{"localhost"},
		IPAddresses:  []string{"127.0.0.1", "::1"},
	}
}

// CertInfo holds details about a loaded or generated certificate.
type CertInfo struct {
	Subject           string   `json:"subject"`
	Issuer            string   `json:"issuer"`
	NotBefore         string   `json:"notBefore"`
	NotAfter          string   `json:"notAfter"`
	SerialNumber      string   `json:"serialNumber"`
	SHA256Fingerprint string   `json:"sha256Fingerprint"`
	Algorithm         string   `json:"algorithm"`
	KeySize           string   `json:"keySize"`
	DNSNames          []string `json:"dnsNames"`
	IPAddresses       []string `json:"ipAddresses"`
	IsSelfSigned      bool     `json:"isSelfSigned"`
	IsExpired         bool     `json:"isExpired"`
	IsValid           bool     `json:"isValid"`
}

// ServerConfig holds user-configurable server parameters.
type ServerConfig struct {
	UDPEnabled    bool        `json:"udpEnabled"`
	TCPEnabled    bool        `json:"tcpEnabled"`
	TLSEnabled    bool        `json:"tlsEnabled"`
	UDPPort       int         `json:"udpPort"`
	TCPPort       int         `json:"tcpPort"`
	TLSPort       int         `json:"tlsPort"`
	MaxBuffer     int         `json:"maxBuffer"`
	CertFile      string      `json:"certFile"`
	KeyFile       string      `json:"keyFile"`
	UseSelfSigned bool        `json:"useSelfSigned"`
	CertOptions   CertOptions `json:"certOptions"`
	MutualTLS     bool        `json:"mutualTLS"`
	CAFile        string      `json:"caFile"`
}

// ServerStatus describes the current state of the server.
type ServerStatus struct {
	Running    bool         `json:"running"`
	UDPRunning bool         `json:"udpRunning"`
	TCPRunning bool         `json:"tcpRunning"`
	TLSRunning bool         `json:"tlsRunning"`
	Config     ServerConfig `json:"config"`
	Error      string       `json:"error,omitempty"`
}

// ServerStats provides the statistics dashboard data.
type ServerStats struct {
	TotalMessages   int64            `json:"totalMessages"`
	MessagesByLevel map[string]int64 `json:"messagesByLevel"`
	TopSources      []SourceCount    `json:"topSources"`
	MessagesPerSec  float64          `json:"messagesPerSec"`
	BufferUsed      int              `json:"bufferUsed"`
	BufferMax       int              `json:"bufferMax"`
}

// SourceCount tracks message count per hostname.
type SourceCount struct {
	Hostname string `json:"hostname"`
	Count    int64  `json:"count"`
}

// FilterCriteria is used to request filtered logs.
type FilterCriteria struct {
	Severities []int  `json:"severities,omitempty"`
	Facilities []int  `json:"facilities,omitempty"`
	Hostname   string `json:"hostname,omitempty"`
	AppName    string `json:"appName,omitempty"`
	SourceIP   string `json:"sourceIP,omitempty"`
	Search     string `json:"search,omitempty"`
	SearchMode string `json:"searchMode,omitempty"`
	DateFrom   string `json:"dateFrom,omitempty"`
	DateTo     string `json:"dateTo,omitempty"`
}

// StorageConfig holds persistence settings.
type StorageConfig struct {
	Enabled       bool   `json:"enabled"`
	Path          string `json:"path"`
	RetentionDays int    `json:"retentionDays"`
	MaxMessages   int    `json:"maxMessages"`
	MaxSizeMB     int    `json:"maxSizeMB"`
}

// StorageStats provides database information.
type StorageStats struct {
	MessageCount    int64   `json:"messageCount"`
	DatabaseSizeMB  float64 `json:"databaseSizeMB"`
	OldestTimestamp string  `json:"oldestTimestamp"`
}

// PagedResult holds a paginated query result.
type PagedResult struct {
	Messages []SyslogMessage `json:"messages"`
	Total    int             `json:"total"`
	Page     int             `json:"page"`
	PageSize int             `json:"pageSize"`
}

// QueryOptions holds parameters for paginated, sorted queries.
type QueryOptions struct {
	Filter    FilterCriteria `json:"filter"`
	Page      int            `json:"page"`
	PageSize  int            `json:"pageSize"`
	SortField string         `json:"sortField"`
	SortDir   string         `json:"sortDir"`
	GroupBy   string         `json:"groupBy"`
}

// GroupSummary holds a group key and its message count.
type GroupSummary struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

// AlertRule defines a condition that triggers an alert.
type AlertRule struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Enabled     bool   `json:"enabled"`
	Pattern     string `json:"pattern"`
	UseRegex    bool   `json:"useRegex"`
	MinSeverity int    `json:"minSeverity"`
	Hostname    string `json:"hostname"`
	AppName     string `json:"appName"`
	Cooldown    int    `json:"cooldown"`
}

// AlertEvent records a triggered alert.
type AlertEvent struct {
	ID        string    `json:"id"`
	RuleID    string    `json:"ruleId"`
	RuleName  string    `json:"ruleName"`
	Message   string    `json:"message"`
	Severity  string    `json:"severity"`
	Hostname  string    `json:"hostname"`
	Timestamp time.Time `json:"timestamp"`
}

// AppConfig is the top-level persisted configuration.
type AppConfig struct {
	Server  ServerConfig  `json:"server"`
	Storage StorageConfig `json:"storage"`
	Alerts  []AlertRule   `json:"alerts"`
}

// UpdateInfo contains information about an available update.
type UpdateInfo struct {
	CurrentVersion string `json:"currentVersion"`
	LatestVersion  string `json:"latestVersion"`
	UpdateURL      string `json:"updateUrl"`
	HasUpdate      bool   `json:"hasUpdate"`
}

// --- Label converters ---

// SeverityToLabel converts a severity level to its string label.
func SeverityToLabel(s Severity) string {
	switch s {
	case SevEmergency:
		return "Emergency"
	case SevAlert:
		return "Alert"
	case SevCritical:
		return "Critical"
	case SevError:
		return "Error"
	case SevWarning:
		return "Warning"
	case SevNotice:
		return "Notice"
	case SevInformational:
		return "Info"
	case SevDebug:
		return "Debug"
	default:
		return "Unknown"
	}
}

// FacilityToLabel converts a facility code to its string label.
func FacilityToLabel(f Facility) string {
	switch f {
	case FacKern:
		return "kern"
	case FacUser:
		return "user"
	case FacMail:
		return "mail"
	case FacDaemon:
		return "daemon"
	case FacAuth:
		return "auth"
	case FacSyslog:
		return "syslog"
	case FacLPR:
		return "lpr"
	case FacNews:
		return "news"
	case FacUUCP:
		return "uucp"
	case FacCron:
		return "cron"
	case FacAuthPriv:
		return "authpriv"
	case FacFTP:
		return "ftp"
	case FacNTP:
		return "ntp"
	case FacAudit:
		return "audit"
	case FacAlert:
		return "alert"
	case FacClock:
		return "clock"
	case FacLocal0:
		return "local0"
	case FacLocal1:
		return "local1"
	case FacLocal2:
		return "local2"
	case FacLocal3:
		return "local3"
	case FacLocal4:
		return "local4"
	case FacLocal5:
		return "local5"
	case FacLocal6:
		return "local6"
	case FacLocal7:
		return "local7"
	default:
		return "unknown"
	}
}

// --- Default factories ---

// DefaultStorageConfig returns sensible defaults for storage.
func DefaultStorageConfig() StorageConfig {
	return StorageConfig{
		Enabled:       true,
		RetentionDays: 7,
		MaxMessages:   1000000,
		MaxSizeMB:     500,
	}
}

// DefaultServerConfig returns sensible defaults.
func DefaultServerConfig() ServerConfig {
	return ServerConfig{
		UDPEnabled:    true,
		TCPEnabled:    false,
		TLSEnabled:    false,
		UDPPort:       514,
		TCPPort:       514,
		TLSPort:       6514,
		MaxBuffer:     10000,
		UseSelfSigned: false,
	}
}

// --- Validation ---

// ValidateServerConfig checks the configuration for errors before starting.
func ValidateServerConfig(c ServerConfig) error {
	if !c.UDPEnabled && !c.TCPEnabled && !c.TLSEnabled {
		return fmt.Errorf("at least one protocol (UDP, TCP, or TLS) must be enabled")
	}

	checkPort := func(name string, port int) error {
		if port < 1 || port > 65535 {
			return fmt.Errorf("%s port %d is out of range (1-65535)", name, port)
		}
		return nil
	}

	if c.UDPEnabled {
		if err := checkPort("UDP", c.UDPPort); err != nil {
			return err
		}
	}
	if c.TCPEnabled {
		if err := checkPort("TCP", c.TCPPort); err != nil {
			return err
		}
	}
	if c.TLSEnabled {
		if err := checkPort("TLS", c.TLSPort); err != nil {
			return err
		}
	}

	type portProto struct {
		port int
		name string
	}
	var active []portProto
	if c.TCPEnabled {
		active = append(active, portProto{c.TCPPort, "TCP"})
	}
	if c.TLSEnabled {
		active = append(active, portProto{c.TLSPort, "TLS"})
	}
	for i := 0; i < len(active); i++ {
		for j := i + 1; j < len(active); j++ {
			if active[i].port == active[j].port {
				return fmt.Errorf("%s and %s cannot use the same port (%d)", active[i].name, active[j].name, active[i].port)
			}
		}
	}

	if c.TLSEnabled && !c.UseSelfSigned {
		if c.CertFile == "" {
			return fmt.Errorf("TLS certificate file path is required")
		}
		if c.KeyFile == "" {
			return fmt.Errorf("TLS private key file path is required")
		}
		if _, err := os.Stat(c.CertFile); err != nil {
			return fmt.Errorf("TLS certificate file not found: %s", c.CertFile)
		}
		if _, err := os.Stat(c.KeyFile); err != nil {
			return fmt.Errorf("TLS key file not found: %s", c.KeyFile)
		}
	}

	if c.TLSEnabled && c.MutualTLS && c.CAFile != "" {
		if _, err := os.Stat(c.CAFile); err != nil {
			return fmt.Errorf("CA certificate file not found: %s", c.CAFile)
		}
	}

	return nil
}

// --- Shared filter utilities (used by syslog, alert, and storage packages) ---

const MaxRegexLen = 200

// SafeCompileRegex compiles a user-supplied regex with length limit to prevent ReDoS.
func SafeCompileRegex(pattern string) (*regexp.Regexp, error) {
	if len(pattern) > MaxRegexLen {
		return nil, fmt.Errorf("regex pattern too long (max %d characters)", MaxRegexLen)
	}
	return regexp.Compile("(?i)" + pattern)
}

// ParseFilterDate parses a date string in RFC 3339 or "YYYY-MM-DD" format.
func ParseFilterDate(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, s)
	if err == nil {
		return t, true
	}
	t, err = time.Parse("2006-01-02", s)
	if err == nil {
		return t, true
	}
	t, err = time.Parse("2006-01-02T15:04", s)
	if err == nil {
		return t, true
	}
	return time.Time{}, false
}
