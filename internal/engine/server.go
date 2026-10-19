package engine

// Listening: starting and stopping the receiver, and what it holds.

import (
	"fmt"
	"net"

	"SyslogStudio/internal/models"
	"SyslogStudio/internal/notify"
)

func (e *Engine) StartServer(config models.ServerConfig) error {
	// A saved identity that is not loaded — still encrypted, or unreadable —
	// must stop the start rather than be replaced. Generating a fresh one here
	// would hand clients a certificate they were never told to trust, and
	// persisting it would overwrite the one they were.
	if config.TLSEnabled && config.UseSelfSigned && !e.tlsManager.HasServerCert() &&
		e.serverCertStore != nil && e.serverCertStore.Exists() {
		return fmt.Errorf("the saved TLS certificate is not loaded; unlock the database, or generate a new certificate in the TLS settings")
	}
	err := e.server.Start(config)
	if err == nil {
		e.configStore.Save(config)
		e.refreshLocalEndpoints(config)
	}
	return err
}

// refreshLocalEndpoints tells the dispatcher which ports this app now listens
// on, so a destination pointing back at one is recognised as a relay loop even
// if it was saved while the listener was elsewhere.
func (e *Engine) refreshLocalEndpoints(config models.ServerConfig) {
	if e.dispatcher == nil {
		return
	}
	ports := make(map[int]bool, 3)
	if config.UDPEnabled {
		ports[config.UDPPort] = true
	}
	if config.TCPEnabled {
		ports[config.TCPPort] = true
	}
	if config.TLSEnabled {
		ports[config.TLSPort] = true
	}
	e.dispatcher.SetLocalEndpoints(notify.LocalEndpoints{Ports: ports, IPs: localIPs()})
}

// localIPs lists this machine's addresses, used only to recognise a
// destination that points back at us.
func localIPs() map[string]bool {
	out := make(map[string]bool)
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return out
	}
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok {
			out[ipNet.IP.String()] = true
		}
	}
	return out
}

func (e *Engine) StopServer() error {
	err := e.server.Stop()
	if err == nil && e.dispatcher != nil {
		// Nothing is listening, so nothing here can be looped back into.
		e.dispatcher.SetLocalEndpoints(notify.LocalEndpoints{})
	}
	return err
}

// GetServerStatus reports what the server is doing, and what it is configured
// with.
//
// The server only learns its configuration in Start, so before the first start
// it has none — and returning that emptiness as "the configuration" is how the
// saved TLS certificate paths came to be wiped on every launch (#45): the
// renderer syncs the TLS fields from this status, and copied blanks over the
// paths it had just loaded. When nothing is running, the honest answer to
// "what is this server set up with" is what was saved.
func (e *Engine) GetServerStatus() models.ServerStatus {
	status := e.server.GetStatus()
	if !status.Running {
		status.Config = e.configStore.Load()
	}
	return status
}

// SaveServerConfig persists the server configuration without starting anything.
//
// Until this existed, settings were only written on a successful start, so
// choosing a certificate and closing the window without pressing Start threw
// the choice away — the same complaint as #45 arriving by a second route.
//
// Deliberately NOT validated. Choosing a certificate and then its key is two
// steps, and a configuration halfway through one is exactly what needs to
// survive; refusing to save it would reintroduce the bug this exists to fix.
// StartServer validates, which is where an incomplete configuration actually
// matters and where the message can say what is missing.
func (e *Engine) SaveServerConfig(config models.ServerConfig) {
	e.configStore.Save(config)
}

func (e *Engine) GetDefaultConfig() models.ServerConfig {
	return e.configStore.Load()
}

func (e *Engine) GetMessages(filter models.FilterCriteria) []models.SyslogMessage {
	return e.server.GetMessages(filter)
}

func (e *Engine) ClearMessages() {
	e.server.ClearMessages()
}

func (e *Engine) GetStats() models.ServerStats {
	return e.server.GetStats()
}

func (e *Engine) GetLocalIPs() []string {
	var ips []string
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ips
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				ips = append(ips, ipnet.IP.String())
			}
		}
	}
	return ips
}

// GetNetworkInterfaces lists bindable local IPv4 addresses with their
// interface name, for the bind-address selector. Interfaces that are down are
// skipped; loopback is included so the server can be restricted to localhost.
func (e *Engine) GetNetworkInterfaces() []models.NetworkInterface {
	var out []models.NetworkInterface
	ifaces, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				if ip4 := ipnet.IP.To4(); ip4 != nil {
					out = append(out, models.NetworkInterface{Name: iface.Name, IP: ip4.String()})
				}
			}
		}
	}
	return out
}
