package main

import (
	"fmt"
	"log/slog"
	"time"

	"SyslogStudio/internal/models"
	"SyslogStudio/internal/notify"
)

// --- Notification routing --------------------------------------------------
//
// Routes decide which messages are interesting; sinks decide where they go.
// Every received message is offered to the router, not only the ones that trip
// an alert, which is what makes relaying a whole stream possible.
//
// Credentials never travel back to the frontend. A sink is returned with its
// Secret field blank and HasSecret set, so the form can show "configured"
// without ever receiving the value.

// GetNotifyRoutes returns the saved routing rules.
func (a *App) GetNotifyRoutes() []notify.Route {
	return a.configStore.LoadRoutes()
}

// GetNotifySinks returns the saved destinations, with credentials stripped.
func (a *App) GetNotifySinks() []notify.SinkConfig {
	sinks := a.configStore.LoadSinks()
	for i := range sinks {
		sinks[i].Secret = ""
		sinks[i].HasSecret = a.secretStore != nil && a.secretStore.Has(sinks[i].ID)
	}
	return sinks
}

// SaveNotifyRoute adds or replaces one routing rule.
func (a *App) SaveNotifyRoute(route notify.Route) error {
	if err := notify.ValidateRoute(route); err != nil {
		return err
	}
	if route.ID == "" {
		route.ID = newID("route")
	}

	routes := a.configStore.LoadRoutes()
	replaced := false
	for i := range routes {
		if routes[i].ID == route.ID {
			routes[i] = route
			replaced = true
			break
		}
	}
	if !replaced {
		routes = append(routes, route)
	}
	a.configStore.SaveRoutes(routes)
	a.reconfigureNotify()
	return nil
}

// DeleteNotifyRoute removes a routing rule.
func (a *App) DeleteNotifyRoute(id string) {
	routes := a.configStore.LoadRoutes()
	out := routes[:0]
	for _, r := range routes {
		if r.ID != id {
			out = append(out, r)
		}
	}
	a.configStore.SaveRoutes(out)
	a.reconfigureNotify()
}

// SaveNotifySink adds or replaces one destination.
//
// The credential handling is the delicate part:
//
//   - A non-empty Secret is a NEW credential. It is stored bound to the
//     destination and cleared before the configuration is persisted, so it
//     never reaches config.json.
//   - An empty Secret means "keep what is on file" — but only if the
//     destination did not change. Moving a webhook to another host, or
//     downgrading SMTP from starttls to none, drops the stored credential
//     rather than carrying it to a place it was never given for.
func (a *App) SaveNotifySink(sink notify.SinkConfig) error {
	if err := notify.ValidateSink(sink); err != nil {
		return err
	}
	if err := notify.ValidateTemplate(sink.Template); err != nil {
		return err
	}
	// Refuse a destination that points back at our own listener. One message
	// would return as two, then four: the receiver stores every copy and the
	// loop only stops when something runs out. Caught here because this is
	// where it can be explained, rather than as a mystery later.
	if sink.Kind == notify.SinkSyslog && a.isSelfDestination(sink.Syslog.Address) {
		return fmt.Errorf("%s points back at this application's own syslog listener, which would loop every message it relays", sink.Syslog.Address)
	}
	if sink.ID == "" {
		sink.ID = newID("sink")
	}

	dest, bindable := notify.Destination(sink)
	if !bindable {
		return fmt.Errorf("destination kind %q cannot be addressed", sink.Kind)
	}

	sinks := a.configStore.LoadSinks()
	var previous *notify.SinkConfig
	for i := range sinks {
		if sinks[i].ID == sink.ID {
			previous = &sinks[i]
			break
		}
	}

	if a.secretStore != nil {
		switch {
		case sink.Secret != "":
			if err := a.secretStore.Set(sink.ID, dest, sink.Secret); err != nil {
				return fmt.Errorf("store credential: %w", err)
			}
		case previous != nil && !notify.SameDestination(*previous, sink):
			// The destination moved. Whatever was on file was given for the old
			// one, so it is dropped rather than followed to the new address.
			if err := a.secretStore.Delete(sink.ID); err != nil {
				slog.Warn("could not drop credential after a destination change",
					"sink", sink.ID, "error", err)
			}
		}
	}
	// Never persisted: the whole SinkConfig is marshalled into config.json.
	sink.Secret = ""

	if previous != nil {
		*previous = sink
	} else {
		sinks = append(sinks, sink)
	}
	a.configStore.SaveSinks(sinks)
	// Re-enabling a destination the breaker cut off has to clear its counters,
	// otherwise the very traffic that tripped it trips it again immediately.
	if a.dispatcher != nil && sink.Enabled {
		a.dispatcher.ResetSink(sink.ID)
	}
	a.reconfigureNotify()
	return nil
}

// DeleteNotifySink removes a destination, its credential, and its mention in
// any route — a route left pointing at a deleted sink would fail every message
// it matched.
func (a *App) DeleteNotifySink(id string) {
	sinks := a.configStore.LoadSinks()
	out := sinks[:0]
	for _, s := range sinks {
		if s.ID != id {
			out = append(out, s)
		}
	}
	a.configStore.SaveSinks(out)

	routes := a.configStore.LoadRoutes()
	for i := range routes {
		ids := routes[i].SinkIDs[:0]
		for _, sid := range routes[i].SinkIDs {
			if sid != id {
				ids = append(ids, sid)
			}
		}
		routes[i].SinkIDs = ids
	}
	a.configStore.SaveRoutes(routes)

	if a.secretStore != nil {
		if err := a.secretStore.Delete(id); err != nil {
			slog.Warn("could not delete credential for a removed destination", "sink", id, "error", err)
		}
	}
	a.reconfigureNotify()
}

// TestNotifySink delivers one sample message immediately, so the UI reports a
// real result instead of queueing something the operator has to go and find.
//
// The configuration comes from the form and may not be saved. A credential is
// resolved only when the form's destination matches the one it was stored
// against — the alternative is an endpoint that reads back any sink's secret by
// naming its id and pointing the URL elsewhere.
func (a *App) TestNotifySink(sink notify.SinkConfig) error {
	if err := notify.ValidateSink(sink); err != nil {
		return err
	}
	if err := notify.ValidateTemplate(sink.Template); err != nil {
		return err
	}

	secret := sink.Secret
	if secret == "" && a.secretStore != nil && sink.ID != "" {
		if dest, ok := notify.Destination(sink); ok {
			secret = a.secretStore.Get(sink.ID, dest)
		}
	}

	now := time.Now()
	sample := models.SyslogMessage{
		ID: "test", Timestamp: now, ReceivedAt: now,
		Severity: models.SevWarning, SeverityLabel: models.SeverityToLabel(models.SevWarning),
		Facility: models.FacLocal7, FacilityLabel: models.FacilityToLabel(models.FacLocal7),
		Hostname: "syslogstudio", AppName: "notify-test", ProcID: "0",
		Message:    "Test message from SyslogStudio",
		RawMessage: "<180>1 - syslogstudio notify-test - - - Test message from SyslogStudio",
		SourceIP:   "127.0.0.1", Protocol: "internal",
	}
	return notify.TestSink(sink, secret, sample)
}

// GetNotifyLog returns the delivery log.
func (a *App) GetNotifyLog() []notify.DeliveryEntry {
	if a.dispatcher == nil {
		return nil
	}
	return a.dispatcher.Log()
}

// ClearNotifyLog empties the delivery log.
func (a *App) ClearNotifyLog() {
	if a.dispatcher != nil {
		a.dispatcher.ClearLog()
	}
}

// GetNotifyStats returns dispatcher counters.
func (a *App) GetNotifyStats() notify.Stats {
	if a.dispatcher == nil {
		return notify.Stats{}
	}
	return a.dispatcher.Stats()
}

// AreSinkCredentialsUnencrypted reports whether credentials rest in plaintext,
// which they do when at-rest encryption is off. The UI surfaces it the same way
// it does for an unencrypted CA key.
func (a *App) AreSinkCredentialsUnencrypted() bool {
	return a.secretStore != nil && a.secretStore.HasAny() && !a.secretStore.IsEncrypted()
}

// persistTrippedSink disables a destination the breaker cut off.
//
// It writes through the same path the UI uses, so the destination simply shows
// as disabled with the reason in the delivery log. Re-enabling it from the UI
// is what clears the breaker.
func (a *App) persistTrippedSink(sinkID string, reason notify.TripReason) {
	sinks := a.configStore.LoadSinks()
	changed := false
	for i := range sinks {
		if sinks[i].ID == sinkID && sinks[i].Enabled {
			sinks[i].Enabled = false
			changed = true
			break
		}
	}
	if !changed {
		return
	}
	a.configStore.SaveSinks(sinks)
	slog.Warn("notify destination disabled after the rate breaker tripped",
		"sink", sinkID, "reason", string(reason))
	a.reconfigureNotify()
}

// isSelfDestination reports whether an address aims at one of this app's own
// listeners. It consults the saved server configuration rather than the live
// one, so the check is just as good while the server is stopped — that is when
// destinations tend to be set up.
func (a *App) isSelfDestination(address string) bool {
	cfg := a.configStore.Load()
	ports := make(map[int]bool, 3)
	if cfg.UDPEnabled {
		ports[cfg.UDPPort] = true
	}
	if cfg.TCPEnabled {
		ports[cfg.TCPPort] = true
	}
	if cfg.TLSEnabled {
		ports[cfg.TLSPort] = true
	}
	return notify.IsSelfDestination(address, notify.LocalEndpoints{Ports: ports, IPs: localIPs()})
}

// reconfigureNotify pushes the saved configuration into the dispatcher.
func (a *App) reconfigureNotify() {
	if a.dispatcher == nil {
		return
	}
	sinks := a.configStore.LoadSinks()
	a.dispatcher.Configure(a.configStore.LoadRoutes(), sinks)

	// Drop credentials for sinks that no longer exist, so a deleted
	// destination does not leave its password behind.
	if a.secretStore != nil {
		keep := make(map[string]bool, len(sinks))
		for _, s := range sinks {
			keep[s.ID] = true
		}
		if err := a.secretStore.Prune(keep); err != nil {
			slog.Warn("could not prune orphaned credentials", "error", err)
		}
	}
}

// newID makes a short unique identifier for a route or sink.
func newID(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
}
