package agent

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/NetwardenHQ/agent/internal/identity"
	"github.com/NetwardenHQ/agent/internal/metrics"
)

// Size budget for one /agent/data post.
//
// maxPostBytes is the agent's own budget from the spool contract (a whole
// post is at most 1 MB), not a server limit: the server refuses bodies over
// 10 MB and more than 16 snapshots. Staying well under that leaves headroom
// for a slow uplink and keeps one post's memory small on both sides.
const (
	maxPostBytes = 1 << 20
	// postSlack covers the envelope (version, hostname, tenant, os_info) and
	// JSON framing that the per-part estimates do not count.
	postSlack = 8 * 1024
)

// deviceRole decides what kind of machine this is: a gateway when the
// OPNsense collector is active, a cluster for the in-cluster agent, else a
// server.
func (a *Agent) deviceRole() string {
	switch {
	case a.opnsenseCollector != nil && a.opnsenseCollector.Enabled():
		return identity.RoleGateway
	case a.k8sCollector != nil && a.k8sCollector.Enabled():
		return identity.RoleCluster
	}
	return identity.RoleServer
}

// buildIdentity assembles the device_identity snapshot for this cycle.
func (a *Agent) buildIdentity() metrics.Snapshot {
	in := identity.Input{
		Role:       a.deviceRole(),
		Interfaces: identity.ReadInterfaces(),
		Extra:      a.spool.Identity(),
	}
	in.Platform, in.PlatformVersion = identity.HostPlatform()

	if in.Role == identity.RoleGateway {
		in.Platform = "opnsense"
		// vendor is the platform's publisher, not the hardware maker: the
		// contract defines it per platform, and OPNsense is published by
		// Deciso. The role is gateway only when the OPNsense collector has
		// detected OPNsense. The version files under
		// /usr/local/opnsense/version name the copyright holder
		// ("Deciso B.V."), which would not match the contract's "Deciso".
		in.Vendor = "Deciso"
		oi, err := a.opnsenseCollector.Identity()
		if err != nil {
			if msg := err.Error(); msg != a.lastIdentityErr {
				a.lastIdentityErr = msg
				a.logger.Warn("opnsense identity incomplete; omitting what could not be verified", "error", err)
			}
		} else {
			a.lastIdentityErr = ""
		}
		in.PlatformVersion = oi.Version
		in.Capabilities = oi.Capabilities
		in.InterfaceRoles = oi.InterfaceRoles
	}
	return identity.Build(in)
}

func jsonLen(v any) int {
	b, err := json.Marshal(v)
	if err != nil {
		return 0
	}
	return len(b)
}

// withExtras adds device_identity and any spool snapshots to the first
// batch's snapshots, staying within the server's 16-snapshot limit and the
// agent's 1 MB post budget. When space is short, spool data is deferred
// first (events, then exposure); the returned ack must run only after the
// post succeeded.
func (a *Agent) withExtras(base []metrics.Snapshot, firstBatch []metrics.Metric) ([]metrics.Snapshot, func()) {
	if !a.identityEnabled {
		return base, nil
	}
	id := a.buildIdentity()
	out := make([]metrics.Snapshot, 0, maxSnapshotsPerPayload)
	out = append(out, id)
	out = append(out, base...)

	slots := maxSnapshotsPerPayload - len(out)
	budget := maxPostBytes - postSlack - jsonLen(a.wireMetrics(firstBatch)) - jsonLen(out)
	if slots <= 0 || budget <= 0 {
		if a.spool != nil {
			a.logger.Warn("post is full; spool data deferred to a later cycle",
				"snapshots", len(out), "budget_bytes", budget)
		}
		return out, nil
	}
	batch := a.spool.Next(slots, budget)
	out = append(out, batch.Snapshots...)
	return out, batch.Ack
}

// wireMetrics converts ms to the type that is serialized. The wire type
// carries host_id and differently named fields, so sizing metrics.Metric
// would under-count every metric.
func (a *Agent) wireMetrics(ms []metrics.Metric) []payloadMetric {
	out := make([]payloadMetric, len(ms))
	for i, m := range ms {
		out[i] = toPayloadMetric(a.hostname, m)
	}
	return out
}

// statusReporter is implemented by transmitters that know the last HTTP status.
type statusReporter interface{ LastStatus() int }

// recordAttempt persists the outcome of one post to state.json. A Send that
// skipped the request while backing off is not an attempt and is not
// recorded: state.json would otherwise report a fresh attempt time, and the
// previous reply's status, for a post that never happened.
func (a *Agent) recordAttempt(at time.Time, err error) {
	if a.state == nil || errors.Is(err, errBackingOff) {
		return
	}
	status := 0
	if sr, ok := a.transmitter.(statusReporter); ok {
		status = sr.LastStatus()
	}
	a.state.Update(attempt{
		At:       at,
		Err:      err,
		Status:   status,
		Interval: a.currentInterval(),
		Sent:     a.spool.SentTotal(),
		Pending:  a.spool.Pending(),
	})
}
