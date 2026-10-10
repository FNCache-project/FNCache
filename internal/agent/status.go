package agent

import (
	"context"
	"time"

	"github.com/cat-cc-Lcos/FNCache/internal/observability"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

func (r *DynamicRuntime) Status(ctx context.Context) observability.Snapshot {
	snapshot := observability.Snapshot{State: reconcile.AgentDisabled, APIHealthy: false, Reason: "AGENT_UNAVAILABLE"}
	if r == nil {
		return snapshot
	}
	snapshot.State = reconcile.AgentBootstrapping
	snapshot.Reason = ""
	if r.lifecycle != nil {
		snapshot.State = r.lifecycle.State()
	}
	if r.queue != nil {
		snapshot.QueueDepth = r.queue.Len()
	}
	if r.observer != nil {
		snapshot.KnownLinks = len(r.observer.KnownLinks())
	}
	if r.healthEpoch != nil && snapshot.State == reconcile.AgentReady {
		epoch := r.healthEpoch.Snapshot()
		snapshot.HeartbeatFresh = r.healthEpoch.IsCurrent(epoch)
	}
	if r.source != nil {
		snapshot.APIHealthy = r.source.Health().FreshAt(time.Now(), time.Duration(r.config.Kube.MaxStaleness))
	}
	if r.components != nil && r.components.pins != nil {
		if actual, err := r.components.pins.Scan(ctx); err == nil {
			snapshot.DatapathEnabled = actual.Control.Verified && actual.Control.Enabled
			snapshot.Generation = actual.Control.Generation
		} else {
			snapshot.Reason = "DATAPATH_STATE_UNAVAILABLE"
		}
	}
	snapshot.Ready = snapshot.State == reconcile.AgentReady && snapshot.DatapathEnabled && snapshot.APIHealthy && snapshot.HeartbeatFresh
	if snapshot.Ready {
		snapshot.Reason = ""
	} else if snapshot.Reason == "" {
		snapshot.Reason = readinessReason(snapshot)
	}
	return snapshot
}

func (r *DynamicRuntime) HTTPAddress() string { return r.config.Server.ListenAddress }

func (r *DynamicRuntime) DebugStateEnabled() bool { return r.config.Features.DebugState }

func readinessReason(snapshot observability.Snapshot) string {
	if snapshot.State != reconcile.AgentReady {
		switch snapshot.State {
		case reconcile.AgentBootstrapping:
			return "AGENT_BOOTSTRAPPING"
		case reconcile.AgentDisabled:
			return "AGENT_DISABLED"
		case reconcile.AgentReconciling:
			return "AGENT_RECONCILING"
		case reconcile.AgentDegraded:
			return "AGENT_DEGRADED"
		case reconcile.AgentStopping:
			return "AGENT_STOPPING"
		default:
			return "AGENT_UNKNOWN_STATE"
		}
	}
	if !snapshot.DatapathEnabled {
		return "DATAPATH_DISABLED"
	}
	if !snapshot.APIHealthy {
		return "KUBE_API_STALE"
	}
	return "HEARTBEAT_STALE"
}
