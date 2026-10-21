package agent

import (
	"context"
	"time"

	"github.com/cat-cc-Lcos/FNCache/internal/observability"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

// Status refreshes the in-process observability snapshot and returns the
// value that was published. It only reads agent-owned state: all BPF and
// Kubernetes observations are produced by background workers and copied into
// the snapshot when those workers finish.
func (r *DynamicRuntime) Status(_ context.Context) observability.Snapshot {
	snapshot := unavailableSnapshot()
	if r == nil {
		return snapshot
	}
	r.statusPublishMu.Lock()
	defer r.statusPublishMu.Unlock()

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

	r.statusMu.RLock()
	snapshot.DatapathEnabled = r.datapathReady
	snapshot.Generation = r.datapathGeneration
	datapathReason := r.datapathReason
	r.statusMu.RUnlock()

	snapshot.Conditions = map[observability.ConditionType]bool{
		observability.DatapathReady:  snapshot.DatapathEnabled,
		observability.KubeAPIHealthy: snapshot.APIHealthy,
		observability.HeartbeatFresh: snapshot.HeartbeatFresh,
	}
	snapshot.Ready = snapshot.State == reconcile.AgentReady && snapshot.HealthReady()
	if snapshot.Ready {
		snapshot.Reason = ""
	} else if snapshot.State == reconcile.AgentReady && datapathReason != "" && !snapshot.DatapathEnabled {
		snapshot.Reason = datapathReason
	} else if snapshot.Reason == "" {
		snapshot.Reason = readinessReason(snapshot)
	}
	if r.snapshots != nil {
		r.snapshots.Update(snapshot)
	}
	return snapshot
}

// SnapshotStore exposes the read-only observability boundary used by HTTP.
func (r *DynamicRuntime) SnapshotStore() *observability.SnapshotStore {
	if r == nil {
		return nil
	}
	return r.snapshots
}

func (r *DynamicRuntime) HTTPAddress() string { return r.config.Server.ListenAddress }

func (r *DynamicRuntime) DebugStateEnabled() bool { return r.config.Features.DebugState }

func unavailableSnapshot() observability.Snapshot {
	return observability.Snapshot{
		State:  reconcile.AgentDisabled,
		Reason: "AGENT_UNAVAILABLE",
		Conditions: map[observability.ConditionType]bool{
			observability.DatapathReady:  false,
			observability.KubeAPIHealthy: false,
			observability.HeartbeatFresh: false,
		},
	}
}

func (r *DynamicRuntime) setDatapathStatus(ready bool, generation uint64) {
	if r == nil {
		return
	}
	r.statusMu.Lock()
	r.datapathReady = ready
	r.datapathGeneration = generation
	r.datapathReason = ""
	r.statusMu.Unlock()
}

func (r *DynamicRuntime) setDatapathUnavailable(reason string) {
	if r == nil {
		return
	}
	r.statusMu.Lock()
	r.datapathReady = false
	r.datapathGeneration = 0
	if reason != "" {
		r.datapathReason = reason
	}
	r.statusMu.Unlock()
}

func (r *DynamicRuntime) recordScanStatus(result ScanResult) {
	if r == nil || result.Level == ScanLight {
		return
	}
	if !result.DatapathObserved {
		if result.Critical || result.Err != nil {
			r.setDatapathUnavailable("DATAPATH_STATE_UNAVAILABLE")
		}
		return
	}
	r.setDatapathStatus(result.DatapathReady, result.DatapathGeneration)
}

func (r *DynamicRuntime) statusLoop(ctx context.Context) {
	interval := time.Duration(r.config.Health.Interval)
	if interval <= 0 {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.Status(ctx)
		}
	}
}

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
	if !snapshot.Condition(observability.DatapathReady) {
		return "DATAPATH_DISABLED"
	}
	if !snapshot.Condition(observability.KubeAPIHealthy) {
		return "KUBE_API_STALE"
	}
	return "HEARTBEAT_STALE"
}
