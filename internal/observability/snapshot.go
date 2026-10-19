package observability

import (
	"sync/atomic"

	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

// ConditionType identifies an independently observable health condition.
//
// Conditions are kept in the in-process snapshot and deliberately omitted
// from the legacy HTTP JSON representation.  The existing flattened fields
// remain the compatibility boundary for clients of /readyz and /metrics.
type ConditionType string

// Condition is retained as an alias so callers can use either terminology
// when constructing a condition set.
type Condition = ConditionType

// HealthCondition is a descriptive alias for integrations that model the
// entries as health conditions.
type HealthCondition = ConditionType

const (
	DatapathReady  ConditionType = "DatapathReady"
	KubeAPIHealthy ConditionType = "KubeAPIHealthy"
	HeartbeatFresh ConditionType = "HeartbeatFresh"
)

// Snapshot is the latest immutable observability view of the agent.
// Conditions is an internal model of the health inputs used to derive Ready;
// it is not serialized so the existing readiness response stays compatible.
type Snapshot struct {
	State           reconcile.AgentState `json:"state"`
	Ready           bool                 `json:"ready"`
	Reason          string               `json:"reason,omitempty"`
	Generation      uint64               `json:"generation"`
	DatapathEnabled bool                 `json:"datapathEnabled"`
	APIHealthy      bool                 `json:"apiHealthy"`
	HeartbeatFresh  bool                 `json:"heartbeatFresh"`
	QueueDepth      int                  `json:"queueDepth"`
	KnownLinks      int                  `json:"knownLinks"`

	Conditions map[ConditionType]bool `json:"-"`
}

// Condition reports a condition, falling back to the legacy flattened field
// when a snapshot was built by an older caller.
func (s Snapshot) Condition(kind ConditionType) bool {
	if value, ok := s.Conditions[kind]; ok {
		return value
	}
	switch kind {
	case DatapathReady:
		return s.DatapathEnabled
	case KubeAPIHealthy:
		return s.APIHealthy
	case HeartbeatFresh:
		return s.HeartbeatFresh
	default:
		return false
	}
}

// HealthReady reports whether the health conditions required for readiness
// are all true.  The lifecycle state is intentionally checked separately so
// callers cannot accidentally make a disabled or stopping agent ready.
func (s Snapshot) HealthReady() bool {
	return s.Condition(DatapathReady) && s.Condition(KubeAPIHealthy) && s.Condition(HeartbeatFresh)
}

// NewSnapshotStore creates a lock-free reader store.  An optional initial
// snapshot is useful for publishing a meaningful pre-start state; without it
// the zero Snapshot is returned until the first update.
func NewSnapshotStore(initial ...Snapshot) *SnapshotStore {
	store := &SnapshotStore{}
	if len(initial) != 0 {
		store.Update(initial[0])
	}
	return store
}

// SnapshotStore publishes complete snapshots atomically.  Readers never
// observe a partially updated set of health fields, and updates do not retain
// a caller-owned Conditions map.
type SnapshotStore struct {
	current atomic.Pointer[Snapshot]
}

// Update publishes snapshot as one atomic observation.
func (s *SnapshotStore) Update(snapshot Snapshot) {
	if s == nil {
		return
	}
	snapshot = normalizeSnapshot(snapshot)
	s.current.Store(&snapshot)
}

// Snapshot returns a copy of the latest observation.  The returned Conditions
// map is also copied so callers can inspect or modify it without racing with
// future updates.
func (s *SnapshotStore) Snapshot() Snapshot {
	if s == nil {
		return Snapshot{}
	}
	current := s.current.Load()
	if current == nil {
		return Snapshot{}
	}
	return cloneSnapshot(*current)
}

func normalizeSnapshot(snapshot Snapshot) Snapshot {
	conditions := cloneConditions(snapshot.Conditions)
	if conditions == nil {
		conditions = make(map[ConditionType]bool, 3)
	}
	if _, ok := conditions[DatapathReady]; !ok {
		conditions[DatapathReady] = snapshot.DatapathEnabled
	}
	if _, ok := conditions[KubeAPIHealthy]; !ok {
		conditions[KubeAPIHealthy] = snapshot.APIHealthy
	}
	if _, ok := conditions[HeartbeatFresh]; !ok {
		conditions[HeartbeatFresh] = snapshot.HeartbeatFresh
	}
	snapshot.Conditions = conditions
	snapshot.DatapathEnabled = conditions[DatapathReady]
	snapshot.APIHealthy = conditions[KubeAPIHealthy]
	snapshot.HeartbeatFresh = conditions[HeartbeatFresh]
	snapshot.Ready = snapshot.State == reconcile.AgentReady && snapshot.HealthReady()
	return snapshot
}

func cloneSnapshot(snapshot Snapshot) Snapshot {
	snapshot.Conditions = cloneConditions(snapshot.Conditions)
	return snapshot
}

func cloneConditions(conditions map[ConditionType]bool) map[ConditionType]bool {
	if conditions == nil {
		return nil
	}
	result := make(map[ConditionType]bool, len(conditions))
	for kind, value := range conditions {
		result[kind] = value
	}
	return result
}
