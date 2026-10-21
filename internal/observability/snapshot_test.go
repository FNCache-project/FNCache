package observability

import (
	"sync"
	"testing"

	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

func TestSnapshotStorePublishesConsistentCopies(t *testing.T) {
	store := NewSnapshotStore(Snapshot{
		State:           reconcile.AgentReady,
		DatapathEnabled: true,
		APIHealthy:      true,
		HeartbeatFresh:  true,
		Conditions:      map[ConditionType]bool{DatapathReady: true, KubeAPIHealthy: true, HeartbeatFresh: true},
	})

	got := store.Snapshot()
	if !got.Ready || !got.Condition(DatapathReady) {
		t.Fatalf("initial snapshot = %+v", got)
	}
	got.Conditions[DatapathReady] = false
	if !store.Snapshot().Condition(DatapathReady) {
		t.Fatal("mutating a returned snapshot changed the store")
	}

	const writers = 4
	const readers = 8
	const iterations = 500
	var wg sync.WaitGroup
	for writer := 0; writer < writers; writer++ {
		wg.Add(1)
		go func(writer int) {
			defer wg.Done()
			for iteration := 0; iteration < iterations; iteration++ {
				ready := (writer+iteration)%2 == 0
				store.Update(Snapshot{
					State:           reconcile.AgentReady,
					DatapathEnabled: ready,
					APIHealthy:      ready,
					HeartbeatFresh:  ready,
					Generation:      uint64(writer*iterations + iteration),
				})
			}
		}(writer)
	}
	for reader := 0; reader < readers; reader++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for iteration := 0; iteration < iterations; iteration++ {
				snapshot := store.Snapshot()
				if snapshot.Ready != snapshot.HealthReady() {
					t.Errorf("inconsistent readiness in snapshot: %+v", snapshot)
					return
				}
			}
		}()
	}
	wg.Wait()
}
