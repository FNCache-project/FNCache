package kubernetes

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/cat-cc-Lcos/FNCache/internal/endpoint"
	"github.com/cat-cc-Lcos/FNCache/internal/kubernetes/queue"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

func TestResyncSchedulerEnqueuesCurrentPods(t *testing.T) {
	store := NewSnapshotStore()
	_ = store.UpsertNode(NodeSnapshot{Identity: endpoint.NodeIdentity{Name: "node-a", UID: "a"}})
	_ = store.UpsertNode(NodeSnapshot{Identity: endpoint.NodeIdentity{Name: "node-b", UID: "b"}})
	for _, pod := range []endpoint.PodSnapshot{
		{Identity: endpoint.PodIdentity{Namespace: "default", Name: "local", UID: "local"}, NodeName: "node-a", Phase: "Pending"},
		{Identity: endpoint.PodIdentity{Namespace: "default", Name: "remote", UID: "remote"}, NodeName: "node-b", PodIPv4: netip.MustParseAddr("10.42.1.2")},
		{Identity: endpoint.PodIdentity{Namespace: "default", Name: "host", UID: "host"}, NodeName: "node-a", HostNetwork: true},
		{Identity: endpoint.PodIdentity{Namespace: "default", Name: "unscheduled", UID: "unscheduled"}},
	} {
		_ = store.UpsertPod(pod)
	}
	target, _ := queue.New(queue.DefaultConfig())
	scheduler, err := NewResyncScheduler(store, "node-a", target, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := scheduler.ResyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if target.Len() != 3 {
		t.Fatalf("resync queue length = %d, want 3", target.Len())
	}
	seen := map[reconcile.ReconcileKind]bool{}
	for target.Len() > 0 {
		key, shutdown := target.Get()
		if shutdown {
			t.Fatal("queue shut down during resync")
		}
		seen[key.Kind] = true
		target.Forget(key)
		target.Done(key)
	}
	if !seen[reconcile.ReconcileGlobal] || !seen[reconcile.ReconcileLocalEndpoint] || !seen[reconcile.ReconcileRemoteEndpoint] {
		t.Fatalf("unexpected resync kinds: %#v", seen)
	}
	target.ShutDown()
}

func TestResyncSchedulerHonorsCancellationAndValidation(t *testing.T) {
	store := NewSnapshotStore()
	target, _ := queue.New(queue.DefaultConfig())
	if _, err := NewResyncScheduler(store, "node-a", target, 0); err == nil {
		t.Fatal("zero interval was accepted")
	}
	scheduler, err := NewResyncScheduler(store, "node-a", target, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := scheduler.ResyncOnce(ctx); err != context.Canceled || target.Len() != 0 {
		t.Fatalf("canceled resync wrote queue: err=%v len=%d", err, target.Len())
	}
	target.ShutDown()
}
