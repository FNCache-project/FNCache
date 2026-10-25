package kubernetes

import (
	"net/netip"
	"sync"
	"testing"

	"github.com/cat-cc-Lcos/FNCache/internal/endpoint"
)

func testPod(uid, node, ip string) endpoint.PodSnapshot {
	return endpoint.PodSnapshot{
		Identity: endpoint.PodIdentity{Namespace: "default", Name: uid, UID: uid},
		NodeName: node, PodIPv4: netip.MustParseAddr(ip), Phase: "Running",
	}
}

func TestSnapshotStoreLifecycleAndCopy(t *testing.T) {
	store := NewSnapshotStore()
	if err := store.UpsertPod(testPod("pod-b", "node-a", "10.42.0.2")); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertPod(testPod("pod-a", "node-a", "10.42.0.3")); err != nil {
		t.Fatal(err)
	}
	node := NodeSnapshot{Identity: endpoint.NodeIdentity{Name: "node-a", UID: "node-1"}, Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.10")}}
	if err := store.UpsertNode(node); err != nil {
		t.Fatal(err)
	}

	pods := store.LocalPods("node-a")
	if len(pods) != 2 || pods[0].Identity.UID != "pod-a" || pods[1].Identity.UID != "pod-b" {
		t.Fatalf("unexpected local pods: %#v", pods)
	}
	snapshot := store.Snapshot()
	delete(snapshot.Pods, "pod-a")
	snapshot.Nodes["node-a"].Addresses[0] = netip.MustParseAddr("192.0.2.11")
	if _, ok := store.GetPod("pod-a"); !ok {
		t.Fatal("mutating returned snapshot changed the pod cache")
	}
	got, ok := store.GetNode("node-a")
	if !ok || got.Addresses[0] != netip.MustParseAddr("192.0.2.10") {
		t.Fatal("mutating returned snapshot changed the node cache")
	}
	if !store.DeletePod("pod-a") || store.DeletePod("pod-a") {
		t.Fatal("pod deletion was not idempotent")
	}
	if store.DeleteNode("node-a", "node-2") || !store.DeleteNode("node-a", "node-1") {
		t.Fatal("node UID deletion guard failed")
	}
}

func TestSnapshotStoreRejectsInvalidInput(t *testing.T) {
	store := NewSnapshotStore()
	if err := store.UpsertPod(endpoint.PodSnapshot{}); err == nil {
		t.Fatal("accepted an invalid Pod snapshot")
	}
	badPod := testPod("pod-a", "node-a", "10.42.0.2")
	badPod.PodIPv4 = netip.MustParseAddr("2001:db8::1")
	if err := store.UpsertPod(badPod); err == nil {
		t.Fatal("accepted an IPv6 Pod snapshot")
	}
	if err := store.UpsertNode(NodeSnapshot{Identity: endpoint.NodeIdentity{Name: "node-a"}}); err == nil {
		t.Fatal("accepted an invalid Node snapshot")
	}
}

func TestSnapshotStoreConcurrentAccess(t *testing.T) {
	store := NewSnapshotStore()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for j := 0; j < 25; j++ {
				uid := string(rune('a'+worker)) + string(rune('a'+j))
				if err := store.UpsertPod(testPod(uid, "node-a", "10.42.0.2")); err != nil {
					t.Errorf("upsert: %v", err)
				}
				_ = store.Snapshot()
			}
		}(i)
	}
	wg.Wait()
	if len(store.Snapshot().Pods) != 200 {
		t.Fatalf("got %d pods, want 200", len(store.Snapshot().Pods))
	}
}
