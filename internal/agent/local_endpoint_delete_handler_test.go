package agent

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"reflect"
	"testing"

	"github.com/cat-cc-Lcos/FNCache/internal/discovery"
	"github.com/cat-cc-Lcos/FNCache/internal/kube"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
	"github.com/cat-cc-Lcos/FNCache/internal/resolver"
)

type deleteOwnership struct {
	state reconcile.OwnershipState
	err   error
}

func (s *deleteOwnership) Load(context.Context) (reconcile.OwnershipState, error) {
	return s.state, s.err
}

type deleteRemover struct {
	events *[]string
	err    error
}

type failingDeleteReuseGuard struct{ err error }

func (g failingDeleteReuseGuard) Check(context.Context, kube.Snapshot, string, reconcile.OwnedEndpoint) error {
	return g.err
}

func (r *deleteRemover) Remove(context.Context, reconcile.OwnedEndpoint, reconcile.ActualState, reconcile.DesiredState) error {
	*r.events = append(*r.events, "remove")
	return r.err
}

func deleteHandlerStore(t *testing.T, pods ...resolver.PodSnapshot) *kube.SnapshotStore {
	t.Helper()
	store := kube.NewSnapshotStore()
	if err := store.UpsertNode(kube.NodeSnapshot{Identity: resolver.NodeIdentity{Name: "node-a", UID: "node-1"}}); err != nil {
		t.Fatal(err)
	}
	for _, pod := range pods {
		if err := store.UpsertPod(pod); err != nil {
			t.Fatal(err)
		}
	}
	return store
}

func deleteHandler(t *testing.T, store *kube.SnapshotStore, ownership localOwnershipSource, events *[]string, publisher *localHandlerPublisher) *LocalEndpointDeleteHandler {
	t.Helper()
	base := reconcile.DesiredState{Enabled: true, Capability: discovery.CapabilityReport{Supported: true}, LocalEndpoints: map[string]resolver.Endpoint{"pod-1": handlerEndpoint("pod-1")}}
	guard, err := NewEndpointReuseGuard(&localHandlerResolver{endpoint: handlerEndpoint("other")}, "node-a")
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewLocalEndpointDeleteHandler(LocalEndpointDeleteHandlerConfig{
		Store: store, Ownership: ownership, LocalNode: "node-a", Desired: &localHandlerDesired{desired: base, events: events}, Scanner: &localHandlerScanner{events: events}, Control: &localHandlerControl{events: events}, Remover: &deleteRemover{events: events}, ReuseGuard: guard, Publisher: publisher,
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func deleteOwnershipState() reconcile.OwnershipState {
	return reconcile.OwnershipState{SchemaVersion: 1, InstallationID: "install-a", NodeUID: "node-1", Endpoints: map[string]reconcile.OwnedEndpoint{"pod-1": {PodUID: "pod-1", PodIPv4: netip.MustParseAddr("10.42.0.2"), NetNSInode: 42, PeerIfIndex: 7, HostIfIndex: 8}}}
}

func TestLocalEndpointDeleteHandlerRemovesAndPublishes(t *testing.T) {
	events := []string{}
	publisher := &localHandlerPublisher{events: &events}
	store := deleteHandlerStore(t)
	handler := deleteHandler(t, store, &deleteOwnership{state: deleteOwnershipState()}, &events, publisher)
	if err := handler.Handle(context.Background(), reconcile.ReconcileKey{Kind: reconcile.ReconcileLocalEndpoint, UID: "pod-1"}); err != nil {
		t.Fatal(err)
	}
	if len(publisher.desired.LocalEndpoints) != 0 || len(events) != 6 {
		t.Fatalf("deleted endpoint was retained: desired=%#v events=%v", publisher.desired.LocalEndpoints, events)
	}
	if events[0] != "disable" || events[1] != "scan" || events[2] != "desired" || events[3] != "remove" || events[4] != "scan" || events[5] != "publish" {
		t.Fatalf("unexpected deletion order: %v", events)
	}
}

func TestLocalEndpointDeleteHandlerSkipsWithoutOwnershipOrForStaleEvent(t *testing.T) {
	events := []string{}
	store := deleteHandlerStore(t, handlerPod())
	handler := deleteHandler(t, store, &deleteOwnership{err: os.ErrNotExist}, &events, &localHandlerPublisher{events: &events})
	if err := handler.Handle(context.Background(), reconcile.ReconcileKey{Kind: reconcile.ReconcileLocalEndpoint, UID: "pod-1"}); err != nil {
		t.Fatal(err)
	}
	if len(events) != 0 {
		t.Fatalf("missing ownership caused deletion: %v", events)
	}
	store = deleteHandlerStore(t, handlerPod())
	handler = deleteHandler(t, store, &deleteOwnership{state: deleteOwnershipState()}, &events, &localHandlerPublisher{events: &events})
	if err := handler.Handle(context.Background(), reconcile.ReconcileKey{Kind: reconcile.ReconcileLocalEndpoint, UID: "pod-1"}); err != nil {
		t.Fatal(err)
	}
	if len(events) != 0 {
		t.Fatalf("stale delete caused deletion: %v", events)
	}
}

func TestLocalEndpointDeleteHandlerDisablesBeforeOwnershipFailure(t *testing.T) {
	events := []string{}
	store := deleteHandlerStore(t)
	handler := deleteHandler(t, store, &deleteOwnership{err: errors.New("ownership unavailable")}, &events, &localHandlerPublisher{events: &events})
	if err := handler.Handle(context.Background(), reconcile.ReconcileKey{Kind: reconcile.ReconcileLocalEndpoint, UID: "pod-1"}); err == nil {
		t.Fatal("ownership failure was not returned")
	}
	if !reflect.DeepEqual(events, []string{"disable"}) {
		t.Fatalf("fast path was not disabled before ownership failure: %v", events)
	}
}

func TestLocalEndpointDeleteHandlerDisablesBeforeReuseFailure(t *testing.T) {
	events := []string{}
	store := deleteHandlerStore(t)
	base := reconcile.DesiredState{Enabled: true, Capability: discovery.CapabilityReport{Supported: true}, LocalEndpoints: map[string]resolver.Endpoint{"pod-1": handlerEndpoint("pod-1")}}
	handler, err := NewLocalEndpointDeleteHandler(LocalEndpointDeleteHandlerConfig{
		Store: store, Ownership: &deleteOwnership{state: deleteOwnershipState()}, LocalNode: "node-a",
		Desired: &localHandlerDesired{desired: base, events: &events}, Scanner: &localHandlerScanner{events: &events}, Control: &localHandlerControl{events: &events},
		Remover: &deleteRemover{events: &events}, ReuseGuard: failingDeleteReuseGuard{err: errors.New("reuse check unavailable")}, Publisher: &localHandlerPublisher{events: &events},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := handler.Handle(context.Background(), reconcile.ReconcileKey{Kind: reconcile.ReconcileLocalEndpoint, UID: "pod-1"}); err == nil {
		t.Fatal("reuse check failure was not returned")
	}
	if !reflect.DeepEqual(events, []string{"disable"}) {
		t.Fatalf("fast path was not disabled before reuse failure: %v", events)
	}
}

func TestLocalEndpointDeleteHandlerDefersIPReuse(t *testing.T) {
	events := []string{}
	old := handlerPod()
	newPod := handlerPod()
	newPod.Identity.UID = "pod-2"
	store := deleteHandlerStore(t, newPod)
	handler := deleteHandler(t, store, &deleteOwnership{state: deleteOwnershipState()}, &events, &localHandlerPublisher{events: &events})
	if err := handler.Handle(context.Background(), reconcile.ReconcileKey{Kind: reconcile.ReconcileLocalEndpoint, UID: old.Identity.UID}); err != nil {
		t.Fatalf("IP reuse cleanup failed: %v", err)
	}
	if len(events) != 6 || events[0] != "disable" || events[1] != "scan" || events[2] != "desired" || events[3] != "remove" || events[4] != "scan" || events[5] != "publish" {
		t.Fatalf("unexpected IP reuse cleanup sequence: %v", events)
	}
}

func TestLocalEndpointDeleteHandlerCleansWhenPodMovesRemote(t *testing.T) {
	events := []string{}
	pod := handlerPod()
	pod.NodeName = "node-b"
	store := deleteHandlerStore(t, pod)
	publisher := &localHandlerPublisher{events: &events}
	handler := deleteHandler(t, store, &deleteOwnership{state: deleteOwnershipState()}, &events, publisher)
	if err := handler.Handle(context.Background(), reconcile.ReconcileKey{Kind: reconcile.ReconcileLocalEndpoint, UID: "pod-1"}); err != nil {
		t.Fatal(err)
	}
	if len(publisher.desired.LocalEndpoints) != 0 || len(events) != 6 || events[2] != "desired" || events[3] != "remove" || events[5] != "publish" {
		t.Fatalf("remote migration did not clean old local endpoint: desired=%#v events=%v", publisher.desired.LocalEndpoints, events)
	}
}
