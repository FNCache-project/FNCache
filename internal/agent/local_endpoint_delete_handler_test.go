package agent

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/cat-cc-Lcos/FNCache/internal/controlplane"
	"github.com/cat-cc-Lcos/FNCache/internal/datapath"
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

func (r *deleteRemover) Remove(context.Context, reconcile.OwnedEndpoint, reconcile.ActualState, reconcile.DesiredState) error {
	*r.events = append(*r.events, "remove")
	return r.err
}

type deleteMapRecorder struct{ calls []string }

func (m *deleteMapRecorder) Delete(_ context.Context, name string, _ []byte) (bool, error) {
	m.calls = append(m.calls, "delete:"+name)
	return true, nil
}

func (m *deleteMapRecorder) Clear(_ context.Context, name string) (int, error) {
	m.calls = append(m.calls, "clear:"+name)
	return 1, nil
}

type deleteTCRecorder struct{ specs []datapath.TCFilterSpec }

func (t *deleteTCRecorder) RemoveFilter(_ context.Context, spec datapath.TCFilterSpec) error {
	t.specs = append(t.specs, spec)
	return nil
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
	control := &localHandlerControl{events: events}
	scanner := &localHandlerScanner{events: events}
	handler, err := NewLocalEndpointDeleteHandler(LocalEndpointDeleteHandlerConfig{
		Store: store, Ownership: ownership, LocalNode: "node-a", Desired: &localHandlerDesired{desired: base, events: events}, Remover: &deleteRemover{events: events}, ReuseGuard: guard, Generation: testLocalGeneration(control, scanner, publisher),
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func deleteOwnershipState() reconcile.OwnershipState {
	return reconcile.OwnershipState{SchemaVersion: 1, InstallationID: "install-a", NodeUID: "node-1", Endpoints: map[string]reconcile.OwnedEndpoint{"pod-1": {PodUID: "pod-1", PodIPv4: netip.MustParseAddr("10.42.0.2"), NetNSInode: 42, PeerIfIndex: 7, HostIfIndex: 8}}}
}

func deleteActualState() reconcile.ActualState {
	return reconcile.ActualState{
		Programs: map[string]reconcile.ProgramState{"tc_init_in": {ID: 11}, "tc_masq": {ID: 12}},
		Attachments: []reconcile.AttachmentState{
			{Link: resolver.LinkIdentity{NetNSInode: 42, IfIndex: 7}, Hook: string(datapath.HookIngress), Program: "tc_init_in", Priority: datapath.FixedTCPriority, Handle: 0x201, ProgramID: 11},
			{Link: resolver.LinkIdentity{IfIndex: 8}, Hook: string(datapath.HookIngress), Program: "tc_masq", Priority: datapath.FixedTCPriority, Handle: 0x200, ProgramID: 12},
		},
	}
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
	if events[0] != "desired" || events[1] != "disable" || events[2] != "scan" || events[3] != "remove" || events[4] != "scan" || events[5] != "publish" {
		t.Fatalf("unexpected deletion order: %v", events)
	}
}

func TestLocalEndpointDeleteHandlerRemovesTerminalPods(t *testing.T) {
	for _, phase := range []string{"Succeeded", "Failed"} {
		t.Run(phase, func(t *testing.T) {
			events := []string{}
			publisher := &localHandlerPublisher{events: &events}
			pod := handlerPod()
			pod.Phase = phase
			store := deleteHandlerStore(t, pod)
			handler := deleteHandler(t, store, &deleteOwnership{state: deleteOwnershipState()}, &events, publisher)
			if err := handler.Handle(context.Background(), reconcile.ReconcileKey{Kind: reconcile.ReconcileLocalEndpoint, UID: pod.Identity.UID}); err != nil {
				t.Fatal(err)
			}
			if len(publisher.desired.LocalEndpoints) != 0 || len(events) != 6 || events[3] != "remove" {
				t.Fatalf("terminal Pod endpoint was not removed: desired=%#v events=%v", publisher.desired.LocalEndpoints, events)
			}
		})
	}
}

func TestLocalEndpointDeleteHandlerSkipsWithoutOwnershipOrForStaleEvent(t *testing.T) {
	events := []string{}
	store := deleteHandlerStore(t, handlerPod())
	handler := deleteHandler(t, store, &deleteOwnership{err: errors.New("not found")}, &events, &localHandlerPublisher{events: &events})
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

func TestLocalEndpointDeleteHandlerDefersIPReuse(t *testing.T) {
	events := []string{}
	old := handlerPod()
	newPod := handlerPod()
	newPod.Identity.UID = "pod-2"
	store := deleteHandlerStore(t, newPod)
	handler := deleteHandler(t, store, &deleteOwnership{state: deleteOwnershipState()}, &events, &localHandlerPublisher{events: &events})
	err := handler.Handle(context.Background(), reconcile.ReconcileKey{Kind: reconcile.ReconcileLocalEndpoint, UID: old.Identity.UID})
	var classified *reconcile.ClassifiedError
	if !errors.As(err, &classified) || classified.ReasonCode() != reconcile.ReasonPodIPReusePending || len(events) != 0 {
		t.Fatalf("IP reuse was not deferred: err=%v events=%v", err, events)
	}
}

func TestLocalEndpointDeleteHandlerStopsBeforeRealRemovalOnReuse(t *testing.T) {
	tests := []struct {
		name        string
		podIP       netip.Addr
		peerIfIndex int
		hostIfIndex int
		reason      string
	}{
		{name: "IP", podIP: netip.MustParseAddr("10.42.0.2"), peerIfIndex: 2, hostIfIndex: 3, reason: reconcile.ReasonPodIPReusePending},
		{name: "ifindex", podIP: netip.MustParseAddr("10.42.0.3"), peerIfIndex: 7, hostIfIndex: 8, reason: reconcile.ReasonEndpointIdentityReuse},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			events := []string{}
			newPod := handlerPod()
			newPod.Identity.UID = "pod-2"
			newPod.PodIPv4 = test.podIP
			endpoint := handlerEndpoint(newPod.Identity.UID)
			endpoint.PodIPv4 = test.podIP
			endpoint.PeerLink.IfIndex = test.peerIfIndex
			endpoint.HostLink.IfIndex = test.hostIfIndex
			guard, err := NewEndpointReuseGuard(&localHandlerResolver{endpoint: endpoint, events: &events}, "node-a")
			if err != nil {
				t.Fatal(err)
			}
			maps := &deleteMapRecorder{}
			tc := &deleteTCRecorder{}
			remover, err := controlplane.NewEndpointRemover(maps, tc)
			if err != nil {
				t.Fatal(err)
			}
			control := &localHandlerControl{events: &events}
			scanner := &localHandlerScanner{actual: deleteActualState(), events: &events}
			publisher := &localHandlerPublisher{events: &events}
			base := reconcile.DesiredState{Enabled: true, Capability: discovery.CapabilityReport{Supported: true}, LocalEndpoints: map[string]resolver.Endpoint{"pod-1": handlerEndpoint("pod-1")}}
			handler, err := NewLocalEndpointDeleteHandler(LocalEndpointDeleteHandlerConfig{
				Store: deleteHandlerStore(t, newPod), Ownership: &deleteOwnership{state: deleteOwnershipState()}, LocalNode: "node-a",
				Desired: &localHandlerDesired{desired: base, events: &events}, Remover: remover, ReuseGuard: guard,
				Generation: testLocalGeneration(control, scanner, publisher),
			})
			if err != nil {
				t.Fatal(err)
			}
			err = handler.Handle(context.Background(), reconcile.ReconcileKey{Kind: reconcile.ReconcileLocalEndpoint, UID: "pod-1"})
			var classified *reconcile.ClassifiedError
			if !errors.As(err, &classified) || classified.ReasonCode() != test.reason {
				t.Fatalf("reuse was not deferred: err=%v events=%v", err, events)
			}
			for _, event := range events {
				if event == "desired" || event == "disable" || event == "scan" || event == "remove" || event == "publish" {
					t.Fatalf("deletion reached mutation path: events=%v", events)
				}
			}
			if len(maps.calls) != 0 || len(tc.specs) != 0 {
				t.Fatalf("real remover had side effects: maps=%v filters=%v", maps.calls, tc.specs)
			}
		})
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
	if len(publisher.desired.LocalEndpoints) != 0 || len(events) != 6 || events[0] != "desired" || events[3] != "remove" || events[5] != "publish" {
		t.Fatalf("remote migration did not clean old local endpoint: desired=%#v events=%v", publisher.desired.LocalEndpoints, events)
	}
}
