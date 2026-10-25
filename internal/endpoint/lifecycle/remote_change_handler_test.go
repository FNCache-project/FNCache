package lifecycle

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/cat-cc-Lcos/FNCache/internal/controlplane"
	"github.com/cat-cc-Lcos/FNCache/internal/endpoint"
	"github.com/cat-cc-Lcos/FNCache/internal/hostnet/discovery"
	"github.com/cat-cc-Lcos/FNCache/internal/kubernetes"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

type remoteMaps struct {
	calls          []string
	remoteEntries  map[netip.Addr]netip.Addr
	remoteMappings int
	baseCalls      int
	deviceMapCalls int
	err            error
	baseErr        error
	deviceMapErr   error
}

type remoteTestOwnership struct{ commits int }

func (s *remoteTestOwnership) Commit(context.Context, reconcile.OwnershipState) error {
	s.commits++
	return nil
}

type remoteTestControlPublisher struct{ publishes int }

func (p *remoteTestControlPublisher) Publish(context.Context, uint64, uint64, uint64, uint32, uint32, uint16) error {
	p.publishes++
	return nil
}

func (m *remoteMaps) Clear(_ context.Context, name string) (int, error) {
	m.calls = append(m.calls, name)
	if name == "egressip_cache" {
		m.remoteEntries = make(map[netip.Addr]netip.Addr)
	}
	return 2, m.err
}

func (m *remoteMaps) EnsureRemoteMappings(_ context.Context, desired reconcile.DesiredState, _ reconcile.ActualState, _ bool) (bool, error) {
	m.remoteMappings++
	if m.remoteEntries == nil {
		m.remoteEntries = make(map[netip.Addr]netip.Addr)
	}
	for podIP, mapping := range desired.RemoteEndpoints {
		m.remoteEntries[podIP] = mapping.NodeIPv4
	}
	return true, m.err
}

func (m *remoteMaps) EnsureBase(_ context.Context, _ reconcile.DesiredState, _ reconcile.ActualState) (bool, error) {
	m.baseCalls++
	return true, m.baseErr
}

func (m *remoteMaps) EnsureDeviceMap(_ context.Context, _ reconcile.DesiredState, _ reconcile.ActualState, _ bool) (bool, error) {
	m.deviceMapCalls++
	return true, m.deviceMapErr
}

func remoteChangeStore(t *testing.T) *kubernetes.SnapshotStore {
	t.Helper()
	store := kubernetes.NewSnapshotStore()
	if err := store.UpsertNode(kubernetes.NodeSnapshot{Identity: endpoint.NodeIdentity{Name: "node-a", UID: "node-1"}}); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertNode(kubernetes.NodeSnapshot{Identity: endpoint.NodeIdentity{Name: "node-b", UID: "node-2"}, InternalIPv4: netip.MustParseAddr("192.0.2.11")}); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertPod(endpoint.PodSnapshot{Identity: endpoint.PodIdentity{Namespace: "default", Name: "remote", UID: "pod-remote"}, NodeName: "node-b", PodIPv4: netip.MustParseAddr("10.42.1.2"), Phase: "Running"}); err != nil {
		t.Fatal(err)
	}
	return store
}

func newRemoteChangeHandler(t *testing.T, store *kubernetes.SnapshotStore, maps *remoteMaps, events *[]string, publisher Publisher) *RemoteChangeHandler {
	t.Helper()
	return newRemoteChangeHandlerWithDesired(t, store, maps, events, publisher, reconcile.DesiredState{Enabled: true, Capability: discovery.CapabilityReport{Supported: true}})
}

func newRemoteChangeHandlerWithDesired(t *testing.T, store *kubernetes.SnapshotStore, maps *remoteMaps, events *[]string, publisher Publisher, base reconcile.DesiredState) *RemoteChangeHandler {
	t.Helper()
	control := &localHandlerControl{events: events}
	scanner := &localHandlerScanner{events: events}
	handler, err := NewRemoteChangeHandler(RemoteChangeHandlerConfig{Store: store, LocalNode: "node-a", Desired: &localHandlerDesired{desired: base, events: events}, Maps: maps, Base: maps, DeviceMap: maps, Generation: testLocalGeneration(control, scanner, publisher)})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

type remoteMapPublisher struct {
	desired                reconcile.DesiredState
	events                 *[]string
	maps                   *remoteMaps
	remoteMappingAtPublish []bool
}

func (p *remoteMapPublisher) CommitAndPublish(_ context.Context, desired reconcile.DesiredState, _ reconcile.ActualState) error {
	_, present := p.maps.remoteEntries[netip.MustParseAddr("10.42.1.2")]
	p.remoteMappingAtPublish = append(p.remoteMappingAtPublish, present)
	p.desired = desired
	*p.events = append(*p.events, "publish")
	return nil
}

func TestRemoteChangeHandlerRetriesWhenEndpointScanIsIncomplete(t *testing.T) {
	events := []string{}
	maps := &remoteMaps{}
	ownership := &remoteTestOwnership{}
	controlPublisher := &remoteTestControlPublisher{}
	publisher, err := controlplane.NewPublisher(ownership, controlPublisher, controlplane.PublishConfig{
		InstallationID: "install-a", NodeUID: "node-a", ELFBuildID: "build-a", HeartbeatNS: 1, HeartbeatTimeoutNS: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	control := &localHandlerControl{events: &events}
	scanner := &localHandlerScanner{events: &events}
	generation, err := controlplane.NewGenerationTransaction(control, scanner, publisher)
	if err != nil {
		t.Fatal(err)
	}
	base := reconcile.DesiredState{
		Generation: 1, Enabled: true, Capability: discovery.CapabilityReport{Supported: true},
		EndpointScanSkipped: map[string]string{"pod-local": endpoint.ErrEndpointNotReady.Error()},
	}
	handler, err := NewRemoteChangeHandler(RemoteChangeHandlerConfig{
		Store: remoteChangeStore(t), LocalNode: "node-a", Desired: &localHandlerDesired{desired: base, events: &events}, Maps: maps, Generation: generation,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = handler.Handle(context.Background(), reconcile.ReconcileKey{Kind: reconcile.ReconcileRemoteEndpoint, UID: "pod-remote"})
	var classified *reconcile.ClassifiedError
	if !errors.As(err, &classified) || classified.Class() != reconcile.ErrorRetryable || classified.ReasonCode() != reconcile.ReasonEndpointNotReady {
		t.Fatalf("incomplete endpoint scan was not retried: err=%v", err)
	}
	if len(events) != 2 || events[0] != "desired" || events[1] != "disable" || len(maps.calls) != 0 || maps.remoteMappings != 0 || ownership.commits != 0 || controlPublisher.publishes != 0 {
		t.Fatalf("incomplete endpoint scan reached mutation: events=%v maps=%v remote=%d commits=%d publishes=%d", events, maps.calls, maps.remoteMappings, ownership.commits, controlPublisher.publishes)
	}
}

func TestRemoteChangeHandlerInvalidatesAndPublishesLatestMapping(t *testing.T) {
	events := []string{}
	maps := &remoteMaps{}
	publisher := &localHandlerPublisher{events: &events}
	handler := newRemoteChangeHandler(t, remoteChangeStore(t), maps, &events, publisher)
	if err := handler.Handle(context.Background(), reconcile.ReconcileKey{Kind: reconcile.ReconcileRemoteEndpoint, UID: "pod-remote"}); err != nil {
		t.Fatal(err)
	}
	if len(maps.calls) != 3 || maps.remoteMappings != 1 || maps.baseCalls != 0 || maps.deviceMapCalls != 0 || len(events) != 5 || events[0] != "desired" || events[1] != "disable" || events[2] != "scan" || events[3] != "scan" || events[4] != "publish" {
		t.Fatalf("unexpected invalidation order: maps=%v events=%v", maps.calls, events)
	}
	remote, ok := publisher.desired.RemoteEndpoints[netip.MustParseAddr("10.42.1.2")]
	if !ok || remote.NodeIPv4 != netip.MustParseAddr("192.0.2.11") {
		t.Fatalf("latest remote mapping was not published: %#v", publisher.desired.RemoteEndpoints)
	}
}

func TestRemoteChangeHandlerRemovesMappingAfterRemotePodTerminates(t *testing.T) {
	events := []string{}
	maps := &remoteMaps{}
	publisher := &remoteMapPublisher{events: &events, maps: maps}
	store := remoteChangeStore(t)
	handler := newRemoteChangeHandler(t, store, maps, &events, publisher)
	key := reconcile.ReconcileKey{Kind: reconcile.ReconcileRemoteEndpoint, UID: "pod-remote"}

	if err := handler.Handle(context.Background(), key); err != nil {
		t.Fatal(err)
	}
	remoteIP := netip.MustParseAddr("10.42.1.2")
	if nodeIP, ok := maps.remoteEntries[remoteIP]; !ok || nodeIP != netip.MustParseAddr("192.0.2.11") {
		t.Fatalf("initial remote mapping was not ensured: %#v", maps.remoteEntries)
	}
	pod, ok := store.GetPod("pod-remote")
	if !ok {
		t.Fatal("remote Pod disappeared from snapshot")
	}
	pod.Phase = "Succeeded"
	if err := store.UpsertPod(pod); err != nil {
		t.Fatal(err)
	}
	if err := handler.Handle(context.Background(), key); err != nil {
		t.Fatal(err)
	}
	if _, ok := maps.remoteEntries[remoteIP]; ok {
		t.Fatalf("terminal remote mapping was not cleared: %#v", maps.remoteEntries)
	}
	if _, ok := publisher.desired.RemoteEndpoints[remoteIP]; ok {
		t.Fatalf("terminal remote mapping was retained: %#v", publisher.desired.RemoteEndpoints)
	}
	if len(publisher.remoteMappingAtPublish) != 2 || !publisher.remoteMappingAtPublish[0] || publisher.remoteMappingAtPublish[1] {
		t.Fatalf("remote mapping cleanup did not precede publication: %#v", publisher.remoteMappingAtPublish)
	}
	if len(maps.calls) != 6 || maps.remoteMappings != 2 {
		t.Fatalf("terminal remote mapping was not invalidated and rebuilt: clears=%v remote=%d", maps.calls, maps.remoteMappings)
	}
}

func TestRemoteChangeHandlerGlobalRefreshesBaseDatapath(t *testing.T) {
	events := []string{}
	maps := &remoteMaps{}
	publisher := &localHandlerPublisher{events: &events}
	handler := newRemoteChangeHandler(t, remoteChangeStore(t), maps, &events, publisher)
	if err := handler.Handle(context.Background(), reconcile.ReconcileKey{Kind: reconcile.ReconcileGlobal}); err != nil {
		t.Fatal(err)
	}
	if maps.baseCalls != 1 || maps.deviceMapCalls != 1 || len(maps.calls) != 3 || maps.remoteMappings != 1 {
		t.Fatalf("global change did not refresh base datapath: base=%d devmap=%d clears=%v remote=%d", maps.baseCalls, maps.deviceMapCalls, maps.calls, maps.remoteMappings)
	}
}

func TestRemoteChangeHandlerGlobalDatapathFailureStopsBeforeRemoteMaps(t *testing.T) {
	tests := []struct {
		name          string
		maps          *remoteMaps
		baseCalls     int
		deviceMapCall int
	}{
		{name: "base", maps: &remoteMaps{baseErr: errors.New("base failed")}, baseCalls: 1},
		{name: "devmap", maps: &remoteMaps{deviceMapErr: errors.New("devmap failed")}, baseCalls: 1, deviceMapCall: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			events := []string{}
			publisher := &localHandlerPublisher{events: &events}
			handler := newRemoteChangeHandler(t, remoteChangeStore(t), test.maps, &events, publisher)
			if err := handler.Handle(context.Background(), reconcile.ReconcileKey{Kind: reconcile.ReconcileGlobal}); err == nil {
				t.Fatal("global datapath failure was ignored")
			}
			if test.maps.baseCalls != test.baseCalls || test.maps.deviceMapCalls != test.deviceMapCall || len(test.maps.calls) != 0 || test.maps.remoteMappings != 0 {
				t.Fatalf("remote maps were touched after datapath failure: base=%d devmap=%d clears=%v remote=%d", test.maps.baseCalls, test.maps.deviceMapCalls, test.maps.calls, test.maps.remoteMappings)
			}
			if len(events) != 3 || events[0] != "desired" || events[1] != "disable" || events[2] != "scan" {
				t.Fatalf("generation continued after datapath failure: %v", events)
			}
		})
	}
}

func TestRemoteChangeHandlerGlobalEventAndFailure(t *testing.T) {
	events := []string{}
	maps := &remoteMaps{err: errors.New("clear failed")}
	handler := newRemoteChangeHandler(t, remoteChangeStore(t), maps, &events, &localHandlerPublisher{events: &events})
	if err := handler.Handle(context.Background(), reconcile.ReconcileKey{Kind: reconcile.ReconcileGlobal}); err == nil || maps.baseCalls != 1 || maps.deviceMapCalls != 1 || len(events) != 3 || events[0] != "desired" || events[1] != "disable" || events[2] != "scan" || len(maps.calls) != 1 {
		t.Fatalf("clear failure was not contained: err=%v maps=%v events=%v", err, maps.calls, events)
	}
	if err := handler.Handle(context.Background(), reconcile.ReconcileKey{Kind: reconcile.ReconcileLocalEndpoint}); err != nil {
		t.Fatal(err)
	}
}
