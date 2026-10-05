package agent

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"testing"

	"github.com/cat-cc-Lcos/FNCache/internal/discovery"
	"github.com/cat-cc-Lcos/FNCache/internal/kube"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
	"github.com/cat-cc-Lcos/FNCache/internal/resolver"
)

type localHandlerResolver struct {
	endpoint resolver.Endpoint
	err      error
	events   *[]string
}

func (r *localHandlerResolver) Resolve(context.Context, resolver.PodSnapshot) (resolver.Endpoint, error) {
	*r.events = append(*r.events, "resolve")
	return r.endpoint, r.err
}
func (r *localHandlerResolver) Validate(context.Context, resolver.Endpoint) error { return nil }

type localHandlerDesired struct {
	desired reconcile.DesiredState
	events  *[]string
}

func (s *localHandlerDesired) Desired(context.Context) (reconcile.DesiredState, error) {
	*s.events = append(*s.events, "desired")
	return s.desired, nil
}

type localHandlerScanner struct {
	actual reconcile.ActualState
	calls  int
	events *[]string
}

func (s *localHandlerScanner) Scan(context.Context) (reconcile.ActualState, error) {
	s.calls++
	*s.events = append(*s.events, "scan")
	return s.actual, nil
}

type localHandlerControl struct{ events *[]string }

func (c *localHandlerControl) Disable(context.Context) error {
	*c.events = append(*c.events, "disable")
	return nil
}

type localHandlerEndpoint struct{ events *[]string }

func (e *localHandlerEndpoint) EnsureEndpoint(context.Context, reconcile.DesiredState, reconcile.ActualState, resolver.Endpoint) (bool, error) {
	*e.events = append(*e.events, "endpoint")
	return true, nil
}

type localHandlerMaps struct{ events *[]string }

func (m *localHandlerMaps) EnsureEndpointMaps(context.Context, reconcile.DesiredState, reconcile.ActualState, resolver.Endpoint, bool) (bool, error) {
	*m.events = append(*m.events, "maps")
	return true, nil
}

type localHandlerRemover struct{}

func (localHandlerRemover) Remove(context.Context, reconcile.OwnedEndpoint, reconcile.ActualState, reconcile.DesiredState) error {
	return nil
}

type recordingLocalHandlerRemover struct{ calls int }

func (r *recordingLocalHandlerRemover) Remove(context.Context, reconcile.OwnedEndpoint, reconcile.ActualState, reconcile.DesiredState) error {
	r.calls++
	return nil
}

type localHandlerPublisher struct {
	desired reconcile.DesiredState
	events  *[]string
}

func (p *localHandlerPublisher) CommitAndPublish(_ context.Context, desired reconcile.DesiredState, _ reconcile.ActualState) error {
	p.desired = desired
	*p.events = append(*p.events, "publish")
	return nil
}

func handlerPod() resolver.PodSnapshot {
	return resolver.PodSnapshot{Identity: resolver.PodIdentity{Namespace: "default", Name: "web", UID: "pod-1"}, NodeName: "node-a", PodIPv4: netip.MustParseAddr("10.42.0.2"), Phase: "Running"}
}

func handlerEndpoint(uid string) resolver.Endpoint {
	return resolver.Endpoint{Pod: resolver.PodIdentity{Namespace: "default", Name: "web", UID: uid}, Node: resolver.NodeIdentity{Name: "node-a"}, PodIPv4: netip.MustParseAddr("10.42.0.2"), NetNSInode: 42, PeerLink: resolver.LinkIdentity{NetNSInode: 42, IfIndex: 2}, HostLink: resolver.LinkIdentity{IfIndex: 3}}
}

func TestLocalEndpointHandlerCreatesAndPublishesEndpoint(t *testing.T) {
	events := make([]string, 0)
	store := kube.NewSnapshotStore()
	if err := store.UpsertNode(kube.NodeSnapshot{Identity: resolver.NodeIdentity{Name: "node-a", UID: "node-1"}}); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertPod(handlerPod()); err != nil {
		t.Fatal(err)
	}
	oldPod := handlerPod()
	oldPod.Identity.UID, oldPod.Identity.Name, oldPod.PodIPv4 = "pod-old", "old", netip.MustParseAddr("10.42.0.3")
	if err := store.UpsertPod(oldPod); err != nil {
		t.Fatal(err)
	}
	base := reconcile.DesiredState{Enabled: true, Capability: discovery.CapabilityReport{Supported: true}, LocalEndpoints: map[string]resolver.Endpoint{"pod-old": handlerEndpoint("pod-old")}}
	publisher := &localHandlerPublisher{events: &events}
	handler, err := NewLocalEndpointHandler(LocalEndpointHandlerConfig{Store: store, Resolver: &localHandlerResolver{endpoint: handlerEndpoint("pod-1"), events: &events}, LocalNode: "node-a", Desired: &localHandlerDesired{desired: base, events: &events}, Scanner: &localHandlerScanner{events: &events}, Control: &localHandlerControl{events: &events}, Endpoint: &localHandlerEndpoint{events: &events}, Maps: &localHandlerMaps{events: &events}, Remover: localHandlerRemover{}, Publisher: publisher})
	if err != nil {
		t.Fatal(err)
	}
	if err := handler.Handle(context.Background(), reconcile.ReconcileKey{Kind: reconcile.ReconcileLocalEndpoint, UID: "pod-1"}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(events, []string{"disable", "resolve", "desired", "scan", "endpoint", "maps", "scan", "publish"}) {
		t.Fatalf("events = %v", events)
	}
	if len(publisher.desired.LocalEndpoints) != 2 {
		t.Fatalf("other endpoints were lost: %#v", publisher.desired.LocalEndpoints)
	}
}

func TestLocalEndpointHandlerClassifiesNotReadyAndSkipsInvalidPod(t *testing.T) {
	store := kube.NewSnapshotStore()
	_ = store.UpsertNode(kube.NodeSnapshot{Identity: resolver.NodeIdentity{Name: "node-a", UID: "node-1"}})
	pod := handlerPod()
	_ = store.UpsertPod(pod)
	events := []string{}
	handler, _ := NewLocalEndpointHandler(LocalEndpointHandlerConfig{Store: store, Resolver: &localHandlerResolver{err: resolver.ErrEndpointNotReady, events: &events}, LocalNode: "node-a", Desired: &localHandlerDesired{events: &events}, Scanner: &localHandlerScanner{events: &events}, Control: &localHandlerControl{events: &events}, Endpoint: &localHandlerEndpoint{events: &events}, Maps: &localHandlerMaps{events: &events}, Remover: localHandlerRemover{}, Publisher: &localHandlerPublisher{events: &events}})
	err := handler.Handle(context.Background(), reconcile.ReconcileKey{Kind: reconcile.ReconcileLocalEndpoint, UID: "pod-1"})
	var classified *reconcile.ClassifiedError
	if !errors.As(err, &classified) || classified.Class() != reconcile.ErrorRetryable || !reflect.DeepEqual(events, []string{"disable", "resolve"}) {
		t.Fatalf("not-ready result: err=%v events=%v", err, events)
	}
	pod.HostNetwork = true
	_ = store.UpsertPod(pod)
	if err := handler.Handle(context.Background(), reconcile.ReconcileKey{Kind: reconcile.ReconcileLocalEndpoint, UID: "pod-1"}); err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("invalid Pod triggered operations: %v", events)
	}
}

func TestLocalEndpointHandlerCleansSameUIDIdentityChange(t *testing.T) {
	store := kube.NewSnapshotStore()
	if err := store.UpsertNode(kube.NodeSnapshot{Identity: resolver.NodeIdentity{Name: "node-a", UID: "node-1"}}); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertPod(handlerPod()); err != nil {
		t.Fatal(err)
	}
	old := handlerEndpoint("pod-1")
	current := old
	current.PodIPv4 = netip.MustParseAddr("10.42.0.9")
	current.NetNSInode = 99
	current.PeerLink = resolver.LinkIdentity{NetNSInode: 99, IfIndex: 12, IfName: "eth0", MAC: []byte{2, 0, 0, 0, 0, 9}}
	current.HostLink = resolver.LinkIdentity{IfIndex: 13, IfName: "vethweb-new", MAC: []byte{2, 0, 0, 0, 0, 8}}
	events := []string{}
	remover := &recordingLocalHandlerRemover{}
	scanner := &localHandlerScanner{events: &events}
	handler, err := NewLocalEndpointHandler(LocalEndpointHandlerConfig{
		Store: store, Resolver: &localHandlerResolver{endpoint: current, events: &events}, LocalNode: "node-a",
		Desired: &localHandlerDesired{desired: reconcile.DesiredState{Enabled: true, Capability: discovery.CapabilityReport{Supported: true}, LocalEndpoints: map[string]resolver.Endpoint{"pod-1": old}}, events: &events},
		Scanner: scanner, Control: &localHandlerControl{events: &events}, Endpoint: &localHandlerEndpoint{events: &events}, Maps: &localHandlerMaps{events: &events}, Remover: remover, Publisher: &localHandlerPublisher{events: &events},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := handler.Handle(context.Background(), reconcile.ReconcileKey{Kind: reconcile.ReconcileLocalEndpoint, UID: "pod-1"}); err != nil {
		t.Fatal(err)
	}
	if remover.calls != 1 || scanner.calls != 3 {
		t.Fatalf("same-UID identity change did not refresh state after cleanup: remover=%d scans=%d events=%v", remover.calls, scanner.calls, events)
	}
}
