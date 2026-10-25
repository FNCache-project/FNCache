package lifecycle

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"reflect"
	"testing"

	"github.com/cat-cc-Lcos/FNCache/internal/controlplane"
	"github.com/cat-cc-Lcos/FNCache/internal/endpoint"
	"github.com/cat-cc-Lcos/FNCache/internal/hostnet/discovery"
	"github.com/cat-cc-Lcos/FNCache/internal/kubernetes"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

type localHandlerResolver struct {
	endpoint endpoint.Endpoint
	err      error
	events   *[]string
}

func (r *localHandlerResolver) Resolve(context.Context, endpoint.PodSnapshot) (endpoint.Endpoint, error) {
	*r.events = append(*r.events, "resolve")
	return r.endpoint, r.err
}
func (r *localHandlerResolver) Validate(context.Context, endpoint.Endpoint) error { return nil }

type localHandlerDesired struct {
	desired reconcile.DesiredState
	events  *[]string
}

func (s *localHandlerDesired) Desired(context.Context) (reconcile.DesiredState, error) {
	*s.events = append(*s.events, "desired")
	return s.desired, nil
}

type localHandlerOwnership struct {
	state reconcile.OwnershipState
	err   error
}

func (s *localHandlerOwnership) Load(context.Context) (reconcile.OwnershipState, error) {
	return s.state, s.err
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

type localHandlerGeneration struct {
	control   Control
	scanner   StateScanner
	publisher Publisher
}

func (g *localHandlerGeneration) Execute(ctx context.Context, desired reconcile.DesiredState, mutate controlplane.GenerationMutator) error {
	if err := g.control.Disable(ctx); err != nil {
		return err
	}
	actual, err := g.scanner.Scan(ctx)
	if err != nil {
		return err
	}
	if err := mutate(ctx, desired, actual); err != nil {
		return err
	}
	actual, err = g.scanner.Scan(ctx)
	if err != nil {
		return err
	}
	return g.publisher.CommitAndPublish(ctx, desired, actual)
}

func testLocalGeneration(control Control, scanner StateScanner, publisher Publisher) GenerationTransaction {
	return &localHandlerGeneration{control: control, scanner: scanner, publisher: publisher}
}

type localHandlerEndpoint struct{ events *[]string }

func (e *localHandlerEndpoint) EnsureEndpoint(context.Context, reconcile.DesiredState, reconcile.ActualState, endpoint.Endpoint) (bool, error) {
	*e.events = append(*e.events, "endpoint")
	return true, nil
}

type localHandlerMaps struct{ events *[]string }

func (m *localHandlerMaps) EnsureEndpointMaps(context.Context, reconcile.DesiredState, reconcile.ActualState, endpoint.Endpoint, bool) (bool, error) {
	*m.events = append(*m.events, "maps")
	return true, nil
}

type localHandlerRemover struct{}

func (localHandlerRemover) Remove(context.Context, reconcile.OwnedEndpoint, reconcile.ActualState, reconcile.DesiredState) error {
	return nil
}

type recordingLocalHandlerRemover struct {
	calls int
	owned []reconcile.OwnedEndpoint
}

func (r *recordingLocalHandlerRemover) Remove(_ context.Context, owned reconcile.OwnedEndpoint, _ reconcile.ActualState, _ reconcile.DesiredState) error {
	r.calls++
	r.owned = append(r.owned, owned)
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

func handlerPod() endpoint.PodSnapshot {
	return endpoint.PodSnapshot{Identity: endpoint.PodIdentity{Namespace: "default", Name: "web", UID: "pod-1"}, NodeName: "node-a", PodIPv4: netip.MustParseAddr("10.42.0.2"), Phase: "Running"}
}

func handlerEndpoint(uid string) endpoint.Endpoint {
	return endpoint.Endpoint{Pod: endpoint.PodIdentity{Namespace: "default", Name: "web", UID: uid}, Node: endpoint.NodeIdentity{Name: "node-a"}, PodIPv4: netip.MustParseAddr("10.42.0.2"), NetNSInode: 42, PeerLink: endpoint.LinkIdentity{NetNSInode: 42, IfIndex: 2}, HostLink: endpoint.LinkIdentity{IfIndex: 3}}
}

func TestLocalEndpointHandlerCreatesAndPublishesEndpoint(t *testing.T) {
	events := make([]string, 0)
	store := kubernetes.NewSnapshotStore()
	if err := store.UpsertNode(kubernetes.NodeSnapshot{Identity: endpoint.NodeIdentity{Name: "node-a", UID: "node-1"}}); err != nil {
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
	base := reconcile.DesiredState{Enabled: true, Capability: discovery.CapabilityReport{Supported: true}, LocalEndpoints: map[string]endpoint.Endpoint{"pod-old": handlerEndpoint("pod-old")}}
	publisher := &localHandlerPublisher{events: &events}
	control := &localHandlerControl{events: &events}
	scanner := &localHandlerScanner{events: &events}
	handler, err := NewLocalEndpointHandler(LocalEndpointHandlerConfig{Store: store, Resolver: &localHandlerResolver{endpoint: handlerEndpoint("pod-1"), events: &events}, LocalNode: "node-a", Desired: &localHandlerDesired{desired: base, events: &events}, Scanner: scanner, Control: control, Endpoint: &localHandlerEndpoint{events: &events}, Maps: &localHandlerMaps{events: &events}, Remover: localHandlerRemover{}, Ownership: &localHandlerOwnership{err: os.ErrNotExist}, Publisher: publisher, Generation: testLocalGeneration(control, scanner, publisher)})
	if err != nil {
		t.Fatal(err)
	}
	if err := handler.Handle(context.Background(), reconcile.ReconcileKey{Kind: reconcile.ReconcileLocalEndpoint, UID: "pod-1"}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(events, []string{"resolve", "desired", "disable", "scan", "endpoint", "maps", "scan", "publish"}) {
		t.Fatalf("events = %v", events)
	}
	if len(publisher.desired.LocalEndpoints) != 2 {
		t.Fatalf("other endpoints were lost: %#v", publisher.desired.LocalEndpoints)
	}
}

func TestLocalEndpointHandlerClassifiesNotReadyAndSkipsInvalidPod(t *testing.T) {
	store := kubernetes.NewSnapshotStore()
	_ = store.UpsertNode(kubernetes.NodeSnapshot{Identity: endpoint.NodeIdentity{Name: "node-a", UID: "node-1"}})
	pod := handlerPod()
	_ = store.UpsertPod(pod)
	events := []string{}
	control := &localHandlerControl{events: &events}
	scanner := &localHandlerScanner{events: &events}
	publisher := &localHandlerPublisher{events: &events}
	handler, _ := NewLocalEndpointHandler(LocalEndpointHandlerConfig{Store: store, Resolver: &localHandlerResolver{err: endpoint.ErrEndpointNotReady, events: &events}, LocalNode: "node-a", Desired: &localHandlerDesired{events: &events}, Scanner: scanner, Control: control, Endpoint: &localHandlerEndpoint{events: &events}, Maps: &localHandlerMaps{events: &events}, Remover: localHandlerRemover{}, Ownership: &localHandlerOwnership{}, Publisher: publisher, Generation: testLocalGeneration(control, scanner, publisher)})
	err := handler.Handle(context.Background(), reconcile.ReconcileKey{Kind: reconcile.ReconcileLocalEndpoint, UID: "pod-1"})
	var classified *reconcile.ClassifiedError
	if !errors.As(err, &classified) || classified.Class() != reconcile.ErrorRetryable || len(events) != 1 {
		t.Fatalf("not-ready result: err=%v events=%v", err, events)
	}
	pod.HostNetwork = true
	_ = store.UpsertPod(pod)
	if err := handler.Handle(context.Background(), reconcile.ReconcileKey{Kind: reconcile.ReconcileLocalEndpoint, UID: "pod-1"}); err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("invalid Pod triggered operations: %v", events)
	}
}

func TestLocalEndpointHandlerSkipsTerminalPods(t *testing.T) {
	for _, phase := range []string{"Succeeded", "Failed"} {
		t.Run(phase, func(t *testing.T) {
			store := kubernetes.NewSnapshotStore()
			if err := store.UpsertNode(kubernetes.NodeSnapshot{Identity: endpoint.NodeIdentity{Name: "node-a", UID: "node-1"}}); err != nil {
				t.Fatal(err)
			}
			pod := handlerPod()
			pod.Phase = phase
			if err := store.UpsertPod(pod); err != nil {
				t.Fatal(err)
			}
			events := []string{}
			control := &localHandlerControl{events: &events}
			scanner := &localHandlerScanner{events: &events}
			publisher := &localHandlerPublisher{events: &events}
			handler, err := NewLocalEndpointHandler(LocalEndpointHandlerConfig{
				Store: store, Resolver: &localHandlerResolver{events: &events}, LocalNode: "node-a",
				Desired: &localHandlerDesired{events: &events}, Scanner: scanner, Control: control, Endpoint: &localHandlerEndpoint{events: &events}, Maps: &localHandlerMaps{events: &events}, Remover: localHandlerRemover{}, Ownership: &localHandlerOwnership{}, Publisher: publisher, Generation: testLocalGeneration(control, scanner, publisher),
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := handler.Handle(context.Background(), reconcile.ReconcileKey{Kind: reconcile.ReconcileLocalEndpoint, UID: pod.Identity.UID}); err != nil {
				t.Fatal(err)
			}
			if len(events) != 0 {
				t.Fatalf("terminal Pod triggered endpoint reconciliation: %v", events)
			}
		})
	}
}

func TestLocalEndpointHandlerCleansSameUIDIdentityChange(t *testing.T) {
	store := kubernetes.NewSnapshotStore()
	if err := store.UpsertNode(kubernetes.NodeSnapshot{Identity: endpoint.NodeIdentity{Name: "node-a", UID: "node-1"}}); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertPod(handlerPod()); err != nil {
		t.Fatal(err)
	}
	old := handlerEndpoint("pod-1")
	current := old
	current.PodIPv4 = netip.MustParseAddr("10.42.0.9")
	current.NetNSInode = 99
	current.PeerLink = endpoint.LinkIdentity{NetNSInode: 99, IfIndex: 12, IfName: "eth0", MAC: []byte{2, 0, 0, 0, 0, 9}}
	current.HostLink = endpoint.LinkIdentity{IfIndex: 13, IfName: "vethweb-new", MAC: []byte{2, 0, 0, 0, 0, 8}}
	events := []string{}
	remover := &recordingLocalHandlerRemover{}
	scanner := &localHandlerScanner{events: &events}
	control := &localHandlerControl{events: &events}
	publisher := &localHandlerPublisher{events: &events}
	ownership := &localHandlerOwnership{state: reconcile.OwnershipState{Endpoints: map[string]reconcile.OwnedEndpoint{
		"pod-1": {PodUID: "pod-1", PodIPv4: old.PodIPv4, NetNSInode: old.NetNSInode, PeerIfIndex: old.PeerLink.IfIndex, HostIfIndex: old.HostLink.IfIndex},
	}}}
	handler, err := NewLocalEndpointHandler(LocalEndpointHandlerConfig{
		Store: store, Resolver: &localHandlerResolver{endpoint: current, events: &events}, LocalNode: "node-a",
		Desired: &localHandlerDesired{desired: reconcile.DesiredState{Enabled: true, Capability: discovery.CapabilityReport{Supported: true}, LocalEndpoints: map[string]endpoint.Endpoint{"pod-1": current}}, events: &events},
		Scanner: scanner, Control: control, Endpoint: &localHandlerEndpoint{events: &events}, Maps: &localHandlerMaps{events: &events}, Remover: remover, Ownership: ownership, Publisher: publisher, Generation: testLocalGeneration(control, scanner, publisher),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := handler.Handle(context.Background(), reconcile.ReconcileKey{Kind: reconcile.ReconcileLocalEndpoint, UID: "pod-1"}); err != nil {
		t.Fatal(err)
	}
	if remover.calls != 1 || scanner.calls != 3 || len(remover.owned) != 1 || remover.owned[0].PodIPv4 != old.PodIPv4 || remover.owned[0].PeerIfIndex != old.PeerLink.IfIndex || remover.owned[0].HostIfIndex != old.HostLink.IfIndex {
		t.Fatalf("same-UID identity change did not refresh state after cleanup: remover=%d scans=%d events=%v", remover.calls, scanner.calls, events)
	}
}
