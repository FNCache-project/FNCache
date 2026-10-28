package controlplane

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"testing"

	"github.com/cat-cc-Lcos/FNCache/internal/endpoint"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

type backendObserver struct {
	desired        reconcile.DesiredState
	actual         reconcile.ActualState
	actualSequence []reconcile.ActualState
	scans          int
}

func (f *backendObserver) Discover(context.Context) (reconcile.DesiredState, error) {
	return f.desired, nil
}
func (f *backendObserver) Scan(context.Context) (reconcile.ActualState, error) {
	f.scans++
	if len(f.actualSequence) != 0 {
		index := f.scans - 1
		if index >= len(f.actualSequence) {
			index = len(f.actualSequence) - 1
		}
		return f.actualSequence[index], nil
	}
	return f.actual, nil
}

type backendControl struct{ disabled bool }

func (f *backendControl) Disable(context.Context) error { f.disabled = true; return nil }

type backendCollection struct {
	calls  int
	err    error
	events *[]string
}

func (f *backendCollection) EnsureCollection(context.Context, reconcile.DesiredState, reconcile.ActualState) (bool, error) {
	f.calls++
	if f.events != nil {
		*f.events = append(*f.events, "collection")
	}
	return true, f.err
}

type backendMarker struct {
	calls  int
	events *[]string
}

func (f *backendMarker) EnsureMarker(context.Context, reconcile.DesiredState) (bool, error) {
	f.calls++
	if f.events != nil {
		*f.events = append(*f.events, "marker")
	}
	return true, nil
}

type backendEnsurer struct {
	calls int
	err   error
}

type backendRemover struct {
	calls int
	uids  []string
}

func (r *backendRemover) Remove(_ context.Context, owned reconcile.OwnedEndpoint, _ reconcile.ActualState, _ reconcile.DesiredState) error {
	r.calls++
	r.uids = append(r.uids, owned.PodUID)
	return nil
}

func (f *backendEnsurer) EnsureBase(context.Context, reconcile.DesiredState, reconcile.ActualState) (bool, error) {
	f.calls++
	return true, f.err
}

func (f *backendEnsurer) EnsureEndpoint(context.Context, reconcile.DesiredState, reconcile.ActualState, endpoint.Endpoint) (bool, error) {
	f.calls++
	return true, f.err
}

func (f *backendEnsurer) EnsureEndpointMaps(context.Context, reconcile.DesiredState, reconcile.ActualState, endpoint.Endpoint, bool) (bool, error) {
	f.calls++
	return true, f.err
}

func TestFirstPassBackendRunsAllStagesAndPublishesLastScan(t *testing.T) {
	desired := publishTestDesired()
	observer := &backendObserver{desired: desired, actual: publishTestActual(desired)}
	control := &backendControl{}
	collection := &backendCollection{}
	marker := &backendMarker{}
	base := &backendEnsurer{}
	endpoint := &backendEnsurer{}
	maps := &backendEnsurer{}
	store := &fakeOwnershipCommitter{events: new([]string)}
	publish := &fakeControlPublisher{events: store.events}
	remover := &backendRemover{}
	publisher, err := NewPublisher(store, publish, publishTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	backend, err := NewFirstPassBackend(FirstPassBackendConfig{
		Observer: observer, Control: control, Collection: collection, Marker: marker,
		Base: base, Endpoint: endpoint, Maps: maps, Ownership: store, Remover: remover, Publisher: publisher,
	})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := reconcile.NewCoordinator(backend)
	if err != nil {
		t.Fatal(err)
	}
	result, err := coordinator.FullReconcile(context.Background())
	if err != nil || result.State != reconcile.AgentReady || !control.disabled {
		t.Fatalf("first-pass reconcile failed: result=%+v err=%v", result, err)
	}
	if collection.calls != 1 || marker.calls != 1 || base.calls != 1 || endpoint.calls != 1 || maps.calls != 1 {
		t.Fatalf("ensure stages were not called once: collection=%d marker=%d base=%d endpoint=%d maps=%d", collection.calls, marker.calls, base.calls, endpoint.calls, maps.calls)
	}
	if observer.scans < 3 || len(*store.events) != 2 || (*store.events)[0] != "commit" || (*store.events)[1] != "publish" {
		t.Fatalf("unexpected scan or publish sequence: scans=%d events=%v", observer.scans, *store.events)
	}
}

func TestFirstPassBackendEnsuresMarkerBeforeCollection(t *testing.T) {
	desired := publishTestDesired()
	events := []string{}
	store := &fakeOwnershipCommitter{events: &events}
	publisher, err := NewPublisher(store, &fakeControlPublisher{events: &events}, publishTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	backend, err := NewFirstPassBackend(FirstPassBackendConfig{
		Observer: &backendObserver{desired: desired, actual: publishTestActual(desired)}, Control: &backendControl{},
		Collection: &backendCollection{events: &events}, Marker: &backendMarker{events: &events},
		Base: &backendEnsurer{}, Endpoint: &backendEnsurer{}, Maps: &backendEnsurer{},
		Ownership: store, Remover: &backendRemover{}, Publisher: publisher,
	})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := reconcile.NewCoordinator(backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.FullReconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(events) < 2 || events[0] != "marker" || events[1] != "collection" {
		t.Fatalf("marker was not ensured before collection: %v", events)
	}
}

func TestFirstPassBackendEnsuresMarkerWhenCollectionFails(t *testing.T) {
	desired := publishTestDesired()
	events := []string{}
	wantErr := errors.New("stale collection")
	store := &fakeOwnershipCommitter{events: &events}
	publisher, err := NewPublisher(store, &fakeControlPublisher{events: &events}, publishTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	backend, err := NewFirstPassBackend(FirstPassBackendConfig{
		Observer: &backendObserver{desired: desired, actual: publishTestActual(desired)}, Control: &backendControl{},
		Collection: &backendCollection{err: wantErr, events: &events}, Marker: &backendMarker{events: &events},
		Base: &backendEnsurer{}, Endpoint: &backendEnsurer{}, Maps: &backendEnsurer{},
		Ownership: store, Remover: &backendRemover{}, Publisher: publisher,
	})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := reconcile.NewCoordinator(backend)
	if err != nil {
		t.Fatal(err)
	}
	result, err := coordinator.FullReconcile(context.Background())
	if !errors.Is(err, wantErr) || result.State != reconcile.AgentDisabled {
		t.Fatalf("collection failure did not remain disabled: result=%+v err=%v", result, err)
	}
	if len(events) < 2 || events[0] != "marker" || events[1] != "collection" {
		t.Fatalf("marker was not ensured before failed collection: %v", events)
	}
}

func TestFirstPassBackendRechecksPublishGuardBeforeControlPublish(t *testing.T) {
	desired := publishTestDesired()
	events := []string{}
	store := &fakeOwnershipCommitter{events: &events}
	publish := &fakeControlPublisher{events: &events}
	publisher, err := NewPublisher(store, publish, publishTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	wantErr := errors.New("Kubernetes state became stale")
	checks := 0
	publisher.SetPublishGuard(func(context.Context) error {
		checks++
		if checks == 2 {
			return wantErr
		}
		return nil
	})
	backend, err := NewFirstPassBackend(FirstPassBackendConfig{
		Observer: &backendObserver{desired: desired, actual: publishTestActual(desired)}, Control: &backendControl{},
		Collection: &backendCollection{}, Marker: &backendMarker{}, Base: &backendEnsurer{}, Endpoint: &backendEnsurer{}, Maps: &backendEnsurer{},
		Ownership: store, Remover: &backendRemover{}, Publisher: publisher,
	})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := reconcile.NewCoordinator(backend)
	if err != nil {
		t.Fatal(err)
	}
	result, err := coordinator.FullReconcile(context.Background())
	if !errors.Is(err, wantErr) || result.State != reconcile.AgentDisabled {
		t.Fatalf("stale publish was not rejected: result=%+v err=%v", result, err)
	}
	if checks != 2 || len(events) != 1 || events[0] != "commit" {
		t.Fatalf("stale state reached control publish: checks=%d events=%v", checks, events)
	}
}

func TestFirstPassBackendLeavesUnsupportedNodeDisabled(t *testing.T) {
	desired := publishTestDesired()
	desired.Enabled = false
	desired.Capability.Supported = false
	observer := &backendObserver{desired: desired, actual: reconcile.ActualState{}}
	control := &backendControl{}
	collection := &backendCollection{}
	marker := &backendMarker{}
	base := &backendEnsurer{}
	endpoint := &backendEnsurer{}
	maps := &backendEnsurer{}
	store := &fakeOwnershipCommitter{events: new([]string)}
	publisher, err := NewPublisher(store, &fakeControlPublisher{events: store.events}, publishTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	backend, err := NewFirstPassBackend(FirstPassBackendConfig{
		Observer: observer, Control: control, Collection: collection, Marker: marker,
		Base: base, Endpoint: endpoint, Maps: maps, Ownership: store, Remover: &backendRemover{}, Publisher: publisher,
	})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := reconcile.NewCoordinator(backend)
	if err != nil {
		t.Fatal(err)
	}
	result, err := coordinator.FullReconcile(context.Background())
	if err != nil || result.State != reconcile.AgentDisabled || !control.disabled {
		t.Fatalf("unsupported node did not remain disabled: result=%+v err=%v controlDisabled=%v", result, err, control.disabled)
	}
	if observer.scans != 0 || collection.calls != 0 || marker.calls != 0 || base.calls != 0 || endpoint.calls != 0 || maps.calls != 0 || len(*store.events) != 0 {
		t.Fatalf("disabled path performed unsafe work: scans=%d collection=%d marker=%d base=%d endpoint=%d maps=%d events=%v", observer.scans, collection.calls, marker.calls, base.calls, endpoint.calls, maps.calls, *store.events)
	}
}

func TestFirstPassBackendPreservesOwnershipWhenEndpointScanIsIncomplete(t *testing.T) {
	desired := publishTestDesired()
	desired.EndpointScanSkipped = map[string]string{"pod-skipped": endpoint.ErrEndpointNotReady.Error()}
	owned := reconcile.OwnedEndpoint{PodUID: "pod-old", PodIPv4: netip.MustParseAddr("10.244.1.11"), NetNSInode: 43, PeerIfIndex: 11, HostIfIndex: 21}
	store := &fakeOwnershipCommitter{events: new([]string), state: reconcile.OwnershipState{
		SchemaVersion: 1, InstallationID: "install-a", NodeUID: "node-a", ELFBuildID: "sha256:build", ABI: reconcile.BPFABIVersion,
		Endpoints: map[string]reconcile.OwnedEndpoint{"pod-old": owned},
	}}
	publisher, err := NewPublisher(store, &fakeControlPublisher{events: store.events}, publishTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	collection := &backendCollection{}
	remover := &backendRemover{}
	backend, err := NewFirstPassBackend(FirstPassBackendConfig{
		Observer: &backendObserver{desired: desired, actual: publishTestActual(desired)}, Control: &backendControl{},
		Collection: collection, Marker: &backendMarker{}, Base: &backendEnsurer{}, Endpoint: &backendEnsurer{}, Maps: &backendEnsurer{},
		Ownership: store, Remover: remover, Publisher: publisher,
	})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := reconcile.NewCoordinator(backend)
	if err != nil {
		t.Fatal(err)
	}
	result, err := coordinator.FullReconcile(context.Background())
	var classified *reconcile.ClassifiedError
	if !errors.As(err, &classified) || classified.Class() != reconcile.ErrorRetryable || result.State != reconcile.AgentDisabled {
		t.Fatalf("incomplete endpoint scan was not blocked safely: result=%+v err=%v", result, err)
	}
	if collection.calls != 0 || remover.calls != 0 || len(*store.events) != 0 {
		t.Fatalf("incomplete endpoint scan performed mutation: collection=%d remover=%d events=%v", collection.calls, remover.calls, *store.events)
	}
	if _, ok := store.state.Endpoints[owned.PodUID]; !ok {
		t.Fatalf("existing ownership was lost: state=%+v", store.state)
	}
}

func TestFirstPassBackendStopsBeforeMutationWhenActualScanIsIncomplete(t *testing.T) {
	desired := publishTestDesired()
	actual := publishTestActual(desired)
	actual.EndpointScanSkipped = map[string]string{"pod-skipped": endpoint.ErrEndpointNotReady.Error()}
	store := &fakeOwnershipCommitter{events: new([]string)}
	publisher, err := NewPublisher(store, &fakeControlPublisher{events: store.events}, publishTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	collection := &backendCollection{}
	backend, err := NewFirstPassBackend(FirstPassBackendConfig{
		Observer: &backendObserver{desired: desired, actual: actual}, Control: &backendControl{},
		Collection: collection, Marker: &backendMarker{}, Base: &backendEnsurer{}, Endpoint: &backendEnsurer{}, Maps: &backendEnsurer{},
		Ownership: store, Remover: &backendRemover{}, Publisher: publisher,
	})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := reconcile.NewCoordinator(backend)
	if err != nil {
		t.Fatal(err)
	}
	result, err := coordinator.FullReconcile(context.Background())
	var classified *reconcile.ClassifiedError
	if !errors.As(err, &classified) || classified.Class() != reconcile.ErrorRetryable || result.State != reconcile.AgentDisabled {
		t.Fatalf("incomplete actual scan was not blocked safely: result=%+v err=%v", result, err)
	}
	if collection.calls != 0 || len(*store.events) != 0 {
		t.Fatalf("incomplete actual scan performed mutation: collection=%d events=%v", collection.calls, *store.events)
	}
}

func TestFirstPassBackendStopsBeforeDownstreamMutationWhenRescanIsIncomplete(t *testing.T) {
	desired := publishTestDesired()
	first := publishTestActual(desired)
	second := publishTestActual(desired)
	second.EndpointScanSkipped = map[string]string{"pod-skipped": endpoint.ErrEndpointNotReady.Error()}
	observer := &backendObserver{desired: desired, actualSequence: []reconcile.ActualState{first, second}}
	store := &fakeOwnershipCommitter{events: new([]string)}
	publisher, err := NewPublisher(store, &fakeControlPublisher{events: store.events}, publishTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	collection := &backendCollection{}
	marker := &backendMarker{}
	base := &backendEnsurer{}
	endpoint := &backendEnsurer{}
	maps := &backendEnsurer{}
	remover := &backendRemover{}
	backend, err := NewFirstPassBackend(FirstPassBackendConfig{
		Observer: observer, Control: &backendControl{}, Collection: collection, Marker: marker,
		Base: base, Endpoint: endpoint, Maps: maps, Ownership: store, Remover: remover, Publisher: publisher,
	})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := reconcile.NewCoordinator(backend)
	if err != nil {
		t.Fatal(err)
	}
	result, err := coordinator.FullReconcile(context.Background())
	var classified *reconcile.ClassifiedError
	if !errors.As(err, &classified) || classified.Class() != reconcile.ErrorRetryable || result.State != reconcile.AgentDisabled {
		t.Fatalf("incomplete rescan was not blocked safely: result=%+v err=%v", result, err)
	}
	if observer.scans < 2 || base.calls != 0 || endpoint.calls != 0 || maps.calls != 0 || remover.calls != 0 || len(*store.events) != 0 {
		t.Fatalf("incomplete rescan reached downstream mutation: scans=%d base=%d endpoint=%d maps=%d remover=%d events=%v", observer.scans, base.calls, endpoint.calls, maps.calls, remover.calls, *store.events)
	}
}

func TestFirstPassBackendStopsBeforeOwnershipOnEnsureFailure(t *testing.T) {
	desired := publishTestDesired()
	store := &fakeOwnershipCommitter{events: new([]string)}
	publisher, _ := NewPublisher(store, &fakeControlPublisher{events: store.events}, publishTestConfig())
	backend, err := NewFirstPassBackend(FirstPassBackendConfig{
		Observer: &backendObserver{desired: desired, actual: publishTestActual(desired)},
		Control:  &backendControl{}, Collection: &backendCollection{}, Marker: &backendMarker{},
		Base: &backendEnsurer{err: errors.New("base failed")}, Endpoint: &backendEnsurer{},
		Maps: &backendEnsurer{}, Ownership: store, Remover: &backendRemover{}, Publisher: publisher,
	})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, _ := reconcile.NewCoordinator(backend)
	if _, err := coordinator.FullReconcile(context.Background()); err == nil {
		t.Fatal("ensure failure was not returned")
	}
	if len(*store.events) != 0 {
		t.Fatalf("ownership was changed after ensure failure: %v", *store.events)
	}
}

func TestFirstPassBackendStopsBeforeMutationWhenOwnershipIsUnsafe(t *testing.T) {
	desired := publishTestDesired()
	for _, loadErr := range []error{errors.New("corrupt ownership state"), errors.New("ownership state unreadable")} {
		t.Run(loadErr.Error(), func(t *testing.T) {
			store := &fakeOwnershipCommitter{events: new([]string), loadErr: loadErr}
			publisher, err := NewPublisher(store, &fakeControlPublisher{events: store.events}, publishTestConfig())
			if err != nil {
				t.Fatal(err)
			}
			collection := &backendCollection{}
			marker := &backendMarker{}
			remover := &backendRemover{}
			backend, err := NewFirstPassBackend(FirstPassBackendConfig{
				Observer: &backendObserver{desired: desired, actual: publishTestActual(desired)}, Control: &backendControl{},
				Collection: collection, Marker: marker, Base: &backendEnsurer{}, Endpoint: &backendEnsurer{}, Maps: &backendEnsurer{},
				Ownership: store, Remover: remover, Publisher: publisher,
			})
			if err != nil {
				t.Fatal(err)
			}
			coordinator, err := reconcile.NewCoordinator(backend)
			if err != nil {
				t.Fatal(err)
			}
			result, err := coordinator.FullReconcile(context.Background())
			if err == nil || result.State != reconcile.AgentDisabled {
				t.Fatalf("unsafe ownership state was not rejected: result=%+v err=%v", result, err)
			}
			if collection.calls != 0 || marker.calls != 0 || remover.calls != 0 || len(*store.events) != 0 {
				t.Fatalf("unsafe ownership state allowed mutation: collection=%d marker=%d remover=%d events=%v", collection.calls, marker.calls, remover.calls, *store.events)
			}
		})
	}
}

func TestFirstPassBackendRebuildsWithoutMissingOwnershipState(t *testing.T) {
	desired := publishTestDesired()
	store := &fakeOwnershipCommitter{events: new([]string), loadErr: os.ErrNotExist}
	publisher, err := NewPublisher(store, &fakeControlPublisher{events: store.events}, publishTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	collection := &backendCollection{}
	backend, err := NewFirstPassBackend(FirstPassBackendConfig{
		Observer: &backendObserver{desired: desired, actual: publishTestActual(desired)}, Control: &backendControl{},
		Collection: collection, Marker: &backendMarker{}, Base: &backendEnsurer{}, Endpoint: &backendEnsurer{}, Maps: &backendEnsurer{},
		Ownership: store, Remover: &backendRemover{}, Publisher: publisher,
	})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := reconcile.NewCoordinator(backend)
	if err != nil {
		t.Fatal(err)
	}
	result, err := coordinator.FullReconcile(context.Background())
	if err != nil || result.State != reconcile.AgentReady || collection.calls != 1 {
		t.Fatalf("missing ownership state did not rebuild safely: result=%+v err=%v collection=%d", result, err, collection.calls)
	}
}

func TestFirstPassBackendCleansRemovedAndReplacedOwnedEndpoints(t *testing.T) {
	tests := []struct {
		name     string
		previous reconcile.OwnedEndpoint
		wantUID  string
	}{
		{name: "removed", previous: reconcile.OwnedEndpoint{PodUID: "pod-old", PodIPv4: netip.MustParseAddr("10.244.1.11"), NetNSInode: 43, PeerIfIndex: 11, HostIfIndex: 21}, wantUID: "pod-old"},
		{name: "replaced", previous: reconcile.OwnedEndpoint{PodUID: "pod-a", PodIPv4: netip.MustParseAddr("10.244.1.11"), NetNSInode: 43, PeerIfIndex: 11, HostIfIndex: 21}, wantUID: "pod-a"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			desired := publishTestDesired()
			store := &fakeOwnershipCommitter{events: new([]string), state: reconcile.OwnershipState{
				SchemaVersion: 1, InstallationID: "install-a", NodeUID: "node-a", ELFBuildID: "sha256:build", ABI: reconcile.BPFABIVersion,
				Endpoints: map[string]reconcile.OwnedEndpoint{tt.previous.PodUID: tt.previous},
			}}
			publisher, err := NewPublisher(store, &fakeControlPublisher{events: store.events}, publishTestConfig())
			if err != nil {
				t.Fatal(err)
			}
			remover := &backendRemover{}
			backend, err := NewFirstPassBackend(FirstPassBackendConfig{
				Observer: &backendObserver{desired: desired, actual: publishTestActual(desired)}, Control: &backendControl{},
				Collection: &backendCollection{}, Marker: &backendMarker{}, Base: &backendEnsurer{}, Endpoint: &backendEnsurer{}, Maps: &backendEnsurer{},
				Ownership: store, Remover: remover, Publisher: publisher,
			})
			if err != nil {
				t.Fatal(err)
			}
			coordinator, err := reconcile.NewCoordinator(backend)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := coordinator.FullReconcile(context.Background()); err != nil {
				t.Fatal(err)
			}
			if remover.calls != 1 || len(remover.uids) != 1 || remover.uids[0] != tt.wantUID {
				t.Fatalf("unexpected cleanup calls: calls=%d uids=%v", remover.calls, remover.uids)
			}
		})
	}
}

func TestFirstPassBackendRefreshesOwnershipAfterBuildMismatch(t *testing.T) {
	desired := publishTestDesired()
	store := &fakeOwnershipCommitter{events: new([]string), state: reconcile.OwnershipState{
		SchemaVersion: 1, InstallationID: "install-a", NodeUID: "node-a", ELFBuildID: "old-build", ABI: reconcile.BPFABIVersion,
		Endpoints: map[string]reconcile.OwnedEndpoint{"pod-old": {PodUID: "pod-old", PodIPv4: netip.MustParseAddr("10.244.1.11"), NetNSInode: 43, PeerIfIndex: 11, HostIfIndex: 21}},
	}}
	publisher, err := NewPublisher(store, &fakeControlPublisher{events: store.events}, publishTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	remover := &backendRemover{}
	backend, err := NewFirstPassBackend(FirstPassBackendConfig{
		Observer: &backendObserver{desired: desired, actual: publishTestActual(desired)}, Control: &backendControl{},
		Collection: &backendCollection{}, Marker: &backendMarker{}, Base: &backendEnsurer{}, Endpoint: &backendEnsurer{}, Maps: &backendEnsurer{},
		Ownership: store, Remover: remover, Publisher: publisher,
	})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := reconcile.NewCoordinator(backend)
	if err != nil {
		t.Fatal(err)
	}
	result, err := coordinator.FullReconcile(context.Background())
	if err != nil || result.State != reconcile.AgentReady {
		t.Fatalf("build mismatch prevented recovery: result=%+v err=%v", result, err)
	}
	if remover.calls != 0 || store.state.ELFBuildID != publishTestConfig().ELFBuildID || store.state.ABI != reconcile.BPFABIVersion {
		t.Fatalf("ownership was not refreshed safely: remover=%d state=%+v", remover.calls, store.state)
	}
}
