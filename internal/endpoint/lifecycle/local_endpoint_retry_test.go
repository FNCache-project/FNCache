package lifecycle

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cat-cc-Lcos/FNCache/internal/endpoint"
	"github.com/cat-cc-Lcos/FNCache/internal/hostnet/discovery"
	"github.com/cat-cc-Lcos/FNCache/internal/kubernetes"
	"github.com/cat-cc-Lcos/FNCache/internal/kubernetes/queue"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

type sequenceEndpointResolver struct {
	mu       sync.Mutex
	errors   []error
	endpoint endpoint.Endpoint
	calls    int
}

func (r *sequenceEndpointResolver) Resolve(context.Context, endpoint.PodSnapshot) (endpoint.Endpoint, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	if len(r.errors) != 0 {
		err := r.errors[0]
		r.errors = r.errors[1:]
		return endpoint.Endpoint{}, err
	}
	return r.endpoint, nil
}
func (r *sequenceEndpointResolver) Validate(context.Context, endpoint.Endpoint) error { return nil }

func (r *sequenceEndpointResolver) Calls() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

type retryPublisher struct {
	calls  int32
	done   chan struct{}
	events *[]string
}

func (p *retryPublisher) CommitAndPublish(context.Context, reconcile.DesiredState, reconcile.ActualState) error {
	if p.events != nil {
		*p.events = append(*p.events, "publish")
	}
	if atomic.AddInt32(&p.calls, 1) == 1 {
		close(p.done)
	}
	return nil
}

func retryHandlerStore(t *testing.T, pod endpoint.PodSnapshot) *kubernetes.SnapshotStore {
	t.Helper()
	store := kubernetes.NewSnapshotStore()
	if err := store.UpsertNode(kubernetes.NodeSnapshot{Identity: endpoint.NodeIdentity{Name: "node-a", UID: "node-1"}}); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertPod(pod); err != nil {
		t.Fatal(err)
	}
	return store
}

func TestLocalEndpointHandlerPendingPodReturnsRetryable(t *testing.T) {
	pod := handlerPod()
	pod.Phase, pod.PodIPv4 = "Pending", netip.Addr{}
	events := []string{}
	control := &localHandlerControl{events: &events}
	scanner := &localHandlerScanner{events: &events}
	publisher := &localHandlerPublisher{events: &events}
	handler, err := NewLocalEndpointHandler(LocalEndpointHandlerConfig{
		Store: retryHandlerStore(t, pod), Resolver: &sequenceEndpointResolver{errors: []error{endpoint.ErrEndpointNotReady}, endpoint: handlerEndpoint("pod-1")}, LocalNode: "node-a",
		Desired: &localHandlerDesired{desired: reconcile.DesiredState{Enabled: true, Capability: discovery.CapabilityReport{Supported: true}}, events: &events},
		Scanner: scanner, Control: control, Endpoint: &localHandlerEndpoint{events: &events}, Maps: &localHandlerMaps{events: &events}, Remover: localHandlerRemover{}, Ownership: &localHandlerOwnership{}, Publisher: publisher, Generation: testLocalGeneration(control, scanner, publisher),
	})
	if err != nil {
		t.Fatal(err)
	}
	err = handler.Handle(context.Background(), reconcile.ReconcileKey{Kind: reconcile.ReconcileLocalEndpoint, UID: pod.Identity.UID})
	var classified *reconcile.ClassifiedError
	if !errors.As(err, &classified) || classified.Class() != reconcile.ErrorRetryable || len(events) != 0 {
		t.Fatalf("pending result: err=%v events=%v", err, events)
	}
}

func TestLocalEndpointHandlerRetriesSandboxUntilReady(t *testing.T) {
	pod := handlerPod()
	events := []string{}
	resolver := &sequenceEndpointResolver{errors: []error{endpoint.ErrEndpointNotReady, endpoint.ErrEndpointNotReady}, endpoint: handlerEndpoint("pod-1")}
	publisher := &retryPublisher{done: make(chan struct{}), events: &events}
	control := &localHandlerControl{events: &events}
	scanner := &localHandlerScanner{events: &events}
	handler, err := NewLocalEndpointHandler(LocalEndpointHandlerConfig{
		Store: retryHandlerStore(t, pod), Resolver: resolver, LocalNode: "node-a",
		Desired: &localHandlerDesired{desired: reconcile.DesiredState{Enabled: true, Capability: discovery.CapabilityReport{Supported: true}}, events: &events},
		Scanner: scanner, Control: control, Endpoint: &localHandlerEndpoint{events: &events}, Maps: &localHandlerMaps{events: &events}, Remover: localHandlerRemover{}, Ownership: &localHandlerOwnership{}, Publisher: publisher, Generation: testLocalGeneration(control, scanner, publisher),
	})
	if err != nil {
		t.Fatal(err)
	}
	work, err := queue.New(queue.Config{BaseDelay: time.Millisecond, MaxDelay: 5 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	worker, err := queue.NewWorker(work, handler.Handle)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	workerDone := make(chan struct{})
	go func() { worker.Run(ctx); close(workerDone) }()
	work.Add(reconcile.ReconcileKey{Kind: reconcile.ReconcileLocalEndpoint, UID: pod.Identity.UID})
	select {
	case <-publisher.done:
	case <-time.After(time.Second):
		t.Fatal("sandbox retry did not reach successful publish")
	}
	if resolver.Calls() < 3 || len(events) == 0 || events[len(events)-1] != "publish" {
		t.Fatalf("retry calls=%d events=%v", resolver.Calls(), events)
	}
	work.ShutDown()
	select {
	case <-workerDone:
	case <-time.After(time.Second):
		t.Fatal("worker did not stop")
	}
}
