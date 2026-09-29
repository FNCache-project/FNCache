package reconcile

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
)

type fakeBackend struct {
	mu       sync.Mutex
	steps    []string
	desired  DesiredState
	changed  bool
	failStep string
	entered  chan string
	proceed  chan struct{}
}

func (f *fakeBackend) step(name string) error {
	f.mu.Lock()
	f.steps = append(f.steps, name)
	f.mu.Unlock()
	if f.entered != nil && name == "disable" {
		f.entered <- name
	}
	if f.proceed != nil && name == "disable" {
		<-f.proceed
	}
	if f.failStep == name {
		return errors.New(name + " failed")
	}
	return nil
}
func (f *fakeBackend) Disable(context.Context) error { return f.step("disable") }
func (f *fakeBackend) Discover(context.Context) (DesiredState, error) {
	return f.desired, f.step("discover")
}
func (f *fakeBackend) Scan(context.Context) (ActualState, error) {
	return ActualState{}, f.step("scan")
}
func (f *fakeBackend) Ensure(context.Context, DesiredState, ActualState) (bool, error) {
	return f.changed, f.step("ensure")
}
func (f *fakeBackend) Verify(context.Context, DesiredState, ActualState) error {
	return f.step("verify")
}
func (f *fakeBackend) Commit(context.Context, DesiredState, ActualState) error {
	return f.step("commit")
}
func (f *fakeBackend) Publish(context.Context, DesiredState) error { return f.step("publish") }

func TestCoordinatorFullReconcilePublishesVerifiedState(t *testing.T) {
	backend := &fakeBackend{desired: DesiredState{Generation: 42}, changed: true}
	coordinator, err := NewCoordinator(backend)
	if err != nil {
		t.Fatal(err)
	}
	result, err := coordinator.FullReconcile(context.Background())
	if err != nil || result.State != AgentReady || result.Generation != 42 || !result.Changed {
		t.Fatalf("unexpected reconcile result: result=%+v err=%v", result, err)
	}
	want := []string{"disable", "discover", "scan", "ensure", "verify", "commit", "publish"}
	if !reflect.DeepEqual(backend.steps, want) {
		t.Fatalf("unexpected stage order: got=%v want=%v", backend.steps, want)
	}
}

func TestCoordinatorFailureDisablesAndDoesNotPublish(t *testing.T) {
	backend := &fakeBackend{desired: DesiredState{Generation: 42}, failStep: "verify"}
	coordinator, _ := NewCoordinator(backend)
	result, err := coordinator.FullReconcile(context.Background())
	if err == nil || result.State != AgentDisabled || coordinator.State() != AgentDisabled {
		t.Fatalf("expected disabled failure: result=%+v err=%v state=%s", result, err, coordinator.State())
	}
	for _, step := range backend.steps {
		if step == "commit" || step == "publish" {
			t.Fatalf("unsafe stage ran after verification failure: %v", backend.steps)
		}
	}
}

func TestCoordinatorSerializesFullReconcile(t *testing.T) {
	backend := &fakeBackend{desired: DesiredState{Generation: 1}, entered: make(chan string, 2), proceed: make(chan struct{})}
	coordinator, _ := NewCoordinator(backend)
	firstDone := make(chan error, 1)
	go func() { _, err := coordinator.FullReconcile(context.Background()); firstDone <- err }()
	if stage := <-backend.entered; stage != "disable" {
		t.Fatalf("first reconcile entered %q", stage)
	}
	secondDone := make(chan error, 1)
	go func() { _, err := coordinator.FullReconcile(context.Background()); secondDone <- err }()
	select {
	case err := <-secondDone:
		t.Fatalf("second reconcile ran before first completed: %v", err)
	default:
	}
	close(backend.proceed)
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
	if err := <-secondDone; err != nil {
		t.Fatal(err)
	}
}

func TestCoordinatorHonorsCancellationBeforeStart(t *testing.T) {
	backend := &fakeBackend{}
	coordinator, _ := NewCoordinator(backend)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := coordinator.FullReconcile(ctx)
	if !errors.Is(err, context.Canceled) || result.State != AgentBootstrapping || len(backend.steps) != 0 {
		t.Fatalf("unexpected cancellation result: result=%+v err=%v steps=%v", result, err, backend.steps)
	}
}

func TestCoordinatorStopsAfterEveryFailedStage(t *testing.T) {
	stages := []string{"disable", "discover", "scan", "ensure", "verify", "commit", "publish"}
	for _, failedStage := range stages {
		t.Run(failedStage, func(t *testing.T) {
			backend := &fakeBackend{desired: DesiredState{Generation: 42}, failStep: failedStage}
			coordinator, err := NewCoordinator(backend)
			if err != nil {
				t.Fatal(err)
			}
			result, err := coordinator.FullReconcile(context.Background())
			if err == nil || result.State != AgentDisabled || coordinator.State() != AgentDisabled {
				t.Fatalf("failed reconcile was not disabled: result=%+v err=%v", result, err)
			}
			for i, stage := range backend.steps {
				if stage == failedStage {
					if len(backend.steps) != i+1 {
						t.Fatalf("stages ran after %s failure: %v", failedStage, backend.steps)
					}
					return
				}
			}
			t.Fatalf("failed stage was not called: stage=%s calls=%v", failedStage, backend.steps)
		})
	}
}

func TestCoordinatorRecoversAfterFailedReconcile(t *testing.T) {
	backend := &fakeBackend{desired: DesiredState{Generation: 42}, failStep: "verify"}
	coordinator, _ := NewCoordinator(backend)
	if _, err := coordinator.FullReconcile(context.Background()); err == nil {
		t.Fatal("expected first reconcile to fail")
	}
	backend.failStep = ""
	backend.steps = nil
	result, err := coordinator.FullReconcile(context.Background())
	if err != nil || result.State != AgentReady || coordinator.State() != AgentReady {
		t.Fatalf("coordinator did not recover: result=%+v err=%v", result, err)
	}
}

func TestCoordinatorTracksLeaseHealthAndShutdown(t *testing.T) {
	coordinator, err := NewCoordinator(&fakeBackend{})
	if err != nil {
		t.Fatal(err)
	}
	coordinator.MarkDegraded()
	if coordinator.State() != AgentDegraded {
		t.Fatalf("coordinator did not enter degraded state: %s", coordinator.State())
	}
	coordinator.MarkStopping()
	if coordinator.State() != AgentStopping {
		t.Fatalf("coordinator did not enter stopping state: %s", coordinator.State())
	}
}
