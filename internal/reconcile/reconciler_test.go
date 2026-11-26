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
	backend := &fakeBackend{desired: DesiredState{Generation: 42, Enabled: true}, changed: true}
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

func TestCoordinatorEmitsCorrelationEvents(t *testing.T) {
	backend := &fakeBackend{desired: DesiredState{Generation: 42, Enabled: true}}
	var events []ReconcileEvent
	coordinator, err := NewCoordinator(backend, func(_ context.Context, event ReconcileEvent) {
		events = append(events, event)
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.FullReconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	var started, completed, transitioned bool
	for _, event := range events {
		switch event.Message {
		case "reconcile started":
			started = event.Attempt == 1 && event.Reason == "RECONCILE_STARTED"
		case "reconcile completed":
			completed = event.Generation == 42 && event.Duration > 0 && event.Reason == "RECONCILE_SUCCEEDED"
		case "agent state transition":
			if event.From == AgentBootstrapping && event.To == AgentReconciling {
				transitioned = true
			}
		}
	}
	if !started || !completed || !transitioned {
		t.Fatalf("missing correlation events: %+v", events)
	}
}

func TestCoordinatorTreatsDisabledDesiredStateAsSafeTerminalState(t *testing.T) {
	backend := &fakeBackend{desired: DesiredState{Generation: 43}}
	coordinator, err := NewCoordinator(backend)
	if err != nil {
		t.Fatal(err)
	}
	result, err := coordinator.FullReconcile(context.Background())
	if err != nil || result.State != AgentDisabled || coordinator.State() != AgentDisabled || result.Generation != 43 || result.Changed {
		t.Fatalf("unexpected disabled reconcile result: result=%+v err=%v state=%s", result, err, coordinator.State())
	}
	want := []string{"disable", "discover"}
	if !reflect.DeepEqual(backend.steps, want) {
		t.Fatalf("unsafe stages ran for disabled desired state: got=%v want=%v", backend.steps, want)
	}
}

func TestCoordinatorFailureDisablesAndDoesNotPublish(t *testing.T) {
	backend := &fakeBackend{desired: DesiredState{Generation: 42, Enabled: true}, failStep: "verify"}
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
	backend := &fakeBackend{desired: DesiredState{Generation: 1, Enabled: true}, entered: make(chan string, 2), proceed: make(chan struct{})}
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

type cancelOnSecondErrContext struct {
	context.Context
	errCalls int
}

func (c *cancelOnSecondErrContext) Err() error {
	c.errCalls++
	if c.errCalls >= 2 {
		return context.Canceled
	}
	return c.Context.Err()
}

func TestCoordinatorReportsDegradedWhenDisableIsSkipped(t *testing.T) {
	backend := &fakeBackend{}
	coordinator, _ := NewCoordinator(backend)
	result, err := coordinator.FullReconcile(&cancelOnSecondErrContext{Context: context.Background()})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(backend.steps) != 0 {
		t.Fatalf("Disable was unexpectedly called: %v", backend.steps)
	}
	if len(result.Actions) != 1 || result.Actions[0].Name != "disable" || result.Actions[0].Completed {
		t.Fatalf("unexpected disable action: %+v", result.Actions)
	}
	if result.State != AgentDegraded || coordinator.State() != AgentDegraded {
		t.Fatalf("skipped Disable did not report Degraded: result=%+v state=%s", result, coordinator.State())
	}
}

func TestCoordinatorStopsAfterEveryFailedStage(t *testing.T) {
	stages := []string{"disable", "discover", "scan", "ensure", "verify", "commit", "publish"}
	for _, failedStage := range stages {
		t.Run(failedStage, func(t *testing.T) {
			backend := &fakeBackend{desired: DesiredState{Generation: 42, Enabled: true}, failStep: failedStage}
			coordinator, err := NewCoordinator(backend)
			if err != nil {
				t.Fatal(err)
			}
			result, err := coordinator.FullReconcile(context.Background())
			wantState := AgentDisabled
			if failedStage == "disable" {
				wantState = AgentDegraded
			}
			if err == nil || result.State != wantState || coordinator.State() != wantState {
				t.Fatalf("failed reconcile state mismatch: result=%+v err=%v state=%s want=%s", result, err, coordinator.State(), wantState)
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
	backend := &fakeBackend{desired: DesiredState{Generation: 42, Enabled: true}, failStep: "verify"}
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
