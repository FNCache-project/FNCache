package reconcile

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// ReconcileBackend keeps orchestration independent from kernel and runtime APIs.
type ReconcileBackend interface {
	Disable(context.Context) error
	Discover(context.Context) (DesiredState, error)
	Scan(context.Context) (ActualState, error)
	Ensure(context.Context, DesiredState, ActualState) (bool, error)
	Verify(context.Context, DesiredState, ActualState) error
	Commit(context.Context, DesiredState, ActualState) error
	Publish(context.Context, DesiredState) error
}

type Reconciler interface {
	FullReconcile(context.Context) (ReconcileResult, error)
	Stop(context.Context) error
	State() AgentState
}

// ReconcileEvent is the dependency-neutral event emitted by a Coordinator.
// The reconcile package deliberately does not depend on observability so that
// callers can adapt these events to their chosen logging implementation.
type ReconcileEvent struct {
	Message    string
	Kind       ReconcileKind
	From       AgentState
	To         AgentState
	Generation uint64
	Reason     string
	Class      string
	Attempt    int
	Duration   time.Duration
	Err        error
}

type EventHandler func(context.Context, ReconcileEvent)

type Coordinator struct {
	backend      ReconcileBackend
	gate         chan struct{}
	lifecycle    *AgentStateMachine
	eventHandler EventHandler
	attempt      int
	generation   uint64
}

func NewCoordinator(backend ReconcileBackend, handlers ...EventHandler) (*Coordinator, error) {
	if backend == nil {
		return nil, fmt.Errorf("reconcile backend is required")
	}
	var handler EventHandler
	if len(handlers) > 0 {
		handler = handlers[0]
	}
	return &Coordinator{backend: backend, gate: make(chan struct{}, 1), lifecycle: NewAgentStateMachine(), eventHandler: handler}, nil
}

func (c *Coordinator) State() AgentState {
	return c.lifecycle.State()
}

func (c *Coordinator) FullReconcile(ctx context.Context) (result ReconcileResult, err error) {
	result = ReconcileResult{State: c.State()}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	select {
	case c.gate <- struct{}{}:
		defer func() { <-c.gate }()
	case <-ctx.Done():
		return result, ctx.Err()
	}
	c.attempt++
	attempt := c.attempt
	started := time.Now()
	c.emit(ctx, ReconcileEvent{Message: "reconcile started", Kind: ReconcileGlobal, Reason: "RECONCILE_STARTED", Class: "Started", Attempt: attempt})
	generation := uint64(0)
	defer func() {
		event := ReconcileEvent{Kind: ReconcileGlobal, Generation: generation, Attempt: attempt, Duration: time.Since(started)}
		if err == nil {
			event.Message = "reconcile completed"
			event.Reason = "RECONCILE_SUCCEEDED"
			event.Class = "Success"
		} else {
			event.Message = "reconcile failed"
			event.Class, event.Reason = classifyReconcileError(err)
			event.Err = err
		}
		c.emit(ctx, event)
	}()

	if err := c.transitionTo(AgentReconciling); err != nil {
		result.State = c.State()
		return result, err
	}
	result.State = AgentReconciling
	if err := c.runStage(ctx, &result, "disable", func() error { return c.backend.Disable(ctx) }); err != nil {
		return c.fail(result, err, false)
	}
	desired, err := c.discover(ctx, &result)
	generation = desired.Generation
	c.generation = desired.Generation
	if err != nil {
		return c.fail(result, err, true)
	}
	if !desired.Enabled {
		result.Generation = desired.Generation
		if err := c.transitionTo(AgentDisabled); err != nil {
			result.State = c.State()
			return result, err
		}
		result.State = AgentDisabled
		return result, nil
	}
	actual, err := c.scan(ctx, &result)
	if err != nil {
		return c.fail(result, err, true)
	}
	changed, err := c.ensure(ctx, &result, desired, actual)
	if err != nil {
		return c.fail(result, err, true)
	}
	if err := c.runStage(ctx, &result, "verify", func() error {
		return c.backend.Verify(ctx, desired, actual)
	}); err != nil {
		return c.fail(result, err, true)
	}
	if err := c.runStage(ctx, &result, "commit", func() error {
		return c.backend.Commit(ctx, desired, actual)
	}); err != nil {
		return c.fail(result, err, true)
	}
	if err := c.runStage(ctx, &result, "publish", func() error {
		return c.backend.Publish(ctx, desired)
	}); err != nil {
		return c.fail(result, err, true)
	}

	result.Generation = desired.Generation
	result.Changed = changed
	if err := c.transitionTo(AgentReady); err != nil {
		result.State = c.State()
		return result, err
	}
	result.State = AgentReady
	return result, nil
}

// Stop serializes shutdown with an in-flight reconciliation and moves a
// healthy or degraded agent into the terminal Stopping state.
func (c *Coordinator) Stop(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("stop context is required")
	}
	select {
	case c.gate <- struct{}{}:
		defer func() { <-c.gate }()
	case <-ctx.Done():
		return ctx.Err()
	}

	if c.State() == AgentStopping {
		return nil
	}
	return c.transitionTo(AgentStopping)
}

func (c *Coordinator) discover(ctx context.Context, result *ReconcileResult) (DesiredState, error) {
	var desired DesiredState
	err := c.runStage(ctx, result, "discover", func() error {
		var err error
		desired, err = c.backend.Discover(ctx)
		return err
	})
	return desired, err
}

func (c *Coordinator) scan(ctx context.Context, result *ReconcileResult) (ActualState, error) {
	var actual ActualState
	err := c.runStage(ctx, result, "scan", func() error {
		var err error
		actual, err = c.backend.Scan(ctx)
		return err
	})
	return actual, err
}

func (c *Coordinator) ensure(ctx context.Context, result *ReconcileResult, desired DesiredState, actual ActualState) (bool, error) {
	var changed bool
	err := c.runStage(ctx, result, "ensure", func() error {
		var err error
		changed, err = c.backend.Ensure(ctx, desired, actual)
		return err
	})
	return changed, err
}

func (c *Coordinator) runStage(ctx context.Context, result *ReconcileResult, name string, fn func() error) error {
	if err := ctx.Err(); err != nil {
		result.Actions = append(result.Actions, ActionResult{Name: name})
		return err
	}
	err := fn()
	result.Actions = append(result.Actions, ActionResult{Name: name, Completed: err == nil})
	return err
}

func (c *Coordinator) fail(result ReconcileResult, err error, disableConfirmed bool) (ReconcileResult, error) {
	state := AgentDegraded
	if disableConfirmed {
		state = AgentDisabled
	}
	if transitionErr := c.transitionTo(state); transitionErr != nil {
		result.State = c.State()
		return result, errors.Join(err, transitionErr)
	}
	result.State = state
	return result, err
}

func (c *Coordinator) transitionTo(state AgentState) error {
	from := c.lifecycle.State()
	if err := c.lifecycle.Transition(state); err != nil {
		return err
	}
	if from != state {
		c.emit(context.Background(), ReconcileEvent{
			Message: "agent state transition", Kind: ReconcileGlobal,
			To: state, From: from, Generation: c.generation,
			Reason: "STATE_TRANSITION", Class: "State",
		})
	}
	return nil
}

func (c *Coordinator) emit(ctx context.Context, event ReconcileEvent) {
	if c.eventHandler != nil {
		c.eventHandler(ctx, event)
	}
}

func classifyReconcileError(err error) (class, reason string) {
	class = string(ErrorInternal)
	reason = "RECONCILE_ERROR"
	var classified *ClassifiedError
	if errors.As(err, &classified) {
		class = string(classified.Class())
		if classified.ReasonCode() != "" {
			reason = classified.ReasonCode()
		}
	}
	return class, reason
}
