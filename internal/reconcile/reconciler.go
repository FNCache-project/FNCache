package reconcile

import (
	"context"
	"fmt"
	"sync"
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
	State() AgentState
}

type Coordinator struct {
	backend ReconcileBackend
	gate    chan struct{}

	stateMu sync.RWMutex
	state   AgentState
}

func NewCoordinator(backend ReconcileBackend) (*Coordinator, error) {
	if backend == nil {
		return nil, fmt.Errorf("reconcile backend is required")
	}
	return &Coordinator{backend: backend, gate: make(chan struct{}, 1), state: AgentBootstrapping}, nil
}

func (c *Coordinator) State() AgentState {
	c.stateMu.RLock()
	defer c.stateMu.RUnlock()
	return c.state
}

// MarkDegraded records that the published datapath lease is no longer
// healthy, without running another reconciliation pass.
func (c *Coordinator) MarkDegraded() {
	c.setState(AgentDegraded)
}

// MarkStopping records an orderly shutdown after the datapath has been
// disabled.
func (c *Coordinator) MarkStopping() {
	c.setState(AgentStopping)
}

func (c *Coordinator) FullReconcile(ctx context.Context) (ReconcileResult, error) {
	result := ReconcileResult{State: c.State()}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	select {
	case c.gate <- struct{}{}:
		defer func() { <-c.gate }()
	case <-ctx.Done():
		return result, ctx.Err()
	}

	c.setState(AgentReconciling)
	result.State = AgentReconciling
	if err := c.runStage(ctx, &result, "disable", func() error { return c.backend.Disable(ctx) }); err != nil {
		return c.fail(result, err)
	}
	desired, err := c.discover(ctx, &result)
	if err != nil {
		return c.fail(result, err)
	}
	actual, err := c.scan(ctx, &result)
	if err != nil {
		return c.fail(result, err)
	}
	changed, err := c.ensure(ctx, &result, desired, actual)
	if err != nil {
		return c.fail(result, err)
	}
	if err := c.runStage(ctx, &result, "verify", func() error {
		return c.backend.Verify(ctx, desired, actual)
	}); err != nil {
		return c.fail(result, err)
	}
	if err := c.runStage(ctx, &result, "commit", func() error {
		return c.backend.Commit(ctx, desired, actual)
	}); err != nil {
		return c.fail(result, err)
	}
	if err := c.runStage(ctx, &result, "publish", func() error {
		return c.backend.Publish(ctx, desired)
	}); err != nil {
		return c.fail(result, err)
	}

	result.Generation = desired.Generation
	result.Changed = changed
	c.setState(AgentReady)
	result.State = AgentReady
	return result, nil
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

func (c *Coordinator) fail(result ReconcileResult, err error) (ReconcileResult, error) {
	c.setState(AgentDisabled)
	result.State = AgentDisabled
	return result, err
}

func (c *Coordinator) setState(state AgentState) {
	c.stateMu.Lock()
	c.state = state
	c.stateMu.Unlock()
}
