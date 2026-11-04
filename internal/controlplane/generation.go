package controlplane

import (
	"context"
	"errors"
	"fmt"

	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

var ErrStaleGeneration = errors.New("stale generation")

type GenerationScanner interface {
	Scan(context.Context) (reconcile.ActualState, error)
}

type GenerationMutator func(context.Context, reconcile.DesiredState, reconcile.ActualState) error

// GenerationPublishGate validates a generation and invokes publish while the
// caller's publication-safety boundary is held.
type GenerationPublishGate func(context.Context, reconcile.DesiredState, reconcile.ActualState, func() error) error

type GenerationTransaction struct {
	control fastPathDisabler
	scanner GenerationScanner
	publish *Publisher
}

func NewGenerationTransaction(control fastPathDisabler, scanner GenerationScanner, publisher *Publisher) (*GenerationTransaction, error) {
	if control == nil || scanner == nil || publisher == nil {
		return nil, fmt.Errorf("generation transaction dependencies are required")
	}
	return &GenerationTransaction{control: control, scanner: scanner, publish: publisher}, nil
}

// Execute disables the fast path, mutates and verifies the generation, then
// publishes it through the optional publication gate.
func (t *GenerationTransaction) Execute(ctx context.Context, desired reconcile.DesiredState, mutate GenerationMutator, gates ...GenerationPublishGate) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !desired.Enabled || desired.Generation == 0 {
		return fmt.Errorf("generation transaction requires an enabled non-zero generation")
	}
	if mutate == nil {
		return fmt.Errorf("generation mutator is required")
	}
	if err := t.control.Disable(ctx); err != nil {
		return fmt.Errorf("disable fast path: %w", err)
	}
	if err := validateEndpointScanCompleteness(desired); err != nil {
		return err
	}
	before, err := t.scanner.Scan(ctx)
	if err != nil {
		return fmt.Errorf("scan before generation mutation: %w", err)
	}
	if err := validateActualEndpointScanCompleteness(before); err != nil {
		return err
	}
	if desired.Generation < before.Control.Generation {
		return fmt.Errorf("%w: got %d want at least %d", ErrStaleGeneration, desired.Generation, before.Control.Generation)
	}
	if err := mutate(ctx, desired, before); err != nil {
		return fmt.Errorf("mutate generation %d: %w", desired.Generation, err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	after, err := t.scanner.Scan(ctx)
	if err != nil {
		return fmt.Errorf("scan after generation mutation: %w", err)
	}
	if err := t.publish.VerifyState(desired, after); err != nil {
		return fmt.Errorf("verify generation %d: %w", desired.Generation, err)
	}
	publish := func() error { return t.publish.CommitAndPublish(ctx, desired, after) }
	if len(gates) > 1 {
		return fmt.Errorf("generation transaction accepts at most one publication gate")
	}
	if len(gates) == 1 && gates[0] != nil {
		if err := gates[0](ctx, desired, after, publish); err != nil {
			return fmt.Errorf("publish generation %d: %w", desired.Generation, err)
		}
		return nil
	}
	if err := publish(); err != nil {
		return fmt.Errorf("publish generation %d: %w", desired.Generation, err)
	}
	return nil
}
