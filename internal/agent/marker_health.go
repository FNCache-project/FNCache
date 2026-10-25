package agent

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cat-cc-Lcos/FNCache/internal/controlplane"
	"github.com/cat-cc-Lcos/FNCache/internal/hostnet/flannel"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

var (
	ErrMarkerUnhealthy = errors.New("MARKER_UNHEALTHY")
	ErrMarkerDrift     = errors.New("MARKER_RULE_DRIFT")
)

type MarkerHealthMonitorConfig struct {
	Source              controlplane.RuleSource
	Pins                controlplane.PinSource
	Spec                flannel.MarkerRuleSpec
	ExpectedFingerprint string
	Interval            time.Duration
}

type MarkerHealthMonitor struct {
	source              controlplane.RuleSource
	pins                controlplane.PinSource
	spec                flannel.MarkerRuleSpec
	expectedFingerprint string
	interval            time.Duration
}

func NewMarkerHealthMonitor(config MarkerHealthMonitorConfig) (*MarkerHealthMonitor, error) {
	if config.Source == nil || config.Pins == nil || config.Spec.Chain == "" || config.Spec.Comment == "" || config.ExpectedFingerprint == "" || config.Interval <= 0 {
		return nil, fmt.Errorf("marker health monitor dependencies are required")
	}
	return &MarkerHealthMonitor{source: config.Source, pins: config.Pins, spec: config.Spec, expectedFingerprint: config.ExpectedFingerprint, interval: config.Interval}, nil
}

func (m *MarkerHealthMonitor) Check(ctx context.Context) error {
	state, err := m.source.Scan(ctx, m.spec)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrMarkerUnhealthy, err)
	}
	if !state.Present || !state.JumpsPresent {
		actual, err := m.pins.Scan(ctx)
		if err != nil {
			return fmt.Errorf("%w: inspect control state: %v", ErrMarkerUnhealthy, err)
		}
		if !actual.Control.Enabled {
			return nil
		}
		return fmt.Errorf("%w: marker rule or jump is missing", ErrMarkerDrift)
	}
	return m.verifyState(state)
}

func (m *MarkerHealthMonitor) CheckForPublish(ctx context.Context) error {
	state, err := m.source.Scan(ctx, m.spec)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrMarkerUnhealthy, err)
	}
	if !state.Present || !state.JumpsPresent {
		return fmt.Errorf("%w: marker rule or jump is missing", ErrMarkerDrift)
	}
	return m.verifyState(state)
}

func (m *MarkerHealthMonitor) verifyState(state reconcile.RuleState) error {
	identity := m.spec.Chain + "/" + m.spec.Comment
	if state.Identity != identity || state.Fingerprint != m.expectedFingerprint {
		return fmt.Errorf("%w: marker identity or fingerprint changed", ErrMarkerDrift)
	}
	return nil
}

func (m *MarkerHealthMonitor) Run(ctx context.Context) error {
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := m.Check(ctx); err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return err
			}
		}
	}
}
