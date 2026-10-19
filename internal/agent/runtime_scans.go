package agent

import (
	"context"
	"errors"

	"github.com/cat-cc-Lcos/FNCache/internal/controlplane"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

type RuntimeScanAdapter struct {
	observer *DynamicObserver
	verify   func(reconcile.DesiredState, reconcile.ActualState) error
	light    []func(context.Context) error
}

func NewRuntimeScanAdapter(observer *DynamicObserver, light ...func(context.Context) error) (*RuntimeScanAdapter, error) {
	return NewRuntimeScanAdapterWithVerifier(observer, controlplane.VerifyState, light...)
}

func NewRuntimeScanAdapterWithVerifier(observer *DynamicObserver, verify func(reconcile.DesiredState, reconcile.ActualState) error, light ...func(context.Context) error) (*RuntimeScanAdapter, error) {
	if observer == nil {
		return nil, errors.New("dynamic observer is required")
	}
	if verify == nil {
		return nil, errors.New("runtime state verifier is required")
	}
	return &RuntimeScanAdapter{observer: observer, verify: verify, light: append([]func(context.Context) error(nil), light...)}, nil
}

func (s *RuntimeScanAdapter) Light(ctx context.Context) ScanResult {
	for _, check := range s.light {
		if err := check(ctx); err != nil {
			return failedScan(ScanLight, err)
		}
	}
	return ScanResult{Level: ScanLight, Reason: "SCAN_LIGHT_OK"}
}

func (s *RuntimeScanAdapter) Incremental(ctx context.Context) ScanResult {
	actual, err := s.observer.IncrementalScan(ctx)
	return s.classifyRuntimeScan(ctx, ScanIncremental, actual, err)
}

func (s *RuntimeScanAdapter) Full(ctx context.Context) ScanResult {
	actual, err := s.observer.Scan(ctx)
	return s.classifyRuntimeScan(ctx, ScanFull, actual, err)
}

func (s *RuntimeScanAdapter) classifyRuntimeScan(ctx context.Context, level ScanLevel, actual reconcile.ActualState, err error) ScanResult {
	result := classifyScan(level, actual, err)
	if result.Critical || err != nil || !actual.Control.Verified {
		return result
	}
	desired, err := s.observer.Desired(ctx)
	if err != nil {
		return failedScan(level, err)
	}
	verification := actual
	verification.Control.Enabled = false
	if err := s.verify(desired, verification); err != nil {
		return ScanResult{
			Level: level, DatapathObserved: true,
			DatapathReady:      actual.Control.Verified && actual.Control.Enabled,
			DatapathGeneration: actual.Control.Generation,
			Critical:           true, InvalidateEpoch: true, Reason: "DATAPATH_STATE_INCOMPLETE", Err: err,
		}
	}
	return result
}

func failedScan(level ScanLevel, err error) ScanResult {
	return ScanResult{Level: level, Critical: true, InvalidateEpoch: true, Reason: "SCAN_FAILED", Err: err}
}

func classifyScan(level ScanLevel, actual reconcile.ActualState, err error) ScanResult {
	if err != nil {
		return failedScan(level, err)
	}
	result := ScanResult{
		Level: level, Reason: "SCAN_OK", DatapathObserved: true,
		DatapathReady:      actual.Control.Verified && actual.Control.Enabled,
		DatapathGeneration: actual.Control.Generation,
	}
	if len(actual.Conflicts) != 0 {
		result.Critical = true
		result.InvalidateEpoch = true
		result.Reason = "SCAN_CONFLICT"
		return result
	}
	if actual.Control.Verified && actual.Control.Enabled && (len(actual.Programs) < 4 || len(actual.Maps) < 8 || !actual.FlannelRule.Present) {
		result.Critical = true
		result.InvalidateEpoch = true
		result.Reason = "DATAPATH_STATE_INCOMPLETE"
	}
	return result
}
