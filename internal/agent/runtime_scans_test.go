package agent

import (
	"context"
	"errors"
	"testing"

	"github.com/cat-cc-Lcos/FNCache/internal/discovery"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

func TestRuntimeScanAdapterClassifiesLightFailure(t *testing.T) {
	want := errors.New("API stale")
	adapter, err := NewRuntimeScanAdapter(&DynamicObserver{}, func(context.Context) error { return want })
	if err != nil {
		t.Fatal(err)
	}
	result := adapter.Light(context.Background())
	if !errors.Is(result.Err, want) || !result.Critical || !result.InvalidateEpoch || result.Reason != "SCAN_FAILED" || result.DatapathObserved {
		t.Fatalf("unexpected light result: %+v", result)
	}
}

func TestClassifyScanDetectsCriticalActualState(t *testing.T) {
	actual := reconcile.ActualState{Control: reconcile.ControlState{Verified: true, Enabled: true}, Programs: map[string]reconcile.ProgramState{"tc_masq": {ID: 1}}, Maps: make(map[string]reconcile.MapState)}
	result := classifyScan(ScanFull, actual, nil)
	if !result.Critical || !result.InvalidateEpoch || result.Reason != "DATAPATH_STATE_INCOMPLETE" || !result.DatapathObserved || !result.DatapathReady {
		t.Fatalf("unexpected incomplete-state result: %+v", result)
	}
}

func TestClassifyScanDetectsConflictsAndSuccess(t *testing.T) {
	conflict := classifyScan(ScanIncremental, reconcile.ActualState{Conflicts: []discovery.Conflict{{Kind: "tc-filter"}}}, nil)
	if !conflict.Critical || conflict.Reason != "SCAN_CONFLICT" || !conflict.DatapathObserved || conflict.DatapathReady {
		t.Fatalf("unexpected conflict result: %+v", conflict)
	}
	success := classifyScan(ScanIncremental, reconcile.ActualState{}, nil)
	if success.Critical || success.InvalidateEpoch || success.Reason != "SCAN_OK" || !success.DatapathObserved || success.DatapathReady {
		t.Fatalf("unexpected success result: %+v", success)
	}
}
