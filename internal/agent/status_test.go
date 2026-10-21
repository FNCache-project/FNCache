package agent

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"k8s.io/client-go/kubernetes/fake"

	"github.com/cat-cc-Lcos/FNCache/internal/observability"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

func TestStatusPublishesCachedHealthAndDatapathState(t *testing.T) {
	runtime := &DynamicRuntime{
		config:      dynamicTestConfig(),
		snapshots:   observability.NewSnapshotStore(),
		lifecycle:   reconcile.NewAgentStateMachine(),
		healthEpoch: NewHealthEpoch(),
	}
	if err := runtime.lifecycle.Transition(reconcile.AgentReconciling); err != nil {
		t.Fatal(err)
	}
	if err := runtime.lifecycle.Transition(reconcile.AgentReady); err != nil {
		t.Fatal(err)
	}
	runtime.recordScanStatus(ScanResult{
		Level:              ScanFull,
		DatapathObserved:   true,
		DatapathReady:      true,
		DatapathGeneration: 42,
	})

	got := runtime.Status(context.Background())
	if got.Generation != 42 || !got.DatapathEnabled || !got.Condition(observability.DatapathReady) {
		t.Fatalf("status = %+v", got)
	}
	if got.Ready {
		t.Fatal("status became ready without a synchronized Kubernetes health observation")
	}
	stored := runtime.snapshots.Snapshot()
	if !reflect.DeepEqual(got, stored) {
		t.Fatalf("published snapshot differs from Status result: got=%+v stored=%+v", got, stored)
	}
}

func TestStatusClearsStaleDatapathMetadataAfterObservedDisabled(t *testing.T) {
	runtime := &DynamicRuntime{
		config:      dynamicTestConfig(),
		snapshots:   observability.NewSnapshotStore(),
		lifecycle:   reconcile.NewAgentStateMachine(),
		healthEpoch: NewHealthEpoch(),
	}
	if err := runtime.lifecycle.Transition(reconcile.AgentReconciling); err != nil {
		t.Fatal(err)
	}
	if err := runtime.lifecycle.Transition(reconcile.AgentReady); err != nil {
		t.Fatal(err)
	}
	runtime.setDatapathStatus(true, 42)
	runtime.setDatapathUnavailable("DATAPATH_STATE_UNAVAILABLE")
	runtime.recordScanStatus(ScanResult{Level: ScanFull, DatapathObserved: true})

	got := runtime.Status(context.Background())
	if got.DatapathEnabled || got.Generation != 0 || got.Reason != "DATAPATH_DISABLED" {
		t.Fatalf("status retained stale datapath metadata: %+v", got)
	}
}

func TestObservabilityRequestsDoNotRefreshRuntimeState(t *testing.T) {
	client := fake.NewSimpleClientset()
	runtime, err := newDynamicRuntimeWithFactory(dynamicTestConfig(), client, func(context.Context, datapathComponentConfig) (*datapathComponents, error) {
		return nil, errors.New("unused datapath factory")
	})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := observability.NewHandler(observability.HandlerConfig{DebugState: true}, runtime.SnapshotStore())
	if err != nil {
		t.Fatal(err)
	}
	before := len(client.Actions())
	for _, path := range []string{"/readyz", "/metrics", "/debug/state"} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
	}
	if after := len(client.Actions()); after != before {
		t.Fatalf("HTTP observability requests issued %d Kubernetes actions", after-before)
	}
}
