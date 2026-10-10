package observability

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

type fakeStatus struct{ snapshot Snapshot }

func (f fakeStatus) Status(context.Context) Snapshot { return f.snapshot }

func TestNewHandlerRequiresStatusProvider(t *testing.T) {
	if _, err := NewHandler(HandlerConfig{}, nil); err == nil {
		t.Fatal("handler accepted a nil status provider")
	}
}

func TestHTTPEndpoints(t *testing.T) {
	provider := fakeStatus{snapshot: Snapshot{State: reconcile.AgentReady, Ready: true, Generation: 7, DatapathEnabled: true, APIHealthy: true, HeartbeatFresh: true, QueueDepth: 2}}
	handler, err := NewHandler(HandlerConfig{}, provider)
	if err != nil {
		t.Fatal(err)
	}
	request := func(path string) *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		return recorder
	}
	if response := request("/livez"); response.Code != http.StatusOK || response.Body.String() != "ok\n" {
		t.Fatalf("livez response = %d %q", response.Code, response.Body.String())
	}
	if response := request("/readyz"); response.Code != http.StatusOK || response.Header().Get("Content-Type") != "application/json" || !strings.Contains(response.Body.String(), `"ready":true`) {
		t.Fatalf("readyz response = %d %s", response.Code, response.Body.String())
	}
	metrics := request("/metrics")
	wantMetrics := strings.Join([]string{
		"# TYPE oncache_agent_state gauge",
		`oncache_agent_state{state="Bootstrapping"} 0`,
		`oncache_agent_state{state="Disabled"} 0`,
		`oncache_agent_state{state="Reconciling"} 0`,
		`oncache_agent_state{state="Ready"} 1`,
		`oncache_agent_state{state="Degraded"} 0`,
		`oncache_agent_state{state="Stopping"} 0`,
		"oncache_datapath_enabled 1",
		"oncache_datapath_generation 7",
		"oncache_queue_depth 2",
		"oncache_kube_api_healthy 1",
		"oncache_heartbeat_fresh 1",
		"",
	}, "\n")
	if metrics.Code != http.StatusOK || metrics.Header().Get("Content-Type") != "text/plain; version=0.0.4; charset=utf-8" || metrics.Body.String() != wantMetrics {
		t.Fatalf("unexpected metrics response = %d %s", metrics.Code, metrics.Body.String())
	}
	if response := request("/debug/state"); response.Code != http.StatusNotFound {
		t.Fatalf("debug state was not disabled: %d", response.Code)
	}

	debugHandler, err := NewHandler(HandlerConfig{DebugState: true}, provider)
	if err != nil {
		t.Fatal(err)
	}
	debugResponse := httptest.NewRecorder()
	debugHandler.ServeHTTP(debugResponse, httptest.NewRequest(http.MethodGet, "/debug/state", nil))
	if debugResponse.Code != http.StatusOK || !strings.Contains(debugResponse.Body.String(), `"generation":7`) {
		t.Fatalf("debug state response = %d %s", debugResponse.Code, debugResponse.Body.String())
	}
}

func TestReadyzReturnsUnavailableForDisabledState(t *testing.T) {
	provider := fakeStatus{snapshot: Snapshot{State: reconcile.AgentDisabled, Reason: "CAPABILITY_UNSUPPORTED"}}
	handler, err := NewHandler(HandlerConfig{}, provider)
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if recorder.Code != http.StatusServiceUnavailable || !strings.Contains(recorder.Body.String(), "CAPABILITY_UNSUPPORTED") {
		t.Fatalf("unexpected disabled readiness response = %d %s", recorder.Code, recorder.Body.String())
	}
}
