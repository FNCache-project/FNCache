package observability

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
)

func TestMetricsExposeParseableCompatibleFamilies(t *testing.T) {
	store := NewSnapshotStore(Snapshot{
		State:           reconcile.AgentReady,
		Generation:      7,
		DatapathEnabled: true,
		APIHealthy:      true,
		HeartbeatFresh:  true,
		QueueDepth:      2,
	})
	m, err := newMetrics(store.Snapshot, buildInfo{version: "v-test", revision: "abc123", goVersion: "go-test"})
	if err != nil {
		t.Fatal(err)
	}

	families := scrapeMetricFamilies(t, m.handler)
	wantNames := map[string]bool{
		metricAgentState:         true,
		metricDatapathEnabled:    true,
		metricDatapathGeneration: true,
		metricQueueDepth:         true,
		metricKubeAPIHealthy:     true,
		metricHeartbeatFresh:     true,
		metricAgentReady:         true,
		metricAgentReadyReason:   true,
		metricBuildInfo:          true,
	}
	if len(families) != len(wantNames) {
		t.Fatalf("metric family count = %d, want %d (%v)", len(families), len(wantNames), families)
	}
	for name := range wantNames {
		family, ok := families[name]
		if !ok {
			t.Fatalf("missing metric family %q", name)
		}
		if family.GetType() != dto.MetricType_GAUGE {
			t.Errorf("%s type = %s, want GAUGE", name, family.GetType())
		}
		if family.GetHelp() == "" {
			t.Errorf("%s has no HELP text", name)
		}
	}

	for _, state := range metricStates {
		want := 0.0
		if state == reconcile.AgentReady {
			want = 1
		}
		assertMetricValue(t, families[metricAgentState], map[string]string{"state": string(state)}, want)
	}
	assertMetricValue(t, families[metricDatapathEnabled], nil, 1)
	assertMetricValue(t, families[metricDatapathGeneration], nil, 7)
	assertMetricValue(t, families[metricQueueDepth], nil, 2)
	assertMetricValue(t, families[metricKubeAPIHealthy], nil, 1)
	assertMetricValue(t, families[metricHeartbeatFresh], nil, 1)
	assertMetricValue(t, families[metricAgentReady], nil, 1)
	assertMetricValue(t, families[metricAgentReadyReason], map[string]string{"reason": readinessReasonNone}, 1)
	if got := len(families[metricAgentReadyReason].GetMetric()); got != len(readinessReasons) {
		t.Fatalf("readiness reason series = %d, want %d", got, len(readinessReasons))
	}
	assertMetricValue(t, families[metricBuildInfo], map[string]string{
		"version":    "v-test",
		"revision":   "abc123",
		"go_version": "go-test",
	}, 1)
}

func TestMetricsUseIndependentRegistries(t *testing.T) {
	store := NewSnapshotStore(Snapshot{State: reconcile.AgentDisabled})
	first, err := newMetrics(store.Snapshot, buildInfo{})
	if err != nil {
		t.Fatal(err)
	}
	second, err := newMetrics(store.Snapshot, buildInfo{})
	if err != nil {
		t.Fatal(err)
	}
	if first.registry == second.registry {
		t.Fatal("metrics instances share a Prometheus registry")
	}
	if _, err := first.registry.Gather(); err != nil {
		t.Fatalf("first registry gather failed: %v", err)
	}
	if _, err := second.registry.Gather(); err != nil {
		t.Fatalf("second registry gather failed: %v", err)
	}
}

func TestReadinessReasonIsBounded(t *testing.T) {
	tests := []struct {
		name     string
		snapshot Snapshot
		want     string
	}{
		{name: "ready", snapshot: Snapshot{Ready: true}, want: readinessReasonNone},
		{name: "capability detail", snapshot: Snapshot{Reason: "CAPABILITY_UNSUPPORTED: BPF_HELPER_MISSING: detail"}, want: readinessReasonCapabilityUnsupported},
		{name: "datapath unavailable", snapshot: Snapshot{Reason: "DATAPATH_STATE_UNAVAILABLE"}, want: readinessReasonDatapathUnavailable},
		{name: "unknown reason", snapshot: Snapshot{State: reconcile.AgentReady, Reason: "runtime detail with unbounded text", DatapathEnabled: true, APIHealthy: true, HeartbeatFresh: true}, want: readinessReasonOther},
		{name: "state fallback", snapshot: Snapshot{State: reconcile.AgentReconciling}, want: readinessReasonAgentReconciling},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := readinessReason(test.snapshot); got != test.want {
				t.Fatalf("readinessReason() = %q, want %q", got, test.want)
			}
		})
	}
	for _, reason := range []string{
		readinessReasonNone,
		readinessReasonAgentBootstrapping,
		readinessReasonAgentDisabled,
		readinessReasonAgentReconciling,
		readinessReasonAgentDegraded,
		readinessReasonAgentStopping,
		readinessReasonAgentUnknownState,
		readinessReasonAgentUnavailable,
		readinessReasonDatapathDisabled,
		readinessReasonDatapathUnavailable,
		readinessReasonKubeAPIStale,
		readinessReasonHeartbeatStale,
		readinessReasonCapabilityUnsupported,
		readinessReasonOther,
	} {
		if !containsString(readinessReasons, reason) {
			t.Errorf("readiness reason %q is missing from the bounded set", reason)
		}
	}
}

func TestMetricsConcurrentScrapes(t *testing.T) {
	store := NewSnapshotStore(Snapshot{State: reconcile.AgentReady, DatapathEnabled: true, APIHealthy: true, HeartbeatFresh: true})
	m, err := newMetrics(store.Snapshot, buildInfo{})
	if err != nil {
		t.Fatal(err)
	}

	const scrapers = 12
	const iterations = 100
	errs := make(chan error, scrapers)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < scrapers*iterations; i++ {
			ready := i%2 == 0
			store.Update(Snapshot{
				State:           reconcile.AgentReady,
				DatapathEnabled: ready,
				APIHealthy:      ready,
				HeartbeatFresh:  ready,
				Generation:      uint64(i),
				QueueDepth:      i,
			})
		}
	}()
	for i := 0; i < scrapers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				recorder := httptest.NewRecorder()
				m.handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
				if recorder.Code != http.StatusOK {
					errs <- fmt.Errorf("metrics status = %d", recorder.Code)
					return
				}
				if _, err := parseMetricFamilies(recorder.Body.String()); err != nil {
					errs <- err
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func scrapeMetricFamilies(t *testing.T, handler http.Handler) map[string]*dto.MetricFamily {
	t.Helper()
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("metrics status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	families, err := parseMetricFamilies(recorder.Body.String())
	if err != nil {
		t.Fatalf("parse metrics: %v\n%s", err, recorder.Body.String())
	}
	return families
}

func parseMetricFamilies(text string) (map[string]*dto.MetricFamily, error) {
	parser := expfmt.NewTextParser(model.LegacyValidation)
	return parser.TextToMetricFamilies(strings.NewReader(text))
}

func assertMetricValue(t *testing.T, family *dto.MetricFamily, labels map[string]string, want float64) {
	t.Helper()
	for _, metric := range family.GetMetric() {
		if metricLabels(metric, labels) && metric.GetGauge().GetValue() == want {
			return
		}
	}
	t.Fatalf("metric %s with labels %v did not have value %v", family.GetName(), labels, want)
}

func metricLabels(metric *dto.Metric, want map[string]string) bool {
	if len(metric.GetLabel()) != len(want) {
		return false
	}
	for _, label := range metric.GetLabel() {
		if want[label.GetName()] != label.GetValue() {
			return false
		}
	}
	return true
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
