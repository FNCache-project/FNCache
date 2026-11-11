package observability

import (
	"fmt"
	"net/http"
	"runtime"
	"strings"

	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// BuildVersion and BuildRevision are populated by release builds through Go
// linker flags. Their defaults keep local builds and tests useful.
var (
	BuildVersion  = "dev"
	BuildRevision = "unknown"
)

const (
	metricAgentState             = "oncache_agent_state"
	metricDatapathEnabled        = "oncache_datapath_enabled"
	metricDatapathGeneration     = "oncache_datapath_generation"
	metricQueueDepth             = "oncache_queue_depth"
	metricKubeAPIHealthy         = "oncache_kube_api_healthy"
	metricHeartbeatFresh         = "oncache_heartbeat_fresh"
	metricAgentReady             = "oncache_agent_ready"
	metricAgentReadyReason       = "oncache_agent_ready_reason"
	metricBuildInfo              = "oncache_build_info"
	metricAgentStateHelp         = "Current agent lifecycle state as a one-hot gauge (unitless)."
	metricDatapathEnabledHelp    = "Whether the datapath is enabled, with 1 for enabled and 0 for disabled (unitless)."
	metricDatapathGenerationHelp = "Current datapath generation number (unitless)."
	metricQueueDepthHelp         = "Current number of items in the reconciliation queue (unit: items)."
	metricKubeAPIHealthyHelp     = "Whether the Kubernetes API health observation is fresh, with 1 for healthy and 0 for unhealthy (unitless)."
	metricHeartbeatFreshHelp     = "Whether the datapath heartbeat is fresh, with 1 for fresh and 0 for stale (unitless)."
	metricAgentReadyHelp         = "Whether the agent is ready, with 1 for ready and 0 for not ready (unitless)."
	metricAgentReadyReasonHelp   = "Current agent readiness reason as a one-hot gauge (unitless)."
	metricBuildInfoHelp          = "Build information for the agent (unitless)."
)

var metricStates = []reconcile.AgentState{
	reconcile.AgentBootstrapping,
	reconcile.AgentDisabled,
	reconcile.AgentReconciling,
	reconcile.AgentReady,
	reconcile.AgentDegraded,
	reconcile.AgentStopping,
}

const (
	readinessReasonNone                  = "NONE"
	readinessReasonAgentBootstrapping    = "AGENT_BOOTSTRAPPING"
	readinessReasonAgentDisabled         = "AGENT_DISABLED"
	readinessReasonAgentReconciling      = "AGENT_RECONCILING"
	readinessReasonAgentDegraded         = "AGENT_DEGRADED"
	readinessReasonAgentStopping         = "AGENT_STOPPING"
	readinessReasonAgentUnknownState     = "AGENT_UNKNOWN_STATE"
	readinessReasonAgentUnavailable      = "AGENT_UNAVAILABLE"
	readinessReasonDatapathDisabled      = "DATAPATH_DISABLED"
	readinessReasonDatapathUnavailable   = "DATAPATH_UNAVAILABLE"
	readinessReasonKubeAPIStale          = "KUBE_API_STALE"
	readinessReasonHeartbeatStale        = "HEARTBEAT_STALE"
	readinessReasonCapabilityUnsupported = "CAPABILITY_UNSUPPORTED"
	readinessReasonOther                 = "OTHER"
)

var readinessReasons = []string{
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
}

type buildInfo struct {
	version   string
	revision  string
	goVersion string
}

type metrics struct {
	registry *prometheus.Registry
	handler  http.Handler
}

type snapshotCollector struct {
	snapshot func() Snapshot
	build    buildInfo

	agentState         *prometheus.Desc
	datapathEnabled    *prometheus.Desc
	datapathGeneration *prometheus.Desc
	queueDepth         *prometheus.Desc
	kubeAPIHealthy     *prometheus.Desc
	heartbeatFresh     *prometheus.Desc
	agentReady         *prometheus.Desc
	agentReadyReason   *prometheus.Desc
	buildInfo          *prometheus.Desc
}

func newMetricsHandler(snapshot func() Snapshot) (http.Handler, error) {
	m, err := newMetrics(snapshot, buildInfo{
		version:   BuildVersion,
		revision:  BuildRevision,
		goVersion: runtime.Version(),
	})
	if err != nil {
		return nil, err
	}
	return m.handler, nil
}

func newMetrics(snapshot func() Snapshot, build buildInfo) (*metrics, error) {
	if snapshot == nil {
		return nil, fmt.Errorf("snapshot function is required")
	}
	collector := newSnapshotCollector(snapshot, normalizeBuildInfo(build))
	registry := prometheus.NewRegistry()
	if err := registry.Register(collector); err != nil {
		return nil, fmt.Errorf("register snapshot collector: %w", err)
	}
	return &metrics{
		registry: registry,
		handler:  promhttp.HandlerFor(registry, promhttp.HandlerOpts{}),
	}, nil
}

func newSnapshotCollector(snapshot func() Snapshot, build buildInfo) *snapshotCollector {
	return &snapshotCollector{
		snapshot: snapshot,
		build:    build,
		agentState: prometheus.NewDesc(
			metricAgentState, metricAgentStateHelp, []string{"state"}, nil,
		),
		datapathEnabled: prometheus.NewDesc(
			metricDatapathEnabled, metricDatapathEnabledHelp, nil, nil,
		),
		datapathGeneration: prometheus.NewDesc(
			metricDatapathGeneration, metricDatapathGenerationHelp, nil, nil,
		),
		queueDepth: prometheus.NewDesc(
			metricQueueDepth, metricQueueDepthHelp, nil, nil,
		),
		kubeAPIHealthy: prometheus.NewDesc(
			metricKubeAPIHealthy, metricKubeAPIHealthyHelp, nil, nil,
		),
		heartbeatFresh: prometheus.NewDesc(
			metricHeartbeatFresh, metricHeartbeatFreshHelp, nil, nil,
		),
		agentReady: prometheus.NewDesc(
			metricAgentReady, metricAgentReadyHelp, nil, nil,
		),
		agentReadyReason: prometheus.NewDesc(
			metricAgentReadyReason, metricAgentReadyReasonHelp, []string{"reason"}, nil,
		),
		buildInfo: prometheus.NewDesc(
			metricBuildInfo, metricBuildInfoHelp, []string{"version", "revision", "go_version"}, nil,
		),
	}
}

func (c *snapshotCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.agentState
	ch <- c.datapathEnabled
	ch <- c.datapathGeneration
	ch <- c.queueDepth
	ch <- c.kubeAPIHealthy
	ch <- c.heartbeatFresh
	ch <- c.agentReady
	ch <- c.agentReadyReason
	ch <- c.buildInfo
}

func (c *snapshotCollector) Collect(ch chan<- prometheus.Metric) {
	snapshot := c.snapshot()
	for _, state := range metricStates {
		value := 0.0
		if snapshot.State == state {
			value = 1
		}
		ch <- prometheus.MustNewConstMetric(c.agentState, prometheus.GaugeValue, value, string(state))
	}
	ch <- prometheus.MustNewConstMetric(c.datapathEnabled, prometheus.GaugeValue, float64(boolValue(snapshot.DatapathEnabled)))
	ch <- prometheus.MustNewConstMetric(c.datapathGeneration, prometheus.GaugeValue, float64(snapshot.Generation))
	ch <- prometheus.MustNewConstMetric(c.queueDepth, prometheus.GaugeValue, float64(snapshot.QueueDepth))
	ch <- prometheus.MustNewConstMetric(c.kubeAPIHealthy, prometheus.GaugeValue, float64(boolValue(snapshot.APIHealthy)))
	ch <- prometheus.MustNewConstMetric(c.heartbeatFresh, prometheus.GaugeValue, float64(boolValue(snapshot.HeartbeatFresh)))
	ch <- prometheus.MustNewConstMetric(c.agentReady, prometheus.GaugeValue, float64(boolValue(snapshot.Ready)))

	currentReason := readinessReason(snapshot)
	for _, reason := range readinessReasons {
		value := 0.0
		if reason == currentReason {
			value = 1
		}
		ch <- prometheus.MustNewConstMetric(c.agentReadyReason, prometheus.GaugeValue, value, reason)
	}
	ch <- prometheus.MustNewConstMetric(c.buildInfo, prometheus.GaugeValue, 1, c.build.version, c.build.revision, c.build.goVersion)
}

func normalizeBuildInfo(build buildInfo) buildInfo {
	if build.version == "" {
		build.version = "dev"
	}
	if build.revision == "" {
		build.revision = "unknown"
	}
	if build.goVersion == "" {
		build.goVersion = runtime.Version()
	}
	return build
}

func readinessReason(snapshot Snapshot) string {
	if snapshot.Ready {
		return readinessReasonNone
	}
	if reason := normalizeReadinessReason(snapshot.Reason); reason != readinessReasonOther {
		return reason
	}
	if snapshot.State != reconcile.AgentReady {
		switch snapshot.State {
		case reconcile.AgentBootstrapping:
			return readinessReasonAgentBootstrapping
		case reconcile.AgentDisabled:
			return readinessReasonAgentDisabled
		case reconcile.AgentReconciling:
			return readinessReasonAgentReconciling
		case reconcile.AgentDegraded:
			return readinessReasonAgentDegraded
		case reconcile.AgentStopping:
			return readinessReasonAgentStopping
		default:
			return readinessReasonAgentUnknownState
		}
	}
	if !snapshot.Condition(DatapathReady) {
		return readinessReasonDatapathDisabled
	}
	if !snapshot.Condition(KubeAPIHealthy) {
		return readinessReasonKubeAPIStale
	}
	if !snapshot.Condition(HeartbeatFresh) {
		return readinessReasonHeartbeatStale
	}
	return readinessReasonOther
}

func normalizeReadinessReason(reason string) string {
	if reason == "" {
		return readinessReasonOther
	}
	if reason == readinessReasonAgentUnavailable {
		return readinessReasonAgentUnavailable
	}
	if strings.HasPrefix(reason, readinessReasonCapabilityUnsupported) {
		return readinessReasonCapabilityUnsupported
	}
	switch reason {
	case readinessReasonAgentBootstrapping,
		readinessReasonAgentDisabled,
		readinessReasonAgentReconciling,
		readinessReasonAgentDegraded,
		readinessReasonAgentStopping,
		readinessReasonAgentUnknownState,
		readinessReasonDatapathDisabled,
		readinessReasonKubeAPIStale,
		readinessReasonHeartbeatStale:
		return reason
	case "DATAPATH_STATE_UNAVAILABLE", "DATAPATH_NOT_READY":
		return readinessReasonDatapathUnavailable
	default:
		return readinessReasonOther
	}
}
