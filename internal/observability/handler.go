package observability

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

type Snapshot struct {
	State           reconcile.AgentState `json:"state"`
	Ready           bool                 `json:"ready"`
	Reason          string               `json:"reason,omitempty"`
	Generation      uint64               `json:"generation"`
	DatapathEnabled bool                 `json:"datapathEnabled"`
	APIHealthy      bool                 `json:"apiHealthy"`
	HeartbeatFresh  bool                 `json:"heartbeatFresh"`
	QueueDepth      int                  `json:"queueDepth"`
	KnownLinks      int                  `json:"knownLinks"`
}

type StatusProvider interface {
	Status(context.Context) Snapshot
}

type HandlerConfig struct {
	DebugState bool
}

type Handler struct {
	provider   StatusProvider
	debugState bool
	mux        *http.ServeMux
}

func NewHandler(config HandlerConfig, provider StatusProvider) (*Handler, error) {
	if provider == nil {
		return nil, fmt.Errorf("status provider is required")
	}
	h := &Handler{provider: provider, debugState: config.DebugState, mux: http.NewServeMux()}
	h.mux.HandleFunc("/livez", h.livez)
	h.mux.HandleFunc("/readyz", h.readyz)
	h.mux.HandleFunc("/metrics", h.metrics)
	h.mux.HandleFunc("/debug/state", h.debug)
	return h, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

func (h *Handler) livez(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

func (h *Handler) readyz(w http.ResponseWriter, r *http.Request) {
	snapshot := h.provider.Status(r.Context())
	status := http.StatusServiceUnavailable
	if snapshot.Ready {
		status = http.StatusOK
	}
	writeJSON(w, status, snapshot)
}

func (h *Handler) metrics(w http.ResponseWriter, r *http.Request) {
	snapshot := h.provider.Status(r.Context())
	var b strings.Builder
	b.WriteString("# TYPE oncache_agent_state gauge\n")
	for _, state := range []reconcile.AgentState{reconcile.AgentBootstrapping, reconcile.AgentDisabled, reconcile.AgentReconciling, reconcile.AgentReady, reconcile.AgentDegraded, reconcile.AgentStopping} {
		value := 0
		if snapshot.State == state {
			value = 1
		}
		_, _ = fmt.Fprintf(&b, "oncache_agent_state{state=%q} %d\n", state, value)
	}
	_, _ = fmt.Fprintf(&b, "oncache_datapath_enabled %d\n", boolValue(snapshot.DatapathEnabled))
	_, _ = fmt.Fprintf(&b, "oncache_datapath_generation %d\n", snapshot.Generation)
	_, _ = fmt.Fprintf(&b, "oncache_queue_depth %d\n", snapshot.QueueDepth)
	_, _ = fmt.Fprintf(&b, "oncache_kube_api_healthy %d\n", boolValue(snapshot.APIHealthy))
	_, _ = fmt.Fprintf(&b, "oncache_heartbeat_fresh %d\n", boolValue(snapshot.HeartbeatFresh))
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(b.String()))
}

func (h *Handler) debug(w http.ResponseWriter, r *http.Request) {
	if !h.debugState {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, h.provider.Status(r.Context()))
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func boolValue(value bool) int {
	if value {
		return 1
	}
	return 0
}
