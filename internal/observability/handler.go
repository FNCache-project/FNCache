package observability

import (
	"encoding/json"
	"fmt"
	"net/http"
)

type HandlerConfig struct {
	DebugState bool
}

type Handler struct {
	snapshot   func() Snapshot
	debugState bool
	mux        *http.ServeMux
}

func NewHandler(config HandlerConfig, store *SnapshotStore) (*Handler, error) {
	if store == nil {
		return nil, fmt.Errorf("snapshot store is required")
	}
	metricsHandler, err := newMetricsHandler(store.Snapshot)
	if err != nil {
		return nil, fmt.Errorf("create metrics handler: %w", err)
	}
	h := &Handler{snapshot: store.Snapshot, debugState: config.DebugState, mux: http.NewServeMux()}
	h.mux.HandleFunc("/livez", h.livez)
	h.mux.HandleFunc("/readyz", h.readyz)
	h.mux.Handle("/metrics", metricsHandler)
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

func (h *Handler) readyz(w http.ResponseWriter, _ *http.Request) {
	snapshot := h.snapshot()
	status := http.StatusServiceUnavailable
	if snapshot.Ready {
		status = http.StatusOK
	}
	writeJSON(w, status, snapshot)
}

func (h *Handler) debug(w http.ResponseWriter, r *http.Request) {
	if !h.debugState {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, h.snapshot())
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
