package agent

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/cat-cc-Lcos/FNCache/internal/endpoint"
	"github.com/cat-cc-Lcos/FNCache/internal/hostnet/flannel"
	"github.com/cat-cc-Lcos/FNCache/internal/observability"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

func scopedLogger(logger observability.EventLogger, component, node string) observability.EventLogger {
	typed, ok := logger.(*observability.Logger)
	if !ok || typed == nil {
		return logger
	}
	if node != "" {
		typed = typed.WithNode(node)
	}
	if component != "" {
		typed = typed.WithComponent(component)
	}
	return typed
}

func logEvent(ctx context.Context, logger observability.EventLogger, event observability.Event) {
	if logger != nil {
		logger.LogEvent(ctx, event)
	}
}

type healthEventBatch struct {
	ctx        context.Context
	events     []observability.Event
	suppressed uint64
}

const (
	healthEventQueueLimit = 64
)

type healthEventDispatcher struct {
	logger  observability.EventLogger
	mu      sync.Mutex
	flushMu sync.Mutex
	queue   []healthEventBatch
	dropped uint64
	closed  bool
}

func newHealthEventDispatcher(logger observability.EventLogger) *healthEventDispatcher {
	return &healthEventDispatcher{logger: logger}
}

func (d *healthEventDispatcher) enqueue(ctx context.Context, events []observability.Event) bool {
	if d == nil || len(events) == 0 {
		return d != nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return false
	}
	if len(d.queue) >= healthEventQueueLimit {
		droppedBatch := d.queue[0]
		d.queue = d.queue[1:]
		d.dropped += droppedBatch.suppressed + uint64(len(droppedBatch.events))
	}
	queuedEvents := append([]observability.Event(nil), events...)
	d.queue = append(d.queue, healthEventBatch{ctx: ctx, events: queuedEvents, suppressed: d.dropped})
	d.dropped = 0
	return true
}

func healthEventsSuppressedEvent(count uint64) observability.Event {
	return observability.Event{
		Level: slog.LevelWarn, Message: "health events suppressed",
		Attrs: []any{"kind", "Health", "reason", "HEALTH_EVENTS_SUPPRESSED", "class", "Health", "suppressed", count},
	}
}

func (d *healthEventDispatcher) flush() {
	if d == nil {
		return
	}
	d.flushMu.Lock()
	defer d.flushMu.Unlock()
	for {
		d.mu.Lock()
		if len(d.queue) == 0 {
			d.mu.Unlock()
			return
		}
		batch := d.queue[0]
		d.queue[0] = healthEventBatch{}
		d.queue = d.queue[1:]
		d.mu.Unlock()
		if batch.suppressed > 0 {
			logEvent(batch.ctx, d.logger, healthEventsSuppressedEvent(batch.suppressed))
		}
		for _, event := range batch.events {
			logEvent(batch.ctx, d.logger, event)
		}
	}
}

func (d *healthEventDispatcher) close() {
	if d == nil {
		return
	}
	// Status and runtime-final events flush while the runtime is still live.
	// Discard only residual events racing shutdown so close never waits on the
	// log sink or leaves a dispatcher goroutine behind.
	d.mu.Lock()
	d.closed = true
	d.queue = nil
	d.dropped = 0
	d.mu.Unlock()
}

func (r *DynamicRuntime) startHealthEventDispatcher() {
	if r == nil || r.logger == nil {
		return
	}
	r.healthEventMu.Lock()
	if r.healthEvents == nil {
		r.healthEvents = newHealthEventDispatcher(r.logger)
	}
	r.healthEventMu.Unlock()
}

func (r *DynamicRuntime) stopHealthEventDispatcher() {
	if r == nil {
		return
	}
	r.healthEventMu.Lock()
	dispatcher := r.healthEvents
	r.healthEvents = nil
	r.healthEventMu.Unlock()
	if dispatcher != nil {
		dispatcher.close()
	}
}

func (r *DynamicRuntime) queueHealthEvents(ctx context.Context, events []observability.Event) *healthEventDispatcher {
	if r == nil || len(events) == 0 {
		return nil
	}
	r.healthEventMu.RLock()
	dispatcher := r.healthEvents
	r.healthEventMu.RUnlock()
	if dispatcher == nil {
		return nil
	}
	if !dispatcher.enqueue(ctx, events) {
		return nil
	}
	return dispatcher
}

func (r *DynamicRuntime) transition(ctx context.Context, to reconcile.AgentState) error {
	if r == nil || r.lifecycle == nil {
		return reconcile.ErrInvalidStateTransition
	}
	from := r.lifecycle.State()
	if err := r.lifecycle.Transition(to); err != nil {
		return err
	}
	if from != to {
		logEvent(ctx, r.logger, stateTransitionEvent(from, to, r.lastKnownGeneration()))
	}
	return nil
}

func reconcileEventLogger(logger observability.EventLogger) reconcile.EventHandler {
	return func(ctx context.Context, event reconcile.ReconcileEvent) {
		if logger == nil {
			return
		}
		level := slog.LevelInfo
		if event.Err != nil {
			level = slog.LevelWarn
			if event.Class == string(reconcile.ErrorInternal) || event.Class == string(reconcile.ErrorConflict) || event.Class == string(reconcile.ErrorSafetyViolation) {
				level = slog.LevelError
			}
		} else if event.Message == "reconcile started" {
			level = slog.LevelDebug
		}
		attrs := []any{"kind", string(event.Kind)}
		if event.Reason != "" {
			attrs = append(attrs, "reason", event.Reason)
		}
		if event.Class != "" {
			attrs = append(attrs, "class", event.Class)
		}
		if event.Generation != 0 {
			attrs = append(attrs, "generation", event.Generation)
		}
		if event.Attempt != 0 {
			attrs = append(attrs, "attempt", event.Attempt)
		}
		if event.Duration > 0 {
			attrs = append(attrs, "duration", observability.DurationMillis(event.Duration))
		}
		if event.From != "" {
			attrs = append(attrs, "from", string(event.From))
		}
		if event.To != "" {
			attrs = append(attrs, "to", string(event.To))
		}
		if event.Err != nil {
			attrs = append(attrs, "error", event.Err.Error())
		}
		rateKey := ""
		if event.Err != nil {
			rateKey = "reconcile:" + event.Class + ":" + event.Reason
		}
		logger.LogEvent(ctx, observability.Event{Level: level, Message: event.Message, RateLimitKey: rateKey, Attrs: attrs})
	}
}

func stateTransitionEvent(from, to reconcile.AgentState, generation uint64) observability.Event {
	attrs := []any{
		"kind", "Agent",
		"reason", "STATE_TRANSITION",
		"class", "State",
		"from", string(from),
		"to", string(to),
	}
	if generation != 0 {
		attrs = append(attrs, "generation", generation)
	}
	return observability.Event{Level: slog.LevelInfo, Message: "agent state transition", Attrs: attrs}
}

func retryEvent(logger observability.EventLogger, ctx context.Context, kind string, err error, attempt int, duration, delay time.Duration) {
	if logger == nil {
		return
	}
	class, reason := errorFields(err, "RETRY")
	attrs := []any{"kind", kind, "reason", reason, "class", class, "attempt", attempt}
	if err != nil {
		attrs = append(attrs, "error", err.Error())
	}
	if duration > 0 {
		attrs = append(attrs, "duration", observability.DurationMillis(duration))
	}
	if delay > 0 {
		attrs = append(attrs, "delay", delay.String())
	}
	logger.LogEvent(ctx, observability.Event{
		Level: slog.LevelWarn, Message: "retry scheduled", RateLimitKey: "retry:" + class + ":" + reason, Attrs: attrs,
	})
}

func errorFields(err error, fallbackReason string) (class, reason string) {
	class = string(reconcile.ErrorInternal)
	reason = fallbackReason
	if reason == "" {
		reason = "RECONCILE_ERROR"
	}
	var classified *reconcile.ClassifiedError
	if errors.As(err, &classified) {
		class = string(classified.Class())
		if classified.ReasonCode() != "" {
			reason = classified.ReasonCode()
		}
		return class, reason
	}
	switch {
	case errors.Is(err, ErrKubernetesSnapshotNotReady):
		return string(reconcile.ErrorRetryable), "KUBERNETES_SNAPSHOT_NOT_READY"
	case errors.Is(err, flannel.ErrDiscoveryNotReady):
		return string(reconcile.ErrorRetryable), "FLANNEL_DISCOVERY_NOT_READY"
	case errors.Is(err, endpoint.ErrContainerdEndpointNotReady):
		return string(reconcile.ErrorRetryable), "CONTAINERD_ENDPOINT_NOT_READY"
	}
	return class, reason
}

func healthTransitionEvents(previous, current observability.Snapshot) []observability.Event {
	if current.State == reconcile.AgentDisabled || current.State == reconcile.AgentStopping {
		return nil
	}
	conditions := []observability.ConditionType{
		observability.DatapathReady,
		observability.KubeAPIHealthy,
		observability.HeartbeatFresh,
	}
	events := make([]observability.Event, 0, len(conditions))
	for _, condition := range conditions {
		before, after := previous.Condition(condition), current.Condition(condition)
		if before == after {
			continue
		}
		healthy := after
		reason := healthReason(condition, healthy)
		message := "health failure"
		level := slog.LevelWarn
		if healthy {
			message = "health recovered"
			level = slog.LevelInfo
		}
		attrs := []any{"kind", "Health", "reason", reason, "class", "Health", "condition", string(condition)}
		generation := current.Generation
		if !healthy && generation == 0 {
			generation = previous.Generation
		}
		if generation != 0 {
			attrs = append(attrs, "generation", generation)
		}
		rateKey := ""
		if !healthy {
			rateKey = "health:" + reason
		}
		events = append(events, observability.Event{Level: level, Message: message, RateLimitKey: rateKey, Attrs: attrs})
	}
	return events
}

func healthReason(condition observability.ConditionType, healthy bool) string {
	if healthy {
		switch condition {
		case observability.DatapathReady:
			return "DATAPATH_RECOVERED"
		case observability.KubeAPIHealthy:
			return "KUBE_API_RECOVERED"
		case observability.HeartbeatFresh:
			return "HEARTBEAT_RECOVERED"
		}
	}
	switch condition {
	case observability.DatapathReady:
		return "DATAPATH_DISABLED"
	case observability.KubeAPIHealthy:
		return "KUBE_API_STALE"
	case observability.HeartbeatFresh:
		return "HEARTBEAT_STALE"
	default:
		return "HEALTH_UNKNOWN"
	}
}
