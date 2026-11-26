package queue

import (
	"log/slog"
	"strings"
	"time"

	"github.com/cat-cc-Lcos/FNCache/internal/observability"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

func reconcileStartedEvent(key reconcile.ReconcileKey, generation uint64, attempt int) observability.Event {
	return observability.Event{
		Level: slog.LevelDebug, Message: "reconcile started",
		Attrs: reconcileAttrs(key, generation, attempt, 0),
	}
}

func reconcileSucceededEvent(key reconcile.ReconcileKey, generation uint64, attempt int, duration time.Duration) observability.Event {
	return observability.Event{
		Level: slog.LevelDebug, Message: "reconcile completed",
		Attrs: reconcileAttrs(key, generation, attempt, duration),
	}
}

func reconcileFailureEvent(key reconcile.ReconcileKey, err error, generation uint64, attempt int, duration time.Duration) observability.Event {
	class, reason := reconcile.ClassifyError(err, key.Reason)
	level := slog.LevelWarn
	if class == reconcile.ErrorInternal || class == reconcile.ErrorSafetyViolation || class == reconcile.ErrorConflict {
		level = slog.LevelError
	}
	attrs := reconcileAttrs(key, generation, attempt, duration)
	attrs = append(attrs, "reason", reason, "class", string(class), "error", err.Error())
	return observability.Event{
		Level: level, Message: "reconcile failed",
		RateLimitKey: strings.Join([]string{string(class), reason}, ":"), Attrs: attrs,
	}
}

func retryScheduledEvent(key reconcile.ReconcileKey, err error, generation uint64, attempt int, duration, delay time.Duration) observability.Event {
	class, reason := reconcile.ClassifyError(err, key.Reason)
	attrs := reconcileAttrs(key, generation, attempt, duration)
	attrs = append(attrs, "reason", reason, "class", string(class), "delay", delay.String())
	return observability.Event{
		Level: slog.LevelWarn, Message: "retry scheduled",
		RateLimitKey: strings.Join([]string{"retry", string(class), reason}, ":"), Attrs: attrs,
	}
}

func reconcileAttrs(key reconcile.ReconcileKey, generation uint64, attempt int, duration time.Duration) []any {
	attrs := []any{"kind", string(key.Kind)}
	if key.Namespace != "" {
		attrs = append(attrs, "namespace", key.Namespace)
	}
	if key.Name != "" {
		attrs = append(attrs, "name", key.Name)
	}
	if key.UID != "" {
		attrs = append(attrs, "uid", key.UID)
	}
	if generation != 0 {
		attrs = append(attrs, "generation", generation)
	}
	if attempt != 0 {
		attrs = append(attrs, "attempt", attempt)
	}
	if duration > 0 {
		attrs = append(attrs, "duration", observability.DurationMillis(duration))
	}
	return attrs
}
