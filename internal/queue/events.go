package queue

import (
	"errors"
	"log/slog"
	"strings"

	"github.com/cat-cc-Lcos/FNCache/internal/observability"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

func reconcileFailureEvent(key reconcile.ReconcileKey, err error) observability.Event {
	class := string(reconcile.ErrorInternal)
	reason := key.Reason
	if reason == "" {
		reason = "RECONCILE_ERROR"
	}
	var classified *reconcile.ClassifiedError
	if errors.As(err, &classified) {
		class = string(classified.Class())
		if classified.ReasonCode() != "" {
			reason = classified.ReasonCode()
		}
	}
	level := slog.LevelWarn
	if class == string(reconcile.ErrorInternal) || class == string(reconcile.ErrorSafetyViolation) || class == string(reconcile.ErrorConflict) {
		level = slog.LevelError
	}
	return observability.Event{
		Level:        level,
		Message:      "reconcile failed",
		RateLimitKey: strings.Join([]string{class, reason}, ":"),
		Attrs: []any{
			"generation", uint64(0),
			"reconcileKey", key.QueueKey(),
			"reason", reason,
			"class", class,
			"error", err.Error(),
		},
	}
}
