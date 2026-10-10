package observability

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"
	"time"
)

func TestParseLevel(t *testing.T) {
	for _, value := range []string{"", "debug", "info", "warn", "warning", "error"} {
		if _, err := ParseLevel(value); err != nil {
			t.Fatalf("ParseLevel(%q) failed: %v", value, err)
		}
	}
	if _, err := ParseLevel("trace"); err == nil {
		t.Fatal("unsupported log level was accepted")
	}
}

func TestLoggerRateLimitsEventsAndReportsSuppressed(t *testing.T) {
	var output bytes.Buffer
	now := time.Unix(100, 0)
	logger, err := New(LoggingConfig{Level: "debug", Component: "queue", Node: "node-a", Writer: &output, RateInterval: time.Second, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	event := Event{
		Level: slog.LevelWarn, Message: "reconcile failed", RateLimitKey: "Retryable:ENDPOINT_NOT_READY",
		Attrs: []any{"generation", uint64(0), "reconcileKey", "LocalEndpoint\x00default\x00web\x00pod-1", "reason", "ENDPOINT_NOT_READY", "class", "Retryable", "error", "context canceled"},
	}
	logger.LogEvent(context.Background(), event)
	logger.LogEvent(context.Background(), event)
	now = now.Add(2 * time.Second)
	logger.LogEvent(context.Background(), event)

	lines := bytes.Split(bytes.TrimSpace(output.Bytes()), []byte{'\n'})
	if len(lines) != 2 {
		t.Fatalf("unexpected rate-limited log count: %d\n%s", len(lines), output.String())
	}
	var first, second map[string]any
	if err := json.Unmarshal(lines[0], &first); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(lines[1], &second); err != nil {
		t.Fatal(err)
	}
	if first["component"] != "queue" || first["node"] != "node-a" || first["reason"] != "ENDPOINT_NOT_READY" || first["class"] != "Retryable" {
		t.Fatalf("missing structured fields: %#v", first)
	}
	if second["suppressed"] != float64(1) {
		t.Fatalf("suppressed count was not reported: %#v", second)
	}
}
