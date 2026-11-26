package queue

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cat-cc-Lcos/FNCache/internal/observability"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

func workerKey() reconcile.ReconcileKey {
	return reconcile.ReconcileKey{Kind: reconcile.ReconcileLocalEndpoint, Namespace: "default", Name: "web", UID: "pod-1"}
}

func TestWorkerRetriesAndForgets(t *testing.T) {
	q, err := New(Config{BaseDelay: time.Millisecond, MaxDelay: 10 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	done := make(chan struct{}, 1)
	worker, err := NewWorker(q, func(context.Context, reconcile.ReconcileKey) error {
		if calls.Add(1) == 1 {
			return reconcile.NewClassifiedError(reconcile.ErrorRetryable, "RETRY", 0, errors.New("temporary"))
		}
		done <- struct{}{}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go worker.Run(ctx)
	q.Add(workerKey())
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("worker did not retry")
	}
	deadline := time.Now().Add(time.Second)
	for q.NumRequeues(workerKey()) != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("requeues after success = %d", q.NumRequeues(workerKey()))
		}
		time.Sleep(time.Millisecond)
	}
	q.ShutDown()
}

func TestWorkerDoesNotRetryStale(t *testing.T) {
	q, _ := New(Config{BaseDelay: time.Millisecond, MaxDelay: 10 * time.Millisecond})
	var calls atomic.Int32
	worker, _ := NewWorker(q, func(context.Context, reconcile.ReconcileKey) error {
		calls.Add(1)
		return reconcile.NewClassifiedError(reconcile.ErrorStale, "STALE", 0, nil)
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go worker.Run(ctx)
	q.Add(workerKey())
	time.Sleep(20 * time.Millisecond)
	if calls.Load() != 1 || q.NumRequeues(workerKey()) != 0 {
		t.Fatalf("stale item was retried: calls=%d requeues=%d", calls.Load(), q.NumRequeues(workerKey()))
	}
	q.ShutDown()
}

func TestWorkerContextStopsQueue(t *testing.T) {
	q, _ := New(DefaultConfig())
	worker, _ := NewWorker(q, func(context.Context, reconcile.ReconcileKey) error { return nil })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { worker.Run(ctx); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("worker did not stop after context cancellation")
	}
}

func TestWorkerUsesExecutionBarrier(t *testing.T) {
	q, _ := New(DefaultConfig())
	barrier := reconcile.NewCoordinationBarrier()
	done := make(chan struct{}, 1)
	worker, err := NewWorkerWithBarrier(q, func(context.Context, reconcile.ReconcileKey) error { done <- struct{}{}; return nil }, barrier)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go worker.Run(ctx)
	q.Add(workerKey())
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("barrier worker did not process item")
	}
	q.ShutDown()
}

func TestWorkerLogsClassifiedFailures(t *testing.T) {
	q, _ := New(Config{BaseDelay: time.Millisecond, MaxDelay: 10 * time.Millisecond})
	var output bytes.Buffer
	logger, err := observability.New(observability.LoggingConfig{Level: "debug", Component: "queue", Writer: &output, RateInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	worker, err := NewWorkerWithBarrierAndLogger(q, func(context.Context, reconcile.ReconcileKey) error {
		return reconcile.NewClassifiedError(reconcile.ErrorUnsupported, "CAPABILITY_UNSUPPORTED", 0, errors.New("unsupported"))
	}, nil, logger)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { worker.Run(ctx); close(done) }()
	q.Add(workerKey())
	time.Sleep(20 * time.Millisecond)
	q.ShutDown()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("worker did not stop")
	}
	lines := bytes.Split(bytes.TrimSpace(output.Bytes()), []byte{'\n'})
	if len(lines) < 2 {
		t.Fatalf("expected start and failure logs, output=%s", output.String())
	}
	var record map[string]any
	if err := json.Unmarshal(lines[len(lines)-1], &record); err != nil {
		t.Fatalf("invalid worker log: %v output=%s", err, output.String())
	}
	if record["reason"] != "CAPABILITY_UNSUPPORTED" || record["class"] != "Unsupported" || record["kind"] != "LocalEndpoint" {
		t.Fatalf("unexpected worker log: %#v", record)
	}
	if _, ok := record["reconcileKey"]; ok || strings.Contains(output.String(), "\x00") {
		t.Fatalf("worker log exposed queue key: %s", output.String())
	}
}

func TestWorkerLogsGenerationAttemptAndDuration(t *testing.T) {
	q, _ := New(Config{BaseDelay: time.Millisecond, MaxDelay: 10 * time.Millisecond})
	var output bytes.Buffer
	logger, err := observability.New(observability.LoggingConfig{Level: "debug", Component: "queue", Writer: &output, RateInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	worker, err := NewWorkerWithBarrierAndLoggerAndGeneration(q, func(context.Context, reconcile.ReconcileKey) error {
		return reconcile.NewClassifiedError(reconcile.ErrorUnsupported, "CAPABILITY_UNSUPPORTED", 0, errors.New("unsupported"))
	}, nil, logger, func() uint64 { return 42 })
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { worker.Run(ctx); close(done) }()
	q.Add(workerKey())
	time.Sleep(20 * time.Millisecond)
	q.ShutDown()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("worker did not stop")
	}
	lines := bytes.Split(bytes.TrimSpace(output.Bytes()), []byte{'\n'})
	var failure map[string]any
	for _, line := range lines {
		var record map[string]any
		if err := json.Unmarshal(line, &record); err != nil {
			t.Fatalf("invalid worker log: %v output=%s", err, output.String())
		}
		if record["msg"] == "reconcile failed" {
			failure = record
		}
	}
	if failure["generation"] != float64(42) || failure["attempt"] != float64(1) {
		t.Fatalf("missing correlation fields: %#v", failure)
	}
	if duration, ok := failure["duration"].(float64); !ok || duration <= 0 {
		t.Fatalf("missing duration: %#v", failure)
	}
}

func TestWorkerLogsRetryAttemptAndRecovery(t *testing.T) {
	q, _ := New(Config{BaseDelay: time.Millisecond, MaxDelay: 10 * time.Millisecond})
	var output bytes.Buffer
	logger, err := observability.New(observability.LoggingConfig{Level: "debug", Component: "queue", Writer: &output, RateInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	done := make(chan struct{}, 1)
	worker, err := NewWorkerWithBarrierAndLoggerAndGeneration(q, func(context.Context, reconcile.ReconcileKey) error {
		if calls.Add(1) == 1 {
			return reconcile.NewClassifiedError(reconcile.ErrorRetryable, "RETRY", 0, errors.New("temporary"))
		}
		done <- struct{}{}
		return nil
	}, nil, logger, func() uint64 { return 9 })
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	workerDone := make(chan struct{})
	go func() { worker.Run(ctx); close(workerDone) }()
	q.Add(workerKey())
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("worker did not recover after retry")
	}
	q.ShutDown()
	select {
	case <-workerDone:
	case <-time.After(time.Second):
		t.Fatal("worker did not stop")
	}
	var retry, completed map[string]any
	for _, line := range bytes.Split(bytes.TrimSpace(output.Bytes()), []byte{'\n'}) {
		var record map[string]any
		if err := json.Unmarshal(line, &record); err != nil {
			t.Fatalf("invalid worker log: %v output=%s", err, output.String())
		}
		switch record["msg"] {
		case "retry scheduled":
			retry = record
		case "reconcile completed":
			completed = record
		}
	}
	if retry["attempt"] != float64(1) || completed["attempt"] != float64(2) || completed["generation"] != float64(9) {
		t.Fatalf("retry correlation fields missing: retry=%#v completed=%#v", retry, completed)
	}
}

func TestNewWorkerWithBarrierAndLoggerReplacesTypedNilLogger(t *testing.T) {
	q, err := New(Config{BaseDelay: time.Millisecond, MaxDelay: 10 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	var typedNilLogger *observability.Logger
	worker, err := NewWorkerWithBarrierAndLogger(q, func(context.Context, reconcile.ReconcileKey) error { return nil }, nil, typedNilLogger)
	if err != nil {
		t.Fatal(err)
	}
	logger, ok := worker.logger.(*observability.Logger)
	if !ok || logger == nil {
		t.Fatalf("typed nil logger was not replaced: %#v", worker.logger)
	}
}
