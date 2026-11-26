package queue

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cat-cc-Lcos/FNCache/internal/observability"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

type Handler func(context.Context, reconcile.ReconcileKey) error
type GenerationProvider func() uint64

type ExecutionBarrier interface {
	Execute(context.Context, reconcile.ReconcileKey, func() error) error
}

type Worker struct {
	queue      *Queue
	handler    Handler
	barrier    ExecutionBarrier
	logger     observability.EventLogger
	generation GenerationProvider
	attempts   map[reconcile.ReconcileKey]int
}

func NewWorker(queue *Queue, handler Handler) (*Worker, error) {
	return NewWorkerWithBarrier(queue, handler, nil)
}

func NewWorkerWithBarrier(queue *Queue, handler Handler, barrier ExecutionBarrier) (*Worker, error) {
	return NewWorkerWithBarrierAndLogger(queue, handler, barrier, observability.NewDefault("queue"))
}

func NewWorkerWithBarrierAndLogger(queue *Queue, handler Handler, barrier ExecutionBarrier, logger observability.EventLogger) (*Worker, error) {
	return NewWorkerWithBarrierAndLoggerAndGeneration(queue, handler, barrier, logger, nil)
}

func NewWorkerWithBarrierAndLoggerAndGeneration(queue *Queue, handler Handler, barrier ExecutionBarrier, logger observability.EventLogger, generation GenerationProvider) (*Worker, error) {
	if queue == nil || handler == nil {
		return nil, fmt.Errorf("queue and handler are required")
	}
	if logger == nil {
		logger = observability.NewDefault("queue")
	}
	if typedLogger, ok := logger.(*observability.Logger); ok && typedLogger == nil {
		logger = observability.NewDefault("queue")
	}
	return &Worker{queue: queue, handler: handler, barrier: barrier, logger: logger, generation: generation, attempts: make(map[reconcile.ReconcileKey]int)}, nil
}

func (w *Worker) Run(ctx context.Context) {
	stopWatcher := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			w.queue.ShutDown()
		case <-stopWatcher:
		}
	}()
	defer close(stopWatcher)

	for {
		key, shutdown := w.queue.Get()
		if shutdown {
			return
		}
		attempt := w.attempts[key] + 1
		w.attempts[key] = attempt
		generation := uint64(0)
		if w.generation != nil {
			generation = w.generation()
		}
		started := time.Now()
		w.logger.LogEvent(ctx, reconcileStartedEvent(key, generation, attempt))
		var err error
		if w.barrier != nil {
			err = w.barrier.Execute(ctx, key, func() error { return w.handler(ctx, key) })
		} else {
			err = w.handler(ctx, key)
		}
		duration := time.Since(started)
		decision := retryResult{}
		if err != nil {
			decision = retryDecision(err)
		}
		if err == nil {
			w.logger.LogEvent(ctx, reconcileSucceededEvent(key, generation, attempt, duration))
		} else if ctx.Err() == nil {
			w.logger.LogEvent(ctx, reconcileFailureEvent(key, err, generation, attempt, duration))
			if decision.retry {
				delay := decision.after
				w.logger.LogEvent(ctx, retryScheduledEvent(key, err, generation, attempt, duration, delay))
			}
		}
		switch {
		case err == nil || ctx.Err() != nil:
			w.queue.Forget(key)
			delete(w.attempts, key)
		case decision.retry:
			if delay := decision.after; delay > 0 {
				w.queue.AddAfter(key, delay)
			} else {
				w.queue.AddRateLimited(key)
			}
		default:
			w.queue.Forget(key)
			delete(w.attempts, key)
		}
		w.queue.Done(key)
	}
}

type retryResult struct {
	retry bool
	after time.Duration
}

func retryDecision(err error) retryResult {
	var classified *reconcile.ClassifiedError
	if !errors.As(err, &classified) {
		return retryResult{retry: true}
	}
	switch classified.Class() {
	case reconcile.ErrorRetryable, reconcile.ErrorInternal:
		return retryResult{retry: true, after: classified.RetryAfter()}
	default:
		return retryResult{}
	}
}
