package queue

import (
	"fmt"
	"math/rand"
	"sync"
	"time"

	"k8s.io/client-go/util/workqueue"

	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

const (
	defaultBaseDelay = 100 * time.Millisecond
	defaultMaxDelay  = 30 * time.Second
	defaultJitter    = 0.10
)

type Config struct {
	BaseDelay time.Duration
	MaxDelay  time.Duration
	Jitter    float64
	Random    func() float64
}

func DefaultConfig() Config {
	return Config{BaseDelay: defaultBaseDelay, MaxDelay: defaultMaxDelay, Jitter: defaultJitter}
}

type Queue struct {
	inner workqueue.TypedRateLimitingInterface[reconcile.ReconcileKey]
}

func New(config Config) (*Queue, error) {
	if config.BaseDelay <= 0 || config.MaxDelay < config.BaseDelay {
		return nil, fmt.Errorf("queue delays are invalid")
	}
	if config.Jitter < 0 || config.Jitter > 1 {
		return nil, fmt.Errorf("queue jitter must be between 0 and 1")
	}
	if config.Random == nil {
		config.Random = rand.Float64
	}
	limiter := &jitterRateLimiter{
		base:   workqueue.NewTypedItemExponentialFailureRateLimiter[reconcile.ReconcileKey](config.BaseDelay, config.MaxDelay),
		jitter: config.Jitter, random: config.Random,
	}
	return &Queue{inner: workqueue.NewTypedRateLimitingQueue(limiter)}, nil
}

func (q *Queue) Add(key reconcile.ReconcileKey) { q.inner.Add(normalize(key)) }

func (q *Queue) AddAfter(key reconcile.ReconcileKey, delay time.Duration) {
	q.inner.AddAfter(normalize(key), delay)
}

func (q *Queue) AddRateLimited(key reconcile.ReconcileKey) { q.inner.AddRateLimited(normalize(key)) }

func (q *Queue) Get() (reconcile.ReconcileKey, bool) { return q.inner.Get() }

func (q *Queue) Done(key reconcile.ReconcileKey) { q.inner.Done(normalize(key)) }

func (q *Queue) Forget(key reconcile.ReconcileKey) { q.inner.Forget(normalize(key)) }

func (q *Queue) NumRequeues(key reconcile.ReconcileKey) int {
	return q.inner.NumRequeues(normalize(key))
}

func (q *Queue) Len() int { return q.inner.Len() }

func (q *Queue) ShutDown() { q.inner.ShutDown() }

func (q *Queue) ShutDownWithDrain() { q.inner.ShutDownWithDrain() }

func (q *Queue) ShuttingDown() bool { return q.inner.ShuttingDown() }

func normalize(key reconcile.ReconcileKey) reconcile.ReconcileKey {
	key.Reason = ""
	return key
}

type jitterRateLimiter struct {
	base   workqueue.TypedRateLimiter[reconcile.ReconcileKey]
	jitter float64
	random func() float64
	mu     sync.Mutex
}

func (r *jitterRateLimiter) When(key reconcile.ReconcileKey) time.Duration {
	delay := r.base.When(key)
	if r.jitter == 0 {
		return delay
	}
	r.mu.Lock()
	value := r.random()
	r.mu.Unlock()
	if value < 0 {
		value = 0
	} else if value > 1 {
		value = 1
	}
	factor := 1 + (2*value-1)*r.jitter
	return time.Duration(float64(delay) * factor)
}

func (r *jitterRateLimiter) Forget(key reconcile.ReconcileKey) { r.base.Forget(key) }

func (r *jitterRateLimiter) NumRequeues(key reconcile.ReconcileKey) int {
	return r.base.NumRequeues(key)
}
