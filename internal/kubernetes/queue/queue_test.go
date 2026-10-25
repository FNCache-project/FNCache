package queue

import (
	"testing"
	"time"

	"k8s.io/client-go/util/workqueue"

	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

func queueKey(reason string) reconcile.ReconcileKey {
	return reconcile.ReconcileKey{Kind: reconcile.ReconcileLocalEndpoint, Namespace: "default", Name: "web", UID: "pod-1", Reason: reason}
}

func TestQueueDeduplicatesByQueueKey(t *testing.T) {
	q, err := New(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	q.Add(queueKey("POD_ADDED"))
	q.Add(queueKey("POD_IP_CHANGED"))
	if q.Len() != 1 {
		t.Fatalf("queue length = %d, want 1", q.Len())
	}
	got, shutdown := q.Get()
	if shutdown || got.Reason != "" || got.QueueKey() != queueKey("").QueueKey() {
		t.Fatalf("got key=%#v shutdown=%v", got, shutdown)
	}
	q.Forget(got)
	q.Done(got)
}

func TestQueueSeparatesResourcesAndForgetResetsRetries(t *testing.T) {
	q, err := New(Config{BaseDelay: time.Millisecond, MaxDelay: 10 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	a := queueKey("A")
	b := a
	b.UID = "pod-2"
	q.Add(a)
	q.Add(b)
	if q.Len() != 2 {
		t.Fatalf("queue length = %d, want 2", q.Len())
	}
	q.AddRateLimited(a)
	if q.NumRequeues(a) != 1 {
		t.Fatalf("requeues = %d, want 1", q.NumRequeues(a))
	}
	q.Forget(a)
	if q.NumRequeues(a) != 0 {
		t.Fatalf("requeues after Forget = %d, want 0", q.NumRequeues(a))
	}
	q.ShutDown()
}

func TestJitterRateLimiterUsesExponentialBounds(t *testing.T) {
	values := []float64{0, 1, 0.5}
	index := 0
	limiter := &jitterRateLimiter{
		base:   workqueue.NewTypedItemExponentialFailureRateLimiter[reconcile.ReconcileKey](100*time.Millisecond, time.Second),
		jitter: 0.1,
		random: func() float64 {
			value := values[index]
			index++
			return value
		},
	}
	key := queueKey("")
	if got := limiter.When(key); got != 90*time.Millisecond {
		t.Fatalf("minimum jitter delay = %s, want 90ms", got)
	}
	if got := limiter.When(key); got != 220*time.Millisecond {
		t.Fatalf("maximum jitter delay = %s, want 220ms", got)
	}
	if got := limiter.When(key); got != 400*time.Millisecond {
		t.Fatalf("center jitter delay = %s, want 400ms", got)
	}
}

func TestQueueShutdown(t *testing.T) {
	q, err := New(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	q.ShutDown()
	if !q.ShuttingDown() {
		t.Fatal("queue did not report shutdown")
	}
	if _, shutdown := q.Get(); !shutdown {
		t.Fatal("Get did not report shutdown")
	}
}
