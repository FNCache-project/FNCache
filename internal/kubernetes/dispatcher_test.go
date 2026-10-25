package kubernetes

import (
	"context"
	"testing"
	"time"

	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"

	"github.com/cat-cc-Lcos/FNCache/internal/kubernetes/queue"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

func TestEventDispatcherEnqueuesInformerAndMigrationEvents(t *testing.T) {
	client := fake.NewSimpleClientset(informerPod(), informerNode())
	store := NewSnapshotStore()
	source, err := NewInformerSource(client, store, 0)
	if err != nil {
		t.Fatal(err)
	}
	classifier, _ := NewEventClassifier("node-a")
	target, _ := queue.New(queue.DefaultConfig())
	dispatcher, err := NewEventDispatcher(source, classifier, target)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go source.Run(ctx)
	syncCtx, syncCancel := context.WithTimeout(context.Background(), time.Second)
	defer syncCancel()
	if err := source.WaitForSync(syncCtx); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return target.Len() == 2 })
	keys := drainDispatchQueue(target)
	if !hasKind(keys, reconcile.ReconcileLocalEndpoint) || !hasKind(keys, reconcile.ReconcileGlobal) {
		t.Fatalf("initial event keys = %#v", keys)
	}
	oldPod := informerPod()
	newPod := oldPod.DeepCopy()
	newPod.Spec.NodeName = "node-b"
	dispatcher.updatePod(oldPod, newPod)
	waitFor(t, func() bool { return target.Len() == 2 })
	keys = drainDispatchQueue(target)
	if len(keys) != 2 || !hasKind(keys, reconcile.ReconcileLocalEndpoint) || !hasKind(keys, reconcile.ReconcileRemoteEndpoint) {
		t.Fatalf("migration event keys = %#v", keys)
	}
}

func TestInformerSourceUpdatesSnapshotBeforeDispatch(t *testing.T) {
	store := NewSnapshotStore()
	pod := informerPod()
	if err := store.UpsertPod(resolverPodSnapshot(pod)); err != nil {
		t.Fatal(err)
	}
	source, err := NewInformerSource(fake.NewSimpleClientset(), store, 0)
	if err != nil {
		t.Fatal(err)
	}
	classifier, _ := NewEventClassifier("node-a")
	target, _ := queue.New(queue.DefaultConfig())
	t.Cleanup(target.ShutDown)
	if _, err := NewEventDispatcher(source, classifier, target); err != nil {
		t.Fatal(err)
	}

	var snapshotPresentDuringDispatch bool
	source.eventMu.Lock()
	dispatch := source.podEventHandler
	if dispatch == nil {
		source.eventMu.Unlock()
		t.Fatal("Pod event handler was not attached")
	}
	source.podEventHandler = func(oldObj, newObj interface{}) {
		_, snapshotPresentDuringDispatch = store.GetPod(string(pod.UID))
		dispatch(oldObj, newObj)
	}
	source.eventMu.Unlock()

	source.deletePod(pod)
	if snapshotPresentDuringDispatch {
		t.Fatal("Pod snapshot was present during dispatch")
	}
	if _, ok := store.GetPod(string(pod.UID)); ok {
		t.Fatal("Pod snapshot was not removed before dispatch")
	}
	if target.Len() != 1 {
		t.Fatalf("dispatch queue length = %d, want 1", target.Len())
	}
	key, shutdown := target.Get()
	if shutdown || key.Kind != reconcile.ReconcileLocalEndpoint || key.UID != string(pod.UID) {
		t.Fatalf("delete key = %#v shutdown=%v", key, shutdown)
	}
	target.Forget(key)
	target.Done(key)
}

func TestEventDispatcherHandlesTombstone(t *testing.T) {
	source, err := NewInformerSource(fake.NewSimpleClientset(), NewSnapshotStore(), 0)
	if err != nil {
		t.Fatal(err)
	}
	classifier, _ := NewEventClassifier("node-a")
	target, _ := queue.New(queue.DefaultConfig())
	dispatcher, err := NewEventDispatcher(source, classifier, target)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher.deletePod(cache.DeletedFinalStateUnknown{Key: "default/web", Obj: informerPod()})
	if target.Len() != 1 {
		t.Fatalf("tombstone queue length = %d", target.Len())
	}
	key, shutdown := target.Get()
	if shutdown || key.Kind != reconcile.ReconcileLocalEndpoint {
		t.Fatalf("tombstone key = %#v shutdown=%v", key, shutdown)
	}
	target.Forget(key)
	target.Done(key)
	target.ShutDown()
}

func drainDispatchQueue(target *queue.Queue) []reconcile.ReconcileKey {
	keys := make([]reconcile.ReconcileKey, 0, target.Len())
	for target.Len() > 0 {
		key, shutdown := target.Get()
		if shutdown {
			break
		}
		keys = append(keys, key)
		target.Forget(key)
		target.Done(key)
	}
	return keys
}

func hasKind(keys []reconcile.ReconcileKey, want reconcile.ReconcileKind) bool {
	for _, key := range keys {
		if key.Kind == want {
			return true
		}
	}
	return false
}
