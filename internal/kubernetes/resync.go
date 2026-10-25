package kubernetes

import (
	"context"
	"fmt"
	"time"

	"github.com/cat-cc-Lcos/FNCache/internal/kubernetes/queue"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

const ReasonPeriodicResync = "PERIODIC_RESYNC"

type ResyncScheduler struct {
	store     *SnapshotStore
	localNode string
	queue     *queue.Queue
	interval  time.Duration
}

func NewResyncScheduler(store *SnapshotStore, localNode string, target *queue.Queue, interval time.Duration) (*ResyncScheduler, error) {
	if store == nil || target == nil || localNode == "" || interval <= 0 {
		return nil, fmt.Errorf("resync store, local node, queue and positive interval are required")
	}
	return &ResyncScheduler{store: store, localNode: localNode, queue: target, interval: interval}, nil
}

func (s *ResyncScheduler) ResyncOnce(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	snapshot := s.store.Snapshot()
	s.queue.Add(reconcile.ReconcileKey{Kind: reconcile.ReconcileGlobal, Name: s.localNode, Reason: ReasonPeriodicResync})
	for _, pod := range snapshot.Pods {
		if pod.NodeName == "" || pod.HostNetwork || pod.Deleting {
			continue
		}
		kind := reconcile.ReconcileRemoteEndpoint
		if pod.NodeName == s.localNode {
			kind = reconcile.ReconcileLocalEndpoint
		}
		s.queue.Add(reconcile.ReconcileKey{Kind: kind, Namespace: pod.Identity.Namespace, Name: pod.Identity.Name, UID: pod.Identity.UID, Reason: ReasonPeriodicResync})
	}
	return nil
}

func (s *ResyncScheduler) Run(ctx context.Context) {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			_ = s.ResyncOnce(ctx)
		case <-ctx.Done():
			return
		}
	}
}
