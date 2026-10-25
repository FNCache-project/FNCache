package kubernetes

import (
	"context"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type APIHealth struct {
	Synced        bool
	LastProbeAt   time.Time
	LastProbeErr  error
	InformerError error
}

func (h APIHealth) FreshAt(now time.Time, maxStaleness time.Duration) bool {
	if !h.Synced || h.LastProbeAt.IsZero() || h.InformerError != nil || maxStaleness <= 0 {
		return false
	}
	age := now.Sub(h.LastProbeAt)
	return age >= 0 && age <= maxStaleness
}

// ProbeAPI verifies that both watched Kubernetes resources can still be read.
// It does not mutate the informer cache or any Kubernetes object.
func (s *InformerSource) ProbeAPI(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		s.recordProbeError(err)
		return err
	}
	if s.client == nil {
		err := fmt.Errorf("Kubernetes API client is unavailable")
		s.recordProbeError(err)
		return err
	}
	if _, err := s.client.CoreV1().Nodes().List(ctx, metav1.ListOptions{Limit: 1}); err != nil {
		err = fmt.Errorf("probe Node API: %w", err)
		s.recordProbeError(err)
		return err
	}
	if _, err := s.client.CoreV1().Pods("").List(ctx, metav1.ListOptions{Limit: 1}); err != nil {
		err = fmt.Errorf("probe Pod API: %w", err)
		s.recordProbeError(err)
		return err
	}
	s.healthMu.Lock()
	s.lastProbeAt = time.Now()
	s.lastProbeErr = nil
	s.healthMu.Unlock()
	return nil
}

func (s *InformerSource) Health() APIHealth {
	s.healthMu.RLock()
	health := APIHealth{Synced: s.synced, LastProbeAt: s.lastProbeAt, LastProbeErr: s.lastProbeErr}
	s.healthMu.RUnlock()
	health.InformerError = s.LastError()
	return health
}

func (s *InformerSource) recordProbeError(err error) {
	s.healthMu.Lock()
	s.lastProbeErr = err
	s.healthMu.Unlock()
}
