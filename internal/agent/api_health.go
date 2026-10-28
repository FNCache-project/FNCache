package agent

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cat-cc-Lcos/FNCache/internal/kubernetes"
)

var ErrKubernetesAPIStale = errors.New("kubernetes API is stale")

type APIHealthSource interface {
	ProbeAPI(context.Context) error
	Health() kubernetes.APIHealth
}

type APIHealthMonitorConfig struct {
	Source       APIHealthSource
	Interval     time.Duration
	MaxStaleness time.Duration
	Now          func() time.Time
}

type APIHealthMonitor struct {
	source       APIHealthSource
	interval     time.Duration
	maxStaleness time.Duration
	now          func() time.Time
}

func NewAPIHealthMonitor(config APIHealthMonitorConfig) (*APIHealthMonitor, error) {
	if config.Source == nil || config.Interval <= 0 || config.MaxStaleness <= 0 {
		return nil, fmt.Errorf("API health monitor dependencies are required")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &APIHealthMonitor{source: config.Source, interval: config.Interval, maxStaleness: config.MaxStaleness, now: config.Now}, nil
}

// Fresh reports whether the most recent successful API observation is still
// within the configured staleness window without issuing another probe.
func (m *APIHealthMonitor) Fresh(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if m.source.Health().FreshAt(m.now(), m.maxStaleness) {
		return nil
	}
	return ErrKubernetesAPIStale
}

func (m *APIHealthMonitor) Check(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	probeErr := m.source.ProbeAPI(ctx)
	if err := ctx.Err(); err != nil {
		return err
	}
	if m.source.Health().FreshAt(m.now(), m.maxStaleness) {
		return nil
	}
	if probeErr != nil {
		return fmt.Errorf("%w: %v", ErrKubernetesAPIStale, probeErr)
	}
	return ErrKubernetesAPIStale
}

func (m *APIHealthMonitor) Run(ctx context.Context) error {
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := m.Check(ctx); err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return err
			}
		}
	}
}
