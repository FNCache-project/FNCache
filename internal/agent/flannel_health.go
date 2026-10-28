package agent

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cat-cc-Lcos/FNCache/internal/controlplane"
	"github.com/cat-cc-Lcos/FNCache/internal/hostnet/flannel"
)

var (
	ErrFlannelUnhealthy   = errors.New("FLANNEL_UNHEALTHY")
	ErrFlannelConfigDrift = errors.New("FLANNEL_CONFIG_DRIFT")
)

type FlannelHealthMonitorConfig struct {
	Source              controlplane.FlannelSource
	Request             flannel.DiscoveryRequest
	ExpectedFingerprint string
	Interval            time.Duration
}

type FlannelHealthMonitor struct {
	source              controlplane.FlannelSource
	request             flannel.DiscoveryRequest
	expectedFingerprint string
	interval            time.Duration
}

func NewFlannelHealthMonitor(config FlannelHealthMonitorConfig) (*FlannelHealthMonitor, error) {
	if config.Source == nil || config.ExpectedFingerprint == "" || config.Interval <= 0 {
		return nil, fmt.Errorf("Flannel health monitor dependencies are required")
	}
	return &FlannelHealthMonitor{source: config.Source, request: config.Request, expectedFingerprint: config.ExpectedFingerprint, interval: config.Interval}, nil
}

func (m *FlannelHealthMonitor) Check(ctx context.Context) error {
	current, err := m.source.Discover(ctx, m.request)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrFlannelUnhealthy, err)
	}
	if err := current.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrFlannelUnhealthy, err)
	}
	if current.Fingerprint != m.expectedFingerprint {
		return fmt.Errorf("%w: got %s want %s", ErrFlannelConfigDrift, current.Fingerprint, m.expectedFingerprint)
	}
	return nil
}

func (m *FlannelHealthMonitor) Run(ctx context.Context) error {
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
