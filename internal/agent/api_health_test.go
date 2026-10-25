package agent

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cat-cc-Lcos/FNCache/internal/kubernetes"
)

type fakeAPIHealthSource struct {
	health   kubernetes.APIHealth
	probeErr error
}

func (s *fakeAPIHealthSource) ProbeAPI(context.Context) error {
	s.health.LastProbeErr = s.probeErr
	if s.probeErr == nil {
		s.health.LastProbeAt = time.Unix(100, 0)
	}
	return s.probeErr
}

func (s *fakeAPIHealthSource) Health() kubernetes.APIHealth { return s.health }

func newAPIHealthMonitor(t *testing.T, source APIHealthSource, now time.Time) *APIHealthMonitor {
	t.Helper()
	monitor, err := NewAPIHealthMonitor(APIHealthMonitorConfig{Source: source, Interval: time.Second, MaxStaleness: time.Second, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	return monitor
}

func TestAPIHealthMonitorFreshUsesLastSuccessfulProbe(t *testing.T) {
	source := &fakeAPIHealthSource{health: kubernetes.APIHealth{Synced: true, LastProbeAt: time.Unix(100, 0)}}
	if err := newAPIHealthMonitor(t, source, time.Unix(100, int64(500*time.Millisecond))).Fresh(context.Background()); err != nil {
		t.Fatalf("fresh API was rejected: %v", err)
	}
	stale := newAPIHealthMonitor(t, source, time.Unix(102, 0))
	if err := stale.Fresh(context.Background()); !errors.Is(err, ErrKubernetesAPIStale) {
		t.Fatalf("stale API error = %v, want ErrKubernetesAPIStale", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := stale.Fresh(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled freshness check = %v, want context.Canceled", err)
	}
}

func TestAPIHealthMonitorAllowsRecentProbeFailure(t *testing.T) {
	source := &fakeAPIHealthSource{health: kubernetes.APIHealth{Synced: true, LastProbeAt: time.Unix(100, 0)}, probeErr: errors.New("temporary API failure")}
	if err := newAPIHealthMonitor(t, source, time.Unix(100, int64(500*time.Millisecond))).Check(context.Background()); err != nil {
		t.Fatalf("recent API failure caused degradation: %v", err)
	}
}

func TestAPIHealthMonitorReportsStaleAPI(t *testing.T) {
	source := &fakeAPIHealthSource{health: kubernetes.APIHealth{Synced: true, LastProbeAt: time.Unix(100, 0)}, probeErr: errors.New("API unavailable")}
	monitor, err := NewAPIHealthMonitor(APIHealthMonitorConfig{Source: source, Interval: time.Second, MaxStaleness: time.Second, Now: func() time.Time { return time.Unix(102, 0) }})
	if err != nil {
		t.Fatal(err)
	}
	if err := monitor.Check(context.Background()); !errors.Is(err, ErrKubernetesAPIStale) {
		t.Fatalf("error = %v, want ErrKubernetesAPIStale", err)
	}
}

func TestAPIHealthMonitorHonorsCancellation(t *testing.T) {
	source := &fakeAPIHealthSource{health: kubernetes.APIHealth{Synced: true, LastProbeAt: time.Unix(100, 0)}}
	monitor := newAPIHealthMonitor(t, source, time.Unix(100, 0))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := monitor.Check(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}
