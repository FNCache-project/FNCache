//go:build linux

package resolver

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
)

func TestResolveContainerdEndpointPrefersFirstReachableCandidate(t *testing.T) {
	var attempts []string
	candidates := []string{
		"unix:///host/run/k3s/containerd/containerd.sock",
		"unix:///host/run/containerd/containerd.sock",
	}
	got, err := resolveContainerdEndpoint(context.Background(), RuntimeEndpointAuto, candidates, func(_ context.Context, path string) (net.Conn, error) {
		attempts = append(attempts, path)
		if strings.HasSuffix(path, "/containerd/containerd.sock") && !strings.Contains(path, "/k3s/") {
			left, right := net.Pipe()
			_ = right.Close()
			return left, nil
		}
		return nil, errors.New("socket unavailable")
	})
	if err != nil || got != candidates[1] {
		t.Fatalf("resolved endpoint = %q err=%v, want %q", got, err, candidates[1])
	}
	if len(attempts) != 2 {
		t.Fatalf("dial attempts = %d, want 2", len(attempts))
	}
}

func TestResolveContainerdEndpointReturnsExplicitEndpoint(t *testing.T) {
	const endpoint = "unix:///host/run/containerd/containerd.sock"
	got, err := resolveContainerdEndpoint(context.Background(), endpoint, nil, nil)
	if err != nil || got != endpoint {
		t.Fatalf("resolved endpoint = %q err=%v, want %q", got, err, endpoint)
	}
}

func TestResolveContainerdEndpointReportsMissingAutoCandidates(t *testing.T) {
	_, err := resolveContainerdEndpoint(context.Background(), RuntimeEndpointAuto, []string{"unix:///missing/containerd.sock"}, func(context.Context, string) (net.Conn, error) {
		return nil, errors.New("missing")
	})
	if err == nil || !errors.Is(err, ErrContainerdEndpointNotReady) {
		t.Fatalf("expected auto discovery error, got %v", err)
	}
}

func TestResolveContainerdEndpointHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := resolveContainerdEndpoint(ctx, RuntimeEndpointAuto, []string{"unix:///missing/containerd.sock"}, func(context.Context, string) (net.Conn, error) {
		return nil, errors.New("missing")
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("endpoint discovery error = %v, want context canceled", err)
	}
}
