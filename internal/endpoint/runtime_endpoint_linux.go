//go:build linux

package endpoint

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

const (
	// RuntimeEndpointAuto asks the resolver to probe supported containerd socket paths.
	RuntimeEndpointAuto         = "auto"
	runtimeEndpointProbeTimeout = 250 * time.Millisecond
)

var (
	// ErrContainerdEndpointNotReady indicates that auto discovery found no reachable socket yet.
	ErrContainerdEndpointNotReady = errors.New("containerd endpoint not ready")
)

var defaultContainerdEndpoints = []string{
	"unix:///host/run/k3s/containerd/containerd.sock",
	"unix:///host/run/containerd/containerd.sock",
	"unix:///run/k3s/containerd/containerd.sock",
	"unix:///run/containerd/containerd.sock",
}

type unixSocketDialer func(context.Context, string) (net.Conn, error)

// ResolveContainerdEndpoint returns an explicit endpoint or the first reachable supported socket.
func ResolveContainerdEndpoint(ctx context.Context, endpoint string) (string, error) {
	return resolveContainerdEndpoint(ctx, endpoint, defaultContainerdEndpoints, dialUnixSocket)
}

// resolveContainerdEndpoint probes candidates with a bounded timeout while preserving cancellation.
func resolveContainerdEndpoint(ctx context.Context, endpoint string, candidates []string, dial unixSocketDialer) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if endpoint != RuntimeEndpointAuto {
		if _, err := unixSocketPath(endpoint); err != nil {
			return "", err
		}
		return endpoint, nil
	}
	if dial == nil {
		return "", fmt.Errorf("containerd endpoint dialer is required")
	}

	failures := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		path, err := unixSocketPath(candidate)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%q: %v", candidate, err))
			continue
		}
		probeCtx, cancel := context.WithTimeout(ctx, runtimeEndpointProbeTimeout)
		conn, dialErr := dial(probeCtx, path)
		cancel()
		if dialErr == nil && conn != nil {
			_ = conn.Close()
			return candidate, nil
		}
		if dialErr == nil {
			dialErr = errors.New("dialer returned nil connection")
		}
		if err := ctx.Err(); err != nil {
			return "", err
		}
		failures = append(failures, fmt.Sprintf("%s: %v", path, dialErr))
	}
	return "", fmt.Errorf("%w: %s", ErrContainerdEndpointNotReady, strings.Join(failures, "; "))
}

// dialUnixSocket opens a Unix socket for endpoint discovery.
func dialUnixSocket(ctx context.Context, path string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "unix", path)
}
