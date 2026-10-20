//go:build linux

package resolver

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

const (
	RuntimeEndpointAuto         = "auto"
	runtimeEndpointProbeTimeout = 250 * time.Millisecond
)

var defaultContainerdEndpoints = []string{
	"unix:///host/run/k3s/containerd/containerd.sock",
	"unix:///host/run/containerd/containerd.sock",
	"unix:///run/k3s/containerd/containerd.sock",
	"unix:///run/containerd/containerd.sock",
}

type unixSocketDialer func(context.Context, string) (net.Conn, error)

func ResolveContainerdEndpoint(ctx context.Context, endpoint string) (string, error) {
	return resolveContainerdEndpoint(ctx, endpoint, defaultContainerdEndpoints, dialUnixSocket)
}

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
		path, err := unixSocketPath(candidate)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%q: %v", candidate, err))
			continue
		}
		probeCtx, cancel := context.WithTimeout(ctx, runtimeEndpointProbeTimeout)
		conn, dialErr := dial(probeCtx, path)
		cancel()
		if dialErr == nil {
			_ = conn.Close()
			return candidate, nil
		}
		failures = append(failures, fmt.Sprintf("%s: %v", path, dialErr))
	}
	return "", fmt.Errorf("auto containerd endpoint unavailable: %s", strings.Join(failures, "; "))
}

func dialUnixSocket(ctx context.Context, path string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "unix", path)
}
