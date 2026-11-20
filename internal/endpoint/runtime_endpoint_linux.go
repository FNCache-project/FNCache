//go:build linux

package endpoint

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	// RuntimeEndpointAuto asks the resolver to probe supported containerd socket paths.
	RuntimeEndpointAuto         = "auto"
	runtimeEndpointProbeTimeout = 250 * time.Millisecond
)

var (
	// ErrContainerdEndpointNotReady indicates that auto discovery found no usable CRI endpoint yet.
	ErrContainerdEndpointNotReady = errors.New("containerd endpoint not ready")
)

var defaultContainerdEndpoints = []string{
	"unix:///host/run/k3s/containerd/containerd.sock",
	"unix:///host/run/containerd/containerd.sock",
	"unix:///run/k3s/containerd/containerd.sock",
	"unix:///run/containerd/containerd.sock",
}

type unixSocketProbe func(context.Context, string) error

// ResolveContainerdEndpoint returns an explicit endpoint or the first usable supported CRI socket.
func ResolveContainerdEndpoint(ctx context.Context, endpoint string) (string, error) {
	return resolveContainerdEndpoint(ctx, endpoint, defaultContainerdEndpoints, probeContainerdCRI)
}

// resolveContainerdEndpoint probes candidates with a bounded timeout while preserving cancellation.
func resolveContainerdEndpoint(ctx context.Context, endpoint string, candidates []string, probe unixSocketProbe) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if endpoint != RuntimeEndpointAuto {
		if _, err := unixSocketPath(endpoint); err != nil {
			return "", err
		}
		return endpoint, nil
	}
	if probe == nil {
		return "", fmt.Errorf("containerd endpoint probe is required")
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
		probeErr := probe(probeCtx, path)
		cancel()
		if probeErr == nil {
			return candidate, nil
		}
		if err := ctx.Err(); err != nil {
			return "", err
		}
		failures = append(failures, fmt.Sprintf("%s: %v", path, probeErr))
	}
	return "", fmt.Errorf("%w: %s", ErrContainerdEndpointNotReady, strings.Join(failures, "; "))
}
