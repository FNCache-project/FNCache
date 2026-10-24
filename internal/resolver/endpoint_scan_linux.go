//go:build linux

package resolver

import (
	"context"
	"errors"
	"fmt"
)

type EndpointScanResult struct {
	Endpoints map[string]Endpoint
	Skipped   map[string]error
}

type EndpointScanner struct {
	resolver EndpointResolver
}

func NewEndpointScanner(resolver EndpointResolver) (*EndpointScanner, error) {
	if resolver == nil {
		return nil, fmt.Errorf("endpoint resolver is required")
	}
	return &EndpointScanner{resolver: resolver}, nil
}

func (s *EndpointScanner) Scan(ctx context.Context, pods []PodSnapshot) (EndpointScanResult, error) {
	result := EndpointScanResult{Endpoints: make(map[string]Endpoint), Skipped: make(map[string]error)}
	seen := make(map[string]PodSnapshot, len(pods))
	for _, pod := range pods {
		if err := ctx.Err(); err != nil {
			return EndpointScanResult{}, err
		}
		uid := pod.Identity.UID
		if previous, ok := seen[uid]; ok {
			if samePodSnapshot(previous, pod) {
				continue
			}
			return EndpointScanResult{}, fmt.Errorf("duplicate Pod UID with different snapshots: %s", uid)
		}
		seen[uid] = pod
		if pod.Deleting || pod.HostNetwork || pod.Phase == "Succeeded" || pod.Phase == "Failed" {
			continue
		}
		if !IsEndpointPhaseReady(pod.Phase) {
			result.Skipped[uid] = fmt.Errorf("%w: pod phase is %s", ErrEndpointNotReady, pod.Phase)
			continue
		}
		endpoint, err := s.resolver.Resolve(ctx, pod)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return EndpointScanResult{}, err
			}
			if isEndpointSkipError(err) {
				result.Skipped[uid] = err
				continue
			}
			return EndpointScanResult{}, fmt.Errorf("resolve local endpoint %s: %w", uid, err)
		}
		if err := s.resolver.Validate(ctx, endpoint); err != nil {
			if isEndpointSkipError(err) {
				result.Skipped[uid] = err
				continue
			}
			return EndpointScanResult{}, fmt.Errorf("validate local endpoint %s: %w", uid, err)
		}
		if endpoint.Pod.UID != uid {
			return EndpointScanResult{}, fmt.Errorf("endpoint identity mismatch: got %s want %s", endpoint.Pod.UID, uid)
		}
		result.Endpoints[uid] = endpoint
	}
	return result, nil
}

func isEndpointSkipError(err error) bool {
	return errors.Is(err, ErrEndpointNotReady) || errors.Is(err, ErrStaleObject) || errors.Is(err, ErrUnsupported)
}

func samePodSnapshot(a, b PodSnapshot) bool {
	return a.Identity == b.Identity && a.NodeName == b.NodeName && a.PodIPv4 == b.PodIPv4 &&
		a.HostNetwork == b.HostNetwork && a.Phase == b.Phase && a.Deleting == b.Deleting &&
		a.ResourceVersion == b.ResourceVersion
}
