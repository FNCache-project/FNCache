package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/cat-cc-Lcos/FNCache/internal/kube"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
	"github.com/cat-cc-Lcos/FNCache/internal/resolver"
)

type localDesiredSource interface {
	Desired(context.Context) (reconcile.DesiredState, error)
}

type localStateScanner interface {
	Scan(context.Context) (reconcile.ActualState, error)
}

type localControl interface {
	Disable(context.Context) error
}

type localEndpointEnsurer interface {
	EnsureEndpoint(context.Context, reconcile.DesiredState, reconcile.ActualState, resolver.Endpoint) (bool, error)
}

type localMapEnsurer interface {
	EnsureEndpointMaps(context.Context, reconcile.DesiredState, reconcile.ActualState, resolver.Endpoint, bool) (bool, error)
}

type localPublisher interface {
	CommitAndPublish(context.Context, reconcile.DesiredState, reconcile.ActualState) error
}

type LocalEndpointHandlerConfig struct {
	Store     *kube.SnapshotStore
	Resolver  resolver.EndpointResolver
	LocalNode string
	Desired   localDesiredSource
	Scanner   localStateScanner
	Control   localControl
	Endpoint  localEndpointEnsurer
	Maps      localMapEnsurer
	Remover   localEndpointRemover
	Publisher localPublisher
}

type LocalEndpointHandler struct {
	config LocalEndpointHandlerConfig
}

func NewLocalEndpointHandler(config LocalEndpointHandlerConfig) (*LocalEndpointHandler, error) {
	if config.Store == nil || config.Resolver == nil || config.LocalNode == "" || config.Desired == nil || config.Scanner == nil || config.Control == nil || config.Endpoint == nil || config.Maps == nil || config.Remover == nil || config.Publisher == nil {
		return nil, fmt.Errorf("local endpoint handler dependencies are required")
	}
	return &LocalEndpointHandler{config: config}, nil
}

func (h *LocalEndpointHandler) Handle(ctx context.Context, key reconcile.ReconcileKey) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if key.Kind != reconcile.ReconcileLocalEndpoint {
		return nil
	}
	snapshot := h.config.Store.Snapshot()
	pod, ok := snapshot.Pods[key.UID]
	if !ok || pod.NodeName != h.config.LocalNode || pod.HostNetwork || pod.Deleting {
		return nil
	}
	if err := h.config.Control.Disable(ctx); err != nil {
		return fmt.Errorf("disable fast path: %w", err)
	}
	endpoint, err := h.config.Resolver.Resolve(ctx, pod)
	if err != nil {
		return classifyEndpointError(err)
	}
	base, err := h.config.Desired.Desired(ctx)
	if err != nil {
		return fmt.Errorf("read desired state: %w", err)
	}
	if !base.Enabled {
		if !base.Capability.Supported {
			return reconcile.NewClassifiedError(reconcile.ErrorUnsupported, reconcile.ReasonCapabilityUnsupported, 0, nil)
		}
		return reconcile.NewClassifiedError(reconcile.ErrorRetryable, reconcile.ReasonDatapathNotReady, 0, nil)
	}
	resolved := make(map[string]resolver.Endpoint, len(base.LocalEndpoints)+1)
	for uid, existing := range base.LocalEndpoints {
		resolved[uid] = existing
	}
	resolved[pod.Identity.UID] = endpoint
	desired, err := kube.BuildDesiredState(snapshot, base, h.config.LocalNode, resolved)
	if err != nil {
		return fmt.Errorf("build local desired state: %w", err)
	}
	actual, err := h.config.Scanner.Scan(ctx)
	if err != nil {
		return fmt.Errorf("scan before local endpoint ensure: %w", err)
	}
	if previous, ok := base.LocalEndpoints[pod.Identity.UID]; ok && endpointIdentityChanged(previous, endpoint) {
		if err := h.config.Remover.Remove(ctx, ownedEndpointFromResolver(previous), actual, desired); err != nil {
			return fmt.Errorf("remove previous local endpoint identity: %w", err)
		}
		actual, err = h.config.Scanner.Scan(ctx)
		if err != nil {
			return fmt.Errorf("scan after previous endpoint removal: %w", err)
		}
	}
	if _, err := h.config.Endpoint.EnsureEndpoint(ctx, desired, actual, endpoint); err != nil {
		return fmt.Errorf("ensure local endpoint: %w", err)
	}
	if _, err := h.config.Maps.EnsureEndpointMaps(ctx, desired, actual, endpoint, true); err != nil {
		return fmt.Errorf("ensure local endpoint Maps: %w", err)
	}
	actual, err = h.config.Scanner.Scan(ctx)
	if err != nil {
		return fmt.Errorf("scan after local endpoint ensure: %w", err)
	}
	if err := h.config.Publisher.CommitAndPublish(ctx, desired, actual); err != nil {
		return fmt.Errorf("publish local endpoint: %w", err)
	}
	return nil
}

func endpointIdentityChanged(previous, current resolver.Endpoint) bool {
	return previous.Pod != current.Pod || previous.Node != current.Node || previous.PodIPv4 != current.PodIPv4 ||
		previous.NetNSInode != current.NetNSInode || !sameLocalLinkIdentity(previous.PeerLink, current.PeerLink) ||
		!sameLocalLinkIdentity(previous.HostLink, current.HostLink)
}

func sameLocalLinkIdentity(previous, current resolver.LinkIdentity) bool {
	return previous.NetNSInode == current.NetNSInode && previous.IfIndex == current.IfIndex && previous.IfName == current.IfName && bytes.Equal(previous.MAC, current.MAC)
}

func ownedEndpointFromResolver(endpoint resolver.Endpoint) reconcile.OwnedEndpoint {
	return reconcile.OwnedEndpoint{PodUID: endpoint.Pod.UID, PodIPv4: endpoint.PodIPv4, NetNSInode: endpoint.NetNSInode, PeerIfIndex: endpoint.PeerLink.IfIndex, HostIfIndex: endpoint.HostLink.IfIndex}
}

func classifyEndpointError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	switch {
	case errors.Is(err, resolver.ErrEndpointNotReady):
		return reconcile.NewClassifiedError(reconcile.ErrorRetryable, reconcile.ReasonEndpointNotReady, 0, err)
	case errors.Is(err, resolver.ErrStaleObject):
		return reconcile.NewClassifiedError(reconcile.ErrorStale, "STALE_ENDPOINT", 0, err)
	case errors.Is(err, resolver.ErrUnsupported):
		return reconcile.NewClassifiedError(reconcile.ErrorUnsupported, "ENDPOINT_UNSUPPORTED", 0, err)
	default:
		return reconcile.NewClassifiedError(reconcile.ErrorInternal, "ENDPOINT_RESOLVE_FAILED", 0, err)
	}
}
