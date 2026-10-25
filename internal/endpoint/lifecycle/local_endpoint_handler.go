package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/cat-cc-Lcos/FNCache/internal/controlplane"
	"github.com/cat-cc-Lcos/FNCache/internal/endpoint"
	"github.com/cat-cc-Lcos/FNCache/internal/kubernetes"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

type DesiredSource interface {
	Desired(context.Context) (reconcile.DesiredState, error)
}

type StateScanner interface {
	Scan(context.Context) (reconcile.ActualState, error)
}

type Control interface {
	Disable(context.Context) error
}

type EndpointEnsurer interface {
	EnsureEndpoint(context.Context, reconcile.DesiredState, reconcile.ActualState, endpoint.Endpoint) (bool, error)
}

type MapEnsurer interface {
	EnsureEndpointMaps(context.Context, reconcile.DesiredState, reconcile.ActualState, endpoint.Endpoint, bool) (bool, error)
}

type Publisher interface {
	CommitAndPublish(context.Context, reconcile.DesiredState, reconcile.ActualState) error
}

type GenerationTransaction interface {
	Execute(context.Context, reconcile.DesiredState, controlplane.GenerationMutator) error
}

type LocalEndpointHandlerConfig struct {
	Store      *kubernetes.SnapshotStore
	Resolver   endpoint.EndpointResolver
	LocalNode  string
	Desired    DesiredSource
	Scanner    StateScanner
	Control    Control
	Endpoint   EndpointEnsurer
	Maps       MapEnsurer
	Remover    EndpointRemover
	Ownership  OwnershipSource
	Publisher  Publisher
	Generation GenerationTransaction
}

type LocalEndpointHandler struct {
	config LocalEndpointHandlerConfig
}

func NewLocalEndpointHandler(config LocalEndpointHandlerConfig) (*LocalEndpointHandler, error) {
	if config.Store == nil || config.Resolver == nil || config.LocalNode == "" || config.Desired == nil || config.Scanner == nil || config.Control == nil || config.Endpoint == nil || config.Maps == nil || config.Remover == nil || config.Ownership == nil || config.Publisher == nil || config.Generation == nil {
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
	if !ok || pod.NodeName != h.config.LocalNode || pod.HostNetwork || pod.Deleting || isTerminalPodPhase(pod.Phase) {
		return nil
	}
	resolvedEndpoint, err := h.config.Resolver.Resolve(ctx, pod)
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
	resolved := make(map[string]endpoint.Endpoint, len(base.LocalEndpoints)+1)
	for uid, existing := range base.LocalEndpoints {
		resolved[uid] = existing
	}
	resolved[pod.Identity.UID] = resolvedEndpoint
	desired, err := kubernetes.BuildDesiredState(snapshot, base, h.config.LocalNode, resolved)
	if err != nil {
		return fmt.Errorf("build local desired state: %w", err)
	}
	previous, hasPrevious, err := h.loadOwnedEndpoint(ctx, pod.Identity.UID)
	if err != nil {
		return err
	}
	if err := h.config.Generation.Execute(ctx, desired, func(ctx context.Context, desired reconcile.DesiredState, actual reconcile.ActualState) error {
		if hasPrevious && ownedEndpointIdentityChanged(previous, resolvedEndpoint) {
			if err := h.config.Remover.Remove(ctx, previous, actual, desired); err != nil {
				return fmt.Errorf("remove previous local endpoint identity: %w", err)
			}
			var err error
			actual, err = h.config.Scanner.Scan(ctx)
			if err != nil {
				return fmt.Errorf("scan after previous endpoint removal: %w", err)
			}
		}
		if _, err := h.config.Endpoint.EnsureEndpoint(ctx, desired, actual, resolvedEndpoint); err != nil {
			return fmt.Errorf("ensure local endpoint: %w", err)
		}
		if _, err := h.config.Maps.EnsureEndpointMaps(ctx, desired, actual, resolvedEndpoint, true); err != nil {
			return fmt.Errorf("ensure local endpoint Maps: %w", err)
		}
		return nil
	}); err != nil {
		return fmt.Errorf("publish local endpoint: %w", err)
	}
	return nil
}

func isTerminalPodPhase(phase string) bool {
	return phase == "Succeeded" || phase == "Failed"
}

func (h *LocalEndpointHandler) loadOwnedEndpoint(ctx context.Context, uid string) (reconcile.OwnedEndpoint, bool, error) {
	state, err := h.config.Ownership.Load(ctx)
	if errors.Is(err, os.ErrNotExist) {
		return reconcile.OwnedEndpoint{}, false, nil
	}
	if err != nil {
		return reconcile.OwnedEndpoint{}, false, fmt.Errorf("load local endpoint ownership: %w", err)
	}
	owned, ok := state.Endpoints[uid]
	return owned, ok, nil
}

func ownedEndpointIdentityChanged(previous reconcile.OwnedEndpoint, current endpoint.Endpoint) bool {
	return previous.PodUID != current.Pod.UID || previous.PodIPv4 != current.PodIPv4 || previous.NetNSInode != current.NetNSInode ||
		previous.PeerIfIndex != current.PeerLink.IfIndex || previous.HostIfIndex != current.HostLink.IfIndex
}

func classifyEndpointError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	switch {
	case errors.Is(err, endpoint.ErrEndpointNotReady):
		return reconcile.NewClassifiedError(reconcile.ErrorRetryable, reconcile.ReasonEndpointNotReady, 0, err)
	case errors.Is(err, endpoint.ErrStaleObject):
		return reconcile.NewClassifiedError(reconcile.ErrorStale, "STALE_ENDPOINT", 0, err)
	case errors.Is(err, endpoint.ErrUnsupported):
		return reconcile.NewClassifiedError(reconcile.ErrorUnsupported, "ENDPOINT_UNSUPPORTED", 0, err)
	default:
		return reconcile.NewClassifiedError(reconcile.ErrorInternal, "ENDPOINT_RESOLVE_FAILED", 0, err)
	}
}
