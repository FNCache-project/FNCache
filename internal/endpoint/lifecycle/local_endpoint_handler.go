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
	Execute(context.Context, reconcile.DesiredState, controlplane.GenerationMutator, ...controlplane.GenerationPublishGate) error
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

// Handle reconciles one local endpoint without publishing an outdated Pod snapshot.
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
	snapshot, err = h.refreshEndpointSnapshot(key.UID, pod, resolvedEndpoint)
	if err != nil {
		return err
	}
	pod = snapshot.Pods[key.UID]
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
		if _, err := h.refreshEndpointSnapshot(key.UID, pod, resolvedEndpoint); err != nil {
			return err
		}
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
	}, h.endpointPublishGate(key.UID, pod, resolvedEndpoint)); err != nil {
		return fmt.Errorf("publish local endpoint: %w", err)
	}
	return nil
}

// endpointPublishGate holds the snapshot read lock while validating and publishing.
func (h *LocalEndpointHandler) endpointPublishGate(uid string, expected endpoint.PodSnapshot, resolved endpoint.Endpoint) controlplane.GenerationPublishGate {
	return func(ctx context.Context, _ reconcile.DesiredState, _ reconcile.ActualState, publish func() error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return h.config.Store.WithReadLock(func(snapshot kubernetes.Snapshot) error {
			if err := validateEndpointSnapshot(snapshot, uid, expected, resolved); err != nil {
				return err
			}
			return publish()
		})
	}
}

// refreshEndpointSnapshot reads and validates the current Pod snapshot.
func (h *LocalEndpointHandler) refreshEndpointSnapshot(uid string, expected endpoint.PodSnapshot, resolved endpoint.Endpoint) (kubernetes.Snapshot, error) {
	snapshot := h.config.Store.Snapshot()
	if err := validateEndpointSnapshot(snapshot, uid, expected, resolved); err != nil {
		return kubernetes.Snapshot{}, err
	}
	return snapshot, nil
}

// validateEndpointSnapshot rejects a resolved endpoint that no longer matches the Pod snapshot.
func validateEndpointSnapshot(snapshot kubernetes.Snapshot, uid string, expected endpoint.PodSnapshot, resolved endpoint.Endpoint) error {
	current, ok := snapshot.Pods[uid]
	if !ok || !sameLocalPodSnapshot(expected, current) || !endpointMatchesPodSnapshot(resolved, current) {
		cause := fmt.Errorf("%w: Pod %s snapshot changed during local endpoint reconciliation", endpoint.ErrStaleObject, uid)
		return reconcile.NewClassifiedError(reconcile.ErrorRetryable, reconcile.ReasonEndpointSnapshotChanged, 0, cause)
	}
	return nil
}

// sameLocalPodSnapshot compares all Pod fields used by local endpoint resolution.
func sameLocalPodSnapshot(a, b endpoint.PodSnapshot) bool {
	return a.Identity == b.Identity && a.NodeName == b.NodeName && a.PodIPv4 == b.PodIPv4 &&
		a.HostNetwork == b.HostNetwork && a.Phase == b.Phase && a.Deleting == b.Deleting &&
		a.ResourceVersion == b.ResourceVersion
}

// endpointMatchesPodSnapshot verifies the resolved endpoint's Kubernetes identity fields.
func endpointMatchesPodSnapshot(resolved endpoint.Endpoint, pod endpoint.PodSnapshot) bool {
	return resolved.Pod == pod.Identity && resolved.Node.Name == pod.NodeName &&
		resolved.PodIPv4 == pod.PodIPv4 && resolved.ResourceVersion == pod.ResourceVersion
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
