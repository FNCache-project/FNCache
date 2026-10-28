package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/cat-cc-Lcos/FNCache/internal/endpoint"
	"github.com/cat-cc-Lcos/FNCache/internal/kubernetes"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

type EndpointReuseGuard struct {
	resolver  endpoint.EndpointResolver
	localNode string
}

func NewEndpointReuseGuard(endpointResolver endpoint.EndpointResolver, localNode string) (*EndpointReuseGuard, error) {
	if endpointResolver == nil || localNode == "" {
		return nil, fmt.Errorf("endpoint resolver and local node are required")
	}
	return &EndpointReuseGuard{resolver: endpointResolver, localNode: localNode}, nil
}

func (g *EndpointReuseGuard) Check(ctx context.Context, snapshot kubernetes.Snapshot, deletedUID string, owned reconcile.OwnedEndpoint) error {
	if hasPodIPReuse(snapshot, deletedUID, owned.PodIPv4) {
		return reconcile.NewClassifiedError(reconcile.ErrorRetryable, reconcile.ReasonPodIPReusePending, 0, nil)
	}
	for uid, pod := range snapshot.Pods {
		if uid == deletedUID || pod.NodeName != g.localNode || pod.HostNetwork || pod.Deleting || isTerminalPodPhase(pod.Phase) {
			continue
		}
		resolved, err := g.resolver.Resolve(ctx, pod)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			if errors.Is(err, endpoint.ErrEndpointNotReady) {
				return reconcile.NewClassifiedError(reconcile.ErrorRetryable, reconcile.ReasonEndpointNotReady, 0, err)
			}
			if errors.Is(err, endpoint.ErrStaleObject) || errors.Is(err, endpoint.ErrUnsupported) {
				return reconcile.NewClassifiedError(reconcile.ErrorRetryable, reconcile.ReasonEndpointIdentityReuse, 0, err)
			}
			return fmt.Errorf("resolve Pod %s for endpoint reuse check: %w", uid, err)
		}
		if resolved.Pod.UID != uid || sameOwnedLinkIdentity(resolved, owned) {
			return reconcile.NewClassifiedError(reconcile.ErrorRetryable, reconcile.ReasonEndpointIdentityReuse, 0, nil)
		}
	}
	return nil
}

func sameOwnedLinkIdentity(endpoint endpoint.Endpoint, owned reconcile.OwnedEndpoint) bool {
	samePeer := endpoint.NetNSInode == owned.NetNSInode && endpoint.PeerLink.IfIndex == owned.PeerIfIndex
	sameHost := endpoint.HostLink.IfIndex == owned.HostIfIndex
	return samePeer || sameHost
}

func hasPodIPReuse(snapshot kubernetes.Snapshot, deletedUID string, podIP netip.Addr) bool {
	if !podIP.IsValid() || !podIP.Is4() {
		return false
	}
	for uid, pod := range snapshot.Pods {
		if uid != deletedUID && !pod.Deleting && pod.PodIPv4 == podIP {
			return true
		}
	}
	return false
}
