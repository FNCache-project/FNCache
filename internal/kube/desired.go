package kube

import (
	"fmt"
	"net/netip"

	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
	"github.com/cat-cc-Lcos/FNCache/internal/resolver"
)

// BuildDesiredState separates Kubernetes Pod intent from resolved endpoint identity.
func BuildDesiredState(snapshot Snapshot, base reconcile.DesiredState, localNode string, resolved map[string]resolver.Endpoint) (reconcile.DesiredState, error) {
	if localNode == "" {
		return reconcile.DesiredState{}, fmt.Errorf("local node name is required")
	}
	if _, ok := snapshot.Nodes[localNode]; !ok {
		return reconcile.DesiredState{}, fmt.Errorf("local Node %q is missing from Snapshot", localNode)
	}

	desired := base
	desired.LocalPods = make(map[string]resolver.PodSnapshot)
	desired.LocalEndpoints = make(map[string]resolver.Endpoint)
	desired.RemoteEndpoints = make(map[netip.Addr]reconcile.RemoteEndpoint)
	for uid, pod := range snapshot.Pods {
		if pod.NodeName == localNode && !pod.HostNetwork && !pod.Deleting {
			desired.LocalPods[uid] = pod
		}
	}
	for uid, endpoint := range resolved {
		if _, ok := desired.LocalPods[uid]; !ok {
			continue
		}
		if endpoint.Pod.UID != uid {
			return reconcile.DesiredState{}, fmt.Errorf("resolved endpoint UID mismatch for %q", uid)
		}
		if err := endpoint.Validate(); err != nil {
			return reconcile.DesiredState{}, fmt.Errorf("validate resolved endpoint %q: %w", uid, err)
		}
		desired.LocalEndpoints[uid] = cloneEndpoint(endpoint)
	}
	for _, pod := range snapshot.Pods {
		if pod.NodeName == "" || pod.NodeName == localNode || pod.HostNetwork || pod.Deleting || !resolver.IsEndpointPhaseReady(pod.Phase) || !pod.PodIPv4.IsValid() || !pod.PodIPv4.Is4() {
			continue
		}
		node, ok := snapshot.Nodes[pod.NodeName]
		if !ok || !node.InternalIPv4.IsValid() {
			continue
		}
		if existing, ok := desired.RemoteEndpoints[pod.PodIPv4]; ok && existing.NodeIPv4 != node.InternalIPv4 {
			return reconcile.DesiredState{}, fmt.Errorf("remote PodIP %s maps to multiple NodeIP addresses", pod.PodIPv4)
		}
		desired.RemoteEndpoints[pod.PodIPv4] = reconcile.RemoteEndpoint{PodIPv4: pod.PodIPv4, NodeIPv4: node.InternalIPv4}
	}
	return desired, nil
}

func cloneEndpoint(endpoint resolver.Endpoint) resolver.Endpoint {
	endpoint.PeerLink.MAC = append([]byte(nil), endpoint.PeerLink.MAC...)
	endpoint.HostLink.MAC = append([]byte(nil), endpoint.HostLink.MAC...)
	return endpoint
}
