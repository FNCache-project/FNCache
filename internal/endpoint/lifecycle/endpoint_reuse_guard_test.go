package lifecycle

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/cat-cc-Lcos/FNCache/internal/endpoint"
	"github.com/cat-cc-Lcos/FNCache/internal/kubernetes"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

func reuseOwned() reconcile.OwnedEndpoint {
	return reconcile.OwnedEndpoint{PodUID: "pod-old", PodIPv4: netip.MustParseAddr("10.42.0.2"), NetNSInode: 42, PeerIfIndex: 7, HostIfIndex: 8}
}

func reuseSnapshot(pod endpoint.PodSnapshot) kubernetes.Snapshot {
	return kubernetes.Snapshot{Nodes: map[string]kubernetes.NodeSnapshot{"node-a": {Identity: endpoint.NodeIdentity{Name: "node-a", UID: "node-1"}}}, Pods: map[string]endpoint.PodSnapshot{pod.Identity.UID: pod}}
}

func TestEndpointReuseGuardDefersSameIPAndIfindexReuse(t *testing.T) {
	owned := reuseOwned()
	newPod := handlerPod()
	newPod.Identity.UID = "pod-new"
	events := []string{}
	guard, _ := NewEndpointReuseGuard(&localHandlerResolver{endpoint: handlerEndpoint("pod-new"), events: &events}, "node-a")
	if err := guard.Check(context.Background(), reuseSnapshot(newPod), owned.PodUID, owned); err == nil {
		t.Fatal("same IP reuse was not deferred")
	}

	newPod.PodIPv4 = netip.MustParseAddr("10.42.0.3")
	endpoint := handlerEndpoint("pod-new")
	endpoint.PodIPv4 = newPod.PodIPv4
	endpoint.PeerLink.IfIndex, endpoint.HostLink.IfIndex = 7, 8
	guard, _ = NewEndpointReuseGuard(&localHandlerResolver{endpoint: endpoint, events: &events}, "node-a")
	var classified *reconcile.ClassifiedError
	err := guard.Check(context.Background(), reuseSnapshot(newPod), owned.PodUID, owned)
	if !errors.As(err, &classified) || classified.ReasonCode() != reconcile.ReasonEndpointIdentityReuse {
		t.Fatalf("ifindex reuse was not deferred: %v", err)
	}
}

func TestEndpointReuseGuardAllowsDifferentIdentity(t *testing.T) {
	owned := reuseOwned()
	pod := handlerPod()
	pod.Identity.UID = "pod-new"
	pod.PodIPv4 = netip.MustParseAddr("10.42.0.3")
	endpoint := handlerEndpoint("pod-new")
	endpoint.PodIPv4 = pod.PodIPv4
	endpoint.NetNSInode, endpoint.PeerLink.IfIndex, endpoint.HostLink.IfIndex = 99, 70, 80
	events := []string{}
	guard, _ := NewEndpointReuseGuard(&localHandlerResolver{endpoint: endpoint, events: &events}, "node-a")
	if err := guard.Check(context.Background(), reuseSnapshot(pod), owned.PodUID, owned); err != nil {
		t.Fatalf("different endpoint identity was rejected: %v", err)
	}
}

func TestEndpointReuseGuardRetriesUnreadyCandidate(t *testing.T) {
	owned := reuseOwned()
	pod := handlerPod()
	pod.Identity.UID = "pod-new"
	pod.PodIPv4 = netip.MustParseAddr("10.42.0.3")
	events := []string{}
	guard, _ := NewEndpointReuseGuard(&localHandlerResolver{err: endpoint.ErrEndpointNotReady, events: &events}, "node-a")
	var classified *reconcile.ClassifiedError
	err := guard.Check(context.Background(), reuseSnapshot(pod), owned.PodUID, owned)
	if !errors.As(err, &classified) || classified.ReasonCode() != reconcile.ReasonEndpointNotReady {
		t.Fatalf("unready candidate was not classified as not ready: %v", err)
	}
}

func TestEndpointReuseGuardSkipsTerminalCandidates(t *testing.T) {
	for _, phase := range []string{"Succeeded", "Failed"} {
		t.Run(phase, func(t *testing.T) {
			owned := reuseOwned()
			pod := handlerPod()
			pod.Identity.UID = "pod-terminal"
			pod.PodIPv4 = netip.MustParseAddr("10.42.0.3")
			pod.Phase = phase
			events := []string{}
			guard, _ := NewEndpointReuseGuard(&localHandlerResolver{err: endpoint.ErrEndpointNotReady, events: &events}, "node-a")
			if err := guard.Check(context.Background(), reuseSnapshot(pod), owned.PodUID, owned); err != nil {
				t.Fatalf("terminal candidate blocked cleanup: %v", err)
			}
			if len(events) != 0 {
				t.Fatalf("terminal candidate was resolved: %v", events)
			}
		})
	}
}
