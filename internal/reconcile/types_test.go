package reconcile_test

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/cat-cc-Lcos/FNCache/internal/endpoint"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

func TestEndpointValidate(t *testing.T) {
	endpoint := endpoint.Endpoint{
		Pod:        endpoint.PodIdentity{UID: "pod-1"},
		Node:       endpoint.NodeIdentity{Name: "node-a"},
		PodIPv4:    netip.MustParseAddr("10.244.1.2"),
		NetNSInode: 42,
		PeerLink:   endpoint.LinkIdentity{NetNSInode: 42, IfIndex: 2, IfName: "eth0", MAC: []byte{2, 0, 0, 0, 0, 2}},
		HostLink:   endpoint.LinkIdentity{IfIndex: 3, IfName: "vethweb", MAC: []byte{2, 0, 0, 0, 0, 3}},
	}
	if err := endpoint.Validate(); err != nil {
		t.Fatal(err)
	}
	if endpoint.StableKey() != "pod-1" {
		t.Fatalf("unexpected stable key: %q", endpoint.StableKey())
	}
}

func TestEndpointValidateRejectsIncompleteLinkIdentity(t *testing.T) {
	base := endpoint.Endpoint{
		Pod:        endpoint.PodIdentity{UID: "pod-1"},
		Node:       endpoint.NodeIdentity{Name: "node-a"},
		PodIPv4:    netip.MustParseAddr("10.244.1.2"),
		NetNSInode: 42,
		PeerLink:   endpoint.LinkIdentity{NetNSInode: 42, IfIndex: 2, IfName: "eth0", MAC: []byte{2, 0, 0, 0, 0, 2}},
		HostLink:   endpoint.LinkIdentity{IfIndex: 3, IfName: "vethweb", MAC: []byte{2, 0, 0, 0, 0, 3}},
	}
	tests := []struct {
		name   string
		mutate func(*endpoint.Endpoint)
	}{
		{name: "empty peer MAC", mutate: func(value *endpoint.Endpoint) { value.PeerLink.MAC = nil }},
		{name: "short host MAC", mutate: func(value *endpoint.Endpoint) { value.HostLink.MAC = []byte{2, 0, 0} }},
		{name: "empty host name", mutate: func(value *endpoint.Endpoint) { value.HostLink.IfName = "" }},
		{name: "peer namespace mismatch", mutate: func(value *endpoint.Endpoint) { value.PeerLink.NetNSInode = 7 }},
		{name: "host namespace mismatch", mutate: func(value *endpoint.Endpoint) { value.HostLink.NetNSInode = 42 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := base
			test.mutate(&value)
			if err := value.Validate(); err == nil {
				t.Fatal("incomplete link identity was accepted")
			}
		})
	}
}

func TestQueueKeyIgnoresReason(t *testing.T) {
	base := reconcile.ReconcileKey{Kind: reconcile.ReconcileLocalEndpoint, UID: "pod-1"}
	other := base
	other.Reason = "different"
	if base.QueueKey() != other.QueueKey() {
		t.Fatal("queue key must deduplicate reasons for one resource")
	}
}

func TestClassifiedError(t *testing.T) {
	cause := errors.New("sandbox is not ready")
	err := reconcile.NewClassifiedError(reconcile.ErrorRetryable, reconcile.ReasonEndpointNotReady, time.Second, cause)
	if err.Class() != reconcile.ErrorRetryable || err.ReasonCode() != reconcile.ReasonEndpointNotReady || err.RetryAfter() != time.Second {
		t.Fatalf("unexpected classification: %#v", err)
	}
	if !errors.Is(err, cause) {
		t.Fatal("classified error must preserve its cause")
	}
}
