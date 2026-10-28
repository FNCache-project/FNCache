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
		PeerLink:   endpoint.LinkIdentity{IfIndex: 2},
		HostLink:   endpoint.LinkIdentity{IfIndex: 3},
	}
	if err := endpoint.Validate(); err != nil {
		t.Fatal(err)
	}
	if endpoint.StableKey() != "pod-1" {
		t.Fatalf("unexpected stable key: %q", endpoint.StableKey())
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
