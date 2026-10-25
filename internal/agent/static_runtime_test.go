package agent

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/cat-cc-Lcos/FNCache/internal/endpoint"
	"github.com/cat-cc-Lcos/FNCache/internal/hostnet/discovery"
	"github.com/cat-cc-Lcos/FNCache/internal/hostnet/flannel"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

type fakeCloser struct {
	closed bool
	err    error
}

type staticRuntimeControl struct {
	disableCalls int
	err          error
}

func (c *staticRuntimeControl) Disable(context.Context) error {
	c.disableCalls++
	return c.err
}

func (c *fakeCloser) Close() error {
	c.closed = true
	return c.err
}

func TestValidateStaticRuntimeConfigRejectsMismatchedPinRoot(t *testing.T) {
	config := validStaticRuntimeConfig()
	config.Preflight.PinRoot = "/sys/fs/bpf/oncache/other"
	if err := validateStaticRuntimeConfig(config); err == nil {
		t.Fatal("mismatched pin roots were accepted")
	}
}

func TestValidateStaticRuntimeConfigRejectsMismatchedStatePath(t *testing.T) {
	config := validStaticRuntimeConfig()
	config.Preflight.StateDir = "/var/lib/oncache/other"
	if err := validateStaticRuntimeConfig(config); err == nil {
		t.Fatal("mismatched state paths were accepted")
	}
}

func TestMergeEndpointLinksIsStableAndDeduplicated(t *testing.T) {
	base := []endpoint.LinkIdentity{{IfIndex: 2}}
	endpoints := map[string]endpoint.Endpoint{
		"b": {PeerLink: endpoint.LinkIdentity{IfIndex: 4}, HostLink: endpoint.LinkIdentity{IfIndex: 5}},
		"a": {PeerLink: endpoint.LinkIdentity{IfIndex: 3}, HostLink: endpoint.LinkIdentity{IfIndex: 4}},
	}
	links := endpoint.MergeEndpointLinks(base, endpoints)
	if len(links) != 4 || links[1].IfIndex != 3 || links[2].IfIndex != 4 || links[3].IfIndex != 5 {
		t.Fatalf("unexpected merged links: %+v", links)
	}
}

func TestMergeEndpointLinksRefreshesExistingIdentity(t *testing.T) {
	base := []endpoint.LinkIdentity{{NetNSInode: 42, IfIndex: 2, IfName: "eth0"}, {IfIndex: 5, IfName: "vethweb"}}
	resolvedEndpoint := endpoint.Endpoint{
		PeerLink: endpoint.LinkIdentity{NetNSInode: 42, IfIndex: 2, IfName: "eth0", NetNSPath: "/proc/123/ns/net"},
		HostLink: endpoint.LinkIdentity{IfIndex: 5, IfName: "vethweb"},
	}
	links := endpoint.MergeEndpointLinks(base, map[string]endpoint.Endpoint{"pod-a": resolvedEndpoint})
	if len(links) != 2 || links[0].NetNSPath != "/proc/123/ns/net" {
		t.Fatalf("existing endpoint identity was not refreshed: %+v", links)
	}
}

func TestStaticRuntimeCloseIsIdempotent(t *testing.T) {
	closer := &fakeCloser{err: errors.New("close failed")}
	runtime := &StaticRuntime{cri: closer}
	if err := runtime.Close(); !errors.Is(err, closer.err) || !closer.closed {
		t.Fatalf("close result is incorrect: err=%v closed=%v", err, closer.closed)
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("second close failed: %v", err)
	}
}

func TestFinalizeStaticRunOnceDisablesReadyFastPath(t *testing.T) {
	control := &staticRuntimeControl{}
	result, err := finalizeStaticRunOnce(context.Background(), control, reconcile.ReconcileResult{State: reconcile.AgentReady})
	if err != nil {
		t.Fatal(err)
	}
	if result.State != reconcile.AgentDisabled {
		t.Fatalf("static one-shot result state=%q, want %q", result.State, reconcile.AgentDisabled)
	}
	if control.disableCalls != 1 {
		t.Fatalf("disable calls=%d, want 1", control.disableCalls)
	}
}

func TestFinalizeStaticRunOnceLeavesNonReadyStateUntouched(t *testing.T) {
	control := &staticRuntimeControl{}
	result, err := finalizeStaticRunOnce(context.Background(), control, reconcile.ReconcileResult{State: reconcile.AgentDisabled})
	if err != nil {
		t.Fatal(err)
	}
	if result.State != reconcile.AgentDisabled {
		t.Fatalf("static one-shot result state=%q, want %q", result.State, reconcile.AgentDisabled)
	}
	if control.disableCalls != 0 {
		t.Fatalf("disable calls=%d, want 0", control.disableCalls)
	}
}

func TestFinalizeStaticRunOncePropagatesDisableFailure(t *testing.T) {
	wantErr := errors.New("control map unavailable")
	control := &staticRuntimeControl{err: wantErr}
	result, err := finalizeStaticRunOnce(context.Background(), control, reconcile.ReconcileResult{State: reconcile.AgentReady})
	if !errors.Is(err, wantErr) {
		t.Fatalf("finalizeStaticRunOnce error=%v, want %v", err, wantErr)
	}
	if result.State != reconcile.AgentReady {
		t.Fatalf("failed static one-shot result state=%q, want %q", result.State, reconcile.AgentReady)
	}
	if control.disableCalls != 1 {
		t.Fatalf("disable calls=%d, want 1", control.disableCalls)
	}
}

func validStaticRuntimeConfig() StaticRuntimeConfig {
	return StaticRuntimeConfig{
		ELFPath: "/var/lib/oncache/build/FNCache/bpf/tc_prog_kern.o", PinRoot: "/sys/fs/bpf/oncache/v1", StatePath: filepath.Join("/var/lib/oncache/v1", "state.json"),
		InstallationID: "install-a", ELFBuildID: "build-a", Generation: 1, HeartbeatNS: 1, HeartbeatTimeoutNS: 5,
		Preflight: discovery.PreflightRequest{Node: endpoint.NodeIdentity{Name: "node-a", UID: "node-uid"}, PinRoot: "/sys/fs/bpf/oncache/v1", StateDir: "/var/lib/oncache/v1", RuntimeURI: "unix:///run/containerd/containerd.sock", Overlay: "flannel-vxlan"},
		Flannel:   flannel.DiscoveryRequest{MissMask: 0x04, EstablishedMask: 0x08, IPTablesBackend: "iptables-nft"},
		Marker:    flannel.MarkerRuleSpec{Chain: "ONCACHE", Comment: "oncache:install-a"},
		TCLinks:   []endpoint.LinkIdentity{{IfIndex: 2}},
		Pods:      []endpoint.PodSnapshot{{Identity: endpoint.PodIdentity{Namespace: "default", Name: "web", UID: "pod-a"}, NodeName: "node-a", PodIPv4: netip.MustParseAddr("10.42.0.2"), Phase: "Running"}},
	}
}
