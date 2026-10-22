package agent

import (
	"errors"
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/cat-cc-Lcos/FNCache/internal/discovery"
	"github.com/cat-cc-Lcos/FNCache/internal/overlay/flannel"
	"github.com/cat-cc-Lcos/FNCache/internal/resolver"
)

type fakeCloser struct {
	closed bool
	err    error
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
	base := []resolver.LinkIdentity{{IfIndex: 2}}
	endpoints := map[string]resolver.Endpoint{
		"b": {PeerLink: resolver.LinkIdentity{IfIndex: 4}, HostLink: resolver.LinkIdentity{IfIndex: 5}},
		"a": {PeerLink: resolver.LinkIdentity{IfIndex: 3}, HostLink: resolver.LinkIdentity{IfIndex: 4}},
	}
	links := resolver.MergeEndpointLinks(base, endpoints)
	if len(links) != 4 || links[1].IfIndex != 3 || links[2].IfIndex != 4 || links[3].IfIndex != 5 {
		t.Fatalf("unexpected merged links: %+v", links)
	}
}

func TestMergeEndpointLinksRefreshesExistingIdentity(t *testing.T) {
	base := []resolver.LinkIdentity{{NetNSInode: 42, IfIndex: 2, IfName: "eth0"}, {IfIndex: 5, IfName: "vethweb"}}
	endpoint := resolver.Endpoint{
		PeerLink: resolver.LinkIdentity{NetNSInode: 42, IfIndex: 2, IfName: "eth0", NetNSPath: "/proc/123/ns/net"},
		HostLink: resolver.LinkIdentity{IfIndex: 5, IfName: "vethweb"},
	}
	links := resolver.MergeEndpointLinks(base, map[string]resolver.Endpoint{"pod-a": endpoint})
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

func validStaticRuntimeConfig() StaticRuntimeConfig {
	return StaticRuntimeConfig{
		ELFPath: "/var/lib/oncache/build/FNCache/bpf/tc_prog_kern.o", PinRoot: "/sys/fs/bpf/oncache/v1", StatePath: filepath.Join("/var/lib/oncache/v1", "state.json"),
		InstallationID: "install-a", ELFBuildID: "build-a", Generation: 1, HeartbeatNS: 1, HeartbeatTimeoutNS: 5,
		Preflight: discovery.PreflightRequest{Node: resolver.NodeIdentity{Name: "node-a", UID: "node-uid"}, PinRoot: "/sys/fs/bpf/oncache/v1", StateDir: "/var/lib/oncache/v1", RuntimeURI: "unix:///run/containerd/containerd.sock", Overlay: "flannel-vxlan"},
		Flannel:   flannel.DiscoveryRequest{MissMask: 0x04, EstablishedMask: 0x08, IPTablesBackend: "iptables-nft"},
		Marker:    flannel.MarkerRuleSpec{Chain: "ONCACHE", Comment: "oncache:install-a"},
		TCLinks:   []resolver.LinkIdentity{{IfIndex: 2}},
		Pods:      []resolver.PodSnapshot{{Identity: resolver.PodIdentity{Namespace: "default", Name: "web", UID: "pod-a"}, NodeName: "node-a", PodIPv4: netip.MustParseAddr("10.42.0.2"), Phase: "Running"}},
	}
}
