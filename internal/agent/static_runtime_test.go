package agent

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

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

func TestMergeEndpointLinksIsStableAndDeduplicated(t *testing.T) {
	base := []resolver.LinkIdentity{{IfIndex: 2}}
	endpoints := map[string]resolver.Endpoint{
		"b": {PeerLink: resolver.LinkIdentity{IfIndex: 4}, HostLink: resolver.LinkIdentity{IfIndex: 5}},
		"a": {PeerLink: resolver.LinkIdentity{IfIndex: 3}, HostLink: resolver.LinkIdentity{IfIndex: 4}},
	}
	links := mergeEndpointLinks(base, endpoints)
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
	links := mergeEndpointLinks(base, map[string]resolver.Endpoint{"pod-a": endpoint})
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

func TestAcquireRuntimeLockSerializesRuntimes(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	first, err := acquireRuntimeLock(statePath)
	if err != nil {
		t.Fatal(err)
	}
	firstClosed := false
	t.Cleanup(func() {
		if !firstClosed {
			_ = first.Close()
		}
	})
	if second, err := acquireRuntimeLock(statePath); err == nil {
		_ = second.Close()
		t.Fatal("second runtime acquired the lock")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	firstClosed = true
	third, err := acquireRuntimeLock(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := third.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestHeartbeatRenewIntervalUsesThirdOfTimeout(t *testing.T) {
	interval, err := heartbeatRenewInterval(900)
	if err != nil || interval != 300*time.Nanosecond {
		t.Fatalf("unexpected heartbeat renewal interval: interval=%s err=%v", interval, err)
	}
	interval, err = heartbeatRenewInterval(1)
	if err != nil || interval != time.Nanosecond {
		t.Fatalf("sub-nanosecond interval was not clamped: interval=%s err=%v", interval, err)
	}
	if _, err := heartbeatRenewInterval(0); err == nil {
		t.Fatal("zero timeout was accepted")
	}
}

func TestRunHeartbeatLeaseRenewsUntilCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	renewed := make(chan struct{}, 1)
	disabled := make(chan struct{}, 1)
	done := make(chan error, 1)
	go func() {
		done <- runHeartbeatLease(ctx, time.Millisecond, func(context.Context) error {
			select {
			case renewed <- struct{}{}:
			default:
			}
			return nil
		}, func(context.Context) error {
			disabled <- struct{}{}
			return nil
		})
	}()
	select {
	case <-renewed:
	case <-time.After(time.Second):
		t.Fatal("heartbeat was not renewed")
	}
	cancel()
	select {
	case <-disabled:
	case <-time.After(time.Second):
		t.Fatal("fast path was not disabled on shutdown")
	}
	if err := <-done; err != nil {
		t.Fatalf("heartbeat lease returned an error on shutdown: %v", err)
	}
}

func TestRunHeartbeatLeaseDisablesAfterRenewFailure(t *testing.T) {
	wantErr := errors.New("renew failed")
	disabled := false
	err := runHeartbeatLease(context.Background(), time.Millisecond, func(context.Context) error {
		return wantErr
	}, func(context.Context) error {
		disabled = true
		return nil
	})
	if err == nil || !errors.Is(err, wantErr) || !disabled {
		t.Fatalf("renewal failure was not handled safely: err=%v disabled=%v", err, disabled)
	}
}

func TestValidateStaticRuntimeConfigDoesNotRequireFixedHeartbeatTimestamp(t *testing.T) {
	config := validStaticRuntimeConfig()
	config.HeartbeatNS = 0
	if err := validateStaticRuntimeConfig(config); err != nil {
		t.Fatalf("fixed heartbeat timestamp was still required: %v", err)
	}
}

func validStaticRuntimeConfig() StaticRuntimeConfig {
	return StaticRuntimeConfig{
		ELFPath: "/var/lib/oncache/build/FNCache/bpf/tc_prog_kern.o", PinRoot: "/sys/fs/bpf/oncache/v1", StatePath: filepath.Join("/var/lib/oncache/v1", "state.json"),
		InstallationID: "install-a", ELFBuildID: "build-a", Generation: 1, HeartbeatNS: 1, HeartbeatTimeoutNS: 5,
		Preflight: discovery.PreflightRequest{Node: resolver.NodeIdentity{Name: "node-a", UID: "node-uid"}, PinRoot: "/sys/fs/bpf/oncache/v1", RuntimeURI: "unix:///run/containerd/containerd.sock", Overlay: "flannel-vxlan"},
		Flannel:   flannel.DiscoveryRequest{MissMask: 0x04, EstablishedMask: 0x08, IPTablesBackend: "iptables-nft"},
		Marker:    flannel.MarkerRuleSpec{Chain: "ONCACHE", Comment: "oncache:install-a"},
		TCLinks:   []resolver.LinkIdentity{{IfIndex: 2}},
		Pods:      []resolver.PodSnapshot{{Identity: resolver.PodIdentity{Namespace: "default", Name: "web", UID: "pod-a"}, NodeName: "node-a", PodIPv4: netip.MustParseAddr("10.42.0.2"), Phase: "Running"}},
	}
}
