//go:build linux

package resolver

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"
)

type fakeSandboxResolver struct {
	infos []SandboxInfo
	calls int
}

func (f *fakeSandboxResolver) ResolveSandbox(context.Context, PodIdentity) (SandboxInfo, error) {
	info := f.infos[f.calls]
	f.calls++
	return info, nil
}

type fakeLinkProbe struct {
	peer    LinkIdentity
	iflink  int
	host    LinkIdentity
	peerErr error
	hostErr error
}

func (f *fakeLinkProbe) PodEth0(context.Context) (LinkIdentity, int, error) {
	return f.peer, f.iflink, f.peerErr
}
func (f *fakeLinkProbe) HostVeth(context.Context, int) (LinkIdentity, error) {
	return f.host, f.hostErr
}

func endpointTestPod() PodSnapshot {
	return PodSnapshot{Identity: PodIdentity{Namespace: "default", Name: "web", UID: "uid-1"}, NodeName: "node-a", PodIPv4: netip.MustParseAddr("10.244.1.10"), Phase: "Running", ResourceVersion: "7"}
}

func endpointTestSandbox(id string) SandboxInfo {
	return SandboxInfo{ID: id, PID: 123, NetNSPath: "/proc/123/ns/net", NetNSInode: 42}
}

func endpointTestResolver(sandbox SandboxResolver, probe LinkProbe) *LinuxEndpointResolver {
	resolver, _ := newLinuxEndpointResolver(sandbox, func(ctx context.Context, _ SandboxInfo, fn func(context.Context) error) error { return fn(ctx) }, probe)
	resolver.now = func() time.Time { return time.Unix(10, 0).UTC() }
	return resolver
}

func TestResolveEndpointBuildsStableLinkIdentity(t *testing.T) {
	sandbox := &fakeSandboxResolver{infos: []SandboxInfo{endpointTestSandbox("sandbox-1"), endpointTestSandbox("sandbox-1")}}
	probe := &fakeLinkProbe{peer: LinkIdentity{IfIndex: 10, IfName: "eth0"}, iflink: 20, host: LinkIdentity{IfIndex: 20, IfName: "vethweb"}}
	endpoint, err := endpointTestResolver(sandbox, probe).Resolve(context.Background(), endpointTestPod())
	if err != nil || endpoint.SandboxID != "sandbox-1" || endpoint.PeerLink.NetNSInode != 42 || endpoint.PeerLink.NetNSPath != "/proc/123/ns/net" || endpoint.HostLink.IfIndex != 20 || endpoint.ObservedAt.Unix() != 10 {
		t.Fatalf("unexpected endpoint: endpoint=%+v err=%v", endpoint, err)
	}
}

func TestResolveEndpointRejectsInvalidPodSnapshots(t *testing.T) {
	for name, mutate := range map[string]func(*PodSnapshot){
		"host network": func(p *PodSnapshot) { p.HostNetwork = true },
		"deleting":     func(p *PodSnapshot) { p.Deleting = true },
		"invalid IP":   func(p *PodSnapshot) { p.PodIPv4 = netip.Addr{} },
		"pending":      func(p *PodSnapshot) { p.Phase = "Pending" },
		"unknown":      func(p *PodSnapshot) { p.Phase = "Unknown" },
		"succeeded":    func(p *PodSnapshot) { p.Phase = "Succeeded" },
		"failed":       func(p *PodSnapshot) { p.Phase = "Failed" },
	} {
		pod := endpointTestPod()
		mutate(&pod)
		resolver := endpointTestResolver(&fakeSandboxResolver{}, &fakeLinkProbe{})
		if _, err := resolver.Resolve(context.Background(), pod); err == nil {
			t.Fatalf("%s snapshot was accepted", name)
		}
	}
}

func TestResolveEndpointRetriesUntilPodIPIsAssigned(t *testing.T) {
	pod := endpointTestPod()
	pod.PodIPv4 = netip.Addr{}
	_, err := endpointTestResolver(&fakeSandboxResolver{}, &fakeLinkProbe{}).Resolve(context.Background(), pod)
	if !errors.Is(err, ErrEndpointNotReady) {
		t.Fatalf("unassigned PodIP was not retryable: %v", err)
	}
}

func TestResolveEndpointRejectsSandboxDrift(t *testing.T) {
	sandbox := &fakeSandboxResolver{infos: []SandboxInfo{endpointTestSandbox("sandbox-1"), endpointTestSandbox("sandbox-2")}}
	probe := &fakeLinkProbe{peer: LinkIdentity{IfIndex: 10, IfName: "eth0"}, iflink: 20, host: LinkIdentity{IfIndex: 20, IfName: "vethweb"}}
	if _, err := endpointTestResolver(sandbox, probe).Resolve(context.Background(), endpointTestPod()); !errors.Is(err, ErrStaleObject) {
		t.Fatalf("expected stale sandbox error: %v", err)
	}
}

func TestResolveEndpointPropagatesLinkReadiness(t *testing.T) {
	sandbox := &fakeSandboxResolver{infos: []SandboxInfo{endpointTestSandbox("sandbox-1")}}
	probe := &fakeLinkProbe{peerErr: ErrEndpointNotReady}
	if _, err := endpointTestResolver(sandbox, probe).Resolve(context.Background(), endpointTestPod()); !errors.Is(err, ErrEndpointNotReady) {
		t.Fatalf("expected endpoint-not-ready error: %v", err)
	}
}

func TestParseIfLink(t *testing.T) {
	if value, err := parseIfLink([]byte("20\n")); err != nil || value != 20 {
		t.Fatalf("unexpected iflink: value=%d err=%v", value, err)
	}
	if _, err := parseIfLink([]byte("0")); err == nil {
		t.Fatal("expected invalid iflink")
	}
}
