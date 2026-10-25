//go:build linux

package endpoint

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/vishvananda/netlink"
)

type PodSnapshot struct {
	Identity        PodIdentity
	NodeName        string
	PodIPv4         netip.Addr
	HostNetwork     bool
	Phase           string
	Deleting        bool
	ResourceVersion string
}

// IsEndpointPhaseReady reports whether a Pod phase permits endpoint resolution.
// An empty phase is retained as an unspecified phase for static/test snapshots.
func IsEndpointPhaseReady(phase string) bool {
	return phase == "" || phase == "Running"
}

type EndpointResolver interface {
	Resolve(context.Context, PodSnapshot) (Endpoint, error)
	Validate(context.Context, Endpoint) error
}

type SandboxResolver interface {
	ResolveSandbox(context.Context, PodIdentity) (SandboxInfo, error)
}

type NetNSRunner func(context.Context, SandboxInfo, func(context.Context) error) error

type LinkProbe interface {
	PodEth0(context.Context) (LinkIdentity, int, error)
	HostVeth(context.Context, int) (LinkIdentity, error)
}

type LinuxEndpointResolver struct {
	sandbox SandboxResolver
	runNS   NetNSRunner
	links   LinkProbe
	now     func() time.Time
}

func NewLinuxEndpointResolver(sandbox SandboxResolver, runNS NetNSRunner) (*LinuxEndpointResolver, error) {
	return newLinuxEndpointResolver(sandbox, runNS, linuxLinkProbe{readFile: os.ReadFile})
}

func newLinuxEndpointResolver(sandbox SandboxResolver, runNS NetNSRunner, links LinkProbe) (*LinuxEndpointResolver, error) {
	if sandbox == nil || runNS == nil || links == nil {
		return nil, fmt.Errorf("sandbox resolver, netns runner and link probe are required")
	}
	return &LinuxEndpointResolver{sandbox: sandbox, runNS: runNS, links: links, now: time.Now}, nil
}

func (r *LinuxEndpointResolver) Resolve(ctx context.Context, pod PodSnapshot) (Endpoint, error) {
	if err := validatePodSnapshot(pod); err != nil {
		return Endpoint{}, err
	}
	first, err := r.sandbox.ResolveSandbox(ctx, pod.Identity)
	if err != nil {
		return Endpoint{}, err
	}
	var peer LinkIdentity
	var hostIfIndex int
	if err := r.runNS(ctx, first, func(ctx context.Context) error {
		var err error
		peer, hostIfIndex, err = r.links.PodEth0(ctx)
		if err == nil {
			peer.NetNSInode = first.NetNSInode
			peer.NetNSPath = first.NetNSPath
		}
		return err
	}); err != nil {
		return Endpoint{}, err
	}
	host, err := r.links.HostVeth(ctx, hostIfIndex)
	if err != nil {
		return Endpoint{}, err
	}
	second, err := r.sandbox.ResolveSandbox(ctx, pod.Identity)
	if err != nil {
		return Endpoint{}, err
	}
	if first.ID != second.ID || first.PID != second.PID || first.NetNSInode != second.NetNSInode {
		return Endpoint{}, fmt.Errorf("%w: sandbox identity changed during endpoint resolution", ErrStaleObject)
	}
	endpoint := Endpoint{
		Pod: pod.Identity, Node: NodeIdentity{Name: pod.NodeName}, PodIPv4: pod.PodIPv4,
		SandboxID: first.ID, SandboxPID: first.PID, NetNSPath: first.NetNSPath, NetNSInode: first.NetNSInode,
		PeerLink: peer, HostLink: host, ResourceVersion: pod.ResourceVersion, ObservedAt: r.now(),
	}
	if err := r.Validate(ctx, endpoint); err != nil {
		return Endpoint{}, err
	}
	return endpoint, nil
}

func (r *LinuxEndpointResolver) Validate(ctx context.Context, endpoint Endpoint) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := endpoint.Validate(); err != nil {
		return err
	}
	if endpoint.PeerLink.NetNSInode != endpoint.NetNSInode || endpoint.PeerLink.IfName != "eth0" || endpoint.PeerLink.IfIndex == endpoint.HostLink.IfIndex {
		return fmt.Errorf("%w: endpoint link identity is inconsistent", ErrUnsupported)
	}
	return nil
}

func validatePodSnapshot(pod PodSnapshot) error {
	if pod.Identity.UID == "" || pod.Identity.Namespace == "" || pod.Identity.Name == "" || pod.NodeName == "" {
		return fmt.Errorf("pod snapshot identity is incomplete")
	}
	if pod.Deleting {
		return fmt.Errorf("%w: pod is deleting", ErrStaleObject)
	}
	if pod.HostNetwork {
		return fmt.Errorf("%w: hostNetwork pod is not supported", ErrUnsupported)
	}
	if !pod.PodIPv4.IsValid() {
		return fmt.Errorf("%w: PodIP is not assigned", ErrEndpointNotReady)
	}
	if !pod.PodIPv4.Is4() {
		return fmt.Errorf("%w: endpoint requires IPv4", ErrUnsupported)
	}
	if !IsEndpointPhaseReady(pod.Phase) {
		return fmt.Errorf("%w: pod phase is %s", ErrEndpointNotReady, pod.Phase)
	}
	return nil
}

type linuxLinkProbe struct {
	readFile func(string) ([]byte, error)
}

func (p linuxLinkProbe) PodEth0(ctx context.Context) (LinkIdentity, int, error) {
	if err := ctx.Err(); err != nil {
		return LinkIdentity{}, 0, err
	}
	link, err := netlink.LinkByName("eth0")
	if err != nil {
		return LinkIdentity{}, 0, fmt.Errorf("%w: find Pod eth0: %v", ErrEndpointNotReady, err)
	}
	attrs := link.Attrs()
	if attrs == nil || attrs.Index <= 0 {
		return LinkIdentity{}, 0, fmt.Errorf("%w: Pod eth0 identity is incomplete", ErrUnsupported)
	}
	iflink := attrs.ParentIndex
	if iflink <= 0 {
		data, err := p.readFile(filepath.Join("/sys/class/net", attrs.Name, "iflink"))
		if err != nil {
			return LinkIdentity{}, 0, fmt.Errorf("%w: read eth0 iflink: %v", ErrEndpointNotReady, err)
		}
		iflink, err = parseIfLink(data)
		if err != nil {
			return LinkIdentity{}, 0, fmt.Errorf("%w: %v", ErrUnsupported, err)
		}
	}
	return LinkIdentity{IfIndex: attrs.Index, IfName: attrs.Name, MAC: cloneMAC(attrs.HardwareAddr)}, iflink, nil
}

func (p linuxLinkProbe) HostVeth(ctx context.Context, iflink int) (LinkIdentity, error) {
	if err := ctx.Err(); err != nil {
		return LinkIdentity{}, err
	}
	link, err := netlink.LinkByIndex(iflink)
	if err != nil {
		return LinkIdentity{}, fmt.Errorf("%w: find host veth %d: %v", ErrEndpointNotReady, iflink, err)
	}
	attrs := link.Attrs()
	if attrs == nil || attrs.Index != iflink {
		return LinkIdentity{}, fmt.Errorf("%w: host veth identity is incomplete", ErrUnsupported)
	}
	return LinkIdentity{IfIndex: attrs.Index, IfName: attrs.Name, MAC: cloneMAC(attrs.HardwareAddr)}, nil
}

func parseIfLink(data []byte) (int, error) {
	iflink, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || iflink <= 0 {
		return 0, fmt.Errorf("invalid iflink %q", strings.TrimSpace(string(data)))
	}
	return iflink, nil
}

func cloneMAC(mac net.HardwareAddr) net.HardwareAddr { return append(net.HardwareAddr(nil), mac...) }
