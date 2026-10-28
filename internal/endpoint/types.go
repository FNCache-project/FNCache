package endpoint

import (
	"fmt"
	"net"
	"net/netip"
	"time"
)

type NodeIdentity struct {
	Name string
	UID  string
}

type PodIdentity struct {
	Namespace string
	Name      string
	UID       string
}

type LinkIdentity struct {
	NetNSInode uint64
	IfIndex    int
	IfName     string
	MAC        net.HardwareAddr
	NetNSPath  string `json:"-"`
}

type Endpoint struct {
	Pod             PodIdentity
	Node            NodeIdentity
	PodIPv4         netip.Addr
	PodCIDR         netip.Prefix
	SandboxID       string
	SandboxPID      int
	NetNSPath       string
	NetNSInode      uint64
	PeerLink        LinkIdentity
	HostLink        LinkIdentity
	ObservedAt      time.Time
	ResourceVersion string
}

func (e Endpoint) StableKey() string { return e.Pod.UID }

func (e Endpoint) Validate() error {
	if e.Pod.UID == "" || e.Node.Name == "" {
		return fmt.Errorf("pod UID and node name are required")
	}
	if !e.PodIPv4.IsValid() || !e.PodIPv4.Is4() {
		return fmt.Errorf("endpoint must have a valid IPv4 address")
	}
	if e.NetNSInode == 0 || e.PeerLink.IfIndex <= 0 || e.HostLink.IfIndex <= 0 {
		return fmt.Errorf("endpoint link identity is incomplete")
	}
	return nil
}
