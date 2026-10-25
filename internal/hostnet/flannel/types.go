package flannel

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/cat-cc-Lcos/FNCache/internal/endpoint"
)

var ErrDiscoveryNotReady = errors.New("Flannel discovery is not ready")

type FlannelConfig struct {
	BackendType     string
	VXLANLink       endpoint.LinkIdentity
	UnderlayLink    endpoint.LinkIdentity
	UnderlayIPv4    netip.Addr
	PodCIDR         netip.Prefix
	VNI             uint32
	UDPPort         uint16
	MTU             int
	MissMask        uint8
	EstablishedMask uint8
	IPTablesBackend string
	Fingerprint     string
}

type DiscoveryRequest struct {
	VXLANLinkName   string
	UnderlayDevice  string
	MissMask        uint8
	EstablishedMask uint8
	IPTablesBackend string
}

func (c FlannelConfig) Validate() error {
	if c.BackendType != "vxlan" || c.VXLANLink.IfIndex <= 0 || c.UnderlayLink.IfIndex <= 0 {
		return fmt.Errorf("invalid Flannel VXLAN link identity")
	}
	if c.VNI == 0 || c.VNI > 0xffffff || c.UDPPort == 0 || c.MTU <= 0 {
		return fmt.Errorf("invalid Flannel VXLAN parameters")
	}
	if !c.UnderlayIPv4.IsValid() || !c.UnderlayIPv4.Is4() || !c.PodCIDR.IsValid() {
		return fmt.Errorf("invalid Flannel address or PodCIDR")
	}
	if c.MissMask != 0x04 || c.EstablishedMask != 0x08 || c.IPTablesBackend != "iptables-nft" {
		return fmt.Errorf("Flannel marker or iptables backend is not supported")
	}
	return nil
}
