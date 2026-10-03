package flannel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strings"

	"github.com/cat-cc-Lcos/FNCache/internal/resolver"
)

type CommandRunner func(context.Context, string, ...string) ([]byte, error)

type Discovery struct{ run CommandRunner }

type linkJSON struct {
	IfIndex  int    `json:"ifindex"`
	IfName   string `json:"ifname"`
	MTU      int    `json:"mtu"`
	Link     string `json:"link"`
	Address  string `json:"address"`
	LinkInfo struct {
		InfoKind string `json:"info_kind"`
		InfoData struct {
			ID   uint32 `json:"id"`
			Port uint16 `json:"port"`
		} `json:"info_data"`
	} `json:"linkinfo"`
}

type addrJSON struct {
	AddrInfo []struct {
		Family string `json:"family"`
		Local  string `json:"local"`
	} `json:"addr_info"`
}

type routeJSON struct {
	Dst string `json:"dst"`
	Dev string `json:"dev"`
}

func NewDiscovery(run CommandRunner) *Discovery {
	if run == nil {
		run = func(ctx context.Context, name string, args ...string) ([]byte, error) {
			return exec.CommandContext(ctx, name, args...).CombinedOutput()
		}
	}
	return &Discovery{run: run}
}

func (d *Discovery) Discover(ctx context.Context, req DiscoveryRequest) (FlannelConfig, error) {
	if req.VXLANLinkName == "" {
		req.VXLANLinkName = "flannel.1"
	}
	if req.MissMask == 0 && req.EstablishedMask == 0 {
		req.MissMask, req.EstablishedMask = 0x04, 0x08
	}
	if req.IPTablesBackend == "" {
		req.IPTablesBackend = "iptables-nft"
	}
	var vxlan []linkJSON
	if err := d.readJSON(ctx, &vxlan, "-j", "-d", "link", "show", "dev", req.VXLANLinkName); err != nil {
		return FlannelConfig{}, err
	}
	if len(vxlan) != 1 || vxlan[0].LinkInfo.InfoKind != "vxlan" {
		return FlannelConfig{}, fmt.Errorf("%s is not a single VXLAN link", req.VXLANLinkName)
	}
	vxlanLink := vxlan[0]
	underlayName := req.UnderlayDevice
	if underlayName == "" || underlayName == "auto" {
		underlayName = vxlanLink.Link
	}
	if underlayName == "" {
		return FlannelConfig{}, fmt.Errorf("Flannel underlay device is missing")
	}
	var underlay []linkJSON
	if err := d.readJSON(ctx, &underlay, "-j", "link", "show", "dev", underlayName); err != nil {
		return FlannelConfig{}, err
	}
	if len(underlay) != 1 {
		return FlannelConfig{}, fmt.Errorf("underlay device %q is not unique", underlayName)
	}
	var addresses []addrJSON
	if err := d.readJSON(ctx, &addresses, "-j", "addr", "show", "dev", underlayName); err != nil {
		return FlannelConfig{}, err
	}
	underlayIPv4, err := firstIPv4(addresses)
	if err != nil {
		return FlannelConfig{}, err
	}
	var routes []routeJSON
	if err := d.readJSON(ctx, &routes, "-j", "route", "show", "dev", req.VXLANLinkName); err != nil {
		return FlannelConfig{}, err
	}
	podCIDR, err := firstPodCIDR(routes, req.VXLANLinkName)
	if err != nil {
		return FlannelConfig{}, err
	}
	vxlanIdentity, err := makeLinkIdentity(vxlanLink)
	if err != nil {
		return FlannelConfig{}, err
	}
	underlayIdentity, err := makeLinkIdentity(underlay[0])
	if err != nil {
		return FlannelConfig{}, err
	}
	cfg := FlannelConfig{BackendType: "vxlan", VXLANLink: vxlanIdentity, UnderlayLink: underlayIdentity,
		UnderlayIPv4: underlayIPv4, PodCIDR: podCIDR, VNI: vxlanLink.LinkInfo.InfoData.ID,
		UDPPort: vxlanLink.LinkInfo.InfoData.Port, MTU: vxlanLink.MTU, MissMask: req.MissMask,
		EstablishedMask: req.EstablishedMask, IPTablesBackend: req.IPTablesBackend}
	if err := cfg.Validate(); err != nil {
		return FlannelConfig{}, err
	}
	cfg.Fingerprint = fingerprint(cfg)
	return cfg, nil
}

func (d *Discovery) readJSON(ctx context.Context, target any, args ...string) error {
	output, err := d.run(ctx, "ip", args...)
	if err != nil {
		return fmt.Errorf("ip %s: %w", strings.Join(args, " "), err)
	}
	if err := json.Unmarshal(output, target); err != nil {
		return fmt.Errorf("decode ip %s: %w", strings.Join(args, " "), err)
	}
	return nil
}

func makeLinkIdentity(link linkJSON) (resolver.LinkIdentity, error) {
	mac, err := net.ParseMAC(link.Address)
	if err != nil {
		return resolver.LinkIdentity{}, fmt.Errorf("parse MAC for %s: %w", link.IfName, err)
	}
	return resolver.LinkIdentity{IfIndex: link.IfIndex, IfName: link.IfName, MAC: mac}, nil
}

func firstIPv4(groups []addrJSON) (netip.Addr, error) {
	for _, group := range groups {
		for _, addr := range group.AddrInfo {
			if addr.Family == "inet" {
				parsed, err := netip.ParseAddr(addr.Local)
				if err == nil && parsed.Is4() {
					return parsed, nil
				}
			}
		}
	}
	return netip.Addr{}, fmt.Errorf("underlay IPv4 address is missing")
}

func firstPodCIDR(routes []routeJSON, device string) (netip.Prefix, error) {
	for _, route := range routes {
		if (route.Dev == "" || route.Dev == device) && route.Dst != "" && route.Dst != "default" {
			prefix, err := netip.ParsePrefix(route.Dst)
			if err == nil && prefix.Addr().Is4() {
				return prefix, nil
			}
		}
	}
	return netip.Prefix{}, fmt.Errorf("PodCIDR route for %s is missing", device)
}

func fingerprint(c FlannelConfig) string {
	value := struct {
		Backend, IPTablesBackend, VXLANName, UnderlayName, UnderlayIPv4, PodCIDR, UnderlayMAC string
		VXLANIf, UnderlayIf, VNI, Port, MTU                                                   int
		Miss, Established                                                                     uint8
	}{c.BackendType, c.IPTablesBackend, c.VXLANLink.IfName, c.UnderlayLink.IfName, c.UnderlayIPv4.String(), c.PodCIDR.String(), c.UnderlayLink.MAC.String(),
		c.VXLANLink.IfIndex, c.UnderlayLink.IfIndex, int(c.VNI), int(c.UDPPort), c.MTU, c.MissMask, c.EstablishedMask}
	data, _ := json.Marshal(value)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
