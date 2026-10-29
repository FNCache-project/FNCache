package agent

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"

	"github.com/cat-cc-Lcos/FNCache/internal/endpoint"
	"github.com/cat-cc-Lcos/FNCache/internal/hostnet/discovery"
	"github.com/cat-cc-Lcos/FNCache/internal/hostnet/flannel"
	"gopkg.in/yaml.v3"
)

type staticRuntimeManifest struct {
	APIVersion       string                  `yaml:"apiVersion"`
	Kind             string                  `yaml:"kind"`
	ELFPath          string                  `yaml:"elfPath"`
	PinRoot          string                  `yaml:"pinRoot"`
	StatePath        string                  `yaml:"statePath"`
	InstallationID   string                  `yaml:"installationID"`
	ELFBuildID       string                  `yaml:"elfBuildID"`
	Generation       uint64                  `yaml:"generation"`
	HeartbeatNS      uint64                  `yaml:"heartbeatNS"`
	HeartbeatTimeout uint64                  `yaml:"heartbeatTimeoutNS"`
	Flags            uint32                  `yaml:"flags"`
	Preflight        staticPreflightManifest `yaml:"preflight"`
	Flannel          staticFlannelManifest   `yaml:"flannel"`
	Marker           flannel.MarkerRuleSpec  `yaml:"marker"`
	Pods             []staticPodManifest     `yaml:"pods"`
	TCLinks          []staticLinkManifest    `yaml:"tcLinks"`
}

type staticPreflightManifest struct {
	NodeName        string `yaml:"nodeName"`
	NodeUID         string `yaml:"nodeUID"`
	StateDir        string `yaml:"stateDir"`
	RuntimeEndpoint string `yaml:"runtimeEndpoint"`
	Overlay         string `yaml:"overlay"`
}

type staticFlannelManifest struct {
	VXLANLinkName   string `yaml:"vxlanLinkName"`
	UnderlayDevice  string `yaml:"underlayDevice"`
	MissMask        uint8  `yaml:"missMask"`
	EstablishedMask uint8  `yaml:"establishedMask"`
	IPTablesBackend string `yaml:"iptablesBackend"`
}

type staticPodManifest struct {
	Namespace       string `yaml:"namespace"`
	Name            string `yaml:"name"`
	UID             string `yaml:"uid"`
	NodeName        string `yaml:"nodeName"`
	PodIPv4         string `yaml:"podIPv4"`
	HostNetwork     bool   `yaml:"hostNetwork"`
	Phase           string `yaml:"phase"`
	Deleting        bool   `yaml:"deleting"`
	ResourceVersion string `yaml:"resourceVersion"`
}

type staticLinkManifest struct {
	NetNSInode uint64 `yaml:"netNSInode"`
	IfIndex    int    `yaml:"ifIndex"`
	IfName     string `yaml:"ifName"`
	MAC        string `yaml:"mac"`
}

func LoadStaticRuntimeManifest(path string) (StaticRuntimeConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return StaticRuntimeConfig{}, fmt.Errorf("read static runtime manifest: %w", err)
	}
	return DecodeStaticRuntimeManifest(bytes.NewReader(data))
}

func DecodeStaticRuntimeManifest(reader io.Reader) (StaticRuntimeConfig, error) {
	if reader == nil {
		return StaticRuntimeConfig{}, fmt.Errorf("static runtime manifest reader is required")
	}
	decoder := yaml.NewDecoder(reader)
	decoder.KnownFields(true)
	var manifest staticRuntimeManifest
	if err := decoder.Decode(&manifest); err != nil {
		return StaticRuntimeConfig{}, fmt.Errorf("decode static runtime manifest: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return StaticRuntimeConfig{}, fmt.Errorf("static runtime manifest contains multiple YAML documents")
		}
		return StaticRuntimeConfig{}, fmt.Errorf("decode static runtime manifest: %w", err)
	}
	if manifest.APIVersion != "oncache.io/v1alpha1" || manifest.Kind != "StaticRuntimeConfiguration" {
		return StaticRuntimeConfig{}, fmt.Errorf("unsupported static manifest apiVersion/kind: %s/%s", manifest.APIVersion, manifest.Kind)
	}
	config, err := manifest.runtimeConfig()
	if err != nil {
		return StaticRuntimeConfig{}, err
	}
	if err := validateStaticRuntimeConfig(config); err != nil {
		return StaticRuntimeConfig{}, err
	}
	return config, nil
}

func (m staticRuntimeManifest) runtimeConfig() (StaticRuntimeConfig, error) {
	pods := make([]endpoint.PodSnapshot, 0, len(m.Pods))
	for _, pod := range m.Pods {
		var ip netip.Addr
		if pod.PodIPv4 != "" {
			parsed, err := netip.ParseAddr(pod.PodIPv4)
			if err != nil {
				return StaticRuntimeConfig{}, fmt.Errorf("parse Pod IPv4 %q: %w", pod.PodIPv4, err)
			}
			ip = parsed
		}
		pods = append(pods, endpoint.PodSnapshot{Identity: endpoint.PodIdentity{Namespace: pod.Namespace, Name: pod.Name, UID: pod.UID}, NodeName: pod.NodeName, PodIPv4: ip, HostNetwork: pod.HostNetwork, Phase: pod.Phase, Deleting: pod.Deleting, ResourceVersion: pod.ResourceVersion})
	}
	links := make([]endpoint.LinkIdentity, 0, len(m.TCLinks))
	for _, link := range m.TCLinks {
		mac, err := net.ParseMAC(link.MAC)
		if err != nil {
			return StaticRuntimeConfig{}, fmt.Errorf("parse TC link MAC %q: %w", link.MAC, err)
		}
		links = append(links, endpoint.LinkIdentity{NetNSInode: link.NetNSInode, IfIndex: link.IfIndex, IfName: link.IfName, MAC: mac})
	}
	return StaticRuntimeConfig{
		ELFPath: m.ELFPath, PinRoot: m.PinRoot, StatePath: m.StatePath, InstallationID: m.InstallationID, ELFBuildID: m.ELFBuildID,
		Generation: m.Generation, HeartbeatNS: m.HeartbeatNS, HeartbeatTimeoutNS: m.HeartbeatTimeout, Flags: m.Flags,
		Preflight: discovery.PreflightRequest{Node: endpoint.NodeIdentity{Name: m.Preflight.NodeName, UID: m.Preflight.NodeUID}, PinRoot: m.PinRoot, StateDir: m.Preflight.StateDir, InstallationID: m.InstallationID, ELFBuildID: m.ELFBuildID, RuntimeURI: m.Preflight.RuntimeEndpoint, Overlay: m.Preflight.Overlay},
		Flannel:   flannel.DiscoveryRequest{VXLANLinkName: m.Flannel.VXLANLinkName, UnderlayDevice: m.Flannel.UnderlayDevice, MissMask: m.Flannel.MissMask, EstablishedMask: m.Flannel.EstablishedMask, IPTablesBackend: m.Flannel.IPTablesBackend}, Marker: m.Marker, Pods: pods, TCLinks: links,
	}, nil
}
