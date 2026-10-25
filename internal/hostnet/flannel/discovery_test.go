package flannel

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

type fixture struct {
	kind, route string
	vni, port   uint32
}

func (f fixture) run(_ context.Context, name string, args ...string) ([]byte, error) {
	if name != "ip" {
		return nil, fmt.Errorf("unexpected command %s", name)
	}
	command := fmt.Sprint(args)
	switch {
	case command == "[-j -d link show dev flannel.1]":
		return []byte(fmt.Sprintf(`[{"ifindex":8,"ifname":"flannel.1","mtu":1450,"address":"02:00:00:00:00:02","linkinfo":{"info_kind":%q,"info_data":{"id":%d,"port":%d,"link":"eth0"}}}]`, f.kind, f.vni, f.port)), nil
	case command == "[-j link show dev eth0]":
		return []byte(`[{"ifindex":2,"ifname":"eth0","mtu":1500,"address":"02:00:00:00:00:01"}]`), nil
	case command == "[-j addr show dev eth0]":
		return []byte(`[{"addr_info":[{"family":"inet","local":"192.0.2.10"}]}]`), nil
	case command == "[-j route show dev flannel.1]":
		if f.route == "" {
			return []byte(`[]`), nil
		}
		if f.route == "pod-no-dev" {
			return []byte(`[{"dst":"10.244.2.0/24"}]`), nil
		}
		return []byte(`[{"dst":"10.244.2.0/24","dev":"flannel.1"}]`), nil
	default:
		return nil, fmt.Errorf("unexpected arguments %s", command)
	}
}

func TestDiscoverFlannelVXLAN(t *testing.T) {
	d := NewDiscovery(fixture{kind: "vxlan", vni: 1, port: 8472, route: "pod"}.run)
	cfg, err := d.Discover(context.Background(), DiscoveryRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.VNI != 1 || cfg.UDPPort != 8472 || cfg.UnderlayLink.IfIndex != 2 || cfg.Fingerprint == "" {
		t.Fatalf("unexpected Flannel config: %+v", cfg)
	}
	other, err := d.Discover(context.Background(), DiscoveryRequest{})
	if err != nil || cfg.Fingerprint != other.Fingerprint {
		t.Fatal("fingerprint is not stable")
	}
}

func TestDiscoverTreatsAutoUnderlayAsAutomatic(t *testing.T) {
	d := NewDiscovery(fixture{kind: "vxlan", vni: 1, port: 8472, route: "pod"}.run)
	cfg, err := d.Discover(context.Background(), DiscoveryRequest{UnderlayDevice: "auto"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.UnderlayLink.IfName != "eth0" {
		t.Fatalf("underlay interface = %q, want eth0", cfg.UnderlayLink.IfName)
	}
}

func TestDiscoverRejectsInvalidRuntimeIdentity(t *testing.T) {
	tests := []struct {
		name string
		fx   fixture
	}{
		{name: "wrong backend", fx: fixture{kind: "bridge", vni: 1, port: 8472, route: "pod"}},
		{name: "invalid VNI", fx: fixture{kind: "vxlan", vni: 0, port: 8472, route: "pod"}},
		{name: "invalid port", fx: fixture{kind: "vxlan", vni: 1, port: 0, route: "pod"}},
		{name: "missing PodCIDR", fx: fixture{kind: "vxlan", vni: 1, port: 8472}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewDiscovery(tc.fx.run).Discover(context.Background(), DiscoveryRequest{}); err == nil {
				t.Fatal("expected discovery validation error")
			}
		})
	}
}

func TestDiscoverAcceptsFilteredRouteWithoutDeviceField(t *testing.T) {
	d := NewDiscovery(fixture{kind: "vxlan", vni: 1, port: 8472, route: "pod-no-dev"}.run)
	if _, err := d.Discover(context.Background(), DiscoveryRequest{}); err != nil {
		t.Fatalf("filtered route without dev field was rejected: %v", err)
	}
}

func TestDiscoverMarksMissingPodCIDRAsNotReady(t *testing.T) {
	_, err := NewDiscovery(fixture{kind: "vxlan", vni: 1, port: 8472}.run).Discover(context.Background(), DiscoveryRequest{})
	if !errors.Is(err, ErrDiscoveryNotReady) {
		t.Fatalf("error = %v, want ErrDiscoveryNotReady", err)
	}
}
