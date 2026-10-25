package agent

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/cat-cc-Lcos/FNCache/internal/endpoint"
	"github.com/cat-cc-Lcos/FNCache/internal/hostnet/flannel"
)

type fakeFlannelHealthSource struct {
	config flannel.FlannelConfig
	err    error
}

func (s *fakeFlannelHealthSource) Discover(context.Context, flannel.DiscoveryRequest) (flannel.FlannelConfig, error) {
	return s.config, s.err
}

func healthFlannelConfig(fingerprint string) flannel.FlannelConfig {
	return flannel.FlannelConfig{
		BackendType: "vxlan", VXLANLink: endpoint.LinkIdentity{IfIndex: 9, IfName: "flannel.1"},
		UnderlayLink: endpoint.LinkIdentity{IfIndex: 2, IfName: "eth0"}, UnderlayIPv4: netip.MustParseAddr("192.0.2.10"),
		PodCIDR: netip.MustParsePrefix("10.42.0.0/24"), VNI: 1, UDPPort: 8472, MTU: 1450,
		MissMask: 0x04, EstablishedMask: 0x08, IPTablesBackend: "iptables-nft", Fingerprint: fingerprint,
	}
}

func TestFlannelHealthMonitorAcceptsStableFingerprint(t *testing.T) {
	source := &fakeFlannelHealthSource{config: healthFlannelConfig("stable")}
	monitor, err := NewFlannelHealthMonitor(FlannelHealthMonitorConfig{Source: source, ExpectedFingerprint: "stable", Interval: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err := monitor.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestFlannelHealthMonitorReportsDriftAndFailure(t *testing.T) {
	source := &fakeFlannelHealthSource{config: healthFlannelConfig("changed")}
	monitor, err := NewFlannelHealthMonitor(FlannelHealthMonitorConfig{Source: source, ExpectedFingerprint: "stable", Interval: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err := monitor.Check(context.Background()); !errors.Is(err, ErrFlannelConfigDrift) {
		t.Fatalf("error = %v, want ErrFlannelConfigDrift", err)
	}
	source.err = errors.New("link missing")
	if err := monitor.Check(context.Background()); !errors.Is(err, ErrFlannelUnhealthy) {
		t.Fatalf("error = %v, want ErrFlannelUnhealthy", err)
	}
}
