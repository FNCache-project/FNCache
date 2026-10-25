package agent

import (
	"testing"

	"github.com/cat-cc-Lcos/FNCache/internal/datapath"
	"github.com/cat-cc-Lcos/FNCache/internal/endpoint"
	"github.com/cat-cc-Lcos/FNCache/internal/hostnet/discovery"
	"github.com/cat-cc-Lcos/FNCache/internal/hostnet/flannel"
)

func validDatapathComponentConfig() datapathComponentConfig {
	return datapathComponentConfig{
		ELFPath: "/opt/oncache/bpf/tc_prog_kern.o", PinRoot: "/sys/fs/bpf/oncache/v1", StatePath: "/var/lib/oncache/v1/state.json",
		InstallationID: "install-a", ELFBuildID: "sha256:test", HeartbeatNS: 1, HeartbeatTimeoutNS: 5,
		MapCapacities: datapath.DefaultMapCapacities(),
		Preflight:     discovery.PreflightRequest{Node: endpoint.NodeIdentity{Name: "node-a", UID: "node-1"}, RuntimeURI: "unix:///run/containerd/containerd.sock"},
		Marker:        flannel.MarkerRuleSpec{Chain: "ONCACHE", Comment: "oncache:install-a"},
	}
}

func TestValidateDatapathComponentConfig(t *testing.T) {
	if err := validateDatapathComponentConfig(validDatapathComponentConfig()); err != nil {
		t.Fatal(err)
	}
	invalid := validDatapathComponentConfig()
	invalid.ELFBuildID = ""
	if err := validateDatapathComponentConfig(invalid); err == nil {
		t.Fatal("missing ELF build ID was accepted")
	}
	invalid = validDatapathComponentConfig()
	invalid.Marker.Comment = ""
	if err := validateDatapathComponentConfig(invalid); err == nil {
		t.Fatal("missing marker identity was accepted")
	}
}
