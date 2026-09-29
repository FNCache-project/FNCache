package agent

import (
	"strings"
	"testing"
)

const validStaticManifest = `apiVersion: oncache.io/v1alpha1
kind: StaticRuntimeConfiguration
elfPath: /var/lib/oncache/build/FNCache/bpf/tc_prog_kern.o
pinRoot: /sys/fs/bpf/oncache/v1
statePath: /var/lib/oncache/v1/state.json
installationID: install-a
elfBuildID: build-a
generation: 1
heartbeatNS: 1
heartbeatTimeoutNS: 5000000000
preflight:
  nodeName: node-a
  nodeUID: node-uid
  stateDir: /var/lib/oncache/v1
  runtimeEndpoint: unix:///run/containerd/containerd.sock
  overlay: flannel-vxlan
flannel:
  missMask: 4
  establishedMask: 8
  iptablesBackend: iptables-nft
marker:
  chain: ONCACHE
  comment: oncache:install-a
tcLinks:
  - ifIndex: 2
    ifName: eth0
    mac: 02:00:00:00:00:01
pods:
  - namespace: default
    name: web
    uid: pod-a
    nodeName: node-a
    podIPv4: 10.42.0.2
    phase: Running
`

func TestDecodeStaticRuntimeManifest(t *testing.T) {
	config, err := DecodeStaticRuntimeManifest(strings.NewReader(validStaticManifest))
	if err != nil {
		t.Fatal(err)
	}
	if config.Preflight.Node.Name != "node-a" || len(config.Pods) != 1 || config.Pods[0].PodIPv4.String() != "10.42.0.2" || len(config.TCLinks) != 1 {
		t.Fatalf("unexpected static runtime config: %+v", config)
	}
}

func TestDecodeStaticRuntimeManifestRejectsUnknownFieldsAndMultipleDocuments(t *testing.T) {
	unknown := validStaticManifest + "unknown: true\n"
	if _, err := DecodeStaticRuntimeManifest(strings.NewReader(unknown)); err == nil {
		t.Fatal("unknown manifest field was accepted")
	}
	multiple := validStaticManifest + "---\n" + validStaticManifest
	if _, err := DecodeStaticRuntimeManifest(strings.NewReader(multiple)); err == nil {
		t.Fatal("multiple manifest documents were accepted")
	}
}

func TestDecodeStaticRuntimeManifestRejectsInvalidIdentity(t *testing.T) {
	invalid := strings.Replace(validStaticManifest, "podIPv4: 10.42.0.2", "podIPv4: not-an-ip", 1)
	if _, err := DecodeStaticRuntimeManifest(strings.NewReader(invalid)); err == nil {
		t.Fatal("invalid Pod IPv4 was accepted")
	}
}
