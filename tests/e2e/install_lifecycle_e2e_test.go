//go:build m3e2e

package e2e

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOneCommandInstallLifecycleE2E(t *testing.T) {
	if os.Getenv("ONCACHE_INSTALL_E2E") != "1" {
		t.Skip("set ONCACHE_INSTALL_E2E=1 to run the one-command install E2E")
	}
	nodeA := requiredEnv(t, "ONCACHE_M3_E2E_NODE_A")
	nodeB := requiredEnv(t, "ONCACHE_M3_E2E_NODE_B")
	workloadImage := requiredEnv(t, "ONCACHE_INSTALL_E2E_WORKLOAD_IMAGE")
	chart := getenv("ONCACHE_INSTALL_E2E_CHART", "../../charts/oncache")
	agentImage := os.Getenv("ONCACHE_INSTALL_E2E_IMAGE")
	strict := os.Getenv("ONCACHE_INSTALL_E2E_STRICT") == "1"
	evidence := getenv("ONCACHE_INSTALL_E2E_EVIDENCE", filepath.Join(os.TempDir(), "fncache-install-e2e"))
	release := getenv("ONCACHE_INSTALL_E2E_RELEASE", "fncache-install")
	namespace := fmt.Sprintf("fncache-install-%d", time.Now().UnixNano())
	if strict && agentImage != "" {
		t.Fatalf("ONCACHE_INSTALL_E2E_IMAGE must be empty in strict mode")
	}
	if !strict && agentImage == "" {
		agentImage = requiredEnv(t, "ONCACHE_INSTALL_E2E_IMAGE")
	}
	if err := os.MkdirAll(evidence, 0750); err != nil {
		t.Fatal(err)
	}
	if err := assertNodesReady(nodeA, nodeB); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = run("helm", "uninstall", release, "--namespace", "kube-system", "--wait")
		_, _ = run("kubectl", "delete", "namespace", namespace, "--ignore-not-found=true", "--wait=false")
	})

	installLifecycleRelease(t, chart, agentImage, release, strict)
	waitAgentPodsStable(t, nodeA, nodeB)
	assertReadyz(t, nodeA, nodeB)

	manifest := installLifecycleManifest(t, namespace, nodeA, nodeB, workloadImage)
	applyManifest(t, manifest)
	waitM4Pod(t, namespace, "pod-a")
	waitM4Pod(t, namespace, "pod-b")
	installObserver(t, namespace, nodeA, workloadImage)
	verifyInstallEvidence(t, namespace, evidence, "initial")
	waitControlEnabled(t, namespace, evidence)

	podAIP := mustOutput(t, "kubectl", "-n", namespace, "get", "pod", "pod-a", "-o", "jsonpath={.status.podIP}")
	podBIP := mustOutput(t, "kubectl", "-n", namespace, "get", "pod", "pod-b", "-o", "jsonpath={.status.podIP}")
	firstBefore := dumpAccelerationMap(t, namespace, evidence, "install-first-before", "policy_cache")
	firstCapture := startAccelerationCapture(t, namespace, evidence, "install-first", podAIP, podBIP)
	assertPing(t, namespace, podBIP, 1)
	firstFlannel, firstUnderlay := firstCapture()
	firstAfter := dumpAccelerationMap(t, namespace, evidence, "install-first-after", "policy_cache")
	if firstBefore == firstAfter || !policyReady(firstAfter) || !hasPacket(firstUnderlay) || !hasPacket(firstFlannel) {
		t.Fatalf("first flow did not show fallback and learning: before=%s after=%s flannel=%q underlay=%q", firstBefore, firstAfter, firstFlannel, firstUnderlay)
	}

	warmCapture := startAccelerationCapture(t, namespace, evidence, "install-warm", podAIP, podBIP)
	assertPing(t, namespace, podBIP, 4)
	warmFlannel, warmUnderlay := warmCapture()
	if hasPacket(warmFlannel) || !hasPacket(warmUnderlay) {
		t.Fatalf("warm flow did not show Flannel bypass: flannel=%q underlay=%q", warmFlannel, warmUnderlay)
	}
	strictAccelerationEvidence(t, namespace, evidence, "install-warm")

	agent := agentPodForNode(t, nodeA)
	signalAgent(t, agent, "KILL")
	waitHeartbeatStable(t, namespace, 6*time.Second, evidence, "install-heartbeat-timeout")
	assertPing(t, namespace, podBIP, 2)
	installLifecycleRelease(t, chart, agentImage, release, strict)
	waitAgentPodsStable(t, nodeA, nodeB)
	waitControlEnabled(t, namespace, evidence)
	assertReadyz(t, nodeA, nodeB)
	assertPing(t, namespace, podBIP, 2)

	if _, err := run("helm", "uninstall", release, "--namespace", "kube-system", "--wait"); err != nil {
		t.Fatal(err)
	}
	assertOwnedPinsRemoved(t, namespace)
}

func installLifecycleRelease(t *testing.T, chart, image, release string, strict bool) {
	t.Helper()
	args := []string{"upgrade", "--install", release, chart, "--namespace", "kube-system", "--create-namespace", "--wait", "--timeout", "180s"}
	if !strict {
		repository, tag := splitImage(image)
		args = append(args, "--set", "image.repository="+repository, "--set", "image.tag="+tag, "--set", "agent.installationID=install-e2e")
	}
	if _, err := run("helm", args...); err != nil {
		t.Fatal(err)
	}
}

func installLifecycleManifest(t *testing.T, namespace, nodeA, nodeB, image string) []byte {
	t.Helper()
	data, err := os.ReadFile("fixtures.yaml")
	if err != nil {
		t.Fatal(err)
	}
	data = bytes.ReplaceAll(data, []byte("NODE_A"), []byte(nodeA))
	data = bytes.ReplaceAll(data, []byte("NODE_B"), []byte(nodeB))
	data = bytes.ReplaceAll(data, []byte(e2eNamespace), []byte(namespace))
	data = bytes.ReplaceAll(data, []byte("oncache-agent:m3-e2e"), []byte(image))
	return data
}

func verifyInstallEvidence(t *testing.T, namespace, evidence, label string) {
	t.Helper()
	output, err := runObserver(namespace, "/opt/oncache/bin/bpftool", "prog", "show")
	if err != nil || strings.TrimSpace(output) == "" {
		t.Fatalf("program evidence unavailable: err=%v output=%q", err, output)
	}
	if err := os.WriteFile(filepath.Join(evidence, "install-"+label+"-programs.txt"), []byte(output), 0600); err != nil {
		t.Fatal(err)
	}
}

func assertOwnedPinsRemoved(t *testing.T, namespace string) {
	t.Helper()
	command := "test ! -e /sys/fs/bpf/oncache/v1/maps/control_map && test ! -e /sys/fs/bpf/oncache/v1/programs/tc_masq"
	if _, err := runObserver(namespace, "sh", "-c", command); err != nil {
		t.Fatalf("owned BPF pins remain after Helm uninstall: %v", err)
	}
}
