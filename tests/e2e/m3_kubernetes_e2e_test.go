//go:build m3e2e

package e2e

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const e2eNamespace = "oncache-e2e"

func TestM3KubernetesE2E(t *testing.T) {
	if os.Getenv("ONCACHE_M3_E2E") != "1" {
		t.Skip("set ONCACHE_M3_E2E=1 to run the two-node Kubernetes E2E")
	}
	nodeA := requiredEnv(t, "ONCACHE_M3_E2E_NODE_A")
	nodeB := requiredEnv(t, "ONCACHE_M3_E2E_NODE_B")
	image := requiredEnv(t, "ONCACHE_M3_E2E_IMAGE")
	chart := getenv("ONCACHE_M3_E2E_CHART", "../../charts/oncache")
	evidence := getenv("ONCACHE_M3_E2E_EVIDENCE", filepath.Join(os.TempDir(), "oncache-m3-e2e"))
	if err := os.MkdirAll(evidence, 0750); err != nil {
		t.Fatal(err)
	}
	if err := assertNodesReady(nodeA, nodeB); err != nil {
		t.Fatal(err)
	}
	resetE2ENamespace(t)
	manifest, err := os.ReadFile("fixtures.yaml")
	if err != nil {
		t.Fatal(err)
	}
	manifest = bytes.ReplaceAll(manifest, []byte("NODE_A"), []byte(nodeA))
	manifest = bytes.ReplaceAll(manifest, []byte("NODE_B"), []byte(nodeB))
	applyManifest(t, manifest)
	if cleanup := os.Getenv("ONCACHE_M3_E2E_CLEANUP") == "1"; cleanup {
		t.Cleanup(func() { _, _ = run("kubectl", "delete", "namespace", e2eNamespace, "--ignore-not-found=true") })
	}
	repository, tag := splitImage(image)
	_, err = run("helm", "upgrade", "--install", "oncache-e2e", chart, "--namespace", "kube-system", "--set", "image.repository="+repository, "--set", "image.tag="+tag, "--set", "agent.installationID=m3-e2e")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := run("kubectl", "-n", "kube-system", "rollout", "restart", "daemonset/oncache-e2e-oncache"); err != nil {
		t.Fatal(err)
	}
	if _, err := run("kubectl", "-n", "kube-system", "rollout", "status", "daemonset/oncache-e2e-oncache", "--timeout=180s"); err != nil {
		t.Fatal(err)
	}
	if got := mustOutput(t, "kubectl", "-n", "kube-system", "get", "daemonset/oncache-e2e-oncache", "-o", "jsonpath={.spec.template.spec.hostPID}"); got != "true" {
		t.Fatalf("agent DaemonSet hostPID = %q, want true", got)
	}
	waitPod(t, "pod-a")
	waitPod(t, "pod-b")
	captureEvidence(t, evidence)
	podBIP := mustOutput(t, "kubectl", "-n", e2eNamespace, "get", "pod", "pod-b", "-o", "jsonpath={.status.podIP}")
	if _, err := run("kubectl", "-n", e2eNamespace, "exec", "pod-a", "--", "ping", "-c", "3", "-W", "2", podBIP); err != nil {
		t.Fatal(err)
	}
	if _, err := run("kubectl", "-n", e2eNamespace, "delete", "pod", "pod-b", "--wait=true"); err != nil {
		t.Fatal(err)
	}
	applyManifest(t, manifest)
	waitPod(t, "pod-b")
	newPodBIP := mustOutput(t, "kubectl", "-n", e2eNamespace, "get", "pod", "pod-b", "-o", "jsonpath={.status.podIP}")
	if newPodBIP != podBIP {
		t.Logf("PodIP changed during recreate: old=%s new=%s; IP reuse guard remains covered by unit tests", podBIP, newPodBIP)
	}

	if _, err := run("kubectl", "-n", e2eNamespace, "delete", "pod", "pod-a", "--wait=true"); err != nil {
		t.Fatal(err)
	}
	migrated := bytes.ReplaceAll(manifest, []byte("nodeName: "+nodeA), []byte("nodeName: "+nodeB))
	applyManifest(t, migrated)
	waitPod(t, "pod-a")
	if got := mustOutput(t, "kubectl", "-n", e2eNamespace, "get", "pod", "pod-a", "-o", "jsonpath={.spec.nodeName}"); got != nodeB {
		t.Fatalf("pod-a did not migrate: node=%s want=%s", got, nodeB)
	}

	for cycle := 0; cycle < 5; cycle++ {
		churn := []byte(fmt.Sprintf("apiVersion: v1\nkind: Pod\nmetadata:\n  name: pod-churn\n  namespace: %s\n  labels:\n    app: oncache-churn\nspec:\n  nodeName: %s\n  containers:\n    - name: app\n      image: oncache-agent:m3-e2e\n      command: [\"sh\", \"-c\", \"sleep 3600\"]\n", e2eNamespace, nodeA))
		applyManifest(t, churn)
		waitPod(t, "pod-churn")
		churnIP := mustOutput(t, "kubectl", "-n", e2eNamespace, "get", "pod", "pod-churn", "-o", "jsonpath={.status.podIP}")
		if _, err := run("kubectl", "-n", e2eNamespace, "exec", "pod-a", "--", "ping", "-c", "1", "-W", "2", churnIP); err != nil {
			t.Fatalf("churn cycle %d communication failed: %v", cycle, err)
		}
		if _, err := run("kubectl", "-n", e2eNamespace, "delete", "pod", "pod-churn", "--wait=true"); err != nil {
			t.Fatalf("churn cycle %d delete failed: %v", cycle, err)
		}
		waitPodDeleted(t, "pod-churn")
	}
	captureEvidence(t, evidence)
}

func assertNodesReady(nodes ...string) error {
	for _, node := range nodes {
		if _, err := run("kubectl", "wait", "--for=condition=Ready", "node/"+node, "--timeout=60s"); err != nil {
			return err
		}
	}
	return nil
}

func applyManifest(t *testing.T, manifest []byte) {
	t.Helper()
	cmd := exec.Command("kubectl", "apply", "-f", "-")
	cmd.Stdin = bytes.NewReader(manifest)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("kubectl apply: %v: %s", err, output)
	}
}

func waitPod(t *testing.T, name string) {
	t.Helper()
	if _, err := run("kubectl", "-n", e2eNamespace, "wait", "--for=condition=Ready", "pod/"+name, "--timeout=120s"); err != nil {
		t.Fatal(err)
	}
}

func resetE2ENamespace(t *testing.T) {
	t.Helper()
	_, _ = run("kubectl", "delete", "namespace", e2eNamespace, "--ignore-not-found=true", "--wait=true", "--timeout=120s")
}

func waitPodDeleted(t *testing.T, name string) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := run("kubectl", "-n", e2eNamespace, "get", "pod", name); err != nil {
			return
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("Pod %s was not deleted", name)
}

func captureEvidence(t *testing.T, dir string) {
	t.Helper()
	artifacts := map[string][]string{
		"nodes.txt":     {"kubectl", "get", "nodes", "-o", "wide"},
		"pods.txt":      {"kubectl", "-n", e2eNamespace, "get", "pods", "-o", "wide"},
		"daemonset.txt": {"kubectl", "-n", "kube-system", "get", "daemonset", "oncache-e2e-oncache", "-o", "yaml"},
	}
	for name, args := range artifacts {
		output, err := run(args[0], args[1:]...)
		if writeErr := os.WriteFile(filepath.Join(dir, name), []byte(output), 0600); err != nil || writeErr != nil {
			t.Logf("evidence %s unavailable: command=%v err=%v write=%v", name, args, err, writeErr)
		}
	}
	pods, err := run("kubectl", "-n", "kube-system", "get", "pods", "-l", "app.kubernetes.io/name=oncache", "-o", "name")
	if err != nil {
		return
	}
	for _, pod := range strings.Fields(pods) {
		name := strings.TrimPrefix(pod, "pod/")
		for suffix, args := range map[string][]string{
			"log":      {"kubectl", "-n", "kube-system", "logs", pod, "--all-containers", "--prefix"},
			"bpftool":  {"kubectl", "-n", "kube-system", "exec", pod, "--", "bpftool", "prog", "show"},
			"tc.json":  {"kubectl", "-n", "kube-system", "exec", pod, "--", "tc", "-j", "qdisc", "show"},
			"iptables": {"kubectl", "-n", "kube-system", "exec", pod, "--", "iptables-nft", "-t", "mangle", "-S"},
		} {
			output, commandErr := run(args[0], args[1:]...)
			if writeErr := os.WriteFile(filepath.Join(dir, name+"-"+suffix+".txt"), []byte(output), 0600); commandErr != nil || writeErr != nil {
				t.Logf("agent evidence %s/%s unavailable: command=%v err=%v write=%v", name, suffix, args, commandErr, writeErr)
			}
		}
	}
}

func run(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("%s %v: %w: %s", name, args, err, output)
	}
	return strings.TrimSpace(string(output)), nil
}

func mustOutput(t *testing.T, name string, args ...string) string {
	t.Helper()
	output, err := run(name, args...)
	if err != nil {
		t.Fatal(err)
	}
	return output
}

func requiredEnv(t *testing.T, name string) string {
	t.Helper()
	value := os.Getenv(name)
	if value == "" {
		t.Fatalf("%s is required", name)
	}
	return value
}

func getenv(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func splitImage(image string) (string, string) {
	index := strings.LastIndex(image, ":")
	if index < strings.LastIndex(image, "/") {
		return image, "dev"
	}
	return image[:index], image[index+1:]
}
