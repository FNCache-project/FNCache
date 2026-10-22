//go:build m3e2e

package e2e

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

const m4ObserverPod = "oncache-m4-observer"

func TestM4ShutdownE2E(t *testing.T) {
	if os.Getenv("ONCACHE_M4_SHUTDOWN_E2E") != "1" {
		t.Skip("set ONCACHE_M4_SHUTDOWN_E2E=1 to run M4 shutdown E2E")
	}
	nodeA := requiredEnv(t, "ONCACHE_M3_E2E_NODE_A")
	nodeB := requiredEnv(t, "ONCACHE_M3_E2E_NODE_B")
	image := requiredEnv(t, "ONCACHE_M3_E2E_IMAGE")
	chart := getenv("ONCACHE_M3_E2E_CHART", "../../charts/oncache")
	evidence := getenv("ONCACHE_M4_SHUTDOWN_EVIDENCE", filepath.Join(os.TempDir(), "oncache-m4-shutdown"))
	m4Namespace := fmt.Sprintf("oncache-m4-%d", time.Now().UnixNano())
	heartbeatTimeout := parseM4Duration(t, "ONCACHE_M4_HEARTBEAT_TIMEOUT", 5*time.Second)
	heartbeatInterval := parseM4Duration(t, "ONCACHE_M4_HEARTBEAT_INTERVAL", time.Second)
	if err := os.MkdirAll(evidence, 0750); err != nil {
		t.Fatal(err)
	}
	if err := assertNodesReady(nodeA, nodeB); err != nil {
		t.Fatal(err)
	}
	manifest, err := os.ReadFile("fixtures.yaml")
	if err != nil {
		t.Fatal(err)
	}
	manifest = bytes.ReplaceAll(manifest, []byte("NODE_A"), []byte(nodeA))
	manifest = bytes.ReplaceAll(manifest, []byte("NODE_B"), []byte(nodeB))
	manifest = bytes.ReplaceAll(manifest, []byte("name: "+e2eNamespace), []byte("name: "+m4Namespace))
	manifest = bytes.ReplaceAll(manifest, []byte("namespace: "+e2eNamespace), []byte("namespace: "+m4Namespace))
	applyManifest(t, manifest)
	if os.Getenv("ONCACHE_M4_SHUTDOWN_CLEANUP") == "1" {
		t.Cleanup(func() {
			_, _ = run("kubectl", "delete", "namespace", m4Namespace, "--ignore-not-found=true", "--wait=false")
		})
	}
	_, _ = run("helm", "uninstall", "oncache-e2e", "--namespace", "kube-system")
	repository, tag := splitImage(image)
	if _, err := run("helm", "upgrade", "--install", "oncache-m4", chart, "--namespace", "kube-system", "--set", "image.repository="+repository, "--set", "image.tag="+tag, "--set", "agent.installationID=m4-shutdown", "--set", "security.privileged=true"); err != nil {
		t.Fatal(err)
	}
	if _, err := run("kubectl", "-n", "kube-system", "rollout", "restart", "daemonset/oncache-m4-oncache"); err != nil {
		t.Fatal(err)
	}
	if _, err := run("kubectl", "-n", "kube-system", "rollout", "status", "daemonset/oncache-m4-oncache", "--timeout=180s"); err != nil {
		t.Fatal(err)
	}
	waitAgentPodsStable(t, nodeA, nodeB)
	waitM4Pod(t, m4Namespace, "pod-a")
	waitM4Pod(t, m4Namespace, "pod-b")
	installObserver(t, m4Namespace, nodeA, image)
	verifyM4Tools(t, m4Namespace, evidence)
	waitControlEnabled(t, m4Namespace, evidence)
	assertM4Traffic(t, m4Namespace)
	agent := agentPodForNode(t, nodeA)
	assertHeartbeatAdvances(t, m4Namespace, heartbeatInterval, evidence)

	signalAgent(t, agent, "TERM")
	waitHeartbeatDisabled(t, m4Namespace, evidence, "sigterm")
	if _, err := run("kubectl", "-n", "kube-system", "rollout", "status", "daemonset/oncache-m4-oncache", "--timeout=180s"); err != nil {
		t.Fatal(err)
	}
	waitAgentPodsStable(t, nodeA, nodeB)
	assertM4Traffic(t, m4Namespace)

	agent = agentPodForNode(t, nodeA)
	assertHeartbeatAdvances(t, m4Namespace, heartbeatInterval, evidence)
	blockM4Recovery(t)
	signalAgent(t, agent, "KILL")
	waitHeartbeatStable(t, m4Namespace, heartbeatTimeout+time.Second, evidence, "sigkill")
	restoreM4Release(t, chart, image)
	if _, err := run("kubectl", "-n", "kube-system", "rollout", "status", "daemonset/oncache-m4-oncache", "--timeout=180s"); err != nil {
		t.Fatal(err)
	}
	waitAgentPodsStable(t, nodeA, nodeB)
	assertM4Traffic(t, m4Namespace)
	captureEvidence(t, m4Namespace, "oncache-m4-oncache", evidence)
}

func installObserver(t *testing.T, namespace, node, image string) {
	installObserverNamed(t, namespace, m4ObserverPod, node, image)
}

func installObserverNamed(t *testing.T, namespace, name, node, image string) {
	t.Helper()
	manifest := fmt.Sprintf(`apiVersion: v1
kind: Pod
metadata:
  name: %s
  namespace: %s
spec:
  nodeName: %s
  hostNetwork: true
  hostPID: true
  restartPolicy: Never
  containers:
    - name: observer
      image: %s
      command: ["sh", "-c", "sleep 3600"]
      securityContext:
        privileged: true
      volumeMounts:
        - name: bpf
          mountPath: /sys/fs/bpf
        - name: oncache-tools
          mountPath: /opt/oncache
  volumes:
    - name: bpf
      hostPath:
        path: /sys/fs/bpf
        type: Directory
    - name: oncache-tools
      hostPath:
        path: /opt/oncache
        type: Directory
	`, name, namespace, node, image)
	applyManifest(t, []byte(manifest))
	if _, err := run("kubectl", "-n", namespace, "wait", "--for=jsonpath={.status.phase}=Running", "pod/"+name, "--timeout=60s"); err != nil {
		t.Fatal(err)
	}
}

func verifyM4Tools(t *testing.T, namespace, evidence string) {
	t.Helper()
	tools := map[string][]string{"bpftool": {"/opt/oncache/bin/bpftool", "version"}, "tc": {"/opt/oncache/sbin/tc", "-V"}, "tcpdump": {"tcpdump", "--version"}, "iptables": {"iptables-nft", "--version"}}
	for name, args := range tools {
		output, err := runObserver(namespace, args...)
		if err != nil || strings.TrimSpace(output) == "" {
			t.Fatalf("M4 evidence tool %s unavailable: err=%v output=%q", name, err, output)
		}
		if err := os.WriteFile(filepath.Join(evidence, "tool-"+name+".txt"), []byte(output), 0600); err != nil {
			t.Fatal(err)
		}
	}
	_ = mustObserverDump(t, namespace, evidence, "initial")
}

func assertM4Traffic(t *testing.T, namespace string) {
	t.Helper()
	podBIP := mustOutput(t, "kubectl", "-n", namespace, "get", "pod", "pod-b", "-o", "jsonpath={.status.podIP}")
	if _, err := run("kubectl", "-n", namespace, "exec", "pod-a", "--", "ping", "-c", "3", "-W", "2", podBIP); err != nil {
		t.Fatal(err)
	}
}

func waitControlEnabled(t *testing.T, namespace, evidence string) {
	t.Helper()
	deadline := time.Now().Add(180 * time.Second)
	for time.Now().Before(deadline) {
		output := mustObserverDump(t, namespace, evidence, "ready-sample")
		if strings.Contains(output, `"enabled":1`) {
			time.Sleep(2 * time.Second)
			stable := mustObserverDump(t, namespace, evidence, "ready-stable")
			if strings.Contains(stable, `"enabled":1`) {
				return
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("control Map did not become enabled after initial reconciliation")
}

func waitM4Pod(t *testing.T, namespace, name string) {
	t.Helper()
	if _, err := run("kubectl", "-n", namespace, "get", "pod/"+name); err != nil {
		t.Fatal(err)
	}
	if _, err := run("kubectl", "-n", namespace, "wait", "--for=condition=Ready", "pod/"+name, "--timeout=120s"); err != nil {
		t.Fatal(err)
	}
}

func agentPodForNode(t *testing.T, node string) string {
	t.Helper()
	output := mustOutput(t, "kubectl", "-n", "kube-system", "get", "pods", "-l", "app.kubernetes.io/name=oncache", "-o", "jsonpath={range .items[*]}{.metadata.name}{\" \"}{.spec.nodeName}{\"\\n\"}{end}")
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[1] == node {
			return fields[0]
		}
	}
	t.Fatalf("no agent Pod found on node %s: %s", node, output)
	return ""
}

func waitAgentPodsStable(t *testing.T, nodes ...string) {
	t.Helper()
	want := make(map[string]bool, len(nodes))
	for _, node := range nodes {
		want[node] = true
	}
	started := time.Now()
	deadline := time.Now().Add(300 * time.Second)
	stableSince := time.Time{}
	lastIdentity := ""
	for time.Now().Before(deadline) {
		output, err := run("kubectl", "-n", "kube-system", "get", "pods", "-l", "app.kubernetes.io/name=oncache", "-o", "jsonpath={range .items[*]}{.metadata.name}{\" \"}{.spec.nodeName}{\" \"}{.status.phase}{\" \"}{.status.containerStatuses[0].ready}{\" \"}{.metadata.deletionTimestamp}{\"\\n\"}{end}")
		if err == nil {
			seen := make(map[string]bool, len(nodes))
			identity := make([]string, 0, len(nodes))
			stable := true
			for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
				fields := strings.Fields(line)
				if len(fields) != 4 && len(fields) != 5 {
					stable = false
					break
				}
				if !want[fields[1]] || fields[2] != "Running" || fields[3] != "true" || (len(fields) == 5 && fields[4] != "<none>") {
					if len(fields) == 5 && fields[4] != "<none>" && time.Since(started) >= 20*time.Second {
						_, _ = run("kubectl", "-n", "kube-system", "delete", "pod", fields[0], "--force", "--grace-period=0", "--wait=false")
					}
					stable = false
					break
				}
				if seen[fields[1]] {
					stable = false
					break
				}
				seen[fields[1]] = true
				identity = append(identity, fields[1]+"="+fields[0])
			}
			if stable && len(seen) == len(want) {
				for node := range want {
					if !agentReadyz(node) {
						stable = false
						break
					}
				}
			}
			if stable && len(seen) == len(want) {
				sort.Strings(identity)
				currentIdentity := strings.Join(identity, ",")
				if currentIdentity != lastIdentity {
					lastIdentity = currentIdentity
					stableSince = time.Now()
				} else if time.Since(stableSince) >= 5*time.Second {
					return
				}
			} else {
				lastIdentity = ""
				stableSince = time.Time{}
			}
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("agent DaemonSet did not settle to one Ready Pod per node")
}

func agentReadyz(node string) bool {
	ip, err := run("kubectl", "get", "node", node, "-o", "jsonpath={.status.addresses[?(@.type==\"InternalIP\")].address}")
	if err != nil || ip == "" {
		return false
	}
	client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 2 * time.Second}
	response, err := client.Get("http://" + ip + ":9090/readyz")
	if err != nil {
		return false
	}
	body, readErr := io.ReadAll(response.Body)
	_ = response.Body.Close()
	return readErr == nil && response.StatusCode == http.StatusOK && strings.Contains(string(body), `"ready":true`)
}

func signalAgent(t *testing.T, pod, signal string) {
	t.Helper()
	if signal != "TERM" && signal != "KILL" {
		t.Fatalf("unsupported agent signal %q", signal)
	}
	args := []string{"-n", "kube-system", "delete", "pod", pod, "--wait=false"}
	if signal == "KILL" {
		args = append(args, "--force", "--grace-period=0")
	}
	output, err := run("kubectl", args...)
	if err != nil {
		t.Fatalf("failed to signal agent: err=%v output=%s", err, output)
	}
}

func waitHeartbeatDisabled(t *testing.T, namespace, evidence, label string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		output := mustObserverDump(t, namespace, evidence, label+"-sample")
		if strings.Contains(output, `"enabled":0`) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("control Map did not enter disabled state after %s", label)
}

func assertHeartbeatAdvances(t *testing.T, namespace string, interval time.Duration, evidence string) {
	t.Helper()
	first := mustObserverDump(t, namespace, evidence, "heartbeat-before")
	if !strings.Contains(first, `"enabled":1`) {
		t.Fatalf("heartbeat baseline is not enabled: %q", first)
	}
	time.Sleep(interval * 2)
	second := mustObserverDump(t, namespace, evidence, "heartbeat-after")
	if !strings.Contains(second, `"enabled":1`) {
		t.Fatalf("heartbeat stopped while fast path was expected to be enabled: %q", second)
	}
	if first == second {
		t.Fatalf("control Map heartbeat did not advance: %q", first)
	}
}

func waitHeartbeatStable(t *testing.T, namespace string, stable time.Duration, evidence, label string) {
	t.Helper()
	previous := mustObserverDump(t, namespace, evidence, label+"-start")
	stableSince := time.Now()
	deadline := time.Now().Add(stable + 2*time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(250 * time.Millisecond)
		current := mustObserverDump(t, namespace, evidence, label+"-sample")
		if current != previous {
			previous = current
			stableSince = time.Now()
		}
		if time.Since(stableSince) >= stable {
			return
		}
	}
	t.Fatalf("heartbeat did not remain stable for %s after %s", stable, label)
}

func blockM4Recovery(t *testing.T) {
	t.Helper()
	invalid := `{"data":{"agent.yaml":"invalid: ["}}`
	if _, err := run("kubectl", "-n", "kube-system", "patch", "configmap", "oncache-m4-oncache", "--type=merge", "-p", invalid); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second)
}

func restoreM4Release(t *testing.T, chart, image string) {
	t.Helper()
	repository, tag := splitImage(image)
	if _, err := run("helm", "upgrade", "--install", "oncache-m4", chart, "--namespace", "kube-system", "--set", "image.repository="+repository, "--set", "image.tag="+tag, "--set", "agent.installationID=m4-shutdown", "--set", "security.privileged=true"); err != nil {
		t.Fatal(err)
	}
	if _, err := run("kubectl", "-n", "kube-system", "rollout", "restart", "daemonset/oncache-m4-oncache"); err != nil {
		t.Fatal(err)
	}
}

func mustObserverDump(t *testing.T, namespace, evidence, label string) string {
	t.Helper()
	output, err := runObserver(namespace, "/opt/oncache/bin/bpftool", "-j", "map", "dump", "pinned", "/sys/fs/bpf/oncache/v1/maps/control_map")
	if err != nil || strings.TrimSpace(output) == "" {
		t.Fatalf("control Map evidence unavailable: err=%v output=%q", err, output)
	}
	if err := os.WriteFile(filepath.Join(evidence, "control-"+label+".json"), []byte(output), 0600); err != nil {
		t.Fatal(err)
	}
	return output
}

func runObserver(namespace string, args ...string) (string, error) {
	return runObserverPod(namespace, m4ObserverPod, args...)
}

func runObserverPod(namespace, pod string, args ...string) (string, error) {
	full := append([]string{"kubectl", "-n", namespace, "exec", pod, "--"}, args...)
	return run(full[0], full[1:]...)
}

func parseM4Duration(t *testing.T, name string, fallback time.Duration) time.Duration {
	t.Helper()
	value := getenv(name, fallback.String())
	duration, err := time.ParseDuration(value)
	if err != nil || duration <= 0 {
		t.Fatalf("invalid %s=%q", name, value)
	}
	return duration
}
