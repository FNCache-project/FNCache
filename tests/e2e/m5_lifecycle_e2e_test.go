//go:build m3e2e

package e2e

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestM5LifecycleE2E(t *testing.T) {
	if os.Getenv("ONCACHE_M5_LIFECYCLE_E2E") != "1" {
		t.Skip("set ONCACHE_M5_LIFECYCLE_E2E=1 to run M5 lifecycle E2E")
	}
	nodeA := requiredEnv(t, "ONCACHE_M3_E2E_NODE_A")
	nodeB := requiredEnv(t, "ONCACHE_M3_E2E_NODE_B")
	image := requiredEnv(t, "ONCACHE_M3_E2E_IMAGE")
	chart := getenv("ONCACHE_M3_E2E_CHART", "../../charts/oncache")
	evidence := getenv("ONCACHE_M5_LIFECYCLE_EVIDENCE", filepath.Join(os.TempDir(), "oncache-m5-lifecycle"))
	resyncInterval := getenv("ONCACHE_M5_RESYNC_INTERVAL", "15s")
	namespace := fmt.Sprintf("oncache-m5-lifecycle-%d", time.Now().UnixNano())
	rounds := lifecycleRounds(t)

	if err := os.MkdirAll(evidence, 0750); err != nil {
		t.Fatal(err)
	}
	if err := assertNodesReady(nodeA, nodeB); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if output, err := run("helm", "uninstall", "oncache-m5-lifecycle", "--namespace", "kube-system", "--wait"); err != nil {
			t.Logf("cleanup Helm release: %v: %s", err, output)
		}
		if output, err := run("kubectl", "delete", "namespace", namespace, "--ignore-not-found=true", "--wait=true", "--timeout=180s"); err != nil {
			t.Logf("cleanup test namespace: %v: %s", err, output)
		}
	})

	repository, tag := splitImage(image)
	if _, err := run("helm", "upgrade", "--install", "oncache-m5-lifecycle", chart, "--namespace", "kube-system",
		"--set", "image.repository="+repository, "--set", "image.tag="+tag,
		"--set", "agent.installationID=m5-lifecycle", "--set", "config.kubernetes.resyncInterval="+resyncInterval); err != nil {
		t.Fatal(err)
	}
	if _, err := run("kubectl", "-n", "kube-system", "rollout", "status", "daemonset/oncache-m5-lifecycle-oncache", "--timeout=180s"); err != nil {
		t.Fatal(err)
	}
	waitAgentPodsStable(t, nodeA, nodeB)
	applyLifecyclePod(t, namespace, "pod-a", nodeA, image)
	applyLifecyclePod(t, namespace, "pod-b", nodeB, image)
	waitLifecyclePod(t, namespace, "pod-a")
	waitLifecyclePod(t, namespace, "pod-b")
	installObserver(t, namespace, nodeA, image)
	cniObserver := installCNIObserver(t, namespace, nodeB, image)
	waitControlEnabled(t, namespace, evidence)

	for cycle := 0; cycle < rounds; cycle++ {
		name := fmt.Sprintf("churn-%03d", cycle)
		applyLifecyclePod(t, namespace, name, nodeB, image)
		waitLifecyclePod(t, namespace, name)
		assertLifecyclePing(t, namespace, lifecyclePodIP(t, namespace, name))
		deleteLifecyclePod(t, namespace, name)
		waitLifecyclePodDeleted(t, namespace, name)
	}

	assertPodIPReuse(t, namespace, nodeB, image, cniObserver)
	simulateLifecycleEventLoss(t, namespace, nodeA, nodeB, image, evidence)
	captureEvidence(t, namespace, "oncache-m5-lifecycle-oncache", evidence)
}

func lifecycleRounds(t *testing.T) int {
	t.Helper()
	value := getenv("ONCACHE_M5_CHURN_ROUNDS", "30")
	rounds, err := strconv.Atoi(value)
	if err != nil || rounds < 1 || rounds > 200 {
		t.Fatalf("invalid ONCACHE_M5_CHURN_ROUNDS=%q", value)
	}
	return rounds
}

func applyLifecyclePod(t *testing.T, namespace, name, node, image string) {
	t.Helper()
	applyManifest(t, lifecyclePodManifest(namespace, name, node, image))
}

func lifecyclePodManifest(namespace, name, node, image string) []byte {
	return []byte(fmt.Sprintf("apiVersion: v1\nkind: Namespace\nmetadata:\n  name: %s\n---\n%s", namespace, lifecyclePodObject(namespace, name, node, image)))
}

func lifecyclePodObject(namespace, name, node, image string) string {
	return fmt.Sprintf(`apiVersion: v1
kind: Pod
metadata:
  name: %s
  namespace: %s
  labels:
    app: oncache-m5-lifecycle
spec:
  nodeName: %s
  containers:
    - name: app
      image: %s
      command: ["sh", "-c", "sleep 3600"]
`, name, namespace, node, image)
}

func waitLifecyclePod(t *testing.T, namespace, name string) {
	t.Helper()
	if _, err := run("kubectl", "-n", namespace, "wait", "--for=condition=Ready", "pod/"+name, "--timeout=120s"); err != nil {
		t.Fatal(err)
	}
}

func deleteLifecyclePod(t *testing.T, namespace, name string) {
	t.Helper()
	if _, err := run("kubectl", "-n", namespace, "delete", "pod", name, "--wait=true"); err != nil {
		t.Fatal(err)
	}
}

func deleteLifecyclePodForce(t *testing.T, namespace, name string) {
	t.Helper()
	if _, err := run("kubectl", "-n", namespace, "delete", "pod", name, "--force", "--grace-period=0", "--wait=false"); err != nil {
		t.Fatal(err)
	}
	waitLifecyclePodDeleted(t, namespace, name)
}

func waitLifecyclePodDeleted(t *testing.T, namespace, name string) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := run("kubectl", "-n", namespace, "get", "pod", name); err != nil {
			return
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("Pod %s was not deleted", name)
}

func lifecyclePodIP(t *testing.T, namespace, name string) string {
	t.Helper()
	return mustOutput(t, "kubectl", "-n", namespace, "get", "pod", name, "-o", "jsonpath={.status.podIP}")
}

func lifecyclePodUID(t *testing.T, namespace, name string) string {
	t.Helper()
	return mustOutput(t, "kubectl", "-n", namespace, "get", "pod", name, "-o", "jsonpath={.metadata.uid}")
}

func assertLifecyclePing(t *testing.T, namespace, ip string) {
	t.Helper()
	if _, err := run("kubectl", "-n", namespace, "exec", "pod-a", "--", "ping", "-c", "1", "-W", "2", ip); err != nil {
		t.Fatal(err)
	}
}

func installCNIObserver(t *testing.T, namespace, node, image string) string {
	t.Helper()
	name := "oncache-m5-cni-observer"
	manifest := fmt.Sprintf(`apiVersion: v1
kind: Pod
metadata:
  name: %s
  namespace: %s
spec:
  nodeName: %s
  hostNetwork: true
  hostPID: true
  restartPolicy: Always
  containers:
    - name: observer
      image: %s
      command: ["sh", "-c", "while :; do sleep 3600; done"]
      securityContext:
        privileged: true
      volumeMounts:
        - name: cni
          mountPath: /host-cni
  volumes:
    - name: cni
      hostPath:
        path: /var/lib/cni
        type: Directory
`, name, namespace, node, image)
	applyManifest(t, []byte(manifest))
	if _, err := run("kubectl", "-n", namespace, "wait", "--for=jsonpath={.status.phase}=Running", "pod/"+name, "--timeout=60s"); err != nil {
		t.Fatal(err)
	}
	return name
}

func assertPodIPReuse(t *testing.T, namespace, node, image, observer string) {
	t.Helper()
	oldName := "reuse-old"
	applyLifecyclePod(t, namespace, oldName, node, image)
	waitLifecyclePod(t, namespace, oldName)
	oldIP, oldUID := lifecyclePodIP(t, namespace, oldName), lifecyclePodUID(t, namespace, oldName)
	deleteLifecyclePodForce(t, namespace, oldName)
	waitCNIAllocationReleased(t, namespace, node, observer, oldIP)
	prepareCNIIPReuse(t, namespace, node, observer, oldIP)
	defer restoreCNIIPReuse(t, namespace, observer)
	if cursor, err := run("kubectl", "-n", namespace, "exec", observer, "--", "cat", "/host-cni/networks/cbr0/last_reserved_ip.0"); err == nil {
		t.Logf("CNI cursor before reuse: %s", cursor)
	}
	name := "reuse-new"
	applyLifecyclePod(t, namespace, name, node, image)
	waitLifecyclePod(t, namespace, name)
	newIP, newUID := lifecyclePodIP(t, namespace, name), lifecyclePodUID(t, namespace, name)
	if cursor, err := run("kubectl", "-n", namespace, "exec", observer, "--", "cat", "/host-cni/networks/cbr0/last_reserved_ip.0"); err == nil {
		t.Logf("CNI cursor after reuse: %s", cursor)
	}
	var reusedIP string
	if newIP == oldIP && newUID != oldUID {
		reusedIP = newIP
	}
	if reusedIP == "" {
		t.Fatalf("PodIP was not reused: old=%s/%s new=%s/%s", oldIP, oldUID, newIP, newUID)
	}
	assertLifecyclePing(t, namespace, reusedIP)
	deleteLifecyclePodForce(t, namespace, name)
}

func waitCNIAllocationReleased(t *testing.T, namespace, node, observer, ip string) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	stable := 0
	for time.Now().Before(deadline) {
		if _, err := run("kubectl", "-n", namespace, "exec", observer, "--", "sh", "-c", "test ! -e \"/host-cni/networks/cbr0/$1\"", "--", ip); err == nil {
			stable++
			if stable >= 5 {
				return
			}
		} else {
			stable = 0
		}
		time.Sleep(time.Second)
	}
	for _, activeIP := range activeNodePodIPs(t, node) {
		if activeIP == ip {
			t.Fatalf("CNI allocation for active Pod IP %s was not released", ip)
		}
	}
	if _, err := run("kubectl", "-n", namespace, "exec", observer, "--", "rm", "-f", "/host-cni/networks/cbr0/"+ip); err != nil {
		t.Fatalf("remove stale CNI allocation for deleted Pod IP %s: %v", ip, err)
	}
	t.Logf("removed stale CNI allocation for deleted Pod IP %s after release timeout", ip)
}

func prepareCNIIPReuse(t *testing.T, namespace, node, observer, oldIP string) {
	t.Helper()
	protectedIPs := activeNodePodIPs(t, node)
	script := `set -eu
state=/host-cni/networks/cbr0
old="$1"
shift
keep=" $* "
last="$state/last_reserved_ip.0"
backup="$state/last_reserved_ip.0.oncache-m5-backup"
test -f "$last"
cp "$last" "$backup"
for file in "$state"/10.42.1.*; do
  test -f "$file" || continue
  ip="${file##*/}"
  case "$keep" in
    *" $ip "*) ;;
    *) rm -f "$file" ;;
  esac
done
rm -f "$state/$old"
IFS=.
set -- $old
case "${4:-}" in
  ''|*[!0-9]*) exit 1 ;;
esac
test "$4" -gt 1
printf '%s.%s.%s.%s' "$1" "$2" "$3" "$(( $4 - 1 ))" > "$last"
`
	args := []string{"kubectl", "-n", namespace, "exec", observer, "--", "sh", "-c", script, "--", oldIP}
	args = append(args, protectedIPs...)
	if _, err := run(args[0], args[1:]...); err != nil {
		t.Fatalf("prepare deterministic CNI reuse for %s: %v", oldIP, err)
	}
}

func activeNodePodIPs(t *testing.T, node string) []string {
	t.Helper()
	output, err := run("kubectl", "get", "pods", "-A", "--field-selector", "spec.nodeName="+node, "-o", "jsonpath={range .items[*]}{.status.podIP}{\"\\n\"}{end}")
	if err != nil {
		t.Fatalf("list active Pod IPs on %s: %v", node, err)
	}
	var protected []string
	for _, ip := range strings.Fields(output) {
		if net.ParseIP(ip) != nil && strings.Contains(ip, ".") {
			protected = append(protected, ip)
		}
	}
	return protected
}

func restoreCNIIPReuse(t *testing.T, namespace, observer string) {
	t.Helper()
	script := `set -eu
state=/host-cni/networks/cbr0
last="$state/last_reserved_ip.0"
backup="$state/last_reserved_ip.0.oncache-m5-backup"
if test -f "$backup"; then
  cp "$backup" "$last"
  rm -f "$backup"
fi`
	if _, err := run("kubectl", "-n", namespace, "exec", observer, "--", "sh", "-c", script); err != nil {
		t.Logf("restore CNI allocator cursor: %v", err)
	}
}

func simulateLifecycleEventLoss(t *testing.T, namespace, nodeA, nodeB, image, evidence string) {
	t.Helper()
	agent := agentPodForNode(t, nodeA)
	if _, err := run("kubectl", "-n", "kube-system", "exec", agent, "--", "kill", "-STOP", "1"); err != nil {
		t.Fatal(err)
	}
	lost := "event-lost"
	applyLifecyclePod(t, namespace, lost, nodeA, image)
	waitLifecyclePod(t, namespace, lost)
	deleteLifecyclePodForce(t, namespace, lost)
	if _, err := run("kubectl", "-n", "kube-system", "exec", agent, "--", "kill", "-CONT", "1"); err != nil {
		t.Fatal(err)
	}
	waitAgentPodsStable(t, nodeA, nodeB)
	recovered := "event-recovered"
	applyLifecyclePod(t, namespace, recovered, nodeB, image)
	waitLifecyclePod(t, namespace, recovered)
	assertLifecyclePing(t, namespace, lifecyclePodIP(t, namespace, recovered))
	deleteLifecyclePodForce(t, namespace, recovered)
	if output, err := run("kubectl", "-n", "kube-system", "get", "pod", agent, "-o", "jsonpath={.status.containerStatuses[0].restartCount}"); err == nil {
		_ = os.WriteFile(filepath.Join(evidence, "event-loss-agent-restarts.txt"), []byte(strings.TrimSpace(output)), 0600)
	}
}
