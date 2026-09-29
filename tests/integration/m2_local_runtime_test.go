//go:build linux && integration

package integration_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type localRuntimeSnapshot struct {
	maps     []string
	programs []string
	tc       string
	marker   string
}

func TestM2LocalStaticRuntime(t *testing.T) {
	requireLocalRuntimeEnvironment(t)
	pinRoot := requiredEnv(t, "ONCACHE_M2_PIN_ROOT")
	statePath := requiredEnv(t, "ONCACHE_M2_STATE_PATH")
	markerComment := requiredEnv(t, "ONCACHE_M2_MARKER_COMMENT")
	underlay := requiredEnv(t, "ONCACHE_M2_UNDERLAY_IFNAME")
	t.Cleanup(func() { cleanupLocalRuntime(t, pinRoot, statePath) })

	runStaticAgent(t)
	first := snapshotLocalRuntime(t, pinRoot, statePath, markerComment, underlay)
	assertExpectedPins(t, first)
	installExternalFilter(t, pinRoot, underlay)
	withExternal := snapshotLocalRuntime(t, pinRoot, statePath, markerComment, underlay)

	runStaticAgent(t)
	second := snapshotLocalRuntime(t, pinRoot, statePath, markerComment, underlay)
	assertSameSnapshot(t, withExternal, second, "repeat reconciliation")
	if !strings.Contains(second.tc, `"handle":"0x900"`) {
		t.Fatalf("external TC filter was not preserved: %s", second.tc)
	}

	runStaticAgent(t)
	third := snapshotLocalRuntime(t, pinRoot, statePath, markerComment, underlay)
	assertSameSnapshot(t, second, third, "restart reconciliation")
	assertFailureDisablesFastPath(t, pinRoot)
}

func installExternalFilter(t *testing.T, pinRoot, underlay string) {
	t.Helper()
	link, err := netlink.LinkByName(underlay)
	if err != nil {
		t.Fatalf("find underlay for external filter: %v", err)
	}
	program, err := ebpf.LoadPinnedProgram(filepath.Join(pinRoot, "programs", "tc_init_e"), nil)
	if err != nil {
		t.Fatalf("load external filter program: %v", err)
	}
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{LinkIndex: link.Attrs().Index, Parent: netlink.HANDLE_MIN_INGRESS, Priority: 2000, Handle: 0x900, Protocol: unix.ETH_P_ALL},
		Fd:          program.FD(), Name: "tc_init_e", DirectAction: true,
	}
	if err := netlink.FilterAdd(filter); err != nil {
		_ = program.Close()
		t.Fatalf("add external filter: %v", err)
	}
	if err := program.Close(); err != nil {
		t.Fatalf("close external filter program: %v", err)
	}
	t.Cleanup(func() {
		filter.Fd = -1
		if err := netlink.FilterDel(filter); err != nil {
			t.Errorf("remove external filter: %v", err)
		}
	})
}

func assertFailureDisablesFastPath(t *testing.T, pinRoot string) {
	t.Helper()
	manifest := requiredEnv(t, "ONCACHE_STATIC_MANIFEST")
	data, err := os.ReadFile(manifest)
	if err != nil {
		t.Fatalf("read runtime manifest for failure test: %v", err)
	}
	data = []byte(strings.Replace(string(data), "vxlanLinkName: flannel.1", "vxlanLinkName: missing-vxlan", 1))
	failureManifest := filepath.Join(t.TempDir(), "failure.yaml")
	if err := os.WriteFile(failureManifest, data, 0o600); err != nil {
		t.Fatalf("write failure manifest: %v", err)
	}
	agent := requiredEnv(t, "ONCACHE_AGENT_BIN")
	output, err := exec.Command(agent, "-static-config", failureManifest).CombinedOutput()
	if err == nil {
		t.Fatalf("failure manifest unexpectedly succeeded: %s", output)
	}
	control := commandOutput(t, "bpftool", "map", "dump", "pinned", filepath.Join(pinRoot, "maps", "control_map"))
	if !strings.Contains(control, `"enabled": 0`) {
		t.Fatalf("fast path remained enabled after discovery failure: %s", control)
	}
}

func requireLocalRuntimeEnvironment(t *testing.T) {
	t.Helper()
	if os.Getenv("ONCACHE_M2_LOCAL") != "1" {
		t.Skip("set ONCACHE_M2_LOCAL=1 to run the VM static runtime test")
	}
	if os.Geteuid() != 0 {
		t.Fatal("M2 local runtime test requires root")
	}
	if err := exec.Command("systemd-detect-virt", "--vm").Run(); err != nil {
		t.Fatal("refusing privileged integration test outside a verified VM")
	}
	for _, name := range []string{"ip", "tc", "iptables-nft", "bpftool"} {
		if _, err := exec.LookPath(name); err != nil {
			t.Fatalf("required command %s is unavailable: %v", name, err)
		}
	}
}

func runStaticAgent(t *testing.T) {
	t.Helper()
	agent := requiredEnv(t, "ONCACHE_AGENT_BIN")
	manifest := requiredEnv(t, "ONCACHE_STATIC_MANIFEST")
	output, err := exec.Command(agent, "-static-config", manifest, "-once").CombinedOutput()
	if err != nil {
		t.Fatalf("static agent failed: %v\n%s", err, output)
	}
	control := commandOutput(t, "bpftool", "map", "dump", "pinned", filepath.Join(requiredEnv(t, "ONCACHE_M2_PIN_ROOT"), "maps", "control_map"))
	if !strings.Contains(control, `"enabled": 0`) {
		t.Fatalf("one-shot static agent left fast path enabled: %s", control)
	}
}

func snapshotLocalRuntime(t *testing.T, pinRoot, statePath, markerComment, underlay string) localRuntimeSnapshot {
	t.Helper()
	maps := readPinNames(t, filepath.Join(pinRoot, "maps"))
	programs := readPinNames(t, filepath.Join(pinRoot, "programs"))
	if _, err := os.Stat(statePath); err != nil {
		t.Fatalf("ownership state is missing: %v", err)
	}
	tcParts := []string{
		commandOutput(t, "tc", "-j", "filter", "show", "dev", underlay, "ingress"),
		commandOutput(t, "tc", "-j", "filter", "show", "dev", underlay, "egress"),
	}
	var links []struct {
		IfName string `json:"ifname"`
	}
	if err := json.Unmarshal([]byte(commandOutput(t, "ip", "-j", "link", "show", "type", "veth")), &links); err != nil {
		t.Fatalf("decode host veth list: %v", err)
	}
	for _, link := range links {
		if output, err := tryCommandOutput("tc", "-j", "filter", "show", "dev", link.IfName, "ingress"); err == nil {
			tcParts = append(tcParts, output)
		}
	}
	entries, err := os.ReadDir("/var/run/netns")
	if err != nil {
		t.Fatalf("read netns directory: %v", err)
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "cni-") {
			continue
		}
		if output, err := tryCommandOutput("ip", "netns", "exec", entry.Name(), "tc", "-j", "filter", "show", "dev", "eth0", "ingress"); err == nil {
			tcParts = append(tcParts, output)
		}
	}
	tc := strings.Join(tcParts, "\n")
	for _, program := range []string{"tc_init_e", "tc_restore", "tc_init_in", "tc_masq"} {
		if !strings.Contains(tc, program) {
			t.Fatalf("TC program %s is missing: %s", program, tc)
		}
	}
	marker := commandOutput(t, "iptables-nft", "-t", "mangle", "-S")
	if !strings.Contains(marker, markerComment) {
		t.Fatalf("marker comment %q is missing from rules: %s", markerComment, marker)
	}
	return localRuntimeSnapshot{maps: maps, programs: programs, tc: tc, marker: marker}
}

func assertExpectedPins(t *testing.T, snapshot localRuntimeSnapshot) {
	t.Helper()
	wantMaps := []string{"control_map", "devmap", "egress_cache", "egressip_cache", "ingress_cache", "policy_cache", "policy_lock_map", "stats_map"}
	wantPrograms := []string{"tc_init_e", "tc_init_in", "tc_masq", "tc_restore"}
	if !reflect.DeepEqual(snapshot.maps, wantMaps) {
		t.Fatalf("unexpected Map pins: got=%v want=%v", snapshot.maps, wantMaps)
	}
	if !reflect.DeepEqual(snapshot.programs, wantPrograms) {
		t.Fatalf("unexpected Program pins: got=%v want=%v", snapshot.programs, wantPrograms)
	}
}

func assertSameSnapshot(t *testing.T, before, after localRuntimeSnapshot, phase string) {
	t.Helper()
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("%s changed runtime objects: before=%+v after=%+v", phase, before, after)
	}
}

func readPinNames(t *testing.T, path string) []string {
	t.Helper()
	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatalf("read pin directory %s: %v", path, err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	return names
}

func cleanupLocalRuntime(t *testing.T, pinRoot, statePath string) {
	t.Helper()
	if os.Getenv("ONCACHE_M2_CLEANUP") != "1" {
		return
	}
	if !strings.HasPrefix(pinRoot, "/sys/fs/bpf/oncache/m2-local-") || !strings.HasPrefix(statePath, "/var/lib/oncache/m2-local-") {
		t.Fatalf("refusing cleanup outside dedicated M2 local prefixes")
	}
	if err := os.RemoveAll(pinRoot); err != nil {
		t.Errorf("remove test pin root: %v", err)
	}
	if err := os.Remove(statePath); err != nil && !os.IsNotExist(err) {
		t.Errorf("remove test state: %v", err)
	}
}

func requiredEnv(t *testing.T, name string) string {
	t.Helper()
	value := os.Getenv(name)
	if value == "" {
		t.Fatalf("environment variable %s is required", name)
	}
	return value
}

func commandOutput(t *testing.T, name string, args ...string) string {
	t.Helper()
	output, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("command %s %s failed: %v\n%s", name, strings.Join(args, " "), err, output)
	}
	return string(output)
}

func tryCommandOutput(name string, args ...string) (string, error) {
	output, err := exec.Command(name, args...).CombinedOutput()
	return string(output), err
}
