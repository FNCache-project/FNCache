package discovery_test

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/cat-cc-Lcos/FNCache/internal/discovery"
	"github.com/cat-cc-Lcos/FNCache/internal/resolver"
)

func TestLinuxProbeReportsBasicCapabilities(t *testing.T) {
	probe, request, _, cleanup := probeFixture(t, true, true, true)
	defer cleanup()
	snapshot, err := probe.Probe(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.KernelRelease != "5.15.0-test" || snapshot.Architecture != runtime.GOARCH || !snapshot.HasBTF || !snapshot.BPFFSMounted || !snapshot.TCSupported {
		t.Fatalf("unexpected host snapshot: %+v", snapshot)
	}
	for _, check := range snapshot.Checks {
		if !check.Supported {
			t.Fatalf("basic check failed: %+v", check)
		}
	}
}

func TestLinuxProbeReportsMissingCapabilities(t *testing.T) {
	tests := []struct {
		name   string
		mount  bool
		btf    bool
		cri    bool
		reason string
	}{
		{name: "bpffs", btf: true, cri: true, reason: "BPFFS_NOT_MOUNTED"},
		{name: "btf", mount: true, cri: true, reason: "BTF_MISSING"},
		{name: "cri", mount: true, btf: true, reason: "CRI_SOCKET_UNAVAILABLE"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			probe, request, _, cleanup := probeFixture(t, tc.mount, tc.btf, tc.cri)
			defer cleanup()
			snapshot, err := probe.Probe(context.Background(), request)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, check := range snapshot.Checks {
				if check.ReasonCode == tc.reason {
					found = true
					if check.Supported {
						t.Fatalf("expected unsupported check: %+v", check)
					}
				}
			}
			if !found {
				t.Fatalf("reason %q was not reported", tc.reason)
			}
		})
	}
}

func TestLinuxProbeAcceptsConfiguredCustomMarker(t *testing.T) {
	runner := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == "iptables-nft" {
			return []byte(`-A FNCACHE -m comment --comment "fncache:marker" -m conntrack --ctstate ESTABLISHED -m tos --tos 0x04/0x04 -j TOS --set-tos 0x08/0x08`), nil
		}
		return fakeCommandRunner(ctx, name, args...)
	}
	probe, request, _, cleanup := probeFixtureWithRunner(t, true, true, true, runner)
	defer cleanup()
	request.MarkerChain = "FNCACHE"
	request.MarkerComment = "fncache:marker"

	snapshot, err := probe.Probe(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, check := range snapshot.Checks {
		if check.Name != "tos" && check.Name != "external/conflicts" {
			continue
		}
		found[check.Name] = true
		if !check.Supported {
			t.Fatalf("configured custom marker was reported as a conflict: %+v", check)
		}
	}
	if !found["tos"] || !found["external/conflicts"] {
		t.Fatalf("custom marker checks were not both reported: %v", found)
	}
}

func TestLinuxProbeAcceptsOwnedObjectsOnRestart(t *testing.T) {
	runner := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == "bpftool" {
			if hasArg(args, "prog") && hasArg(args, "-f") {
				return []byte(`[{"id":10,"pinned":["/sys/fs/bpf/oncache/v1/programs/tc_init_e"]}]`), nil
			}
			if hasArg(args, "map") && hasArg(args, "-f") {
				return []byte(`[{"id":20,"pinned":["/sys/fs/bpf/oncache/v1/maps/control_map"]}]`), nil
			}
		}
		if name == "tc" {
			for _, arg := range args {
				if arg == "filter" {
					return []byte(`[{"pref":1000,"kind":"bpf"},{"pref":1000,"kind":"bpf","options":{"handle":"0x100","bpf_name":"tc_init_e","prog":{"id":10}}}]`), nil
				}
			}
		}
		return fakeCommandRunner(ctx, name, args...)
	}
	probe, request, root, cleanup := probeFixtureWithRunner(t, true, true, true, runner)
	defer cleanup()
	request.Node = resolver.NodeIdentity{Name: "node-a", UID: "node-1"}
	request.StateDir = "/var/lib/oncache/v1"
	request.InstallationID = "install-a"
	request.ELFBuildID = "sha256:test"
	if err := os.MkdirAll(filepath.Join(root, "var/lib/oncache/v1"), 0755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, "var/lib/oncache/v1/state.json"), `{"schemaVersion":1,"installationID":"install-a","nodeUID":"node-1","elfBuildID":"sha256:test","bpfABI":1,"programs":{"tc_init_e":{"ID":10}},"maps":{"control_map":{"ID":20}},"attachments":[{"Program":"tc_init_e","Priority":1000,"Handle":256,"ProgramID":10}]}`)

	snapshot, err := probe.Probe(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	for _, check := range snapshot.Checks {
		if check.Name == "external/conflicts" && !check.Supported {
			t.Fatalf("owned objects were treated as external conflicts: %+v", check)
		}
	}
}

func TestLinuxProbeRejectsForeignObjectAlongsideOwnedState(t *testing.T) {
	runner := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == "bpftool" {
			if hasArg(args, "prog") && hasArg(args, "-f") {
				return []byte(`[{"id":10,"pinned":["/sys/fs/bpf/oncache/v1/programs/tc_init_e"]},{"id":99,"pinned":["/sys/fs/bpf/oncache/v1/programs/foreign"]}]`), nil
			}
			if hasArg(args, "map") && hasArg(args, "-f") {
				return []byte(`[{"id":20,"pinned":["/sys/fs/bpf/oncache/v1/maps/control_map"]}]`), nil
			}
		}
		if name == "tc" {
			for _, arg := range args {
				if arg == "filter" {
					return []byte(`[{"pref":1000,"kind":"bpf"},{"pref":1000,"kind":"bpf","options":{"handle":"0x100","bpf_name":"tc_init_e","prog":{"id":10}}}]`), nil
				}
			}
		}
		return fakeCommandRunner(ctx, name, args...)
	}
	probe, request, root, cleanup := probeFixtureWithRunner(t, true, true, true, runner)
	defer cleanup()
	request.Node = resolver.NodeIdentity{Name: "node-a", UID: "node-1"}
	request.StateDir = "/var/lib/oncache/v1"
	request.InstallationID = "install-a"
	request.ELFBuildID = "sha256:test"
	if err := os.MkdirAll(filepath.Join(root, "var/lib/oncache/v1"), 0755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, "var/lib/oncache/v1/state.json"), `{"schemaVersion":1,"installationID":"install-a","nodeUID":"node-1","elfBuildID":"sha256:test","bpfABI":1,"programs":{"tc_init_e":{"ID":10}},"maps":{"control_map":{"ID":20}},"attachments":[{"Program":"tc_init_e","Priority":1000,"Handle":256,"ProgramID":10}]}`)

	snapshot, err := probe.Probe(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	for _, check := range snapshot.Checks {
		if check.Name != "external/conflicts" {
			continue
		}
		if check.Supported || check.ReasonCode != "EXTERNAL_OBJECT_CONFLICT" {
			t.Fatalf("foreign object was not rejected: %+v", check)
		}
		return
	}
	t.Fatal("external conflict check was not reported")
}

func TestLinuxProbeDetectsPinnedBPFConflict(t *testing.T) {
	var progArgs, mapArgs []string
	runner := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == "bpftool" {
			if hasArg(args, "prog") {
				progArgs = append([]string(nil), args...)
				if !hasArg(args, "-f") {
					return []byte(`[{"id":1}]`), nil
				}
				return []byte(`[{"id":1,"pinned":["/sys/fs/bpf/oncache/v1/external_prog"]}]`), nil
			}
			if hasArg(args, "map") {
				mapArgs = append([]string(nil), args...)
				return []byte(`[]`), nil
			}
		}
		return fakeCommandRunner(ctx, name, args...)
	}
	probe, request, _, cleanup := probeFixtureWithRunner(t, true, true, true, runner)
	defer cleanup()

	snapshot, err := probe.Probe(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if !hasArg(progArgs, "-f") {
		t.Fatalf("bpftool program query did not request pinned paths: %v", progArgs)
	}
	if !hasArg(mapArgs, "-f") {
		t.Fatalf("bpftool map query did not request pinned paths: %v", mapArgs)
	}

	found := false
	for _, check := range snapshot.Checks {
		if check.Name != "external/conflicts" {
			continue
		}
		found = true
		if check.Supported || check.ReasonCode != "EXTERNAL_OBJECT_CONFLICT" {
			t.Fatalf("expected pinned BPF conflict, got %+v", check)
		}
	}
	if !found {
		t.Fatal("external conflict check was not reported")
	}
}

func TestLinuxProbeDetectsPinnedBPFMapConflict(t *testing.T) {
	var mapArgs []string
	runner := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == "bpftool" {
			if hasArg(args, "prog") {
				if !hasArg(args, "-f") {
					return []byte(`[{"id":1}]`), nil
				}
				return []byte(`[]`), nil
			}
			if hasArg(args, "map") {
				mapArgs = append([]string(nil), args...)
				if !hasArg(args, "-f") {
					return []byte(`[]`), nil
				}
				return []byte(`[{"id":1,"pinned":["/sys/fs/bpf/oncache/v1/maps/external_map"]}]`), nil
			}
		}
		return fakeCommandRunner(ctx, name, args...)
	}
	probe, request, _, cleanup := probeFixtureWithRunner(t, true, true, true, runner)
	defer cleanup()

	snapshot, err := probe.Probe(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if !hasArg(mapArgs, "-f") {
		t.Fatalf("bpftool map query did not request pinned paths: %v", mapArgs)
	}

	for _, check := range snapshot.Checks {
		if check.Name != "external/conflicts" {
			continue
		}
		if check.Supported || check.ReasonCode != "EXTERNAL_OBJECT_CONFLICT" {
			t.Fatalf("expected pinned BPF map conflict, got %+v", check)
		}
		return
	}
	t.Fatal("external conflict check was not reported")
}

func probeFixture(t *testing.T, mount, btf, cri bool) (*discovery.LinuxProbe, discovery.PreflightRequest, string, func()) {
	return probeFixtureWithRunner(t, mount, btf, cri, fakeCommandRunner)
}

func probeFixtureWithRunner(t *testing.T, mount, btf, cri bool, runner discovery.CommandRunner) (*discovery.LinuxProbe, discovery.PreflightRequest, string, func()) {
	t.Helper()
	root := t.TempDir()
	for _, dir := range []string{"proc/sys/kernel", "proc/sys/net/ipv4", "sys/fs/bpf", "sys/kernel/btf", "run"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0755); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, filepath.Join(root, "proc/sys/kernel/osrelease"), "5.15.0-test\n")
	writeFile(t, filepath.Join(root, "proc/sys/net/ipv4/ip_forward"), "1\n")
	mounts := "none /sys/fs/other tmpfs rw 0 0\n"
	if mount {
		mounts = "none /sys/fs/bpf bpf rw 0 0\n"
	}
	writeFile(t, filepath.Join(root, "proc/mounts"), mounts)
	if btf {
		writeFile(t, filepath.Join(root, "sys/kernel/btf/vmlinux"), "BTF")
	}
	var listener net.Listener
	if cri {
		var err error
		listener, err = net.Listen("unix", filepath.Join(root, "run/containerd.sock"))
		if err != nil {
			t.Fatal(err)
		}
	}
	cleanup := func() {
		if listener != nil {
			_ = listener.Close()
		}
	}
	return discovery.NewLinuxProbeWithRunner(root, runner), discovery.PreflightRequest{RuntimeURI: "unix:///run/containerd.sock", PinRoot: "/sys/fs/bpf/oncache/v1"}, root, cleanup
}

func fakeCommandRunner(_ context.Context, name string, args ...string) ([]byte, error) {
	switch name {
	case "bpftool":
		return []byte("bpf_map_lookup_elem bpf_map_update_elem bpf_get_hash_recalc bpf_skb_adjust_room bpf_skb_store_bytes bpf_l3_csum_replace bpf_spin_lock bpf_spin_unlock direct_action"), nil
	case "tc":
		for _, arg := range args {
			if arg == "filter" {
				return []byte("[]"), nil
			}
		}
		return []byte(`[{"kind":"clsact"}]`), nil
	case "ip":
		return []byte(`[{"dst":"default"}]`), nil
	case "iptables-nft":
		return []byte(""), nil
	default:
		return []byte(""), nil
	}
}

func hasArg(args []string, want string) bool {
	for _, arg := range args {
		if arg == want {
			return true
		}
	}
	return false
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}
