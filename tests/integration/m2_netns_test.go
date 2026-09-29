//go:build linux && integration

package integration_test

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/cat-cc-Lcos/FNCache/internal/controlplane"
	"github.com/cat-cc-Lcos/FNCache/internal/datapath"
	"github.com/cat-cc-Lcos/FNCache/internal/ownership"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
	"github.com/cat-cc-Lcos/FNCache/internal/resolver"
	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func TestM2NetnsTCEnsureRestartAndConflict(t *testing.T) {
	requireIntegrationEnvironment(t)
	elf := os.Getenv("ONCACHE_BPF_ELF")
	if elf == "" {
		t.Fatal("ONCACHE_BPF_ELF is required")
	}
	if _, err := os.Stat(elf); err != nil {
		t.Fatalf("BPF ELF is unavailable: %v", err)
	}

	lab := newNetNSLab(t)
	pinRoot := filepath.Join("/sys/fs/bpf/oncache", fmt.Sprintf("m2-integration-%d", os.Getpid()))
	if _, err := os.Stat(pinRoot); err == nil {
		t.Fatalf("integration pin root already exists: %s", pinRoot)
	}
	defer os.RemoveAll(pinRoot)
	statePath := filepath.Join(t.TempDir(), "state.json")
	var firstCount int
	var desired reconcile.DesiredState
	if err := lab.withNetNS(func(ctx context.Context) error {
		underlay, err := linkIdentity(lab.underlay, lab.netnsInode, lab.path)
		if err != nil {
			return err
		}
		desired = baseDesired(underlay)
		desired.Generation = 1
		runtime := newFirstPassRuntime(t, elf, pinRoot, statePath, desired, underlay)
		result, err := runtime.coordinator.FullReconcile(ctx)
		if err != nil || result.State != reconcile.AgentReady || !result.Changed {
			return fmt.Errorf("first full reconcile: result=%+v err=%w", result, err)
		}
		observed, err := runtime.observer.Scan(ctx)
		if err != nil {
			return err
		}
		firstCount = len(observed.Attachments)
		if firstCount != 2 {
			return fmt.Errorf("expected two coordinated base filters, got %d", firstCount)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	if err := lab.withNetNS(func(ctx context.Context) error {
		underlay, err := linkIdentity(lab.underlay, lab.netnsInode, lab.path)
		if err != nil {
			return err
		}
		runtime := newFirstPassRuntime(t, elf, pinRoot, statePath, desired, underlay)
		result, err := runtime.coordinator.FullReconcile(ctx)
		if err != nil || result.State != reconcile.AgentReady || result.Changed {
			return fmt.Errorf("restart full reconcile was not idempotent: result=%+v err=%w", result, err)
		}
		observed, err := runtime.observer.Scan(ctx)
		if err != nil {
			return err
		}
		if len(observed.Attachments) != firstCount {
			return fmt.Errorf("restart changed attachment count: before=%d after=%d", firstCount, len(observed.Attachments))
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	if err := lab.withNetNS(func(ctx context.Context) error {
		underlay, err := linkIdentity(lab.underlay, lab.netnsInode, lab.path)
		if err != nil {
			return err
		}
		store, err := ownership.NewStore(statePath)
		if err != nil {
			return err
		}
		before, err := store.Load(ctx)
		if err != nil {
			return err
		}
		backend, err := datapath.NewLinuxTCBackend(pinRoot)
		if err != nil {
			return err
		}
		tc, err := datapath.NewTCManager(backend)
		if err != nil {
			return err
		}
		if _, err := tc.EnsureClsact(ctx, underlay); err != nil {
			return err
		}
		program, err := ebpf.LoadPinnedProgram(filepath.Join(pinRoot, "programs", "tc_init_e"), nil)
		if err != nil {
			return err
		}
		filter := &netlink.BpfFilter{
			FilterAttrs: netlink.FilterAttrs{LinkIndex: underlay.IfIndex, Parent: netlink.HANDLE_MIN_EGRESS, Priority: 1000, Handle: 0x900, Protocol: unix.ETH_P_ALL},
			Fd:          program.FD(), Name: "external-m2", DirectAction: true,
		}
		if err := netlink.FilterAdd(filter); err != nil {
			_ = program.Close()
			return err
		}
		if err := program.Close(); err != nil {
			return err
		}
		runtime := newFirstPassRuntime(t, elf, pinRoot, statePath, desired, underlay)
		result, err := runtime.coordinator.FullReconcile(ctx)
		if err == nil || result.State != reconcile.AgentDisabled {
			return fmt.Errorf("expected conflict to disable coordination: result=%+v err=%v", result, err)
		}
		enabled, err := readControlEnabled(pinRoot)
		if err != nil {
			return err
		}
		if enabled {
			return fmt.Errorf("control Map remained enabled after conflict")
		}
		after, err := store.Load(ctx)
		if err != nil {
			return err
		}
		if after.Generation != before.Generation || !after.LastCommittedAt.Equal(before.LastCommittedAt) {
			return fmt.Errorf("ownership changed after conflict: before=%+v after=%+v", before, after)
		}
		filters, err := tc.ListFilters(ctx, underlay)
		if err != nil {
			return err
		}
		for _, filter := range filters {
			if filter.Handle == 0x900 {
				return nil
			}
		}
		return fmt.Errorf("external TC filter was not preserved")
	}); err != nil {
		t.Fatal(err)
	}
}

func TestTCBackendTargetsPodNetns(t *testing.T) {
	requireIntegrationEnvironment(t)
	elf := os.Getenv("ONCACHE_BPF_ELF")
	if elf == "" {
		t.Fatal("ONCACHE_BPF_ELF is required")
	}
	if _, err := os.Stat(elf); err != nil {
		t.Fatalf("BPF ELF is unavailable: %v", err)
	}

	lab := newNetNSLab(t)
	pinRoot := filepath.Join("/sys/fs/bpf/oncache", fmt.Sprintf("tc-netns-integration-%d", os.Getpid()))
	if _, err := os.Stat(pinRoot); err == nil {
		t.Fatalf("integration pin root already exists: %s", pinRoot)
	}
	defer os.RemoveAll(pinRoot)

	before := currentNetNSInode(t)
	var podLink resolver.LinkIdentity
	if err := lab.withNetNS(func(context.Context) error {
		var err error
		podLink, err = linkIdentity(lab.underlay, lab.netnsInode, lab.path)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if got := currentNetNSInode(t); got != before {
		t.Fatalf("namespace changed while resolving Pod link: got %d want %d", got, before)
	}

	collection := &pinnedCollectionEnsurer{elf: elf, pinRoot: pinRoot}
	if _, err := collection.EnsureCollection(context.Background(), reconcile.DesiredState{}, reconcile.ActualState{}); err != nil {
		t.Fatalf("pin BPF collection: %v", err)
	}
	pins, err := datapath.NewPinScanner(pinRoot)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := pins.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	program, ok := actual.Programs["tc_init_in"]
	if !ok || program.ID == 0 {
		t.Fatalf("tc_init_in program is unavailable: %+v", actual.Programs)
	}

	backend, err := datapath.NewLinuxTCBackend(pinRoot)
	if err != nil {
		t.Fatal(err)
	}
	tc, err := datapath.NewTCManager(backend)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := datapath.NewFixedFilter(podLink, "tc_init_in", program.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tc.EnsureFilter(context.Background(), spec); err != nil {
		t.Fatalf("attach tc_init_in in Pod netns: %v", err)
	}
	if got := currentNetNSInode(t); got != before {
		t.Fatalf("namespace was not restored after TC operation: got %d want %d", got, before)
	}

	if err := lab.withNetNS(func(context.Context) error {
		link, err := netlink.LinkByName(lab.underlay)
		if err != nil {
			return err
		}
		filters, err := netlink.FilterList(link, netlink.HANDLE_MIN_INGRESS)
		if err != nil {
			return err
		}
		for _, filter := range filters {
			attrs := filter.Attrs()
			if attrs == nil || attrs.Handle != 0x201 {
				continue
			}
			bpf, ok := filter.(*netlink.BpfFilter)
			if !ok || bpf.Name != "tc_init_in" {
				return fmt.Errorf("unexpected Pod ingress filter: %T/%q", filter, bpfName(filter))
			}
			return nil
		}
		return fmt.Errorf("tc_init_in was not attached in Pod netns")
	}); err != nil {
		t.Fatal(err)
	}

	hostLink, err := netlink.LinkByName(lab.hostLink)
	if err != nil {
		t.Fatal(err)
	}
	hostFilters, err := netlink.FilterList(hostLink, netlink.HANDLE_MIN_INGRESS)
	if err != nil {
		t.Fatal(err)
	}
	for _, filter := range hostFilters {
		attrs := filter.Attrs()
		if attrs != nil && attrs.Handle == 0x201 {
			t.Fatalf("tc_init_in was attached to host veth instead of Pod eth0")
		}
	}
}

type firstPassRuntime struct {
	coordinator *reconcile.Coordinator
	observer    *integrationObserver
	tc          *datapath.TCManager
}

type integrationObserver struct {
	desired reconcile.DesiredState
	pins    *datapath.PinScanner
	tc      *datapath.TCScanner
	links   []resolver.LinkIdentity
}

func (o *integrationObserver) Discover(context.Context) (reconcile.DesiredState, error) {
	return o.desired, nil
}

func (o *integrationObserver) Scan(ctx context.Context) (reconcile.ActualState, error) {
	actual, err := o.pins.Scan(ctx)
	if err != nil {
		return reconcile.ActualState{}, err
	}
	tc, err := o.tc.Scan(ctx, o.links)
	if err != nil {
		return reconcile.ActualState{}, err
	}
	actual.Attachments = append(actual.Attachments, tc.Attachments...)
	actual.Conflicts = append(actual.Conflicts, tc.Conflicts...)
	actual.FlannelRule = reconcile.RuleState{Present: true, Identity: "m2-integration-marker", Fingerprint: "m2-integration"}
	return actual, nil
}

type pinnedCollectionEnsurer struct {
	elf     string
	pinRoot string
}

func (e *pinnedCollectionEnsurer) EnsureCollection(ctx context.Context, _ reconcile.DesiredState, actual reconcile.ActualState) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if collectionReady(actual) {
		return false, nil
	}
	file, err := os.Open(e.elf)
	if err != nil {
		return false, err
	}
	defer file.Close()
	manager, err := datapath.NewManager(e.pinRoot)
	if err != nil {
		return false, err
	}
	spec, err := manager.LoadCollection(file, datapath.V1Schema())
	if err != nil {
		return false, err
	}
	loaded, err := manager.LoadAndPin(spec, datapath.V1Schema())
	if err != nil {
		return false, err
	}
	if err := loaded.Close(); err != nil {
		return false, err
	}
	if err := initializeControlMap(e.pinRoot); err != nil {
		return false, err
	}
	return true, nil
}

func collectionReady(actual reconcile.ActualState) bool {
	schema := datapath.V1Schema()
	if len(actual.Programs) != len(schema.Programs) || len(actual.Maps) != len(schema.Maps) {
		return false
	}
	for _, name := range schema.Programs {
		if _, ok := actual.Programs[name]; !ok {
			return false
		}
	}
	for _, schema := range schema.Maps {
		if _, ok := actual.Maps[schema.Name]; !ok {
			return false
		}
	}
	return true
}

type staticMarkerEnsurer struct{}

func (staticMarkerEnsurer) EnsureMarker(context.Context, reconcile.DesiredState) (bool, error) {
	return false, nil
}

type integrationControl struct {
	writer  *datapath.ControlWriter
	pinRoot string
}

func (c *integrationControl) Disable(ctx context.Context) error {
	path := filepath.Join(c.pinRoot, "maps", "control_map")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	return c.writer.Disable(ctx)
}

func (c *integrationControl) Publish(ctx context.Context, generation, heartbeatTimeoutNS uint64, flags uint32) error {
	return c.writer.Publish(ctx, generation, heartbeatTimeoutNS, flags)
}

func newFirstPassRuntime(t *testing.T, elf, pinRoot, statePath string, desired reconcile.DesiredState, link resolver.LinkIdentity) *firstPassRuntime {
	t.Helper()
	backend, err := datapath.NewLinuxTCBackend(pinRoot)
	if err != nil {
		t.Fatal(err)
	}
	tc, err := datapath.NewTCManager(backend)
	if err != nil {
		t.Fatal(err)
	}
	pins, err := datapath.NewPinScanner(pinRoot)
	if err != nil {
		t.Fatal(err)
	}
	tcScanner, err := datapath.NewTCScanner(tc)
	if err != nil {
		t.Fatal(err)
	}
	observer := &integrationObserver{desired: desired, pins: pins, tc: tcScanner, links: []resolver.LinkIdentity{link}}
	controlWriter, err := datapath.NewControlWriter(pinRoot)
	if err != nil {
		t.Fatal(err)
	}
	control := &integrationControl{writer: controlWriter, pinRoot: pinRoot}
	base, err := controlplane.NewBaseEnsurer(tc)
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := controlplane.NewEndpointEnsurer(tc)
	if err != nil {
		t.Fatal(err)
	}
	mapWriter, err := datapath.NewMapWriter(pinRoot)
	if err != nil {
		t.Fatal(err)
	}
	maps, err := controlplane.NewMapEnsurer(mapWriter)
	if err != nil {
		t.Fatal(err)
	}
	store, err := ownership.NewStore(statePath)
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := controlplane.NewPublisher(store, control, controlplane.PublishConfig{
		InstallationID: "m2-integration", NodeUID: "node-b", ELFBuildID: "integration-elf",
		HeartbeatTimeoutNS: 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	firstPass, err := controlplane.NewFirstPassBackend(controlplane.FirstPassBackendConfig{
		Observer: observer, Control: control, Collection: &pinnedCollectionEnsurer{elf: elf, pinRoot: pinRoot},
		Marker: staticMarkerEnsurer{}, Base: base, Endpoint: endpoint, Maps: maps, Publisher: publisher,
	})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := reconcile.NewCoordinator(firstPass)
	if err != nil {
		t.Fatal(err)
	}
	return &firstPassRuntime{coordinator: coordinator, observer: observer, tc: tc}
}

func initializeControlMap(pinRoot string) error {
	control, err := ebpf.LoadPinnedMap(filepath.Join(pinRoot, "maps", "control_map"), nil)
	if err != nil {
		return err
	}
	value := datapath.ControlV1{ABIVersion: 1, HeartbeatTimeoutNS: 500}
	if err := control.Update(uint32(0), &value, ebpf.UpdateAny); err != nil {
		_ = control.Close()
		return err
	}
	return control.Close()
}

func readControlEnabled(pinRoot string) (bool, error) {
	control, err := ebpf.LoadPinnedMap(filepath.Join(pinRoot, "maps", "control_map"), nil)
	if err != nil {
		return false, err
	}
	var value datapath.ControlV1
	err = control.Lookup(uint32(0), &value)
	_ = control.Close()
	return value.Enabled == 1, err
}

type netNSLab struct {
	name, hostLink, underlay, vxlan, path string
	netnsInode                            uint64
}

func newNetNSLab(t *testing.T) *netNSLab {
	t.Helper()
	suffix := strconv.Itoa(os.Getpid())
	lab := &netNSLab{name: "ocm2-" + suffix, hostLink: "ocm2h-" + suffix, underlay: "ocm2u-" + suffix, vxlan: "flannel.1"}
	if err := run("ip", "netns", "add", lab.name); err != nil {
		t.Fatal(err)
	}
	lab.path = filepath.Join("/var/run/netns", lab.name)
	stat := unix.Stat_t{}
	if err := unix.Stat(lab.path, &stat); err != nil {
		t.Fatalf("stat netns: %v", err)
	}
	lab.netnsInode = uint64(stat.Ino)
	t.Cleanup(func() {
		_ = run("ip", "netns", "del", lab.name)
		_ = run("ip", "link", "del", lab.hostLink)
	})
	peer := "ocm2p-" + suffix
	if err := run("ip", "link", "add", lab.hostLink, "type", "veth", "peer", "name", peer); err != nil {
		t.Fatal(err)
	}
	if err := run("ip", "link", "set", peer, "netns", lab.name); err != nil {
		t.Fatal(err)
	}
	if err := run("ip", "addr", "add", "192.0.2.1/24", "dev", lab.hostLink); err != nil {
		t.Fatal(err)
	}
	if err := run("ip", "link", "set", lab.hostLink, "up"); err != nil {
		t.Fatal(err)
	}
	if err := runNetNS(lab.name, "ip", "link", "set", "lo", "up"); err != nil {
		t.Fatal(err)
	}
	if err := runNetNS(lab.name, "ip", "link", "set", "dev", peer, "name", lab.underlay); err != nil {
		t.Fatal(err)
	}
	if err := runNetNS(lab.name, "ip", "addr", "add", "192.0.2.2/24", "dev", lab.underlay); err != nil {
		t.Fatal(err)
	}
	if err := runNetNS(lab.name, "ip", "link", "set", lab.underlay, "up"); err != nil {
		t.Fatal(err)
	}
	if err := runNetNS(lab.name, "ip", "link", "add", lab.vxlan, "type", "vxlan", "id", "1", "dev", lab.underlay, "local", "192.0.2.2", "dstport", "8472"); err != nil {
		t.Fatal(err)
	}
	if err := runNetNS(lab.name, "ip", "link", "set", lab.vxlan, "up"); err != nil {
		t.Fatal(err)
	}
	return lab
}

func (l *netNSLab) withNetNS(fn func(context.Context) error) error {
	manager := datapath.NewNetNSManager()
	return manager.WithNetNS(context.Background(), datapath.NetNSRef{Path: l.path, Inode: l.netnsInode}, fn)
}

func baseDesired(link resolver.LinkIdentity) reconcile.DesiredState {
	return reconcile.DesiredState{Enabled: true, Flannel: reconcile.FlannelState{UnderlayLink: link, UnderlayIPv4: netip.MustParseAddr("192.0.2.2")}}
}

func linkIdentity(name string, netnsInode uint64, netnsPath string) (resolver.LinkIdentity, error) {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return resolver.LinkIdentity{}, err
	}
	attrs := link.Attrs()
	if attrs == nil || attrs.Index <= 0 {
		return resolver.LinkIdentity{}, fmt.Errorf("link identity is incomplete: %s", name)
	}
	return resolver.LinkIdentity{NetNSInode: netnsInode, NetNSPath: netnsPath, IfIndex: attrs.Index, IfName: attrs.Name, MAC: append([]byte(nil), attrs.HardwareAddr...)}, nil
}

func currentNetNSInode(t *testing.T) uint64 {
	t.Helper()
	var stat unix.Stat_t
	if err := unix.Stat("/proc/self/ns/net", &stat); err != nil {
		t.Fatal(err)
	}
	return uint64(stat.Ino)
}

func bpfName(filter netlink.Filter) string {
	if bpf, ok := filter.(*netlink.BpfFilter); ok {
		return bpf.Name
	}
	return ""
}

func requireIntegrationEnvironment(t *testing.T) {
	t.Helper()
	if os.Getenv("ONCACHE_M2_INTEGRATION") != "1" {
		t.Skip("set ONCACHE_M2_INTEGRATION=1 to run privileged integration tests")
	}
	if os.Geteuid() != 0 {
		t.Fatal("M2 integration tests require root")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Fatal(err)
	}
	if _, err := exec.LookPath("tc"); err != nil {
		t.Fatal(err)
	}
	if err := exec.Command("systemd-detect-virt", "--vm").Run(); err != nil {
		t.Fatal("refusing privileged integration test outside a verified VM")
	}
}

func run(name string, args ...string) error {
	_, err := command(name, args...)
	return err
}

func runNetNS(namespace string, args ...string) error {
	_, err := runNetNSOutput(namespace, args...)
	return err
}

func runNetNSOutput(namespace string, args ...string) ([]byte, error) {
	commandArgs := append([]string{"netns", "exec", namespace}, args...)
	return command("ip", commandArgs...)
}

func command(name string, args ...string) ([]byte, error) {
	output, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return output, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return output, nil
}
