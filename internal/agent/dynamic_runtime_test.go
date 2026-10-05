package agent

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/cat-cc-Lcos/FNCache/internal/config"
	"github.com/cat-cc-Lcos/FNCache/internal/controlplane"
	"github.com/cat-cc-Lcos/FNCache/internal/datapath"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
	"github.com/cat-cc-Lcos/FNCache/internal/resolver"
)

type dynamicRuntimeMaps struct{}

func (dynamicRuntimeMaps) Delete(context.Context, string, []byte) (bool, error) { return true, nil }
func (dynamicRuntimeMaps) Clear(context.Context, string) (int, error)           { return 0, nil }

type dynamicRuntimeTC struct{}

func (dynamicRuntimeTC) RemoveFilter(context.Context, datapath.TCFilterSpec) error { return nil }

type dynamicRuntimeCommitter struct{}

func (dynamicRuntimeCommitter) Commit(context.Context, reconcile.OwnershipState) error { return nil }

type dynamicRuntimePublisherControl struct {
	refreshSignal chan<- uint64
}

func (*dynamicRuntimePublisherControl) Publish(context.Context, uint64, uint64, uint64, uint32) error {
	return nil
}

func (c *dynamicRuntimePublisherControl) RefreshHeartbeat(_ context.Context, heartbeat uint64) error {
	if c.refreshSignal != nil {
		c.refreshSignal <- heartbeat
	}
	return nil
}

type dynamicRuntimeEnsurers struct {
	collection int32
	marker     int32
	base       int32
}

func (e *dynamicRuntimeEnsurers) EnsureCollection(context.Context, reconcile.DesiredState, reconcile.ActualState) (bool, error) {
	atomic.AddInt32(&e.collection, 1)
	return true, nil
}

func (e *dynamicRuntimeEnsurers) EnsureMarker(context.Context, reconcile.DesiredState) (bool, error) {
	atomic.AddInt32(&e.marker, 1)
	return true, nil
}

func (e *dynamicRuntimeEnsurers) EnsureBase(context.Context, reconcile.DesiredState, reconcile.ActualState) (bool, error) {
	atomic.AddInt32(&e.base, 1)
	return true, nil
}

type dynamicRuntimeEndpoints struct{}

func (dynamicRuntimeEndpoints) Scan(context.Context, []resolver.PodSnapshot) (resolver.EndpointScanResult, error) {
	return resolver.EndpointScanResult{Endpoints: map[string]resolver.Endpoint{}}, nil
}

type dynamicRuntimePins struct{}

func (dynamicRuntimePins) Scan(context.Context) (reconcile.ActualState, error) {
	schema := datapath.V1Schema()
	actual := reconcile.ActualState{
		Control:  reconcile.ControlState{Verified: true},
		Programs: make(map[string]reconcile.ProgramState),
		Maps:     make(map[string]reconcile.MapState),
	}
	for index, name := range schema.Programs {
		actual.Programs[name] = reconcile.ProgramState{ID: uint32(index + 1), Name: name}
	}
	for _, expected := range schema.Maps {
		actual.Maps[expected.Name] = reconcile.MapState{
			ID: 1, Name: expected.Name, KeySize: expected.KeySize, ValueSize: expected.ValueSize, MaxEntries: expected.MaxEntries,
		}
	}
	return actual, nil
}

type dynamicRuntimeScanTC struct{}

func (dynamicRuntimeScanTC) Scan(context.Context, []resolver.LinkIdentity) (reconcile.ActualState, error) {
	actual := reconcile.ActualState{}
	programs := []struct {
		name string
		id   uint32
	}{
		{name: "tc_init_e", id: 1},
		{name: "tc_restore", id: 4},
	}
	for _, program := range programs {
		spec, err := datapath.NewFixedFilter(resolver.LinkIdentity{IfIndex: 2, IfName: "eth0", MAC: []byte{1, 2, 3, 4, 5, 6}}, program.name, program.id, true)
		if err != nil {
			return reconcile.ActualState{}, err
		}
		actual.Attachments = append(actual.Attachments, reconcile.AttachmentState{
			Link: spec.Link, Hook: string(spec.Hook), Program: spec.Program, Priority: spec.Priority, Handle: spec.Handle, ProgramID: spec.ProgramID,
		})
	}
	return actual, nil
}

func dynamicRuntimePublisher(t *testing.T) *controlplane.Publisher {
	t.Helper()
	publisher, err := controlplane.NewPublisher(dynamicRuntimeCommitter{}, &dynamicRuntimePublisherControl{}, controlplane.PublishConfig{InstallationID: "install", NodeUID: "node-a", ELFBuildID: "sha256:test", HeartbeatNS: 1, HeartbeatTimeoutNS: 5})
	if err != nil {
		t.Fatal(err)
	}
	return publisher
}

func TestRunDynamicHeartbeatRefreshesPeriodically(t *testing.T) {
	refreshes := make(chan uint64, 1)
	refresher := &dynamicRuntimePublisherControl{refreshSignal: refreshes}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ticks := make(chan time.Time, 1)
	heartbeat := uint64(100)
	now := func() (uint64, error) {
		heartbeat++
		return heartbeat, nil
	}
	done := make(chan struct{})
	go func() {
		runDynamicHeartbeatLoop(ctx, ticks, now, refresher)
		close(done)
	}()
	select {
	case got := <-refreshes:
		if got != 101 {
			t.Fatalf("initial heartbeat = %d, want 101", got)
		}
	case <-time.After(time.Second):
		t.Fatal("initial heartbeat was not refreshed")
	}
	ticks <- time.Time{}
	select {
	case got := <-refreshes:
		if got != 102 {
			t.Fatalf("periodic heartbeat = %d, want 102", got)
		}
	case <-time.After(time.Second):
		t.Fatal("periodic heartbeat was not refreshed")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("dynamic heartbeat did not stop after cancellation")
	}
}

func dynamicTestConfig() config.AgentConfiguration {
	return config.AgentConfiguration{
		APIVersion: "oncache.io/v1alpha1", Kind: "AgentConfiguration", NodeName: "node-a", RuntimeEndpoint: "unix:///run/containerd/containerd.sock",
		PinRoot: "/sys/fs/bpf/oncache/v1", StateDir: "/var/lib/oncache/v1", Datapath: config.DatapathConfig{ELFPath: "/opt/oncache/bpf/tc_prog_kern.o", ELFBuildID: "sha256:test"}, Overlay: config.OverlayConfig{Type: "flannel-vxlan", Device: "auto", VXLANLinkName: "flannel.1"},
		Markers: config.MarkerConfig{Chain: "ONCACHE", Comment: "oncache:test", MissMask: 0x04, EstablishedMask: 0x08}, Heartbeat: config.HeartbeatConfig{Interval: config.Duration(time.Second), Timeout: config.Duration(5 * time.Second)},
		Kube: config.KubeConfig{MaxStaleness: config.Duration(30 * time.Second), ResyncInterval: config.Duration(10 * time.Millisecond)}, Health: config.HealthConfig{Interval: config.Duration(5 * time.Second)},
		Scan: config.ScanConfig{IncrementalInterval: config.Duration(30 * time.Second), FullInterval: config.Duration(5 * time.Minute)}, Maps: config.MapConfig{IngressCacheMaxEntries: 1024, EgressIPCacheMaxEntries: 4096, EgressCacheMaxEntries: 1024, PolicyCacheMaxEntries: 4096, DevMapMaxEntries: 8},
		Server: config.ServerConfig{ListenAddress: ":9090"}, Features: config.FeatureConfig{Enabled: true},
	}
}

func TestDynamicRuntimeRunsInitialFullReconcileOnEmptyNode(t *testing.T) {
	sources := controlplane.Sources{Preflight: dynamicObserverPreflight{}, Flannel: dynamicObserverFlannel{}, Endpoints: dynamicRuntimeEndpoints{}, Pins: dynamicRuntimePins{}, TC: dynamicRuntimeScanTC{}, Rules: dynamicObserverRules{}}
	events := []string{}
	ensurers := &dynamicRuntimeEnsurers{}
	factory := func(context.Context, datapathComponentConfig) (*datapathComponents, error) {
		return &datapathComponents{
			cri: &fakeCloser{}, endpointResolver: &localHandlerResolver{endpoint: handlerEndpoint("unused"), events: &events}, sources: sources,
			tc: dynamicRuntimeTC{}, mapWriter: dynamicRuntimeMaps{}, ownership: &deleteOwnership{state: reconcile.OwnershipState{SchemaVersion: 1, InstallationID: "install", NodeUID: "node-a"}},
			control: &localHandlerControl{events: &events}, collection: ensurers, marker: ensurers, base: ensurers,
			endpoint: &localHandlerEndpoint{events: &events}, maps: &localHandlerMaps{events: &events}, publisher: dynamicRuntimePublisher(t),
		}, nil
	}
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-a", UID: types.UID("node-a")}}
	cfg := dynamicTestConfig()
	cfg.Kube.ResyncInterval = config.Duration(time.Hour)
	runtime, err := newDynamicRuntimeWithFactory(cfg, fake.NewSimpleClientset(node), factory)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runtime.Run(ctx) }()
	deadline := time.Now().Add(time.Second)
	for (atomic.LoadInt32(&ensurers.collection) == 0 || atomic.LoadInt32(&ensurers.marker) == 0 || atomic.LoadInt32(&ensurers.base) == 0) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if runtime.State() != KubeBootstrapReady || atomic.LoadInt32(&ensurers.collection) != 1 || atomic.LoadInt32(&ensurers.marker) != 1 || atomic.LoadInt32(&ensurers.base) != 1 {
		t.Fatalf("initial dynamic reconcile did not ensure base datapath: state=%s collection=%d marker=%d base=%d", runtime.State(), atomic.LoadInt32(&ensurers.collection), atomic.LoadInt32(&ensurers.marker), atomic.LoadInt32(&ensurers.base))
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("dynamic runtime did not stop")
	}
}

func TestNewDynamicRuntimeRejectsInvalidConfiguration(t *testing.T) {
	cfg := dynamicTestConfig()
	cfg.NodeName = ""
	if _, err := newDynamicRuntime(cfg, fake.NewSimpleClientset()); err == nil {
		t.Fatal("invalid dynamic configuration was accepted")
	}
}
