package agent

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/cat-cc-Lcos/FNCache/internal/config"
	"github.com/cat-cc-Lcos/FNCache/internal/controlplane"
	"github.com/cat-cc-Lcos/FNCache/internal/datapath"
	"github.com/cat-cc-Lcos/FNCache/internal/overlay/flannel"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
	"github.com/cat-cc-Lcos/FNCache/internal/resolver"
)

type dynamicRuntimeMaps struct{}

func (dynamicRuntimeMaps) Delete(context.Context, string, []byte) (bool, error) { return true, nil }
func (dynamicRuntimeMaps) Clear(context.Context, string) (int, error)           { return 0, nil }
func (dynamicRuntimeMaps) EnsureRemoteMappings(context.Context, reconcile.DesiredState, reconcile.ActualState, bool) (bool, error) {
	return true, nil
}
func (dynamicRuntimeMaps) EnsureDeviceMap(context.Context, reconcile.DesiredState, reconcile.ActualState, bool) (bool, error) {
	return true, nil
}

type dynamicRuntimeTC struct{}

func (dynamicRuntimeTC) RemoveFilter(context.Context, datapath.TCFilterSpec) error { return nil }

func (dynamicRuntimeTC) Scan(_ context.Context, links []resolver.LinkIdentity) (reconcile.ActualState, error) {
	attachments := make([]reconcile.AttachmentState, 0, 4)
	for _, link := range links {
		switch link.IfIndex {
		case 2:
			attachments = append(attachments, dynamicRuntimeAttachment(link, "tc_init_e", 1), dynamicRuntimeAttachment(link, "tc_restore", 4))
		case 7:
			attachments = append(attachments, dynamicRuntimeAttachment(link, "tc_init_in", 2))
		case 8:
			attachments = append(attachments, dynamicRuntimeAttachment(link, "tc_masq", 3))
		}
	}
	return reconcile.ActualState{Attachments: attachments}, nil
}

func dynamicRuntimeAttachment(link resolver.LinkIdentity, program string, programID uint32) reconcile.AttachmentState {
	spec, _ := datapath.NewFixedFilter(link, program, programID, true)
	return reconcile.AttachmentState{Link: spec.Link, Hook: string(spec.Hook), Program: spec.Program, Priority: spec.Priority, Handle: spec.Handle, ProgramID: spec.ProgramID}
}

type dynamicRuntimePins struct{}

func (dynamicRuntimePins) Scan(context.Context) (reconcile.ActualState, error) {
	schema := datapath.V1Schema()
	programs := make(map[string]reconcile.ProgramState, len(schema.Programs))
	for index, name := range schema.Programs {
		programs[name] = reconcile.ProgramState{ID: uint32(index + 1), Name: name}
	}
	maps := make(map[string]reconcile.MapState, len(schema.Maps))
	for index, expected := range schema.Maps {
		maps[expected.Name] = reconcile.MapState{ID: uint32(index + 1), Name: expected.Name, KeySize: expected.KeySize, ValueSize: expected.ValueSize, MaxEntries: expected.MaxEntries}
	}
	return reconcile.ActualState{Control: reconcile.ControlState{Verified: true}, Programs: programs, Maps: maps}, nil
}

type dynamicRuntimeEnsurers struct{}

func (dynamicRuntimeEnsurers) EnsureCollection(context.Context, reconcile.DesiredState, reconcile.ActualState) (bool, error) {
	return true, nil
}
func (dynamicRuntimeEnsurers) EnsureMarker(context.Context, reconcile.DesiredState) (bool, error) {
	return true, nil
}
func (dynamicRuntimeEnsurers) EnsureBase(context.Context, reconcile.DesiredState, reconcile.ActualState) (bool, error) {
	return true, nil
}

type dynamicRuntimeCommitter struct{}

func (dynamicRuntimeCommitter) Commit(context.Context, reconcile.OwnershipState) error { return nil }

type dynamicRuntimePublisherControl struct {
	published *atomic.Bool
}

func (c dynamicRuntimePublisherControl) Publish(context.Context, uint64, uint64, uint64, uint32, uint32, uint16) error {
	if c.published != nil {
		c.published.Store(true)
	}
	return nil
}

type dynamicRuntimeFlannelHealth struct{ drift *atomic.Bool }

func (s dynamicRuntimeFlannelHealth) Discover(ctx context.Context, request flannel.DiscoveryRequest) (flannel.FlannelConfig, error) {
	config, err := (dynamicObserverFlannel{}).Discover(ctx, request)
	if err == nil && s.drift.Load() {
		config.Fingerprint = "drifted"
	}
	return config, err
}

type dynamicRuntimeMarkerHealth struct{ drift *atomic.Bool }

func (s dynamicRuntimeMarkerHealth) Scan(ctx context.Context, spec flannel.MarkerRuleSpec) (reconcile.RuleState, error) {
	state, err := (dynamicObserverRules{}).Scan(ctx, spec)
	if err == nil && s.drift.Load() {
		state.Fingerprint = "drifted"
	}
	return state, err
}

type dynamicRuntimeHeartbeatControl struct {
	*localHandlerControl
	mu         sync.Mutex
	heartbeats []uint64
	refreshErr error
	disables   atomic.Int64
}

// Disable records a control-map disable operation for runtime assertions.
func (c *dynamicRuntimeHeartbeatControl) Disable(ctx context.Context) error {
	c.disables.Add(1)
	return c.localHandlerControl.Disable(ctx)
}

func (c *dynamicRuntimeHeartbeatControl) RefreshHeartbeat(_ context.Context, heartbeat uint64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.refreshErr != nil {
		return c.refreshErr
	}
	c.heartbeats = append(c.heartbeats, heartbeat)
	return nil
}

func (c *dynamicRuntimeHeartbeatControl) HeartbeatCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.heartbeats)
}

// DisableCount reports the number of recorded disable operations.
func (c *dynamicRuntimeHeartbeatControl) DisableCount() int64 {
	return c.disables.Load()
}

func TestInitialReconcileRetryOnlyCoversEndpointNotReady(t *testing.T) {
	endpointErr := reconcile.NewClassifiedError(reconcile.ErrorRetryable, reconcile.ReasonEndpointNotReady, 2*time.Second, errors.New("sandbox pending"))
	if delay, retry := initialReconcileRetry(endpointErr); !retry || delay != 2*time.Second {
		t.Fatalf("endpoint-not-ready error = delay %s retry %t, want 2s/true", delay, retry)
	}
	otherErr := reconcile.NewClassifiedError(reconcile.ErrorRetryable, reconcile.ReasonFlannelLinkMissing, 2*time.Second, errors.New("link missing"))
	if delay, retry := initialReconcileRetry(otherErr); retry || delay != 0 {
		t.Fatalf("other retryable error = delay %s retry %t, want 0/false", delay, retry)
	}
}

func TestInitialDatapathRetryCoversTransientDependencies(t *testing.T) {
	for name, err := range map[string]error{
		"snapshot": fmt.Errorf("bootstrap: %w", ErrKubernetesSnapshotNotReady),
		"flannel":  fmt.Errorf("baseline: %w", flannel.ErrDiscoveryNotReady),
	} {
		t.Run(name, func(t *testing.T) {
			if delay, retry := initialDatapathRetry(err); !retry || delay != time.Second {
				t.Fatalf("retry = %t after %s, want true after 1s", retry, delay)
			}
		})
	}
	if delay, retry := initialDatapathRetry(errors.New("invalid configuration")); retry || delay != 0 {
		t.Fatalf("fatal error retry = %t after %s, want false/0", retry, delay)
	}
}

// TestWaitForRuntimeStopHandlesClosedScanResults verifies the closed-channel stop path.
func TestWaitForRuntimeStopHandlesClosedScanResults(t *testing.T) {
	runtime := &DynamicRuntime{healthEpoch: NewHealthEpoch(), lifecycle: reconcile.NewAgentStateMachine()}
	if err := runtime.lifecycle.Transition(reconcile.AgentReconciling); err != nil {
		t.Fatal(err)
	}
	if err := runtime.lifecycle.Transition(reconcile.AgentReady); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	heartbeatDone := make(chan error)
	scanResults := make(chan ScanResult)
	close(scanResults)
	result := runtime.waitForRuntimeStop(ctx, nil, heartbeatDone, scanResults)
	if !result.stoppingRequested {
		t.Fatal("closed scan results did not request graceful stopping")
	}
	if result.stopErr != nil {
		t.Fatalf("graceful stop transition error = %v", result.stopErr)
	}
	if result.failureErr != nil {
		t.Fatalf("graceful scan closure reported failure: %v", result.failureErr)
	}
	if runtime.AgentState() != reconcile.AgentStopping {
		t.Fatalf("agent state = %s, want %s", runtime.AgentState(), reconcile.AgentStopping)
	}
	if runtime.healthEpoch.IsCurrent(1) {
		t.Fatal("health epoch remained current after scan scheduler closure")
	}
}

func dynamicRuntimePublisher(t *testing.T, published *atomic.Bool) *controlplane.Publisher {
	t.Helper()
	publisher, err := controlplane.NewPublisher(dynamicRuntimeCommitter{}, dynamicRuntimePublisherControl{published: published}, controlplane.PublishConfig{InstallationID: "install", NodeUID: "node-a", ELFBuildID: "sha256:test", HeartbeatNS: 1, HeartbeatTimeoutNS: 5})
	if err != nil {
		t.Fatal(err)
	}
	return publisher
}

func dynamicRuntimeComponents(t *testing.T, sources controlplane.Sources, control localControl, events *[]string, published *atomic.Bool) *datapathComponents {
	t.Helper()
	publisher := dynamicRuntimePublisher(t, published)
	return &datapathComponents{
		cri: &fakeCloser{}, endpointResolver: &localHandlerResolver{endpoint: handlerEndpoint("unused"), events: events}, sources: sources,
		tc: dynamicRuntimeTC{}, mapWriter: dynamicRuntimeMaps{}, ownership: &deleteOwnership{state: reconcile.OwnershipState{SchemaVersion: 1, InstallationID: "install", NodeUID: "node-a"}},
		control: control, collection: dynamicRuntimeEnsurers{}, marker: dynamicRuntimeEnsurers{}, base: dynamicRuntimeEnsurers{},
		endpoint: &localHandlerEndpoint{events: events}, maps: &localHandlerMaps{events: events}, deviceMap: dynamicRuntimeMaps{}, publisher: publisher,
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

// TestDynamicRuntimeStartsKubernetesControlChain verifies startup and graceful shutdown.
func TestDynamicRuntimeStartsKubernetesControlChain(t *testing.T) {
	sources := controlplane.Sources{Preflight: dynamicObserverPreflight{}, Flannel: dynamicObserverFlannel{}, Endpoints: dynamicObserverEndpoints{}, Pins: dynamicRuntimePins{}, TC: dynamicRuntimeTC{}, Rules: dynamicObserverRules{}}
	events := []string{}
	published := &atomic.Bool{}
	cfg := dynamicTestConfig()
	cfg.Heartbeat.Interval = config.Duration(10 * time.Millisecond)
	control := &dynamicRuntimeHeartbeatControl{localHandlerControl: &localHandlerControl{events: &events}}
	factory := func(context.Context, datapathComponentConfig) (*datapathComponents, error) {
		return dynamicRuntimeComponents(t, sources, control, &events, published), nil
	}
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-a", UID: types.UID("node-a")}}
	runtime, err := newDynamicRuntimeWithFactory(cfg, fake.NewSimpleClientset(node), factory)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runtime.Run(ctx) }()
	deadline := time.Now().Add(time.Second)
	for runtime.State() != KubeBootstrapReady && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if runtime.State() != KubeBootstrapReady {
		t.Fatalf("dynamic runtime state = %s", runtime.State())
	}
	deadline = time.Now().Add(time.Second)
	for runtime.AgentState() != reconcile.AgentReady && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if runtime.AgentState() != reconcile.AgentReady {
		t.Fatalf("agent state = %s, want %s", runtime.AgentState(), reconcile.AgentReady)
	}
	if !published.Load() {
		t.Fatal("initial full reconciliation did not publish control state")
	}
	deadline = time.Now().Add(time.Second)
	for control.HeartbeatCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if control.HeartbeatCount() == 0 {
		t.Fatal("dynamic runtime did not start heartbeat refresh")
	}
	disablesBeforeShutdown := control.DisableCount()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("dynamic runtime did not stop")
	}
	if runtime.AgentState() != reconcile.AgentStopping {
		t.Fatalf("agent state after stop = %s, want %s", runtime.AgentState(), reconcile.AgentStopping)
	}
	if control.DisableCount() <= disablesBeforeShutdown || len(events) == 0 || events[len(events)-1] != "disable" {
		t.Fatalf("shutdown did not disable fast path: disables before=%d after=%d events=%v", disablesBeforeShutdown, control.DisableCount(), events)
	}
	heartbeats := control.HeartbeatCount()
	time.Sleep(20 * time.Millisecond)
	if control.HeartbeatCount() != heartbeats {
		t.Fatalf("heartbeat continued after runtime stop: before=%d after=%d", heartbeats, control.HeartbeatCount())
	}
	if err := runtime.Run(context.Background()); err == nil {
		t.Fatal("restarting a stopped runtime unexpectedly succeeded")
	}
}

func TestDynamicRuntimeBlocksQueuedPublishAfterKubernetesFreshnessExpires(t *testing.T) {
	sources := controlplane.Sources{Preflight: dynamicObserverPreflight{}, Flannel: dynamicObserverFlannel{}, Endpoints: dynamicObserverEndpoints{}, Pins: dynamicRuntimePins{}, TC: dynamicRuntimeTC{}, Rules: dynamicObserverRules{}}
	events := []string{}
	published := &atomic.Bool{}
	control := &dynamicRuntimeHeartbeatControl{localHandlerControl: &localHandlerControl{events: &events}}
	cfg := dynamicTestConfig()
	cfg.Health.Interval = config.Duration(10 * time.Millisecond)
	cfg.Kube.MaxStaleness = config.Duration(100 * time.Millisecond)
	cfg.Kube.ResyncInterval = config.Duration(time.Second)
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-a", UID: types.UID("node-a")}}
	client := fake.NewSimpleClientset(node)
	var apiDown atomic.Bool
	for _, resource := range []string{"nodes", "pods"} {
		client.PrependReactor("list", resource, func(k8stesting.Action) (bool, runtime.Object, error) {
			if apiDown.Load() {
				return true, nil, errors.New("API unavailable")
			}
			return false, nil, nil
		})
	}
	factory := func(context.Context, datapathComponentConfig) (*datapathComponents, error) {
		return dynamicRuntimeComponents(t, sources, control, &events, published), nil
	}
	runtime, err := newDynamicRuntimeWithFactory(cfg, client, factory)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := runtime.bootstrap.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runtime.initializeDatapath(ctx); err != nil {
		t.Fatal(err)
	}
	workerDone := make(chan struct{})
	go func() {
		runtime.worker.Run(ctx)
		close(workerDone)
	}()
	defer func() {
		cancel()
		runtime.queue.ShutDown()
		<-workerDone
		_ = runtime.components.Close()
	}()

	apiDown.Store(true)
	if err := runtime.source.ProbeAPI(ctx); err == nil {
		t.Fatal("API probe unexpectedly succeeded after API outage")
	}
	deadline := time.Now().Add(time.Second)
	for {
		if errors.Is(runtime.apiHealth.Fresh(ctx), ErrKubernetesAPIStale) {
			break
		}
		if !time.Now().Before(deadline) {
			t.Fatal("Kubernetes API freshness did not expire")
		}
		time.Sleep(time.Millisecond)
	}
	published.Store(false)
	key := reconcile.ReconcileKey{Kind: reconcile.ReconcileGlobal, Name: "node-a"}
	runtime.queue.Add(key)
	deadline = time.Now().Add(time.Second)
	for runtime.queue.NumRequeues(key) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if runtime.queue.NumRequeues(key) == 0 {
		t.Fatal("stale queued reconciliation did not return an error")
	}
	if published.Load() {
		t.Fatal("stale queued reconciliation published control state")
	}
}

func TestDynamicRuntimeDegradesWhenHeartbeatFails(t *testing.T) {
	sources := controlplane.Sources{Preflight: dynamicObserverPreflight{}, Flannel: dynamicObserverFlannel{}, Endpoints: dynamicObserverEndpoints{}, Pins: dynamicRuntimePins{}, TC: dynamicRuntimeTC{}, Rules: dynamicObserverRules{}}
	events := []string{}
	wantErr := errors.New("heartbeat map unavailable")
	control := &dynamicRuntimeHeartbeatControl{localHandlerControl: &localHandlerControl{events: &events}, refreshErr: wantErr}
	cfg := dynamicTestConfig()
	cfg.Heartbeat.Interval = config.Duration(10 * time.Millisecond)
	factory := func(context.Context, datapathComponentConfig) (*datapathComponents, error) {
		return dynamicRuntimeComponents(t, sources, control, &events, nil), nil
	}
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-a", UID: types.UID("node-a")}}
	runtime, err := newDynamicRuntimeWithFactory(cfg, fake.NewSimpleClientset(node), factory)
	if err != nil {
		t.Fatal(err)
	}
	err = runtime.Run(context.Background())
	if !errors.Is(err, wantErr) {
		t.Fatalf("Run error = %v, want %v", err, wantErr)
	}
	if runtime.AgentState() != reconcile.AgentDegraded {
		t.Fatalf("agent state = %s, want %s", runtime.AgentState(), reconcile.AgentDegraded)
	}
	if len(events) == 0 || events[len(events)-1] != "disable" {
		t.Fatalf("heartbeat failure did not disable fast path: events=%v", events)
	}
}

func TestDynamicRuntimeDegradesWhenKubernetesAPIStale(t *testing.T) {
	sources := controlplane.Sources{Preflight: dynamicObserverPreflight{}, Flannel: dynamicObserverFlannel{}, Endpoints: dynamicObserverEndpoints{}, Pins: dynamicRuntimePins{}, TC: dynamicRuntimeTC{}, Rules: dynamicObserverRules{}}
	events := []string{}
	control := &dynamicRuntimeHeartbeatControl{localHandlerControl: &localHandlerControl{events: &events}}
	cfg := dynamicTestConfig()
	cfg.Heartbeat.Interval = config.Duration(10 * time.Millisecond)
	cfg.Health.Interval = config.Duration(10 * time.Millisecond)
	cfg.Kube.MaxStaleness = config.Duration(25 * time.Millisecond)
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-a", UID: types.UID("node-a")}}
	client := fake.NewSimpleClientset(node)
	var apiDown atomic.Bool
	for _, resource := range []string{"nodes", "pods"} {
		client.PrependReactor("list", resource, func(k8stesting.Action) (bool, runtime.Object, error) {
			if apiDown.Load() {
				return true, nil, errors.New("API unavailable")
			}
			return false, nil, nil
		})
	}
	factory := func(context.Context, datapathComponentConfig) (*datapathComponents, error) {
		return dynamicRuntimeComponents(t, sources, control, &events, nil), nil
	}
	runtime, err := newDynamicRuntimeWithFactory(cfg, client, factory)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- runtime.Run(context.Background()) }()
	deadline := time.Now().Add(time.Second)
	for runtime.AgentState() != reconcile.AgentReady && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if runtime.AgentState() != reconcile.AgentReady {
		t.Fatalf("agent state = %s, want %s", runtime.AgentState(), reconcile.AgentReady)
	}
	apiDown.Store(true)
	select {
	case err := <-done:
		if !errors.Is(err, ErrKubernetesAPIStale) {
			t.Fatalf("Run error = %v, want ErrKubernetesAPIStale", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("stale Kubernetes API did not stop runtime")
	}
	if runtime.AgentState() != reconcile.AgentDegraded {
		t.Fatalf("agent state = %s, want %s", runtime.AgentState(), reconcile.AgentDegraded)
	}
	if len(events) == 0 || events[len(events)-1] != "disable" {
		t.Fatalf("stale API did not disable fast path: events=%v", events)
	}
}

func TestDynamicRuntimeDegradesWhenFlannelDrifts(t *testing.T) {
	events := []string{}
	control := &dynamicRuntimeHeartbeatControl{localHandlerControl: &localHandlerControl{events: &events}}
	cfg := dynamicTestConfig()
	cfg.Heartbeat.Interval = config.Duration(10 * time.Millisecond)
	cfg.Health.Interval = config.Duration(10 * time.Millisecond)
	cfg.Kube.MaxStaleness = config.Duration(30 * time.Millisecond)
	var drift atomic.Bool
	sources := controlplane.Sources{Preflight: dynamicObserverPreflight{}, Flannel: dynamicRuntimeFlannelHealth{drift: &drift}, Endpoints: dynamicObserverEndpoints{}, Pins: dynamicRuntimePins{}, TC: dynamicRuntimeTC{}, Rules: dynamicObserverRules{}}
	factory := func(context.Context, datapathComponentConfig) (*datapathComponents, error) {
		return dynamicRuntimeComponents(t, sources, control, &events, nil), nil
	}
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-a", UID: types.UID("node-a")}}
	runtime, err := newDynamicRuntimeWithFactory(cfg, fake.NewSimpleClientset(node), factory)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- runtime.Run(context.Background()) }()
	deadline := time.Now().Add(time.Second)
	for runtime.AgentState() != reconcile.AgentReady && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if runtime.AgentState() != reconcile.AgentReady {
		t.Fatalf("agent state = %s, want %s", runtime.AgentState(), reconcile.AgentReady)
	}
	drift.Store(true)
	select {
	case err := <-done:
		if !errors.Is(err, ErrFlannelConfigDrift) {
			t.Fatalf("Run error = %v, want ErrFlannelConfigDrift", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Flannel drift did not stop runtime")
	}
	if runtime.AgentState() != reconcile.AgentDegraded {
		t.Fatalf("agent state = %s, want %s", runtime.AgentState(), reconcile.AgentDegraded)
	}
	if len(events) == 0 || events[len(events)-1] != "disable" {
		t.Fatalf("Flannel drift did not disable fast path: events=%v", events)
	}
}

func TestDynamicRuntimeDegradesWhenMarkerRuleDrifts(t *testing.T) {
	events := []string{}
	control := &dynamicRuntimeHeartbeatControl{localHandlerControl: &localHandlerControl{events: &events}}
	cfg := dynamicTestConfig()
	cfg.Heartbeat.Interval = config.Duration(10 * time.Millisecond)
	cfg.Health.Interval = config.Duration(10 * time.Millisecond)
	cfg.Kube.MaxStaleness = config.Duration(30 * time.Millisecond)
	var drift atomic.Bool
	sources := controlplane.Sources{Preflight: dynamicObserverPreflight{}, Flannel: dynamicObserverFlannel{}, Endpoints: dynamicObserverEndpoints{}, Pins: dynamicRuntimePins{}, TC: dynamicRuntimeTC{}, Rules: dynamicRuntimeMarkerHealth{drift: &drift}}
	factory := func(context.Context, datapathComponentConfig) (*datapathComponents, error) {
		return dynamicRuntimeComponents(t, sources, control, &events, nil), nil
	}
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-a", UID: types.UID("node-a")}}
	runtime, err := newDynamicRuntimeWithFactory(cfg, fake.NewSimpleClientset(node), factory)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- runtime.Run(context.Background()) }()
	deadline := time.Now().Add(time.Second)
	for runtime.AgentState() != reconcile.AgentReady && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if runtime.AgentState() != reconcile.AgentReady {
		t.Fatalf("agent state = %s, want %s", runtime.AgentState(), reconcile.AgentReady)
	}
	drift.Store(true)
	select {
	case err := <-done:
		if !errors.Is(err, ErrMarkerDrift) {
			t.Fatalf("Run error = %v, want ErrMarkerDrift", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("marker drift did not stop runtime")
	}
	if runtime.AgentState() != reconcile.AgentDegraded {
		t.Fatalf("agent state = %s, want %s", runtime.AgentState(), reconcile.AgentDegraded)
	}
	if len(events) == 0 || events[len(events)-1] != "disable" {
		t.Fatalf("marker drift did not disable fast path: events=%v", events)
	}
}

func TestDynamicRuntimeDisablesAfterDatapathInitializationFailure(t *testing.T) {
	wantErr := errors.New("datapath unavailable")
	factory := func(context.Context, datapathComponentConfig) (*datapathComponents, error) {
		return nil, wantErr
	}
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-a", UID: types.UID("node-a")}}
	runtime, err := newDynamicRuntimeWithFactory(dynamicTestConfig(), fake.NewSimpleClientset(node), factory)
	if err != nil {
		t.Fatal(err)
	}
	err = runtime.Run(context.Background())
	if !errors.Is(err, wantErr) {
		t.Fatalf("Run error = %v, want %v", err, wantErr)
	}
	if runtime.AgentState() != reconcile.AgentDisabled {
		t.Fatalf("agent state = %s, want %s", runtime.AgentState(), reconcile.AgentDisabled)
	}
}

func TestNewDynamicRuntimeRejectsInvalidConfiguration(t *testing.T) {
	cfg := dynamicTestConfig()
	cfg.NodeName = ""
	if _, err := newDynamicRuntime(cfg, fake.NewSimpleClientset()); err == nil {
		t.Fatal("invalid dynamic configuration was accepted")
	}
}
