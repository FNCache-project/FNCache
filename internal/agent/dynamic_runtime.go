package agent

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/cat-cc-Lcos/FNCache/internal/config"
	"github.com/cat-cc-Lcos/FNCache/internal/controlplane"
	"github.com/cat-cc-Lcos/FNCache/internal/discovery"
	"github.com/cat-cc-Lcos/FNCache/internal/kube"
	"github.com/cat-cc-Lcos/FNCache/internal/overlay/flannel"
	"github.com/cat-cc-Lcos/FNCache/internal/queue"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

type DynamicRuntime struct {
	config      config.AgentConfiguration
	store       *kube.SnapshotStore
	source      *kube.InformerSource
	bootstrap   *KubeBootstrap
	resync      *kube.ResyncScheduler
	queue       *queue.Queue
	barrier     *reconcile.CoordinationBarrier
	factory     datapathComponentFactory
	components  *datapathComponents
	observer    *DynamicObserver
	coordinator *reconcile.Coordinator
	worker      *queue.Worker
}

type datapathComponentFactory func(context.Context, datapathComponentConfig) (*datapathComponents, error)

type dynamicObservationBackend struct {
	observer *DynamicObserver
}

type heartbeatRefresher interface {
	RefreshHeartbeat(context.Context, uint64) error
}

func runDynamicHeartbeat(ctx context.Context, interval time.Duration, refresher heartbeatRefresher) {
	if interval <= 0 || refresher == nil {
		return
	}
	refresh := func() {
		if ctx.Err() != nil {
			return
		}
		heartbeat, err := monotonicNowNS()
		if err != nil {
			return
		}
		// A failed refresh deliberately leaves the BPF fast path fail-safe;
		// the next tick gets another opportunity to refresh it.
		_ = refresher.RefreshHeartbeat(ctx, heartbeat)
	}

	refresh()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			refresh()
		case <-ctx.Done():
			return
		}
	}
}

func (b dynamicObservationBackend) Discover(ctx context.Context) (reconcile.DesiredState, error) {
	return b.observer.Desired(ctx)
}

func (b dynamicObservationBackend) Scan(ctx context.Context) (reconcile.ActualState, error) {
	return b.observer.Scan(ctx)
}

func NewDynamicRuntime(configPath string) (*DynamicRuntime, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, fmt.Errorf("load agent configuration: %w", err)
	}
	clusterConfig, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("load in-cluster Kubernetes configuration: %w", err)
	}
	client, err := kubernetes.NewForConfig(clusterConfig)
	if err != nil {
		return nil, fmt.Errorf("create Kubernetes client: %w", err)
	}
	return newDynamicRuntime(cfg, client)
}

func newDynamicRuntime(cfg config.AgentConfiguration, client kubernetes.Interface) (*DynamicRuntime, error) {
	return newDynamicRuntimeWithFactory(cfg, client, newDatapathComponents)
}

func newDynamicRuntimeWithFactory(cfg config.AgentConfiguration, client kubernetes.Interface, factory datapathComponentFactory) (*DynamicRuntime, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if client == nil || factory == nil {
		return nil, fmt.Errorf("Kubernetes client is required")
	}
	store := kube.NewSnapshotStore()
	interval := time.Duration(cfg.Kube.ResyncInterval)
	source, err := kube.NewInformerSource(client, store, interval)
	if err != nil {
		return nil, err
	}
	target, err := queue.New(queue.DefaultConfig())
	if err != nil {
		return nil, fmt.Errorf("create coordination queue: %w", err)
	}
	classifier, err := kube.NewEventClassifier(cfg.NodeName)
	if err != nil {
		return nil, err
	}
	if _, err := kube.NewEventDispatcher(source, classifier, target); err != nil {
		return nil, err
	}
	bootstrap, err := NewKubeBootstrap(source, store)
	if err != nil {
		return nil, err
	}
	resync, err := kube.NewResyncScheduler(store, cfg.NodeName, target, interval)
	if err != nil {
		return nil, err
	}
	return &DynamicRuntime{config: cfg, store: store, source: source, bootstrap: bootstrap, resync: resync, queue: target, barrier: reconcile.NewCoordinationBarrier(), factory: factory}, nil
}

func (r *DynamicRuntime) Run(ctx context.Context) error {
	if err := r.bootstrap.Start(ctx); err != nil {
		return err
	}
	if err := r.initializeDatapath(ctx); err != nil {
		return err
	}
	if _, err := r.coordinator.FullReconcile(ctx); err != nil {
		_ = r.components.Close()
		return fmt.Errorf("initial dynamic full reconcile: %w", err)
	}
	heartbeatDone := make(chan struct{})
	go func() {
		defer close(heartbeatDone)
		runDynamicHeartbeat(ctx, time.Duration(r.config.Heartbeat.Interval), r.components.publisher)
	}()
	go r.resync.Run(ctx)
	workerDone := make(chan struct{})
	go func() {
		r.worker.Run(ctx)
		close(workerDone)
	}()
	<-ctx.Done()
	r.queue.ShutDown()
	<-workerDone
	<-heartbeatDone
	if r.components != nil {
		return r.components.Close()
	}
	return nil
}

func (r *DynamicRuntime) State() KubeBootstrapState { return r.bootstrap.State() }

func (r *DynamicRuntime) initializeDatapath(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	snapshot, err := r.bootstrap.Snapshot()
	if err != nil {
		return err
	}
	node, ok := snapshot.Nodes[r.config.NodeName]
	if !ok || node.Identity.UID == "" {
		return fmt.Errorf("local Node %q is missing from Snapshot", r.config.NodeName)
	}
	heartbeat, err := monotonicNowNS()
	if err != nil {
		return fmt.Errorf("read monotonic clock: %w", err)
	}
	components, err := r.factory(ctx, datapathComponentConfig{
		ELFPath: r.config.Datapath.ELFPath, PinRoot: r.config.PinRoot, StatePath: filepath.Join(r.config.StateDir, "state.json"),
		InstallationID: r.config.InstallationID, ELFBuildID: r.config.Datapath.ELFBuildID, HeartbeatNS: heartbeat,
		HeartbeatTimeoutNS: uint64(time.Duration(r.config.Heartbeat.Timeout)), Flags: 0,
		Preflight: discovery.PreflightRequest{Node: node.Identity, PinRoot: r.config.PinRoot, StateDir: r.config.StateDir, RuntimeURI: r.config.RuntimeEndpoint, Overlay: r.config.Overlay.Type},
		Flannel:   flannel.DiscoveryRequest{VXLANLinkName: r.config.Overlay.VXLANLinkName, UnderlayDevice: r.config.Overlay.Device, MissMask: r.config.Markers.MissMask, EstablishedMask: r.config.Markers.EstablishedMask, IPTablesBackend: "iptables-nft"},
		Marker:    flannel.MarkerRuleSpec{Chain: r.config.Markers.Chain, Comment: r.config.Markers.Comment},
	})
	if err != nil {
		return fmt.Errorf("create dynamic datapath components: %w", err)
	}
	observer, err := NewDynamicObserver(r.config, r.store, components.sources)
	if err != nil {
		_ = components.Close()
		return err
	}
	remover, err := controlplane.NewEndpointRemover(components.mapWriter, components.tc)
	if err != nil {
		_ = components.Close()
		return err
	}
	backend, err := controlplane.NewFirstPassBackend(controlplane.FirstPassBackendConfig{
		Observer: dynamicObservationBackend{observer: observer}, Control: components.control, Collection: components.collection, Marker: components.marker,
		Base: components.base, Endpoint: components.endpoint, Maps: components.maps, Ownership: components.ownership,
		Remover: remover, Publisher: components.publisher,
	})
	if err != nil {
		_ = components.Close()
		return err
	}
	coordinator, err := reconcile.NewCoordinator(backend)
	if err != nil {
		_ = components.Close()
		return err
	}
	guard, err := NewEndpointReuseGuard(components.endpointResolver, r.config.NodeName)
	if err != nil {
		_ = components.Close()
		return err
	}
	local, err := NewLocalEndpointHandler(LocalEndpointHandlerConfig{Store: r.store, Resolver: components.endpointResolver, LocalNode: r.config.NodeName, Desired: observer, Scanner: observer, Control: components.control, Endpoint: components.endpoint, Maps: components.maps, Remover: remover, Publisher: components.publisher})
	if err != nil {
		_ = components.Close()
		return err
	}
	deleting, err := NewLocalEndpointDeleteHandler(LocalEndpointDeleteHandlerConfig{Store: r.store, Ownership: components.ownership, LocalNode: r.config.NodeName, Desired: observer, Scanner: observer, Control: components.control, Remover: remover, ReuseGuard: guard, Publisher: components.publisher})
	if err != nil {
		_ = components.Close()
		return err
	}
	remote, err := NewRemoteChangeHandler(RemoteChangeHandlerConfig{Store: r.store, LocalNode: r.config.NodeName, Desired: observer, Scanner: observer, Control: components.control, Maps: components.mapWriter, Publisher: components.publisher})
	if err != nil {
		_ = components.Close()
		return err
	}
	router, err := NewDynamicHandlerRouter(local, deleting, remote)
	if err != nil {
		_ = components.Close()
		return err
	}
	worker, err := queue.NewWorkerWithBarrier(r.queue, router.Handle, r.barrier)
	if err != nil {
		_ = components.Close()
		return err
	}
	r.components, r.observer, r.coordinator, r.worker = components, observer, coordinator, worker
	return nil
}
