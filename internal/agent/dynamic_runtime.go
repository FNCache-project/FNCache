package agent

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	k8skubernetes "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/cat-cc-Lcos/FNCache/internal/cleanup"
	"github.com/cat-cc-Lcos/FNCache/internal/config"
	"github.com/cat-cc-Lcos/FNCache/internal/controlplane"
	"github.com/cat-cc-Lcos/FNCache/internal/datapath"
	"github.com/cat-cc-Lcos/FNCache/internal/endpoint"
	endpointlifecycle "github.com/cat-cc-Lcos/FNCache/internal/endpoint/lifecycle"
	"github.com/cat-cc-Lcos/FNCache/internal/hostnet/discovery"
	"github.com/cat-cc-Lcos/FNCache/internal/hostnet/flannel"
	"github.com/cat-cc-Lcos/FNCache/internal/kubernetes"
	"github.com/cat-cc-Lcos/FNCache/internal/kubernetes/queue"
	"github.com/cat-cc-Lcos/FNCache/internal/observability"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

type DynamicRuntime struct {
	config        config.AgentConfiguration
	snapshots     *observability.SnapshotStore
	store         *kubernetes.SnapshotStore
	source        *kubernetes.InformerSource
	bootstrap     *KubeBootstrap
	resync        *kubernetes.ResyncScheduler
	queue         *queue.Queue
	barrier       *reconcile.CoordinationBarrier
	lifecycle     *reconcile.AgentStateMachine
	healthEpoch   *HealthEpoch
	factory       datapathComponentFactory
	logger        observability.EventLogger
	components    *datapathComponents
	observer      *DynamicObserver
	worker        *queue.Worker
	heartbeat     *HeartbeatRefresher
	apiHealth     *APIHealthMonitor
	flannelHealth *FlannelHealthMonitor
	markerHealth  *MarkerHealthMonitor
	scanScheduler *ScanScheduler

	statusMu           sync.RWMutex
	statusPublishMu    sync.Mutex
	datapathReady      bool
	datapathGeneration uint64
	datapathReason     string
}

var ErrKubernetesSnapshotNotReady = errors.New("kubernetes snapshot is not ready")

type datapathComponentFactory func(context.Context, datapathComponentConfig) (*datapathComponents, error)

type dynamicObservationBackend struct {
	observer *DynamicObserver
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
	client, err := k8skubernetes.NewForConfig(clusterConfig)
	if err != nil {
		return nil, fmt.Errorf("create Kubernetes client: %w", err)
	}
	return newDynamicRuntime(cfg, client)
}

func newDynamicRuntime(cfg config.AgentConfiguration, client k8skubernetes.Interface) (*DynamicRuntime, error) {
	return newDynamicRuntimeWithFactory(cfg, client, newDatapathComponents)
}

func newDynamicRuntimeWithFactory(cfg config.AgentConfiguration, client k8skubernetes.Interface, factory datapathComponentFactory) (*DynamicRuntime, error) {
	return newDynamicRuntimeWithFactoryAndLogger(cfg, client, factory, observability.NewDefault("queue"))
}

func newDynamicRuntimeWithFactoryAndLogger(cfg config.AgentConfiguration, client k8skubernetes.Interface, factory datapathComponentFactory, logger observability.EventLogger) (*DynamicRuntime, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if client == nil || factory == nil {
		return nil, fmt.Errorf("Kubernetes client is required")
	}
	if logger == nil {
		logger = observability.NewDefault("queue")
	}
	store := kubernetes.NewSnapshotStore()
	interval := time.Duration(cfg.Kube.ResyncInterval)
	source, err := kubernetes.NewInformerSource(client, store, interval)
	if err != nil {
		return nil, err
	}
	target, err := queue.New(queue.DefaultConfig())
	if err != nil {
		return nil, fmt.Errorf("create coordination queue: %w", err)
	}
	classifier, err := kubernetes.NewEventClassifier(cfg.NodeName)
	if err != nil {
		return nil, err
	}
	if _, err := kubernetes.NewEventDispatcher(source, classifier, target); err != nil {
		return nil, err
	}
	bootstrap, err := NewKubeBootstrap(source, store)
	if err != nil {
		return nil, err
	}
	resync, err := kubernetes.NewResyncScheduler(store, cfg.NodeName, target, interval)
	if err != nil {
		return nil, err
	}
	apiHealth, err := NewAPIHealthMonitor(APIHealthMonitorConfig{Source: source, Interval: time.Duration(cfg.Health.Interval), MaxStaleness: time.Duration(cfg.Kube.MaxStaleness)})
	if err != nil {
		return nil, err
	}
	snapshots := observability.NewSnapshotStore(observability.Snapshot{
		State:  reconcile.AgentBootstrapping,
		Reason: "AGENT_BOOTSTRAPPING",
		Conditions: map[observability.ConditionType]bool{
			observability.DatapathReady:  false,
			observability.KubeAPIHealthy: false,
			observability.HeartbeatFresh: false,
		},
	})
	return &DynamicRuntime{config: cfg, snapshots: snapshots, store: store, source: source, bootstrap: bootstrap, resync: resync, queue: target, barrier: reconcile.NewCoordinationBarrier(), lifecycle: reconcile.NewAgentStateMachine(), healthEpoch: NewHealthEpoch(), factory: factory, logger: logger, apiHealth: apiHealth}, nil
}

// Run starts the dynamic runtime and blocks until it stops or fails.
func (r *DynamicRuntime) Run(ctx context.Context) error {
	if !r.config.Features.Enabled {
		if err := r.lifecycle.Transition(reconcile.AgentDisabled); err != nil {
			return err
		}
		r.Status(ctx)
		<-ctx.Done()
		return nil
	}
	r.Status(ctx)
	if err := r.bootstrap.Start(ctx); err != nil {
		if transitionErr := r.lifecycle.Transition(reconcile.AgentDisabled); transitionErr != nil {
			r.Status(ctx)
			return errors.Join(err, transitionErr)
		}
		r.Status(ctx)
		return err
	}
	if err := r.lifecycle.Transition(reconcile.AgentReconciling); err != nil {
		return err
	}
	r.Status(ctx)
	if err := r.initializeDatapathWithRetry(ctx); err != nil {
		if transitionErr := r.lifecycle.Transition(reconcile.AgentDisabled); transitionErr != nil {
			r.Status(ctx)
			return errors.Join(err, transitionErr)
		}
		r.Status(ctx)
		return err
	}
	if err := r.reconcileInitial(ctx); err != nil {
		if transitionErr := r.lifecycle.Transition(reconcile.AgentDisabled); transitionErr != nil {
			_ = r.components.Close()
			r.Status(ctx)
			return errors.Join(err, transitionErr)
		}
		_ = r.components.Close()
		r.Status(ctx)
		return err
	}
	r.Status(ctx)
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go r.resync.Run(runCtx)
	workerDone := make(chan struct{})
	go func() {
		r.worker.Run(runCtx)
		close(workerDone)
	}()
	if err := r.lifecycle.Transition(reconcile.AgentReady); err != nil {
		cancel()
		r.queue.ShutDown()
		<-workerDone
		_ = r.components.Close()
		r.Status(ctx)
		return err
	}
	r.Status(ctx)
	r.healthEpoch.Advance()
	r.Status(ctx)
	heartbeatDone := make(chan error, 1)
	go func() { heartbeatDone <- r.heartbeat.Run(runCtx) }()
	statusDone := make(chan struct{})
	go func() {
		r.statusLoop(runCtx)
		close(statusDone)
	}()
	scanResults := r.scanScheduler.Run(runCtx)
	_ = r.scanScheduler.Trigger(ScanFull)
	stopResult := r.waitForRuntimeStop(ctx, ctx.Done(), heartbeatDone, scanResults)
	cancel()
	<-statusDone
	r.queue.ShutDown()
	heartbeatObserved := stopResult.heartbeatObserved
	failureErr := stopResult.failureErr
	var runErr error
	stopErr := stopResult.stopErr
	stoppingRequested := stopResult.stoppingRequested
	shutdownTimeout := time.Duration(r.config.Heartbeat.Timeout) + time.Second
	shutdownWaiter, waiterErr := NewShutdownWaiter(shutdownTimeout)
	if waiterErr != nil {
		return errors.Join(runErr, stopErr, waiterErr)
	}
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer shutdownCancel()
	var shutdownErr error
	if !heartbeatObserved {
		shutdownErr = errors.Join(shutdownErr, shutdownWaiter.WaitError(shutdownCtx, heartbeatDone))
	}
	shutdownErr = errors.Join(shutdownErr, shutdownWaiter.Drain(shutdownCtx, scanResults))
	r.queue.ShutDown()
	shutdownErr = errors.Join(shutdownErr, shutdownWaiter.Wait(shutdownCtx, workerDone))
	if stoppingRequested && shutdownErr == nil {
		shutdownErr = errors.Join(shutdownErr, r.disableFastPathForShutdown())
		if r.config.Features.CleanupOnShutdown {
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
			shutdownErr = errors.Join(shutdownErr, r.cleanupOwnedObjects(cleanupCtx))
			cleanupCancel()
		}
	}
	if failureErr != nil {
		disableCtx, disableCancel := context.WithTimeout(context.Background(), time.Duration(r.config.Heartbeat.Timeout))
		disableErr := r.components.control.Disable(disableCtx)
		disableCancel()
		degradedErr := r.lifecycle.Transition(reconcile.AgentDegraded)
		runErr = errors.Join(failureErr, disableErr, degradedErr)
		r.Status(context.Background())
	}
	var closeErr error
	if r.components != nil && shutdownErr == nil {
		closeErr = shutdownWaiter.Close(shutdownCtx, r.components.Close)
	}
	if r.components != nil {
		return errors.Join(runErr, stopErr, shutdownErr, closeErr)
	}
	return errors.Join(runErr, stopErr, shutdownErr)
}

// cleanupOwnedObjects removes only objects proven to belong to this installation.
// cleanupOwnedObjects removes only objects proven to belong to this installation.
func (r *DynamicRuntime) cleanupOwnedObjects(ctx context.Context) error {
	_, err := cleanup.Run(ctx, cleanup.Options{
		PinRoot: r.config.PinRoot, StatePath: filepath.Join(r.config.StateDir, "state.json"), InstallationID: r.config.InstallationID,
		MarkerChain: r.config.Markers.Chain, MarkerComment: r.config.Markers.Comment,
		MapCapacities: datapath.MapCapacities{
			IngressCacheMaxEntries: r.config.Maps.IngressCacheMaxEntries, EgressIPCacheMaxEntries: r.config.Maps.EgressIPCacheMaxEntries,
			EgressCacheMaxEntries: r.config.Maps.EgressCacheMaxEntries, PolicyCacheMaxEntries: r.config.Maps.PolicyCacheMaxEntries,
			DevMapMaxEntries: r.config.Maps.DevMapMaxEntries,
		},
	}, false)
	if err != nil {
		return fmt.Errorf("cleanup owned objects: %w", err)
	}
	return nil
}

type runtimeStopResult struct {
	heartbeatObserved bool
	failureErr        error
	stopErr           error
	stoppingRequested bool
}

// waitForRuntimeStop waits for the first runtime stop or failure event.
func (r *DynamicRuntime) waitForRuntimeStop(ctx context.Context, stopCh <-chan struct{}, heartbeatDone <-chan error, scanResults <-chan ScanResult) runtimeStopResult {
	var result runtimeStopResult
	for {
		select {
		case heartbeatErr := <-heartbeatDone:
			result.heartbeatObserved = true
			r.healthEpoch.Invalidate()
			if ctx.Err() != nil {
				result.stoppingRequested = true
				result.stopErr = r.lifecycle.Transition(reconcile.AgentStopping)
			} else {
				if heartbeatErr == nil {
					heartbeatErr = fmt.Errorf("heartbeat refresher stopped unexpectedly")
				}
				result.failureErr = heartbeatErr
			}
			r.Status(context.Background())
			return result
		case scanResult, ok := <-scanResults:
			if !ok {
				result.stopErr, result.failureErr = r.handleClosedScanResults(ctx, &result.stoppingRequested)
				r.Status(context.Background())
				return result
			}
			r.recordScanStatus(scanResult)
			if scanResult.Critical || scanResult.InvalidateEpoch {
				r.healthEpoch.Invalidate()
				r.Status(context.Background())
				result.failureErr = scanResult.Err
				if result.failureErr == nil {
					result.failureErr = fmt.Errorf("%s", scanResult.Reason)
				}
				return result
			}
			r.Status(context.Background())
		case <-stopCh:
			r.healthEpoch.Invalidate()
			result.stoppingRequested = true
			result.stopErr = r.lifecycle.Transition(reconcile.AgentStopping)
			r.Status(context.Background())
			return result
		}
	}
}

// handleClosedScanResults classifies a closed scan channel as graceful or failed.
func (r *DynamicRuntime) handleClosedScanResults(ctx context.Context, stoppingRequested *bool) (stopErr, failureErr error) {
	r.healthEpoch.Invalidate()
	if ctx.Err() != nil {
		*stoppingRequested = true
		return r.lifecycle.Transition(reconcile.AgentStopping), nil
	}
	return nil, fmt.Errorf("scan scheduler stopped unexpectedly")
}

// initializeDatapathWithRetry waits for transient startup dependencies without ignoring cancellation.
func (r *DynamicRuntime) initializeDatapathWithRetry(ctx context.Context) error {
	for {
		if err := r.initializeDatapath(ctx); err == nil {
			return nil
		} else if delay, retry := initialDatapathRetry(err); !retry {
			return err
		} else {
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
	}
}

// initialDatapathRetry classifies dependencies that may become ready after startup.
func initialDatapathRetry(err error) (time.Duration, bool) {
	if errors.Is(err, ErrKubernetesSnapshotNotReady) || errors.Is(err, flannel.ErrDiscoveryNotReady) || errors.Is(err, endpoint.ErrContainerdEndpointNotReady) {
		return time.Second, true
	}
	return 0, false
}

func (r *DynamicRuntime) disableFastPathForShutdown() error {
	if r.components == nil || r.components.control == nil {
		return nil
	}
	timeout := time.Duration(r.config.Heartbeat.Timeout)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := r.components.control.Disable(ctx); err != nil {
		return fmt.Errorf("disable fast path during shutdown: %w", err)
	}
	return nil
}

func (r *DynamicRuntime) reconcileInitial(ctx context.Context) error {
	if err := r.components.control.Disable(ctx); err != nil {
		return fmt.Errorf("disable before initial discovery: %w", err)
	}
	desired, err := r.observer.Discover(ctx)
	if err != nil {
		return fmt.Errorf("initial discovery: %w", err)
	}
	if !desired.Enabled {
		return fmt.Errorf("initial discovery disabled: %s", formatCapabilityReasons(desired.Capability.Reasons))
	}
	remover, err := controlplane.NewEndpointRemover(r.components.mapWriter, r.components.tc)
	if err != nil {
		return fmt.Errorf("create initial endpoint remover: %w", err)
	}
	backend, err := controlplane.NewFirstPassBackend(controlplane.FirstPassBackendConfig{
		Observer: initialObservationBackend{observer: r.observer, desired: desired}, Control: r.components.control, Collection: r.components.collection,
		Marker: r.components.marker, Base: r.components.base, Endpoint: r.components.endpoint,
		Maps: r.components.maps, Ownership: r.components.ownership, Remover: remover,
		Publisher: r.components.publisher,
	})
	if err != nil {
		return fmt.Errorf("create initial reconciliation backend: %w", err)
	}
	coordinator, err := reconcile.NewCoordinator(backend)
	if err != nil {
		return fmt.Errorf("create initial reconciliation coordinator: %w", err)
	}
	for {
		result, err := coordinator.FullReconcile(ctx)
		if err == nil {
			if result.State != reconcile.AgentReady {
				return fmt.Errorf("initial full reconciliation ended in %s", result.State)
			}
			r.setDatapathStatus(true, result.Generation)
			return nil
		}
		if delay, retry := initialReconcileRetry(err); retry {
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
			continue
		}
		return fmt.Errorf("initial full reconciliation: %w", err)
	}
}

func initialReconcileRetry(err error) (time.Duration, bool) {
	var classified *reconcile.ClassifiedError
	if !errors.As(err, &classified) || classified.Class() != reconcile.ErrorRetryable || classified.ReasonCode() != reconcile.ReasonEndpointNotReady {
		return 0, false
	}
	if classified.RetryAfter() > 0 {
		return classified.RetryAfter(), true
	}
	return time.Second, true
}

type initialObservationBackend struct {
	observer *DynamicObserver
	desired  reconcile.DesiredState
}

func (o initialObservationBackend) Discover(context.Context) (reconcile.DesiredState, error) {
	return o.desired, nil
}

func (o initialObservationBackend) Scan(ctx context.Context) (reconcile.ActualState, error) {
	return o.observer.Scan(ctx)
}

func formatCapabilityReasons(reasons []discovery.Reason) string {
	if len(reasons) == 0 {
		return "no capability reason reported"
	}
	parts := make([]string, 0, len(reasons))
	for _, reason := range reasons {
		if reason.Code == "" {
			parts = append(parts, reason.Message)
			continue
		}
		if reason.Message == "" {
			parts = append(parts, reason.Code)
			continue
		}
		parts = append(parts, reason.Code+": "+reason.Message)
	}
	return strings.Join(parts, "; ")
}

func (r *DynamicRuntime) State() KubeBootstrapState { return r.bootstrap.State() }

func (r *DynamicRuntime) AgentState() reconcile.AgentState { return r.lifecycle.State() }

func (r *DynamicRuntime) flannelDiscoveryRequest() flannel.DiscoveryRequest {
	return flannel.DiscoveryRequest{VXLANLinkName: r.config.Overlay.VXLANLinkName, UnderlayDevice: r.config.Overlay.Device, MissMask: r.config.Markers.MissMask, EstablishedMask: r.config.Markers.EstablishedMask, IPTablesBackend: "iptables-nft"}
}

func (r *DynamicRuntime) markerRuleSpec() flannel.MarkerRuleSpec {
	return flannel.MarkerRuleSpec{Chain: r.config.Markers.Chain, Comment: r.config.Markers.Comment}
}

// initializeDatapath resolves runtime dependencies and creates the datapath components.
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
		return fmt.Errorf("%w: local Node %q is missing from Snapshot", ErrKubernetesSnapshotNotReady, r.config.NodeName)
	}
	runtimeEndpoint, err := endpoint.ResolveContainerdEndpoint(ctx, r.config.RuntimeEndpoint)
	if err != nil {
		return fmt.Errorf("resolve containerd endpoint: %w", err)
	}
	r.config.RuntimeEndpoint = runtimeEndpoint
	heartbeat, err := monotonicNowNS()
	if err != nil {
		return fmt.Errorf("read monotonic clock: %w", err)
	}
	components, err := r.factory(ctx, datapathComponentConfig{
		ELFPath: r.config.Datapath.ELFPath, PinRoot: r.config.PinRoot, StatePath: filepath.Join(r.config.StateDir, "state.json"),
		InstallationID: r.config.InstallationID, ELFBuildID: r.config.Datapath.ELFBuildID, HeartbeatNS: heartbeat,
		HeartbeatTimeoutNS: uint64(time.Duration(r.config.Heartbeat.Timeout)), Flags: 0,
		MapCapacities: datapath.MapCapacities{
			IngressCacheMaxEntries: r.config.Maps.IngressCacheMaxEntries, EgressIPCacheMaxEntries: r.config.Maps.EgressIPCacheMaxEntries,
			EgressCacheMaxEntries: r.config.Maps.EgressCacheMaxEntries, PolicyCacheMaxEntries: r.config.Maps.PolicyCacheMaxEntries,
			DevMapMaxEntries: r.config.Maps.DevMapMaxEntries,
		},
		Preflight: discovery.PreflightRequest{Node: node.Identity, PinRoot: r.config.PinRoot, StateDir: r.config.StateDir, InstallationID: r.config.InstallationID, ELFBuildID: r.config.Datapath.ELFBuildID, RuntimeURI: r.config.RuntimeEndpoint, Overlay: r.config.Overlay.Type},
		Flannel:   r.flannelDiscoveryRequest(),
		Marker:    r.markerRuleSpec(),
	})
	if err != nil {
		return fmt.Errorf("create dynamic datapath components: %w", err)
	}
	heartbeatControl, ok := components.control.(HeartbeatControl)
	if !ok {
		_ = components.Close()
		return fmt.Errorf("dynamic datapath heartbeat control is unavailable")
	}
	heartbeatRefresher, err := NewHeartbeatRefresher(HeartbeatRefresherConfig{
		Control: heartbeatControl, Epoch: r.healthEpoch, State: r.AgentState,
		Interval: time.Duration(r.config.Heartbeat.Interval), Now: monotonicNowNS,
	})
	if err != nil {
		_ = components.Close()
		return err
	}
	flannelRequest := r.flannelDiscoveryRequest()
	flannelBaseline, err := components.sources.Flannel.Discover(ctx, flannelRequest)
	if err != nil {
		_ = components.Close()
		return fmt.Errorf("discover Flannel baseline: %w", err)
	}
	if err := flannelBaseline.Validate(); err != nil {
		_ = components.Close()
		return fmt.Errorf("validate Flannel baseline: %w", err)
	}
	flannelHealth, err := NewFlannelHealthMonitor(FlannelHealthMonitorConfig{Source: components.sources.Flannel, Request: flannelRequest, ExpectedFingerprint: flannelBaseline.Fingerprint, Interval: time.Duration(r.config.Health.Interval)})
	if err != nil {
		_ = components.Close()
		return err
	}
	markerSpec := r.markerRuleSpec()
	markerHealth, err := NewMarkerHealthMonitor(MarkerHealthMonitorConfig{Source: components.sources.Rules, Pins: components.sources.Pins, Spec: markerSpec, ExpectedFingerprint: flannel.ExpectedMarkerFingerprint(markerSpec), Interval: time.Duration(r.config.Health.Interval)})
	if err != nil {
		_ = components.Close()
		return err
	}
	components.publisher.SetPublishGuard(func(ctx context.Context) error {
		if err := r.apiHealth.Fresh(ctx); err != nil {
			return err
		}
		if err := flannelHealth.Check(ctx); err != nil {
			return err
		}
		return markerHealth.CheckForPublish(ctx)
	})
	observer, err := NewDynamicObserver(r.config, r.store, components.sources)
	if err != nil {
		_ = components.Close()
		return err
	}
	scanAdapter, err := NewRuntimeScanAdapterWithVerifier(observer, components.publisher.VerifyState, r.apiHealth.Check, flannelHealth.Check, markerHealth.Check)
	if err != nil {
		_ = components.Close()
		return err
	}
	scanScheduler, err := NewScanScheduler(ScanSchedulerConfig{
		Light: scanAdapter.Light, Incremental: scanAdapter.Incremental, Full: scanAdapter.Full,
		LightInterval: time.Duration(r.config.Health.Interval), IncrementalInterval: time.Duration(r.config.Scan.IncrementalInterval), FullInterval: time.Duration(r.config.Scan.FullInterval),
	})
	if err != nil {
		_ = components.Close()
		return err
	}
	generationTransaction, err := controlplane.NewGenerationTransaction(components.control, observer, components.publisher)
	if err != nil {
		_ = components.Close()
		return err
	}
	remover, err := controlplane.NewEndpointRemover(components.mapWriter, components.tc)
	if err != nil {
		_ = components.Close()
		return err
	}
	guard, err := endpointlifecycle.NewEndpointReuseGuard(components.endpointResolver, r.config.NodeName)
	if err != nil {
		_ = components.Close()
		return err
	}
	local, err := endpointlifecycle.NewLocalEndpointHandler(endpointlifecycle.LocalEndpointHandlerConfig{Store: r.store, Resolver: components.endpointResolver, LocalNode: r.config.NodeName, Desired: observer, Scanner: observer, Control: components.control, Endpoint: components.endpoint, Maps: components.maps, Remover: remover, Ownership: components.ownership, Publisher: components.publisher, Generation: generationTransaction})
	if err != nil {
		_ = components.Close()
		return err
	}
	deleting, err := endpointlifecycle.NewLocalEndpointDeleteHandler(endpointlifecycle.LocalEndpointDeleteHandlerConfig{Store: r.store, Ownership: components.ownership, LocalNode: r.config.NodeName, Desired: observer, Remover: remover, ReuseGuard: guard, Generation: generationTransaction})
	if err != nil {
		_ = components.Close()
		return err
	}
	remote, err := endpointlifecycle.NewRemoteChangeHandler(endpointlifecycle.RemoteChangeHandlerConfig{Store: r.store, LocalNode: r.config.NodeName, Desired: observer, Maps: components.mapWriter, Base: components.base, DeviceMap: components.deviceMap, Generation: generationTransaction})
	if err != nil {
		_ = components.Close()
		return err
	}
	router, err := endpointlifecycle.NewDynamicHandlerRouter(local, deleting, remote)
	if err != nil {
		_ = components.Close()
		return err
	}
	worker, err := queue.NewWorkerWithBarrierAndLogger(r.queue, router.Handle, r.barrier, r.logger)
	if err != nil {
		_ = components.Close()
		return err
	}
	r.components, r.observer, r.worker, r.heartbeat, r.flannelHealth, r.markerHealth, r.scanScheduler = components, observer, worker, heartbeatRefresher, flannelHealth, markerHealth, scanScheduler
	return nil
}
