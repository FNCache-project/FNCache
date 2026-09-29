package agent

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/cat-cc-Lcos/FNCache/internal/controlplane"
	"github.com/cat-cc-Lcos/FNCache/internal/datapath"
	"github.com/cat-cc-Lcos/FNCache/internal/discovery"
	"github.com/cat-cc-Lcos/FNCache/internal/overlay/flannel"
	"github.com/cat-cc-Lcos/FNCache/internal/ownership"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
	"github.com/cat-cc-Lcos/FNCache/internal/resolver"
	"golang.org/x/sys/unix"
)

type StaticRuntimeConfig struct {
	ELFPath        string
	PinRoot        string
	StatePath      string
	InstallationID string
	ELFBuildID     string
	Generation     uint64
	// HeartbeatNS is retained for manifest compatibility; the datapath writer
	// now obtains the timestamp from CLOCK_MONOTONIC at publish time.
	HeartbeatNS        uint64
	HeartbeatTimeoutNS uint64
	Flags              uint32
	Preflight          discovery.PreflightRequest
	Flannel            flannel.DiscoveryRequest
	Marker             flannel.MarkerRuleSpec
	Pods               []resolver.PodSnapshot
	TCLinks            []resolver.LinkIdentity
}

type StaticRuntime struct {
	config          StaticRuntimeConfig
	cri             io.Closer
	lock            *os.File
	endpointScanner *resolver.EndpointScanner
	pins            *datapath.PinScanner
	tcScanner       *datapath.TCScanner
	sources         controlplane.Sources
	control         *runtimeControl
	collection      *controlplane.CollectionEnsurer
	marker          *controlplane.FlannelMarkerEnsurer
	base            *controlplane.BaseEnsurer
	endpoint        *controlplane.EndpointEnsurer
	maps            *controlplane.MapEnsurer
	publisher       *controlplane.Publisher
}

const runtimeLockDirectory = "/run/lock/oncache"

func NewStaticRuntime(ctx context.Context, config StaticRuntimeConfig) (*StaticRuntime, error) {
	if err := validateStaticRuntimeConfig(config); err != nil {
		return nil, err
	}
	lock, err := acquireRuntimeLock(config.PinRoot, runtimeLockDirectory)
	if err != nil {
		return nil, err
	}
	sandbox, cri, err := resolver.DialContainerdCRI(ctx, config.Preflight.RuntimeURI)
	if err != nil {
		_ = lock.Close()
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			_ = cri.Close()
			_ = lock.Close()
		}
	}()

	netns := datapath.NewNetNSManager()
	endpointResolver, err := resolver.NewLinuxEndpointResolver(sandbox, func(ctx context.Context, info resolver.SandboxInfo, fn func(context.Context) error) error {
		return netns.WithNetNS(ctx, datapath.NetNSRef{Path: info.NetNSPath, Inode: info.NetNSInode}, fn)
	})
	if err != nil {
		return nil, err
	}
	endpointScanner, err := resolver.NewEndpointScanner(endpointResolver)
	if err != nil {
		return nil, err
	}
	pins, err := datapath.NewPinScanner(config.PinRoot)
	if err != nil {
		return nil, err
	}
	tcBackend, err := datapath.NewLinuxTCBackend(config.PinRoot)
	if err != nil {
		return nil, err
	}
	tc, err := datapath.NewTCManagerWithNetNS(tcBackend, netns)
	if err != nil {
		return nil, err
	}
	tcScanner, err := datapath.NewTCScanner(tc)
	if err != nil {
		return nil, err
	}
	controlWriter, err := datapath.NewControlWriter(config.PinRoot)
	if err != nil {
		return nil, err
	}
	collection, err := controlplane.NewCollectionEnsurer(config.ELFPath, config.PinRoot)
	if err != nil {
		return nil, err
	}
	markerManager := flannel.NewMarkerRuleManager(nil)
	marker, err := controlplane.NewFlannelMarkerEnsurer(markerManager, config.Marker)
	if err != nil {
		return nil, err
	}
	base, err := controlplane.NewBaseEnsurer(tc)
	if err != nil {
		return nil, err
	}
	endpoint, err := controlplane.NewEndpointEnsurer(tc)
	if err != nil {
		return nil, err
	}
	mapWriter, err := datapath.NewMapWriter(config.PinRoot)
	if err != nil {
		return nil, err
	}
	maps, err := controlplane.NewMapEnsurer(mapWriter)
	if err != nil {
		return nil, err
	}
	store, err := ownership.NewStore(config.StatePath)
	if err != nil {
		return nil, err
	}
	publisher, err := controlplane.NewPublisher(store, controlWriter, controlplane.PublishConfig{
		InstallationID: config.InstallationID, NodeUID: config.Preflight.Node.UID, ELFBuildID: config.ELFBuildID,
		HeartbeatTimeoutNS: config.HeartbeatTimeoutNS, Flags: config.Flags,
	})
	if err != nil {
		return nil, err
	}
	preflight := discovery.NewPreflight(discovery.NewLinuxProbe("/"))
	flannelSource := flannel.NewDiscovery(nil)
	ruleScanner := flannel.NewRuleScanner(nil)
	runtime := &StaticRuntime{
		config: config, cri: cri, lock: lock, endpointScanner: endpointScanner, pins: pins, tcScanner: tcScanner,
		sources: controlplane.Sources{Preflight: preflight, Flannel: flannelSource, Endpoints: endpointScanner, Pins: pins, TC: tcScanner, Rules: ruleScanner},
		control: &runtimeControl{pinRoot: config.PinRoot, writer: controlWriter}, collection: collection, marker: marker,
		base: base, endpoint: endpoint, maps: maps, publisher: publisher,
	}
	ok = true
	return runtime, nil
}

func (r *StaticRuntime) RunOnce(ctx context.Context) (reconcile.ReconcileResult, error) {
	result, _, err := r.reconcileOnce(ctx)
	if err != nil {
		return result, err
	}
	if err := r.disableForShutdown(); err != nil {
		return result, fmt.Errorf("disable fast path after one-shot reconcile: %w", err)
	}
	result.State = reconcile.AgentDisabled
	return result, nil
}

// Run reconciles once, then keeps the published control Map lease alive until
// the context is canceled or the lease can no longer be renewed.
func (r *StaticRuntime) Run(ctx context.Context) (reconcile.ReconcileResult, error) {
	result, coordinator, err := r.reconcileOnce(ctx)
	if err != nil {
		return result, err
	}
	interval, err := heartbeatRenewInterval(r.config.HeartbeatTimeoutNS)
	if err != nil {
		coordinator.MarkDegraded()
		result.State = coordinator.State()
		if disableErr := r.disableForShutdown(); disableErr != nil {
			return result, fmt.Errorf("configure heartbeat renewal: %v; disable fast path: %w", err, disableErr)
		}
		return result, fmt.Errorf("configure heartbeat renewal: %w", err)
	}
	if err := runHeartbeatLease(ctx, interval, func(ctx context.Context) error {
		return r.control.Renew(ctx, r.config.Generation)
	}, r.control.Disable); err != nil {
		if ctx.Err() != nil {
			coordinator.MarkStopping()
		} else {
			coordinator.MarkDegraded()
		}
		result.State = coordinator.State()
		return result, err
	}
	coordinator.MarkStopping()
	result.State = coordinator.State()
	return result, nil
}

func (r *StaticRuntime) reconcileOnce(ctx context.Context) (reconcile.ReconcileResult, *reconcile.Coordinator, error) {
	if err := ctx.Err(); err != nil {
		return reconcile.ReconcileResult{}, nil, err
	}
	endpoints, err := r.endpointScanner.Scan(ctx, r.config.Pods)
	if err != nil {
		return reconcile.ReconcileResult{}, nil, fmt.Errorf("prepare endpoint links: %w", err)
	}
	links := mergeEndpointLinks(r.config.TCLinks, endpoints.Endpoints)
	observer, err := controlplane.NewObserver(r.sources, controlplane.ObservationInput{
		Generation: r.config.Generation, PreflightRequest: r.config.Preflight, FlannelRequest: r.config.Flannel,
		MarkerRule: r.config.Marker, Pods: r.config.Pods, TCLinks: links,
	})
	if err != nil {
		return reconcile.ReconcileResult{}, nil, err
	}
	backend, err := controlplane.NewFirstPassBackend(controlplane.FirstPassBackendConfig{
		Observer: observer, Control: r.control, Collection: r.collection, Marker: r.marker,
		Base: r.base, Endpoint: r.endpoint, Maps: r.maps, Publisher: r.publisher,
	})
	if err != nil {
		return reconcile.ReconcileResult{}, nil, err
	}
	coordinator, err := reconcile.NewCoordinator(backend)
	if err != nil {
		return reconcile.ReconcileResult{}, nil, err
	}
	result, err := coordinator.FullReconcile(ctx)
	return result, coordinator, err
}

func (r *StaticRuntime) Close() error {
	if r == nil {
		return nil
	}
	var closeErrs []error
	if r.cri != nil {
		if err := r.cri.Close(); err != nil {
			closeErrs = append(closeErrs, err)
		}
		r.cri = nil
	}
	if r.lock != nil {
		if err := r.lock.Close(); err != nil {
			closeErrs = append(closeErrs, err)
		}
		r.lock = nil
	}
	return errors.Join(closeErrs...)
}

type runtimeControl struct {
	pinRoot string
	writer  *datapath.ControlWriter
}

func (c *runtimeControl) Disable(ctx context.Context) error {
	path := filepath.Join(c.pinRoot, "maps", "control_map")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	return c.writer.Disable(ctx)
}

func (c *runtimeControl) Publish(ctx context.Context, generation, heartbeatTimeoutNS uint64, flags uint32) error {
	return c.writer.Publish(ctx, generation, heartbeatTimeoutNS, flags)
}

func (c *runtimeControl) Renew(ctx context.Context, expectedGeneration uint64) error {
	return c.writer.Renew(ctx, expectedGeneration)
}

func (r *StaticRuntime) disableForShutdown() error {
	return disableWithTimeout(r.control.Disable)
}

func acquireRuntimeLock(pinRoot, lockDir string) (*os.File, error) {
	identity := sha256.Sum256([]byte(filepath.Clean(pinRoot)))
	lockPath := filepath.Join(lockDir, fmt.Sprintf("runtime-%x.lock", identity[:12]))
	if err := os.MkdirAll(filepath.Dir(lockPath), 0750); err != nil {
		return nil, fmt.Errorf("create runtime lock directory: %w", err)
	}
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("open runtime lock: %w", err)
	}
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = lock.Close()
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, fmt.Errorf("static runtime is already running")
		}
		return nil, fmt.Errorf("acquire runtime lock: %w", err)
	}
	return lock, nil
}

func disableWithTimeout(disable func(context.Context) error) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	return disable(ctx)
}

func runHeartbeatLease(ctx context.Context, interval time.Duration, renew func(context.Context) error, disable func(context.Context) error) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			if err := disableWithTimeout(disable); err != nil {
				return fmt.Errorf("disable fast path on shutdown: %w", err)
			}
			return nil
		case <-ticker.C:
			if err := renew(ctx); err != nil {
				if ctx.Err() != nil {
					if disableErr := disableWithTimeout(disable); disableErr != nil {
						return fmt.Errorf("disable fast path on shutdown: %w", disableErr)
					}
					return nil
				}
				if disableErr := disableWithTimeout(disable); disableErr != nil {
					return fmt.Errorf("renew heartbeat: %v; disable fast path: %w", err, disableErr)
				}
				return fmt.Errorf("renew heartbeat: %w", err)
			}
		}
	}
}

func heartbeatRenewInterval(timeoutNS uint64) (time.Duration, error) {
	if err := datapath.ValidateHeartbeatTimeoutNS(timeoutNS); err != nil {
		return 0, err
	}
	intervalNS := timeoutNS / 3
	if intervalNS > uint64(1<<63-1) {
		return 0, fmt.Errorf("heartbeat timeout is too large")
	}
	return time.Duration(intervalNS), nil
}

func validateStaticRuntimeConfig(config StaticRuntimeConfig) error {
	if config.ELFPath == "" || !filepath.IsAbs(config.ELFPath) {
		return fmt.Errorf("ELFPath must be an absolute file path")
	}
	if config.PinRoot == "" || !filepath.IsAbs(config.PinRoot) || filepath.Clean(config.PinRoot) == string(filepath.Separator) {
		return fmt.Errorf("PinRoot must be a dedicated absolute directory")
	}
	if config.Preflight.PinRoot != config.PinRoot {
		return fmt.Errorf("preflight PinRoot must match runtime PinRoot")
	}
	if config.StatePath == "" || !filepath.IsAbs(config.StatePath) || filepath.Clean(config.StatePath) == string(filepath.Separator) {
		return fmt.Errorf("StatePath must be a dedicated absolute file")
	}
	if config.Preflight.Node.Name == "" || config.Preflight.Node.UID == "" || config.Preflight.RuntimeURI == "" {
		return fmt.Errorf("node identity and runtime endpoint are required")
	}
	if config.InstallationID == "" || config.ELFBuildID == "" || config.HeartbeatTimeoutNS == 0 {
		return fmt.Errorf("installation, ELF build and heartbeat values are required")
	}
	if _, err := heartbeatRenewInterval(config.HeartbeatTimeoutNS); err != nil {
		return err
	}
	if len(config.TCLinks) == 0 {
		return fmt.Errorf("at least one TC link is required")
	}
	if config.Marker.Chain == "" || config.Marker.Comment == "" {
		return fmt.Errorf("marker identity is required")
	}
	return nil
}

func mergeEndpointLinks(base []resolver.LinkIdentity, endpoints map[string]resolver.Endpoint) []resolver.LinkIdentity {
	result := append([]resolver.LinkIdentity(nil), base...)
	positions := make(map[[2]uint64]int, len(result))
	for index, link := range result {
		key := [2]uint64{link.NetNSInode, uint64(link.IfIndex)}
		if _, ok := positions[key]; !ok {
			positions[key] = index
		}
	}
	uids := make([]string, 0, len(endpoints))
	for uid := range endpoints {
		uids = append(uids, uid)
	}
	sort.Strings(uids)
	for _, uid := range uids {
		endpoint := endpoints[uid]
		for _, link := range []resolver.LinkIdentity{endpoint.PeerLink, endpoint.HostLink} {
			key := [2]uint64{link.NetNSInode, uint64(link.IfIndex)}
			if index, ok := positions[key]; ok {
				result[index] = link
				continue
			}
			positions[key] = len(result)
			result = append(result, link)
		}
	}
	return result
}
