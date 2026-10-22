package agent

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/cat-cc-Lcos/FNCache/internal/controlplane"
	"github.com/cat-cc-Lcos/FNCache/internal/datapath"
	"github.com/cat-cc-Lcos/FNCache/internal/discovery"
	"github.com/cat-cc-Lcos/FNCache/internal/overlay/flannel"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
	"github.com/cat-cc-Lcos/FNCache/internal/resolver"
)

type StaticRuntimeConfig struct {
	ELFPath            string
	PinRoot            string
	StatePath          string
	InstallationID     string
	ELFBuildID         string
	Generation         uint64
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
	endpointScanner *resolver.EndpointScanner
	pins            *datapath.PinScanner
	tcScanner       *datapath.TCScanner
	sources         controlplane.Sources
	control         localControl
	collection      localCollectionEnsurer
	marker          localMarkerEnsurer
	base            localBaseEnsurer
	endpoint        localEndpointEnsurer
	maps            localMapEnsurer
	ownership       localOwnershipSource
	remover         *controlplane.EndpointRemover
	publisher       *controlplane.Publisher
}

func NewStaticRuntime(ctx context.Context, config StaticRuntimeConfig) (*StaticRuntime, error) {
	config.Preflight.InstallationID = config.InstallationID
	config.Preflight.ELFBuildID = config.ELFBuildID
	if err := validateStaticRuntimeConfig(config); err != nil {
		return nil, err
	}
	components, err := newDatapathComponents(ctx, datapathComponentConfig{
		ELFPath: config.ELFPath, PinRoot: config.PinRoot, StatePath: config.StatePath, InstallationID: config.InstallationID,
		ELFBuildID: config.ELFBuildID, HeartbeatNS: config.HeartbeatNS, HeartbeatTimeoutNS: config.HeartbeatTimeoutNS,
		Flags: config.Flags, MapCapacities: datapath.DefaultMapCapacities(), Preflight: config.Preflight, Flannel: config.Flannel, Marker: config.Marker,
	})
	if err != nil {
		return nil, err
	}
	remover, err := controlplane.NewEndpointRemover(components.mapWriter, components.tc)
	if err != nil {
		_ = components.Close()
		return nil, err
	}
	runtime := &StaticRuntime{
		config: config, cri: components.cri, endpointScanner: components.endpointScanner, pins: components.pins, tcScanner: components.tcScanner,
		sources: components.sources, control: components.control, collection: components.collection, marker: components.marker,
		base: components.base, endpoint: components.endpoint, maps: components.maps, ownership: components.ownership, remover: remover, publisher: components.publisher,
	}
	return runtime, nil
}

func (r *StaticRuntime) RunOnce(ctx context.Context) (reconcile.ReconcileResult, error) {
	if err := ctx.Err(); err != nil {
		return reconcile.ReconcileResult{}, err
	}
	endpoints, err := r.endpointScanner.Scan(ctx, r.config.Pods)
	if err != nil {
		return reconcile.ReconcileResult{}, fmt.Errorf("prepare endpoint links: %w", err)
	}
	links := resolver.MergeEndpointLinks(r.config.TCLinks, endpoints.Endpoints)
	observer, err := controlplane.NewObserver(r.sources, controlplane.ObservationInput{
		Generation: r.config.Generation, PreflightRequest: r.config.Preflight, FlannelRequest: r.config.Flannel,
		MarkerRule: r.config.Marker, Pods: r.config.Pods, TCLinks: links, BaseTCLinks: r.config.TCLinks,
	})
	if err != nil {
		return reconcile.ReconcileResult{}, err
	}
	backend, err := controlplane.NewFirstPassBackend(controlplane.FirstPassBackendConfig{
		Observer: observer, Control: r.control, Collection: r.collection, Marker: r.marker,
		Base: r.base, Endpoint: r.endpoint, Maps: r.maps, Ownership: r.ownership, Remover: r.remover, Publisher: r.publisher,
	})
	if err != nil {
		return reconcile.ReconcileResult{}, err
	}
	coordinator, err := reconcile.NewCoordinator(backend)
	if err != nil {
		return reconcile.ReconcileResult{}, err
	}
	return coordinator.FullReconcile(ctx)
}

func (r *StaticRuntime) Close() error {
	if r == nil || r.cri == nil {
		return nil
	}
	err := r.cri.Close()
	r.cri = nil
	return err
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

func (c *runtimeControl) Publish(ctx context.Context, generation, heartbeatNS, heartbeatTimeoutNS uint64, flags uint32, vxlanVNI uint32, vxlanUDPPort uint16) error {
	return c.writer.Publish(ctx, generation, heartbeatNS, heartbeatTimeoutNS, flags, vxlanVNI, vxlanUDPPort)
}

func (c *runtimeControl) RefreshHeartbeat(ctx context.Context, heartbeatNS uint64) error {
	return c.writer.RefreshHeartbeat(ctx, heartbeatNS)
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
	if config.Preflight.StateDir == "" || !filepath.IsAbs(config.Preflight.StateDir) || filepath.Clean(config.Preflight.StateDir) == string(filepath.Separator) {
		return fmt.Errorf("preflight StateDir must be a dedicated absolute directory")
	}
	if filepath.Clean(config.StatePath) != filepath.Join(filepath.Clean(config.Preflight.StateDir), "state.json") {
		return fmt.Errorf("preflight StateDir must match StatePath")
	}
	if config.Preflight.Node.Name == "" || config.Preflight.Node.UID == "" || config.Preflight.RuntimeURI == "" {
		return fmt.Errorf("node identity and runtime endpoint are required")
	}
	if config.InstallationID == "" || config.ELFBuildID == "" || config.HeartbeatNS == 0 || config.HeartbeatTimeoutNS == 0 {
		return fmt.Errorf("installation, ELF build and heartbeat values are required")
	}
	if len(config.TCLinks) == 0 {
		return fmt.Errorf("at least one TC link is required")
	}
	if config.Marker.Chain == "" || config.Marker.Comment == "" {
		return fmt.Errorf("marker identity is required")
	}
	return nil
}
