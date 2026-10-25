package agent

import (
	"context"
	"fmt"
	"io"
	"path/filepath"

	"github.com/cat-cc-Lcos/FNCache/internal/controlplane"
	"github.com/cat-cc-Lcos/FNCache/internal/datapath"
	"github.com/cat-cc-Lcos/FNCache/internal/endpoint"
	"github.com/cat-cc-Lcos/FNCache/internal/hostnet/discovery"
	"github.com/cat-cc-Lcos/FNCache/internal/hostnet/flannel"
	"github.com/cat-cc-Lcos/FNCache/internal/ownership"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

type datapathComponentConfig struct {
	ELFPath            string
	PinRoot            string
	StatePath          string
	InstallationID     string
	ELFBuildID         string
	HeartbeatNS        uint64
	HeartbeatTimeoutNS uint64
	Flags              uint32
	MapCapacities      datapath.MapCapacities
	Preflight          discovery.PreflightRequest
	Flannel            flannel.DiscoveryRequest
	Marker             flannel.MarkerRuleSpec
}

type datapathComponents struct {
	cri              io.Closer
	endpointResolver endpoint.EndpointResolver
	endpointScanner  *endpoint.EndpointScanner
	pins             *datapath.PinScanner
	tcScanner        *datapath.TCScanner
	tc               controlplane.EndpointFilterRemover
	mapWriter        controlplane.EndpointMapRemover
	ownership        localOwnershipSource
	sources          controlplane.Sources
	control          localControl
	collection       localCollectionEnsurer
	marker           localMarkerEnsurer
	base             localBaseEnsurer
	endpoint         localEndpointEnsurer
	maps             localMapEnsurer
	deviceMap        localDeviceMapEnsurer
	publisher        *controlplane.Publisher
}

type endpointMapWriter interface {
	controlplane.EndpointMapRemover
	EnsureRemoteMappings(context.Context, reconcile.DesiredState, reconcile.ActualState, bool) (bool, error)
}

type endpointMapWriterAdapter struct {
	writer *datapath.MapWriter
	maps   *controlplane.MapEnsurer
}

func (a *endpointMapWriterAdapter) Delete(ctx context.Context, name string, key []byte) (bool, error) {
	return a.writer.Delete(ctx, name, key)
}

func (a *endpointMapWriterAdapter) Clear(ctx context.Context, name string) (int, error) {
	return a.writer.Clear(ctx, name)
}

func (a *endpointMapWriterAdapter) EnsureRemoteMappings(ctx context.Context, desired reconcile.DesiredState, actual reconcile.ActualState, fastPathDisabled bool) (bool, error) {
	return a.maps.EnsureRemoteMappings(ctx, desired, actual, fastPathDisabled)
}

type localCollectionEnsurer interface {
	EnsureCollection(context.Context, reconcile.DesiredState, reconcile.ActualState) (bool, error)
}

type localMarkerEnsurer interface {
	EnsureMarker(context.Context, reconcile.DesiredState) (bool, error)
}

func (c *datapathComponents) Close() error {
	if c == nil || c.cri == nil {
		return nil
	}
	err := c.cri.Close()
	c.cri = nil
	return err
}

func newDatapathComponents(ctx context.Context, config datapathComponentConfig) (*datapathComponents, error) {
	if err := validateDatapathComponentConfig(config); err != nil {
		return nil, err
	}
	schema := datapath.V1SchemaWithCapacities(config.MapCapacities)
	sandbox, cri, err := endpoint.DialContainerdCRI(ctx, config.Preflight.RuntimeURI)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			_ = cri.Close()
		}
	}()

	netns := datapath.NewNetNSManager()
	endpointResolver, err := endpoint.NewLinuxEndpointResolver(sandbox, func(ctx context.Context, info endpoint.SandboxInfo, fn func(context.Context) error) error {
		return netns.WithNetNS(ctx, datapath.NetNSRef{Path: info.NetNSPath, Inode: info.NetNSInode}, fn)
	})
	if err != nil {
		return nil, err
	}
	endpointScanner, err := endpoint.NewEndpointScanner(endpointResolver)
	if err != nil {
		return nil, err
	}
	pins, err := datapath.NewPinScannerWithSchema(config.PinRoot, schema)
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
	collection, err := controlplane.NewCollectionEnsurerWithSchema(config.ELFPath, config.PinRoot, schema)
	if err != nil {
		return nil, err
	}
	marker, err := controlplane.NewFlannelMarkerEnsurer(flannel.NewMarkerRuleManager(nil), config.Marker)
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
	maps, err := controlplane.NewMapEnsurerWithSchema(mapWriter, schema)
	if err != nil {
		return nil, err
	}
	store, err := ownership.NewStore(config.StatePath)
	if err != nil {
		return nil, err
	}
	publisher, err := controlplane.NewPublisher(store, controlWriter, controlplane.PublishConfig{
		InstallationID: config.InstallationID, NodeUID: config.Preflight.Node.UID, ELFBuildID: config.ELFBuildID,
		Schema:      schema,
		HeartbeatNS: config.HeartbeatNS, HeartbeatTimeoutNS: config.HeartbeatTimeoutNS, Flags: config.Flags,
	})
	if err != nil {
		return nil, err
	}
	components := &datapathComponents{
		cri: cri, endpointResolver: endpointResolver, endpointScanner: endpointScanner, pins: pins, tcScanner: tcScanner, tc: tc, mapWriter: &endpointMapWriterAdapter{writer: mapWriter, maps: maps}, ownership: store,
		sources: controlplane.Sources{Preflight: discovery.NewPreflight(discovery.NewLinuxProbe("/")), Flannel: flannel.NewDiscovery(nil), Endpoints: endpointScanner, Pins: pins, TC: tcScanner, Rules: flannel.NewRuleScanner(nil)},
		control: &runtimeControl{pinRoot: config.PinRoot, writer: controlWriter}, collection: collection, marker: marker,
		base: base, endpoint: endpoint, maps: maps, deviceMap: maps, publisher: publisher,
	}
	ok = true
	return components, nil
}

func validateDatapathComponentConfig(config datapathComponentConfig) error {
	if config.ELFPath == "" || !filepath.IsAbs(config.ELFPath) || config.PinRoot == "" || !filepath.IsAbs(config.PinRoot) || config.StatePath == "" || !filepath.IsAbs(config.StatePath) {
		return fmt.Errorf("datapath paths must be absolute")
	}
	if config.InstallationID == "" || config.ELFBuildID == "" || config.Preflight.Node.Name == "" || config.Preflight.Node.UID == "" || config.Preflight.RuntimeURI == "" {
		return fmt.Errorf("datapath installation, build and node identity are required")
	}
	if config.HeartbeatNS == 0 || config.HeartbeatTimeoutNS == 0 || config.Marker.Chain == "" || config.Marker.Comment == "" {
		return fmt.Errorf("datapath heartbeat and marker identity are required")
	}
	if err := config.MapCapacities.Validate(); err != nil {
		return err
	}
	return nil
}
