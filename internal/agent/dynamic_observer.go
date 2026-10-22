package agent

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"

	"github.com/cat-cc-Lcos/FNCache/internal/config"
	"github.com/cat-cc-Lcos/FNCache/internal/controlplane"
	"github.com/cat-cc-Lcos/FNCache/internal/discovery"
	"github.com/cat-cc-Lcos/FNCache/internal/kube"
	"github.com/cat-cc-Lcos/FNCache/internal/overlay/flannel"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
	"github.com/cat-cc-Lcos/FNCache/internal/resolver"
)

type DynamicObserver struct {
	config         config.AgentConfiguration
	store          *kube.SnapshotStore
	sources        controlplane.Sources
	generation     atomic.Uint64
	linksMu        sync.RWMutex
	knownLinks     []resolver.LinkIdentity
	knownEndpoints map[string]resolver.Endpoint
}

func NewDynamicObserver(cfg config.AgentConfiguration, store *kube.SnapshotStore, sources controlplane.Sources) (*DynamicObserver, error) {
	if store == nil || sources.Preflight == nil || sources.Flannel == nil || sources.Endpoints == nil || sources.Pins == nil || sources.TC == nil || sources.Rules == nil {
		return nil, fmt.Errorf("dynamic observer sources are required")
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &DynamicObserver{config: cfg, store: store, sources: sources, knownEndpoints: make(map[string]resolver.Endpoint)}, nil
}

func (o *DynamicObserver) Desired(ctx context.Context) (reconcile.DesiredState, error) {
	snapshot := o.store.Snapshot()
	observer, err := o.buildObserver(ctx, snapshot)
	if err != nil {
		return reconcile.DesiredState{}, err
	}
	desired, err := observer.Discover(ctx)
	if err != nil {
		return reconcile.DesiredState{}, err
	}
	return kube.BuildDesiredState(snapshot, desired, o.config.NodeName, desired.LocalEndpoints)
}

func (o *DynamicObserver) Discover(ctx context.Context) (reconcile.DesiredState, error) {
	return o.Desired(ctx)
}

func (o *DynamicObserver) Scan(ctx context.Context) (reconcile.ActualState, error) {
	snapshot := o.store.Snapshot()
	observer, err := o.buildObserver(ctx, snapshot)
	if err != nil {
		return reconcile.ActualState{}, err
	}
	return observer.Scan(ctx)
}

func (o *DynamicObserver) buildObserver(ctx context.Context, snapshot kube.Snapshot) (*controlplane.Observer, error) {
	node, ok := snapshot.Nodes[o.config.NodeName]
	if !ok || node.Identity.UID == "" {
		return nil, fmt.Errorf("local Node %q is missing from Snapshot", o.config.NodeName)
	}
	flannelRequest := flannel.DiscoveryRequest{
		VXLANLinkName: o.config.Overlay.VXLANLinkName, UnderlayDevice: o.config.Overlay.Device,
		MissMask: o.config.Markers.MissMask, EstablishedMask: o.config.Markers.EstablishedMask, IPTablesBackend: "iptables-nft",
	}
	flannelConfig, err := o.sources.Flannel.Discover(ctx, flannelRequest)
	if err != nil {
		return nil, fmt.Errorf("discover Flannel for dynamic observer: %w", err)
	}
	if err := flannelConfig.Validate(); err != nil {
		return nil, fmt.Errorf("validate Flannel for dynamic observer: %w", err)
	}
	localPods := localPodsFromSnapshot(snapshot, o.config.NodeName)
	endpoints, err := o.sources.Endpoints.Scan(ctx, localPods)
	if err != nil {
		return nil, fmt.Errorf("scan local endpoints for dynamic observer: %w", err)
	}
	baseLinks := []resolver.LinkIdentity{flannelConfig.UnderlayLink}
	links := o.rememberEndpointScan(baseLinks, localPods, endpoints)
	observer, err := controlplane.NewObserver(o.sources, controlplane.ObservationInput{
		Generation:       o.generation.Add(1),
		PreflightRequest: discovery.PreflightRequest{Node: node.Identity, PinRoot: o.config.PinRoot, StateDir: o.config.StateDir, InstallationID: o.config.InstallationID, ELFBuildID: o.config.Datapath.ELFBuildID, RuntimeURI: o.config.RuntimeEndpoint, Overlay: o.config.Overlay.Type},
		FlannelRequest:   flannelRequest,
		MarkerRule:       flannel.MarkerRuleSpec{Chain: o.config.Markers.Chain, Comment: o.config.Markers.Comment},
		Pods:             localPods, TCLinks: links, BaseTCLinks: baseLinks, EndpointScanSkipped: endpoints.Skipped,
	})
	if err != nil {
		return nil, err
	}
	return observer, nil
}

func (o *DynamicObserver) rememberEndpointScan(baseLinks []resolver.LinkIdentity, localPods []resolver.PodSnapshot, result resolver.EndpointScanResult) []resolver.LinkIdentity {
	current := make(map[string]struct{}, len(localPods))
	for _, pod := range localPods {
		current[pod.Identity.UID] = struct{}{}
	}
	o.linksMu.Lock()
	defer o.linksMu.Unlock()
	if o.knownEndpoints == nil {
		o.knownEndpoints = make(map[string]resolver.Endpoint)
	}
	for uid := range o.knownEndpoints {
		if _, ok := current[uid]; !ok {
			delete(o.knownEndpoints, uid)
		}
	}
	for uid, endpoint := range result.Endpoints {
		o.knownEndpoints[uid] = endpoint
	}
	links := resolver.MergeEndpointLinks(baseLinks, o.knownEndpoints)
	o.knownLinks = append([]resolver.LinkIdentity(nil), links...)
	return links
}

func (o *DynamicObserver) IncrementalScan(ctx context.Context) (reconcile.ActualState, error) {
	if err := ctx.Err(); err != nil {
		return reconcile.ActualState{}, err
	}
	o.linksMu.RLock()
	links := append([]resolver.LinkIdentity(nil), o.knownLinks...)
	o.linksMu.RUnlock()
	if len(links) == 0 {
		return reconcile.ActualState{}, fmt.Errorf("incremental scan has no known links")
	}
	actual, err := o.sources.Pins.Scan(ctx)
	if err != nil {
		return reconcile.ActualState{}, fmt.Errorf("incremental scan BPF pins: %w", err)
	}
	tc, err := o.sources.TC.Scan(ctx, links)
	if err != nil {
		return reconcile.ActualState{}, fmt.Errorf("incremental scan TC: %w", err)
	}
	actual.Attachments = append(actual.Attachments, tc.Attachments...)
	actual.Conflicts = append(actual.Conflicts, tc.Conflicts...)
	if actual.ScannedAt.IsZero() {
		actual.ScannedAt = tc.ScannedAt
	}
	marker := flannel.MarkerRuleSpec{Chain: o.config.Markers.Chain, Comment: o.config.Markers.Comment}
	actual.FlannelRule, err = o.sources.Rules.Scan(ctx, marker)
	if err != nil {
		return reconcile.ActualState{}, fmt.Errorf("incremental scan Flannel rule: %w", err)
	}
	return actual, nil
}

func (o *DynamicObserver) KnownLinks() []resolver.LinkIdentity {
	o.linksMu.RLock()
	defer o.linksMu.RUnlock()
	return append([]resolver.LinkIdentity(nil), o.knownLinks...)
}

func localPodsFromSnapshot(snapshot kube.Snapshot, nodeName string) []resolver.PodSnapshot {
	pods := make([]resolver.PodSnapshot, 0)
	for _, pod := range snapshot.Pods {
		if pod.NodeName == nodeName {
			pods = append(pods, pod)
		}
	}
	sort.Slice(pods, func(i, j int) bool { return pods[i].Identity.UID < pods[j].Identity.UID })
	return pods
}
