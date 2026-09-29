package controlplane

import (
	"context"
	"fmt"
	"sort"

	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
	"github.com/cat-cc-Lcos/FNCache/internal/resolver"
)

type observationBackend interface {
	Discover(context.Context) (reconcile.DesiredState, error)
	Scan(context.Context) (reconcile.ActualState, error)
}

type collectionEnsurer interface {
	EnsureCollection(context.Context, reconcile.DesiredState, reconcile.ActualState) (bool, error)
}

type markerEnsurer interface {
	EnsureMarker(context.Context, reconcile.DesiredState) (bool, error)
}

type baseEnsurer interface {
	EnsureBase(context.Context, reconcile.DesiredState, reconcile.ActualState) (bool, error)
}

type endpointEnsurer interface {
	EnsureEndpoint(context.Context, reconcile.DesiredState, reconcile.ActualState, resolver.Endpoint) (bool, error)
}

type endpointMapEnsurer interface {
	EnsureEndpointMaps(context.Context, reconcile.DesiredState, reconcile.ActualState, resolver.Endpoint, bool) (bool, error)
}

type fastPathDisabler interface {
	Disable(context.Context) error
}

type FirstPassBackendConfig struct {
	Observer   observationBackend
	Control    fastPathDisabler
	Collection collectionEnsurer
	Marker     markerEnsurer
	Base       baseEnsurer
	Endpoint   endpointEnsurer
	Maps       endpointMapEnsurer
	Publisher  *Publisher
}

// FirstPassBackend is the one-shot M2 coordination adapter. It deliberately
// has no event loop; callers trigger FullReconcile when needed.
type FirstPassBackend struct {
	observer   observationBackend
	control    fastPathDisabler
	collection collectionEnsurer
	marker     markerEnsurer
	base       baseEnsurer
	endpoint   endpointEnsurer
	maps       endpointMapEnsurer
	publisher  *Publisher
}

func NewFirstPassBackend(config FirstPassBackendConfig) (*FirstPassBackend, error) {
	missing := make([]string, 0, 8)
	if config.Observer == nil {
		missing = append(missing, "observer")
	}
	if config.Control == nil {
		missing = append(missing, "control")
	}
	if config.Collection == nil {
		missing = append(missing, "collection")
	}
	if config.Marker == nil {
		missing = append(missing, "marker")
	}
	if config.Base == nil {
		missing = append(missing, "base")
	}
	if config.Endpoint == nil {
		missing = append(missing, "endpoint")
	}
	if config.Maps == nil {
		missing = append(missing, "maps")
	}
	if config.Publisher == nil {
		missing = append(missing, "publisher")
	}
	if len(missing) != 0 {
		return nil, fmt.Errorf("first-pass backend dependencies are required: %v", missing)
	}
	return &FirstPassBackend{
		observer: config.Observer, control: config.Control, collection: config.Collection,
		marker: config.Marker, base: config.Base, endpoint: config.Endpoint,
		maps: config.Maps, publisher: config.Publisher,
	}, nil
}

func (b *FirstPassBackend) Disable(ctx context.Context) error {
	return b.control.Disable(ctx)
}

func (b *FirstPassBackend) Discover(ctx context.Context) (reconcile.DesiredState, error) {
	return b.observer.Discover(ctx)
}

func (b *FirstPassBackend) Scan(ctx context.Context) (reconcile.ActualState, error) {
	return b.observer.Scan(ctx)
}

func (b *FirstPassBackend) Ensure(ctx context.Context, desired reconcile.DesiredState, actual reconcile.ActualState) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if !desired.Enabled {
		return false, nil
	}
	changed, err := b.collection.EnsureCollection(ctx, desired, actual)
	if err != nil {
		return changed, fmt.Errorf("ensure collection: %w", err)
	}
	markerChanged, err := b.marker.EnsureMarker(ctx, desired)
	if err != nil {
		return changed || markerChanged, fmt.Errorf("ensure Flannel marker: %w", err)
	}
	changed = changed || markerChanged
	current, err := b.observer.Scan(ctx)
	if err != nil {
		return changed, fmt.Errorf("rescan after collection ensure: %w", err)
	}
	baseChanged, err := b.base.EnsureBase(ctx, desired, current)
	if err != nil {
		return changed || baseChanged, fmt.Errorf("ensure base: %w", err)
	}
	changed = changed || baseChanged
	uids := make([]string, 0, len(desired.LocalEndpoints))
	for uid := range desired.LocalEndpoints {
		uids = append(uids, uid)
	}
	sort.Strings(uids)
	for _, uid := range uids {
		endpoint := desired.LocalEndpoints[uid]
		endpointChanged, err := b.endpoint.EnsureEndpoint(ctx, desired, current, endpoint)
		if err != nil {
			return changed || endpointChanged, fmt.Errorf("ensure endpoint %s: %w", uid, err)
		}
		changed = changed || endpointChanged
		mapChanged, err := b.maps.EnsureEndpointMaps(ctx, desired, current, endpoint, true)
		if err != nil {
			return changed || mapChanged, fmt.Errorf("ensure endpoint Maps %s: %w", uid, err)
		}
		changed = changed || mapChanged
	}
	return changed, nil
}

func (b *FirstPassBackend) Verify(ctx context.Context, desired reconcile.DesiredState, _ reconcile.ActualState) error {
	actual, err := b.observer.Scan(ctx)
	if err != nil {
		return fmt.Errorf("verify scan: %w", err)
	}
	return VerifyState(desired, actual)
}

func (b *FirstPassBackend) Commit(ctx context.Context, desired reconcile.DesiredState, _ reconcile.ActualState) error {
	actual, err := b.observer.Scan(ctx)
	if err != nil {
		return fmt.Errorf("commit scan: %w", err)
	}
	if err := VerifyState(desired, actual); err != nil {
		return err
	}
	if err := b.publisher.store.Commit(ctx, b.publisher.ownershipState(desired, actual)); err != nil {
		return fmt.Errorf("commit ownership: %w", err)
	}
	return nil
}

func (b *FirstPassBackend) Publish(ctx context.Context, desired reconcile.DesiredState) error {
	config := b.publisher.config
	return b.publisher.control.Publish(ctx, desired.Generation, config.HeartbeatTimeoutNS, config.Flags)
}
