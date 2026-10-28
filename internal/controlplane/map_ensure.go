package controlplane

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"sort"

	"github.com/cat-cc-Lcos/FNCache/internal/datapath"
	"github.com/cat-cc-Lcos/FNCache/internal/endpoint"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

type MapStore interface {
	Ensure(context.Context, string, []byte, []byte) (bool, error)
}

type MapEnsurer struct {
	store  MapStore
	schema datapath.CollectionSchema
}

func NewMapEnsurer(store MapStore) (*MapEnsurer, error) {
	return NewMapEnsurerWithSchema(store, datapath.V1Schema())
}

func NewMapEnsurerWithSchema(store MapStore, schema datapath.CollectionSchema) (*MapEnsurer, error) {
	if store == nil {
		return nil, fmt.Errorf("Map store is required")
	}
	return &MapEnsurer{store: store, schema: schema}, nil
}

func (e *MapEnsurer) EnsureEndpointMaps(ctx context.Context, desired reconcile.DesiredState, actual reconcile.ActualState, endpoint endpoint.Endpoint, fastPathDisabled bool) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if !desired.Enabled {
		return false, nil
	}
	if !fastPathDisabled || !actual.Control.Verified || actual.Control.Enabled {
		return false, fmt.Errorf("refusing Map update while fast path is enabled or unverified")
	}
	expected, ok := desired.LocalEndpoints[endpoint.Pod.UID]
	if !ok || !sameEndpointIdentity(expected, endpoint) {
		return false, fmt.Errorf("endpoint is not the current desired identity: %s", endpoint.Pod.UID)
	}
	if err := endpoint.Validate(); err != nil {
		return false, fmt.Errorf("validate endpoint: %w", err)
	}
	if err := validateMapState(actual, e.schema, "ingress_cache"); err != nil {
		return false, err
	}
	if len(endpoint.PeerLink.MAC) != 6 || len(endpoint.HostLink.MAC) != 6 {
		return false, fmt.Errorf("endpoint MAC identity must contain 6 bytes")
	}
	if err := validateDeviceMapInput(desired, actual, e.schema); err != nil {
		return false, err
	}

	ingressKey, ingressValue := encodeIngressEntry(endpoint)
	changed, err := e.store.Ensure(ctx, "ingress_cache", ingressKey, ingressValue)
	if err != nil {
		return changed, fmt.Errorf("ensure ingress_cache: %w", err)
	}
	deviceChanged, err := e.ensureDeviceMap(ctx, desired)
	if err != nil {
		return changed || deviceChanged, fmt.Errorf("ensure devmap: %w", err)
	}
	return changed || deviceChanged, nil
}

func (e *MapEnsurer) EnsureDeviceMap(ctx context.Context, desired reconcile.DesiredState, actual reconcile.ActualState, fastPathDisabled bool) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if !desired.Enabled {
		return false, nil
	}
	if !fastPathDisabled || !actual.Control.Verified || actual.Control.Enabled {
		return false, fmt.Errorf("refusing Map update while fast path is enabled or unverified")
	}
	if err := validateDeviceMapInput(desired, actual, e.schema); err != nil {
		return false, err
	}
	return e.ensureDeviceMap(ctx, desired)
}

func (e *MapEnsurer) ensureDeviceMap(ctx context.Context, desired reconcile.DesiredState) (bool, error) {
	devKey, devValue := encodeDeviceEntry(desired.Flannel.UnderlayLink, desired.Flannel.UnderlayIPv4)
	changed, err := e.store.Ensure(ctx, "devmap", devKey, devValue)
	if err != nil {
		return changed, fmt.Errorf("ensure devmap: %w", err)
	}
	return changed, nil
}

func (e *MapEnsurer) EnsureRemoteMappings(ctx context.Context, desired reconcile.DesiredState, actual reconcile.ActualState, fastPathDisabled bool) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if !desired.Enabled {
		return false, nil
	}
	if !fastPathDisabled || !actual.Control.Verified || actual.Control.Enabled {
		return false, fmt.Errorf("refusing remote Map update while fast path is enabled or unverified")
	}
	if err := validateMapState(actual, e.schema, "egressip_cache"); err != nil {
		return false, err
	}
	addresses := make([]netip.Addr, 0, len(desired.RemoteEndpoints))
	for podIP := range desired.RemoteEndpoints {
		addresses = append(addresses, podIP)
	}
	sort.Slice(addresses, func(i, j int) bool { return addresses[i].Less(addresses[j]) })
	changed := false
	for _, podIP := range addresses {
		mapping := desired.RemoteEndpoints[podIP]
		if !podIP.Is4() || !mapping.NodeIPv4.IsValid() || !mapping.NodeIPv4.Is4() {
			return changed, fmt.Errorf("remote mapping must use IPv4: pod=%s node=%s", podIP, mapping.NodeIPv4)
		}
		podKey := podIP.As4()
		nodeValue := mapping.NodeIPv4.As4()
		updated, err := e.store.Ensure(ctx, "egressip_cache", podKey[:], nodeValue[:])
		if err != nil {
			return changed || updated, fmt.Errorf("ensure egressip_cache for %s: %w", podIP, err)
		}
		changed = changed || updated
	}
	return changed, nil
}

func validateMapState(actual reconcile.ActualState, schema datapath.CollectionSchema, name string) error {
	state, ok := actual.Maps[name]
	if !ok {
		return fmt.Errorf("required Map is unavailable: %s", name)
	}
	expected, ok := mapSchema(schema, name)
	if !ok {
		return fmt.Errorf("required Map schema is unavailable: %s", name)
	}
	if state.KeySize != expected.KeySize || state.ValueSize != expected.ValueSize || state.MaxEntries != expected.MaxEntries {
		return fmt.Errorf("Map schema mismatch for %s: got key=%d value=%d max=%d want key=%d value=%d max=%d", name, state.KeySize, state.ValueSize, state.MaxEntries, expected.KeySize, expected.ValueSize, expected.MaxEntries)
	}
	return nil
}

func validateDeviceMapInput(desired reconcile.DesiredState, actual reconcile.ActualState, schema datapath.CollectionSchema) error {
	if err := validateMapState(actual, schema, "devmap"); err != nil {
		return err
	}
	if desired.Flannel.UnderlayLink.IfIndex <= 0 || len(desired.Flannel.UnderlayLink.MAC) != 6 ||
		!desired.Flannel.UnderlayIPv4.IsValid() || !desired.Flannel.UnderlayIPv4.Is4() {
		return fmt.Errorf("underlay device identity is incomplete")
	}
	return nil
}

func mapSchema(schema datapath.CollectionSchema, name string) (datapath.MapSchema, bool) {
	for _, expected := range schema.Maps {
		if expected.Name == name {
			return expected, true
		}
	}
	return datapath.MapSchema{}, false
}

func encodeIngressEntry(endpoint endpoint.Endpoint) ([]byte, []byte) {
	key := endpoint.PodIPv4.As4()
	value := make([]byte, 16)
	binary.NativeEndian.PutUint32(value[:4], uint32(endpoint.HostLink.IfIndex))
	copy(value[4:10], endpoint.PeerLink.MAC)
	copy(value[10:16], endpoint.HostLink.MAC)
	return key[:], value
}

func encodeDeviceEntry(link endpoint.LinkIdentity, ip netip.Addr) ([]byte, []byte) {
	key := make([]byte, 4)
	binary.NativeEndian.PutUint32(key, uint32(link.IfIndex))
	value := make([]byte, 12)
	ipv4 := ip.As4()
	copy(value[:4], ipv4[:])
	copy(value[4:10], link.MAC)
	return key, value
}
