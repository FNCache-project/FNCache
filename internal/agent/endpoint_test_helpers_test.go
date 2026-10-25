package agent

import (
	"context"
	"net/netip"

	"github.com/cat-cc-Lcos/FNCache/internal/endpoint"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

type localHandlerResolver struct {
	endpoint endpoint.Endpoint
	events   *[]string
}

func (r *localHandlerResolver) Resolve(context.Context, endpoint.PodSnapshot) (endpoint.Endpoint, error) {
	if r.events != nil {
		*r.events = append(*r.events, "resolve")
	}
	return r.endpoint, nil
}

func (r *localHandlerResolver) Validate(context.Context, endpoint.Endpoint) error { return nil }

func handlerEndpoint(uid string) endpoint.Endpoint {
	return endpoint.Endpoint{
		Pod:  endpoint.PodIdentity{Namespace: "default", Name: "web", UID: uid},
		Node: endpoint.NodeIdentity{Name: "node-a"}, PodIPv4: netip.MustParseAddr("10.42.0.2"), NetNSInode: 42,
		PeerLink: endpoint.LinkIdentity{NetNSInode: 42, IfIndex: 2}, HostLink: endpoint.LinkIdentity{IfIndex: 3},
	}
}

type localHandlerControl struct{ events *[]string }

func (c localHandlerControl) Disable(context.Context) error {
	if c.events != nil {
		*c.events = append(*c.events, "disable")
	}
	return nil
}

type localHandlerEndpoint struct{ events *[]string }

func (e localHandlerEndpoint) EnsureEndpoint(context.Context, reconcile.DesiredState, reconcile.ActualState, endpoint.Endpoint) (bool, error) {
	if e.events != nil {
		*e.events = append(*e.events, "endpoint")
	}
	return true, nil
}

type localHandlerMaps struct{ events *[]string }

func (m localHandlerMaps) EnsureEndpointMaps(context.Context, reconcile.DesiredState, reconcile.ActualState, endpoint.Endpoint, bool) (bool, error) {
	if m.events != nil {
		*m.events = append(*m.events, "maps")
	}
	return true, nil
}

type deleteOwnership struct {
	state reconcile.OwnershipState
}

func (s *deleteOwnership) Load(context.Context) (reconcile.OwnershipState, error) {
	return s.state, nil
}
