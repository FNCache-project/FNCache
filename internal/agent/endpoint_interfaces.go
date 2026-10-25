package agent

import (
	"context"

	"github.com/cat-cc-Lcos/FNCache/internal/controlplane"
	"github.com/cat-cc-Lcos/FNCache/internal/endpoint"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

// These local interfaces keep the runtime composition root independent from
// the endpoint lifecycle package's concrete implementations.
type localControl interface {
	Disable(context.Context) error
}

type localOwnershipSource interface {
	Load(context.Context) (reconcile.OwnershipState, error)
}

type localEndpointRemover interface {
	Remove(context.Context, reconcile.OwnedEndpoint, reconcile.ActualState, reconcile.DesiredState) error
}

type localEndpointEnsurer interface {
	EnsureEndpoint(context.Context, reconcile.DesiredState, reconcile.ActualState, endpoint.Endpoint) (bool, error)
}

type localMapEnsurer interface {
	EnsureEndpointMaps(context.Context, reconcile.DesiredState, reconcile.ActualState, endpoint.Endpoint, bool) (bool, error)
}

type localPublisher interface {
	CommitAndPublish(context.Context, reconcile.DesiredState, reconcile.ActualState) error
}

type localGenerationTransaction interface {
	Execute(context.Context, reconcile.DesiredState, controlplane.GenerationMutator) error
}

type localBaseEnsurer interface {
	EnsureBase(context.Context, reconcile.DesiredState, reconcile.ActualState) (bool, error)
}

type localDeviceMapEnsurer interface {
	EnsureDeviceMap(context.Context, reconcile.DesiredState, reconcile.ActualState, bool) (bool, error)
}
