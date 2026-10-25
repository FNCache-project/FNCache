package lifecycle

import (
	"context"
	"fmt"

	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

type DynamicHandlerRouter struct {
	local  *LocalEndpointHandler
	delete *LocalEndpointDeleteHandler
	remote *RemoteChangeHandler
}

func NewDynamicHandlerRouter(local *LocalEndpointHandler, delete *LocalEndpointDeleteHandler, remote *RemoteChangeHandler) (*DynamicHandlerRouter, error) {
	if local == nil || delete == nil || remote == nil {
		return nil, fmt.Errorf("dynamic handler dependencies are required")
	}
	return &DynamicHandlerRouter{local: local, delete: delete, remote: remote}, nil
}

func (r *DynamicHandlerRouter) Handle(ctx context.Context, key reconcile.ReconcileKey) error {
	switch key.Kind {
	case reconcile.ReconcileLocalEndpoint:
		if err := r.delete.Handle(ctx, key); err != nil {
			return err
		}
		return r.local.Handle(ctx, key)
	case reconcile.ReconcileRemoteEndpoint, reconcile.ReconcileGlobal:
		return r.remote.Handle(ctx, key)
	default:
		return nil
	}
}
