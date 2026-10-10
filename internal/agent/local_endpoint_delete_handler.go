package agent

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/cat-cc-Lcos/FNCache/internal/kube"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
	"github.com/cat-cc-Lcos/FNCache/internal/resolver"
)

type localOwnershipSource interface {
	Load(context.Context) (reconcile.OwnershipState, error)
}

type localEndpointRemover interface {
	Remove(context.Context, reconcile.OwnedEndpoint, reconcile.ActualState, reconcile.DesiredState) error
}

type localEndpointReuseGuard interface {
	Check(context.Context, kube.Snapshot, string, reconcile.OwnedEndpoint) error
}

type LocalEndpointDeleteHandlerConfig struct {
	Store      *kube.SnapshotStore
	Ownership  localOwnershipSource
	LocalNode  string
	Desired    localDesiredSource
	Remover    localEndpointRemover
	ReuseGuard localEndpointReuseGuard
	Generation localGenerationTransaction
}

type LocalEndpointDeleteHandler struct {
	config LocalEndpointDeleteHandlerConfig
}

func NewLocalEndpointDeleteHandler(config LocalEndpointDeleteHandlerConfig) (*LocalEndpointDeleteHandler, error) {
	if config.Store == nil || config.Ownership == nil || config.LocalNode == "" || config.Desired == nil || config.Remover == nil || config.ReuseGuard == nil || config.Generation == nil {
		return nil, fmt.Errorf("local endpoint delete handler dependencies are required")
	}
	return &LocalEndpointDeleteHandler{config: config}, nil
}

func (h *LocalEndpointDeleteHandler) Handle(ctx context.Context, key reconcile.ReconcileKey) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if key.Kind != reconcile.ReconcileLocalEndpoint || key.UID == "" {
		return nil
	}
	snapshot := h.config.Store.Snapshot()
	if pod, ok := snapshot.Pods[key.UID]; ok && !pod.Deleting && pod.NodeName == h.config.LocalNode && !isTerminalPodPhase(pod.Phase) {
		return nil
	}
	state, err := h.config.Ownership.Load(ctx)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("load ownership: %w", err)
	}
	owned, ok := state.Endpoints[key.UID]
	if !ok {
		return nil
	}
	if err := h.config.ReuseGuard.Check(ctx, snapshot, key.UID, owned); err != nil {
		return err
	}
	base, err := h.config.Desired.Desired(ctx)
	if err != nil {
		return fmt.Errorf("read desired state: %w", err)
	}
	resolved := make(map[string]resolver.Endpoint, len(base.LocalEndpoints))
	for uid, endpoint := range base.LocalEndpoints {
		if uid != key.UID {
			resolved[uid] = endpoint
		}
	}
	desired, err := kube.BuildDesiredState(h.config.Store.Snapshot(), base, h.config.LocalNode, resolved)
	if err != nil {
		return fmt.Errorf("build desired state after local endpoint removal: %w", err)
	}
	if err := h.config.Generation.Execute(ctx, desired, func(ctx context.Context, desired reconcile.DesiredState, actual reconcile.ActualState) error {
		snapshot := h.config.Store.Snapshot()
		if err := h.config.ReuseGuard.Check(ctx, snapshot, key.UID, owned); err != nil {
			return err
		}
		return h.config.Remover.Remove(ctx, owned, actual, desired)
	}); err != nil {
		return fmt.Errorf("publish local endpoint removal: %w", err)
	}
	return nil
}
