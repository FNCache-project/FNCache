package agent

import (
	"context"
	"fmt"
	"sync"

	"github.com/cat-cc-Lcos/FNCache/internal/kubernetes"
)

type KubeBootstrapState string

const (
	KubeBootstrapBootstrapping KubeBootstrapState = "Bootstrapping"
	KubeBootstrapReady         KubeBootstrapState = "Ready"
	KubeBootstrapDisabled      KubeBootstrapState = "Disabled"
)

// KubeBootstrap gates Snapshot reads until both Kubernetes informers sync.
type KubeBootstrap struct {
	source *kubernetes.InformerSource
	store  *kubernetes.SnapshotStore

	mu      sync.RWMutex
	state   KubeBootstrapState
	started bool
}

func NewKubeBootstrap(source *kubernetes.InformerSource, store *kubernetes.SnapshotStore) (*KubeBootstrap, error) {
	if source == nil || store == nil {
		return nil, fmt.Errorf("informer source and snapshot store are required")
	}
	return &KubeBootstrap{source: source, store: store, state: KubeBootstrapBootstrapping}, nil
}

func (b *KubeBootstrap) Start(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("bootstrap context is required")
	}
	b.mu.Lock()
	if b.started {
		b.mu.Unlock()
		return fmt.Errorf("kubernetes bootstrap already started")
	}
	b.started = true
	b.mu.Unlock()

	go b.source.Run(ctx)
	if err := b.source.WaitForSync(ctx); err != nil {
		b.setState(KubeBootstrapDisabled)
		return err
	}
	b.setState(KubeBootstrapReady)
	return nil
}

func (b *KubeBootstrap) State() KubeBootstrapState {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.state
}

func (b *KubeBootstrap) Snapshot() (kubernetes.Snapshot, error) {
	if b.State() != KubeBootstrapReady {
		return kubernetes.Snapshot{}, fmt.Errorf("kubernetes snapshot is not ready: %s", b.State())
	}
	return b.store.Snapshot(), nil
}

func (b *KubeBootstrap) setState(state KubeBootstrapState) {
	b.mu.Lock()
	b.state = state
	b.mu.Unlock()
}
