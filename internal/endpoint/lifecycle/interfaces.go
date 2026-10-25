package lifecycle

import (
	"context"

	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

type BaseEnsurer interface {
	EnsureBase(context.Context, reconcile.DesiredState, reconcile.ActualState) (bool, error)
}
