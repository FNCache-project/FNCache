package ownership

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

const schemaVersion uint32 = 1

var (
	ErrStateMissing    = errors.New("ownership state is missing")
	ErrStateUnreadable = errors.New("ownership state is unreadable")
	ErrStateInvalid    = errors.New("ownership state is invalid")
	ErrStateCommit     = errors.New("ownership state commit failed")
)

type OwnershipStore interface {
	Load(context.Context) (reconcile.OwnershipState, error)
	Commit(context.Context, reconcile.OwnershipState) error
	Remove(context.Context) error
}

type Store struct{ path string }

func NewStore(path string) (*Store, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) == string(filepath.Separator) {
		return nil, fmt.Errorf("ownership state path must be a dedicated absolute file")
	}
	return &Store{path: filepath.Clean(path)}, nil
}

func (s *Store) Load(ctx context.Context) (reconcile.OwnershipState, error) {
	if err := ctx.Err(); err != nil {
		return reconcile.OwnershipState{}, err
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return reconcile.OwnershipState{}, fmt.Errorf("%w: %w", ErrStateMissing, err)
		}
		return reconcile.OwnershipState{}, fmt.Errorf("%w: %v", ErrStateUnreadable, err)
	}
	var state reconcile.OwnershipState
	if err := json.Unmarshal(data, &state); err != nil {
		return reconcile.OwnershipState{}, fmt.Errorf("%w: decode ownership state: %v", ErrStateInvalid, err)
	}
	if err := validateState(state); err != nil {
		return reconcile.OwnershipState{}, fmt.Errorf("%w: %v", ErrStateInvalid, err)
	}
	return state, nil
}

func (s *Store) Commit(ctx context.Context, state reconcile.OwnershipState) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateState(state); err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("%w: create ownership state directory: %v", ErrStateCommit, err)
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("encode ownership state: %w", err)
	}
	data = append(data, '\n')
	tmp, err := os.CreateTemp(dir, ".state-*.tmp")
	if err != nil {
		return fmt.Errorf("%w: create ownership state temporary file: %v", ErrStateCommit, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("%w: set ownership state permissions: %v", ErrStateCommit, err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("%w: write ownership state: %v", ErrStateCommit, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("%w: sync ownership state: %v", ErrStateCommit, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("%w: close ownership state: %v", ErrStateCommit, err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		return fmt.Errorf("%w: replace ownership state: %v", ErrStateCommit, err)
	}
	if err := syncDirectory(dir); err != nil {
		return fmt.Errorf("%w: %v", ErrStateCommit, err)
	}
	return nil
}

func (s *Store) Remove(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	err := os.Remove(s.path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("remove ownership state: %w", err)
	}
	return syncDirectory(filepath.Dir(s.path))
}

func validateState(state reconcile.OwnershipState) error {
	if state.SchemaVersion != schemaVersion {
		return fmt.Errorf("unsupported ownership schema version: %d", state.SchemaVersion)
	}
	if state.InstallationID == "" || state.NodeUID == "" {
		return fmt.Errorf("ownership state installationID and nodeUID are required")
	}
	for _, attachment := range state.Attachments {
		if !attachment.DirectAction {
			return fmt.Errorf("ownership state contains a non-direct-action TC attachment")
		}
	}
	return nil
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open ownership state directory: %w", err)
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("sync ownership state directory: %w", err)
	}
	return nil
}
