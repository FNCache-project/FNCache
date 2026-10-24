package ownership

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
	"github.com/cat-cc-Lcos/FNCache/internal/resolver"
)

func TestStoreCommitLoadRoundTrip(t *testing.T) {
	store, path := testStore(t)
	state := testState()
	if err := store.Commit(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("unexpected state file: info=%v err=%v", info, err)
	}
	data, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(data), `"schemaVersion"`) {
		t.Fatalf("state schema was not written: %s", data)
	}
	loaded, err := store.Load(context.Background())
	if err != nil || loaded.InstallationID != state.InstallationID || loaded.Generation != state.Generation {
		t.Fatalf("unexpected loaded state: state=%+v err=%v", loaded, err)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 1 || entries[0].Name() != "state.json" {
		t.Fatalf("temporary state file was not cleaned up: entries=%v err=%v", entries, err)
	}
}

func TestStoreDoesNotPersistNetNSPath(t *testing.T) {
	store, path := testStore(t)
	state := testState()
	state.Attachments = []reconcile.AttachmentState{{
		Link: resolver.LinkIdentity{NetNSInode: 42, NetNSPath: "/proc/123/ns/net", IfIndex: 10, IfName: "eth0"}, DirectAction: true,
	}}
	if err := store.Commit(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "NetNSPath") || strings.Contains(string(data), "/proc/123/ns/net") {
		t.Fatalf("runtime netns path was persisted: %s", data)
	}
	loaded, err := store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := loaded.Attachments[0].Link.NetNSPath; got != "" {
		t.Fatalf("runtime netns path was restored from ownership state: %q", got)
	}
}

func TestStoreRejectsNonDirectActionAttachment(t *testing.T) {
	store, _ := testStore(t)
	state := testState()
	state.Attachments = []reconcile.AttachmentState{{DirectAction: false}}
	if err := store.Commit(context.Background(), state); err == nil || !strings.Contains(err.Error(), "non-direct-action") {
		t.Fatalf("non-direct-action ownership state was accepted: %v", err)
	}
}

func TestStoreRejectsCorruptAndUnsupportedState(t *testing.T) {
	store, path := testStore(t)
	if err := os.WriteFile(path, []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(context.Background()); !errors.Is(err, ErrStateInvalid) {
		t.Fatal("expected corrupt state error")
	}
	data, _ := json.Marshal(map[string]any{"schemaVersion": 2, "installationID": "i", "nodeUID": "n"})
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(context.Background()); !errors.Is(err, ErrStateInvalid) {
		t.Fatal("expected schema version error")
	}
}

func TestStoreClassifiesMissingAndUnreadableState(t *testing.T) {
	store, _ := testStore(t)
	if _, err := store.Load(context.Background()); !errors.Is(err, ErrStateMissing) || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing state was not classified: %v", err)
	}

	parent := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(parent, []byte("block"), 0600); err != nil {
		t.Fatal(err)
	}
	blocked, err := NewStore(filepath.Join(parent, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := blocked.Load(context.Background()); !errors.Is(err, ErrStateUnreadable) {
		t.Fatalf("unreadable state was not classified: %v", err)
	}
}

func TestStoreCommitFailureIsClassified(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.Mkdir(path, 0750); err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Commit(context.Background(), testState()); !errors.Is(err, ErrStateCommit) {
		t.Fatalf("commit failure was not classified: %v", err)
	}
	if info, err := os.Stat(path); err != nil || !info.IsDir() {
		t.Fatalf("commit failure replaced protected path: info=%v err=%v", info, err)
	}
}

func TestStoreRemoveIsIdempotent(t *testing.T) {
	store, path := testStore(t)
	if err := store.Commit(context.Background(), testState()); err != nil {
		t.Fatal(err)
	}
	if err := store.Remove(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := store.Remove(context.Background()); err != nil {
		t.Fatalf("remove was not idempotent: err=%v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("state file still exists: %v", err)
	}
}

func TestStoreHonorsCanceledContext(t *testing.T) {
	store, _ := testStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := store.Commit(ctx, testState()); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected canceled commit: %v", err)
	}
}

func testStore(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.json")
	store, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	return store, path
}

func testState() reconcile.OwnershipState {
	return reconcile.OwnershipState{SchemaVersion: 1, InstallationID: "install-a", NodeUID: "node-a", Generation: 7, LastCommittedAt: time.Unix(10, 0).UTC()}
}
