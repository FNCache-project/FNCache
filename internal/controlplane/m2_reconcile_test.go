package controlplane

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/cat-cc-Lcos/FNCache/internal/datapath"
	"github.com/cat-cc-Lcos/FNCache/internal/discovery"
	"github.com/cat-cc-Lcos/FNCache/internal/ownership"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

func TestM2BaseEnsureIsIdempotentAcrossScans(t *testing.T) {
	backend := &fakeBaseTCBackend{}
	tc, err := datapath.NewTCManager(backend)
	if err != nil {
		t.Fatal(err)
	}
	ensurer, err := NewBaseEnsurer(tc)
	if err != nil {
		t.Fatal(err)
	}
	desired := baseDesiredState()
	actual := baseActualState()
	changed, err := ensurer.EnsureBase(context.Background(), desired, actual)
	if err != nil || !changed || len(backend.attached) != 2 {
		t.Fatalf("unexpected first ensure: changed=%v attached=%d err=%v", changed, len(backend.attached), err)
	}
	actual.Attachments = attachmentsFromFilters(backend.filters)
	changed, err = ensurer.EnsureBase(context.Background(), desired, actual)
	if err != nil || changed || len(backend.attached) != 2 {
		t.Fatalf("second ensure was not idempotent: changed=%v attached=%d err=%v", changed, len(backend.attached), err)
	}
}

func TestM2OwnershipSurvivesPublisherRestart(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "state.json")
	store, err := ownership.NewStore(statePath)
	if err != nil {
		t.Fatal(err)
	}
	events := []string{}
	control := &fakeControlPublisher{events: &events}
	publisher, err := NewPublisher(store, control, publishTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	desired := publishTestDesired()
	if err := publisher.CommitAndPublish(context.Background(), desired, publishTestActual(desired)); err != nil {
		t.Fatal(err)
	}
	restartedStore, err := ownership.NewStore(statePath)
	if err != nil {
		t.Fatal(err)
	}
	state, err := restartedStore.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if state.Generation != desired.Generation || state.InstallationID != "install-a" || state.NodeUID != "node-a" ||
		state.ABI != reconcile.BPFABIVersion || len(state.Programs) != 4 || len(state.Maps) != len(datapath.V1Schema().Maps) || len(state.Endpoints) != 1 {
		t.Fatalf("ownership state did not survive restart: %+v", state)
	}
	for _, attachment := range state.Attachments {
		if !attachment.DirectAction {
			t.Fatalf("ownership state lost direct-action evidence: %+v", state.Attachments)
		}
	}
}

func TestM2ConflictPreventsCommitAndPublish(t *testing.T) {
	desired := publishTestDesired()
	actual := publishTestActual(desired)
	actual.Conflicts = []discovery.Conflict{{Kind: "tc-filter", Identity: "foreign"}}
	events := []string{}
	store := &fakeOwnershipCommitter{events: &events}
	control := &fakeControlPublisher{events: &events}
	publisher, _ := NewPublisher(store, control, publishTestConfig())
	if err := publisher.CommitAndPublish(context.Background(), desired, actual); err == nil || len(events) != 0 {
		t.Fatalf("conflict was not fail-closed: err=%v events=%v", err, events)
	}
}

func attachmentsFromFilters(filters []datapath.TCFilterState) []reconcile.AttachmentState {
	attachments := make([]reconcile.AttachmentState, 0, len(filters))
	for _, filter := range filters {
		attachments = append(attachments, reconcile.AttachmentState{Link: filter.Link, Hook: string(filter.Hook), Program: filter.Program, Priority: filter.Priority, Handle: filter.Handle, ProgramID: filter.ProgramID, DirectAction: filter.DirectAction})
	}
	return attachments
}
