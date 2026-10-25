package controlplane

import (
	"context"
	"testing"

	"github.com/cat-cc-Lcos/FNCache/internal/datapath"
	"github.com/cat-cc-Lcos/FNCache/internal/endpoint"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

type fakeOwnedAttachmentRemover struct {
	attachments []reconcile.AttachmentState
}

func (r *fakeOwnedAttachmentRemover) RemoveOwnedAttachment(_ context.Context, attachment reconcile.AttachmentState) error {
	r.attachments = append(r.attachments, attachment)
	return nil
}

type fakeOwnedMarkerRepairer struct {
	calls int
}

func (r *fakeOwnedMarkerRepairer) RepairOwnedMarker(_ context.Context, _ reconcile.OwnedRule) (bool, error) {
	r.calls++
	return true, nil
}

func TestRepairOwnedOrphansRemovesOnlyStaleOwnedBaseAttachments(t *testing.T) {
	desired := publishTestDesired()
	actual := publishTestActual(desired)
	stale := reconcile.AttachmentState{Link: endpoint.LinkIdentity{IfIndex: 3}, Hook: string(datapath.HookEgress), Program: "tc_init_e", Priority: datapath.FixedTCPriority, Handle: 0x100, ProgramID: 10, DirectAction: true}
	foreign := stale
	foreign.Link.IfIndex = 4
	foreign.ProgramID = 99
	actual.Attachments = append(actual.Attachments, stale, foreign)
	state := reconcile.OwnershipState{
		Programs:    map[string]reconcile.ProgramState{"tc_init_e": {ID: 10}, "tc_restore": {ID: 11}},
		Attachments: []reconcile.AttachmentState{stale, foreign},
	}
	remover := &fakeOwnedAttachmentRemover{}
	marker := &fakeOwnedMarkerRepairer{}
	changed, err := repairOwnedOrphans(context.Background(), state, desired, actual, remover, marker)
	if err != nil || !changed || len(remover.attachments) != 1 || remover.attachments[0].Link.IfIndex != 3 || marker.calls != 0 {
		t.Fatalf("unexpected orphan repair: changed=%v err=%v attachments=%+v markerCalls=%d", changed, err, remover.attachments, marker.calls)
	}
}

func TestRepairOwnedOrphansRepairsStaleMarker(t *testing.T) {
	desired := publishTestDesired()
	actual := publishTestActual(desired)
	state := reconcile.OwnershipState{FlannelRule: reconcile.OwnedRule{Identity: "OLD/oncache:install-a", Fingerprint: "old-fingerprint"}}
	remover := &fakeOwnedAttachmentRemover{}
	marker := &fakeOwnedMarkerRepairer{}
	changed, err := repairOwnedOrphans(context.Background(), state, desired, actual, remover, marker)
	if err != nil || !changed || marker.calls != 1 || len(remover.attachments) != 0 {
		t.Fatalf("stale marker was not repaired: changed=%v err=%v markerCalls=%d attachments=%v", changed, err, marker.calls, remover.attachments)
	}
}

func TestRepairOwnedOrphansLeavesUnprovenObjectsUntouched(t *testing.T) {
	desired := publishTestDesired()
	actual := publishTestActual(desired)
	actual.Orphans = []reconcile.OwnedObject{{Kind: "map-pin", Identity: "/sys/fs/bpf/oncache/v1/maps/foreign"}}
	state := reconcile.OwnershipState{}
	remover := &fakeOwnedAttachmentRemover{}
	marker := &fakeOwnedMarkerRepairer{}
	changed, err := repairOwnedOrphans(context.Background(), state, desired, actual, remover, marker)
	if err != nil || changed || len(remover.attachments) != 0 || marker.calls != 0 {
		t.Fatalf("unproven object was modified: changed=%v err=%v attachments=%v markerCalls=%d", changed, err, remover.attachments, marker.calls)
	}
}
