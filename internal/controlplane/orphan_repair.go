package controlplane

import (
	"context"
	"fmt"

	"github.com/cat-cc-Lcos/FNCache/internal/datapath"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
	"github.com/cat-cc-Lcos/FNCache/internal/resolver"
)

type ownedAttachmentRemover interface {
	RemoveOwnedAttachment(context.Context, reconcile.AttachmentState) error
}

type ownedMarkerRepairer interface {
	RepairOwnedMarker(context.Context, reconcile.OwnedRule) (bool, error)
}

type attachmentIdentity struct {
	netns     uint64
	ifindex   int
	hook      string
	program   string
	priority  uint16
	handle    uint32
	programID uint32
	direct    bool
}

func repairOwnedOrphans(ctx context.Context, state reconcile.OwnershipState, desired reconcile.DesiredState, actual reconcile.ActualState, attachmentTarget, markerTarget any) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	changed := false
	expected := expectedAttachments(desired, actual)
	attachmentRemover, hasAttachmentRemover := attachmentTarget.(ownedAttachmentRemover)
	for _, owned := range state.Attachments {
		if owned.Program != "tc_init_e" && owned.Program != "tc_restore" {
			continue
		}
		if stateProgramID(state, owned.Program) != owned.ProgramID {
			continue
		}
		if _, ok := expected[attachmentKey(owned)]; ok {
			continue
		}
		if !hasExactAttachment(actual.Attachments, owned) {
			continue
		}
		if !hasAttachmentRemover {
			return changed, fmt.Errorf("owned TC orphan repair is unavailable for %s", owned.Program)
		}
		if err := attachmentRemover.RemoveOwnedAttachment(ctx, owned); err != nil {
			return changed, fmt.Errorf("repair owned TC orphan %s/%d: %w", owned.Program, owned.Handle, err)
		}
		changed = true
	}

	if state.FlannelRule.Identity != "" {
		markerRepairer, ok := markerTarget.(ownedMarkerRepairer)
		if !ok {
			return changed, fmt.Errorf("owned marker orphan repair is unavailable")
		}
		markerChanged, err := markerRepairer.RepairOwnedMarker(ctx, state.FlannelRule)
		if err != nil {
			return changed, fmt.Errorf("repair owned marker orphan: %w", err)
		}
		changed = changed || markerChanged
	}
	return changed, nil
}

func expectedAttachments(desired reconcile.DesiredState, actual reconcile.ActualState) map[attachmentIdentity]struct{} {
	expected := make(map[attachmentIdentity]struct{})
	add := func(link resolver.LinkIdentity, program string) {
		state, ok := actual.Programs[program]
		if !ok || state.ID == 0 {
			return
		}
		spec, err := datapath.NewFixedFilter(link, program, state.ID, true)
		if err != nil {
			return
		}
		expected[attachmentKey(reconcile.AttachmentState{Link: spec.Link, Hook: string(spec.Hook), Program: spec.Program, Priority: spec.Priority, Handle: spec.Handle, ProgramID: spec.ProgramID, DirectAction: spec.DirectAction})] = struct{}{}
	}
	add(desired.Flannel.UnderlayLink, "tc_init_e")
	add(desired.Flannel.UnderlayLink, "tc_restore")
	for _, endpoint := range desired.LocalEndpoints {
		add(endpoint.PeerLink, "tc_init_in")
		add(endpoint.HostLink, "tc_masq")
	}
	return expected
}

func stateProgramID(state reconcile.OwnershipState, program string) uint32 {
	programState, ok := state.Programs[program]
	if !ok {
		return 0
	}
	return programState.ID
}

func hasExactAttachment(attachments []reconcile.AttachmentState, wanted reconcile.AttachmentState) bool {
	wantedKey := attachmentKey(wanted)
	for _, attachment := range attachments {
		if attachmentKey(attachment) == wantedKey {
			return true
		}
	}
	return false
}

func attachmentKey(attachment reconcile.AttachmentState) attachmentIdentity {
	return attachmentIdentity{netns: attachment.Link.NetNSInode, ifindex: attachment.Link.IfIndex, hook: attachment.Hook, program: attachment.Program, priority: attachment.Priority, handle: attachment.Handle, programID: attachment.ProgramID, direct: attachment.DirectAction}
}
