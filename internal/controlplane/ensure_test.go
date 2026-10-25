package controlplane

import (
	"context"
	"errors"
	"testing"

	"github.com/cat-cc-Lcos/FNCache/internal/datapath"
	"github.com/cat-cc-Lcos/FNCache/internal/endpoint"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

type fakeBaseTCBackend struct {
	filters  []datapath.TCFilterState
	attached []datapath.TCFilterSpec
}

func (f *fakeBaseTCBackend) EnsureClsact(ctx context.Context, link endpoint.LinkIdentity) (datapath.TCQdiscState, error) {
	if err := ctx.Err(); err != nil {
		return datapath.TCQdiscState{}, err
	}
	return datapath.TCQdiscState{Link: link, Exists: true}, nil
}

func (f *fakeBaseTCBackend) ListFilters(ctx context.Context, link endpoint.LinkIdentity) ([]datapath.TCFilterState, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	result := make([]datapath.TCFilterState, 0, len(f.filters))
	for _, filter := range f.filters {
		if filter.Link.IfIndex == link.IfIndex && filter.Link.NetNSInode == link.NetNSInode {
			result = append(result, filter)
		}
	}
	return result, nil
}

func (f *fakeBaseTCBackend) AttachFilter(ctx context.Context, spec datapath.TCFilterSpec) (datapath.TCFilterState, error) {
	if err := ctx.Err(); err != nil {
		return datapath.TCFilterState{}, err
	}
	f.attached = append(f.attached, spec)
	state := datapath.TCFilterState{Link: spec.Link, Hook: spec.Hook, Program: spec.Program, ProgramID: spec.ProgramID, Priority: spec.Priority, Handle: spec.Handle, DirectAction: spec.DirectAction}
	f.filters = append(f.filters, state)
	return state, nil
}

func (f *fakeBaseTCBackend) RemoveFilter(context.Context, datapath.TCFilterSpec) error { return nil }

func TestBaseEnsurerAttachesUnderlayPrograms(t *testing.T) {
	backend := &fakeBaseTCBackend{}
	tc, err := datapath.NewTCManager(backend)
	if err != nil {
		t.Fatal(err)
	}
	ensurer, err := NewBaseEnsurer(tc)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := ensurer.EnsureBase(context.Background(), baseDesiredState(), baseActualState())
	if err != nil || !changed || len(backend.attached) != 2 {
		t.Fatalf("unexpected base ensure: changed=%v attached=%+v err=%v", changed, backend.attached, err)
	}
	if backend.attached[0].Program != "tc_init_e" || backend.attached[0].Hook != datapath.HookEgress || backend.attached[0].Handle != 0x100 ||
		backend.attached[1].Program != "tc_restore" || backend.attached[1].Hook != datapath.HookIngress || backend.attached[1].Handle != 0x101 {
		t.Fatalf("unexpected fixed attachments: %+v", backend.attached)
	}
}

func TestBaseEnsurerReusesExistingAttachments(t *testing.T) {
	actual := baseActualState()
	link := baseDesiredState().Flannel.UnderlayLink
	actual.Attachments = []reconcile.AttachmentState{
		{Link: link, Hook: string(datapath.HookEgress), Program: "tc_init_e", ProgramID: 10, Priority: datapath.FixedTCPriority, Handle: 0x100, DirectAction: true},
		{Link: link, Hook: string(datapath.HookIngress), Program: "tc_restore", ProgramID: 11, Priority: datapath.FixedTCPriority, Handle: 0x101, DirectAction: true},
	}
	backend := &fakeBaseTCBackend{filters: []datapath.TCFilterState{
		{Link: link, Hook: datapath.HookEgress, Program: "tc_init_e", ProgramID: 10, Priority: datapath.FixedTCPriority, Handle: 0x100, DirectAction: true},
		{Link: link, Hook: datapath.HookIngress, Program: "tc_restore", ProgramID: 11, Priority: datapath.FixedTCPriority, Handle: 0x101, DirectAction: true},
	}}
	tc, _ := datapath.NewTCManager(backend)
	ensurer, _ := NewBaseEnsurer(tc)
	changed, err := ensurer.EnsureBase(context.Background(), baseDesiredState(), actual)
	if err != nil || changed || len(backend.attached) != 0 {
		t.Fatalf("existing attachments were not reused: changed=%v attached=%+v err=%v", changed, backend.attached, err)
	}
}

func TestBaseEnsurerValidatesProgramsBeforeWriting(t *testing.T) {
	backend := &fakeBaseTCBackend{}
	tc, _ := datapath.NewTCManager(backend)
	ensurer, _ := NewBaseEnsurer(tc)
	actual := baseActualState()
	delete(actual.Programs, "tc_restore")
	if _, err := ensurer.EnsureBase(context.Background(), baseDesiredState(), actual); err == nil || len(backend.attached) != 0 {
		t.Fatalf("missing program was not rejected before writes: err=%v attached=%+v", err, backend.attached)
	}
}

func TestBaseEnsurerPropagatesForeignConflict(t *testing.T) {
	link := baseDesiredState().Flannel.UnderlayLink
	backend := &fakeBaseTCBackend{filters: []datapath.TCFilterState{{Link: link, Hook: datapath.HookEgress, Program: "foreign", ProgramID: 99, Priority: datapath.FixedTCPriority, Handle: 0x999}}}
	tc, _ := datapath.NewTCManager(backend)
	ensurer, _ := NewBaseEnsurer(tc)
	_, err := ensurer.EnsureBase(context.Background(), baseDesiredState(), baseActualState())
	var classified *reconcile.ClassifiedError
	if !errors.As(err, &classified) || classified.Class() != reconcile.ErrorConflict || len(backend.attached) != 0 {
		t.Fatalf("foreign conflict was not propagated: err=%v attached=%+v", err, backend.attached)
	}
}

func TestBaseEnsurerDisabledIsNoOp(t *testing.T) {
	backend := &fakeBaseTCBackend{}
	tc, _ := datapath.NewTCManager(backend)
	ensurer, _ := NewBaseEnsurer(tc)
	desired := baseDesiredState()
	desired.Enabled = false
	changed, err := ensurer.EnsureBase(context.Background(), desired, baseActualState())
	if err != nil || changed || len(backend.attached) != 0 {
		t.Fatalf("disabled ensure changed state: changed=%v attached=%+v err=%v", changed, backend.attached, err)
	}
}

func baseDesiredState() reconcile.DesiredState {
	return reconcile.DesiredState{Enabled: true, Flannel: reconcile.FlannelState{UnderlayLink: endpoint.LinkIdentity{IfIndex: 2, IfName: "eth0"}}}
}

func baseActualState() reconcile.ActualState {
	return reconcile.ActualState{Programs: map[string]reconcile.ProgramState{
		"tc_init_e":  {ID: 10, Name: "tc_init_e"},
		"tc_restore": {ID: 11, Name: "tc_restore"},
	}}
}
