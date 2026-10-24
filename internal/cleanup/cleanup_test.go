package cleanup

import (
	"context"
	"testing"

	"github.com/cat-cc-Lcos/FNCache/internal/datapath"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
	"github.com/cat-cc-Lcos/FNCache/internal/resolver"
)

type fakeExecutor struct{ calls []string }

func (f *fakeExecutor) Disable(context.Context) error {
	f.calls = append(f.calls, "disable")
	return nil
}
func (f *fakeExecutor) RemoveAttachment(context.Context, reconcile.AttachmentState) error {
	f.calls = append(f.calls, ActionTC)
	return nil
}
func (f *fakeExecutor) RemoveMarker(context.Context, reconcile.OwnedRule) error {
	f.calls = append(f.calls, ActionMarker)
	return nil
}
func (f *fakeExecutor) RemoveMap(context.Context, string, uint32) error {
	f.calls = append(f.calls, ActionMap)
	return nil
}
func (f *fakeExecutor) RemoveProgram(context.Context, string, uint32) error {
	f.calls = append(f.calls, ActionProgram)
	return nil
}
func (f *fakeExecutor) RemoveState(context.Context) error {
	f.calls = append(f.calls, ActionState)
	return nil
}

func TestBuildPlanRequiresMatchingOwnershipEvidence(t *testing.T) {
	link := resolver.LinkIdentity{IfIndex: 2}
	state := reconcile.OwnershipState{
		Programs:       map[string]reconcile.ProgramState{"tc_init_e": {ID: 10}},
		Maps:           map[string]reconcile.MapState{"control_map": {ID: 20}},
		Attachments:    []reconcile.AttachmentState{{Link: link, Hook: string(datapath.HookEgress), Program: "tc_init_e", Priority: datapath.FixedTCPriority, Handle: 0x100, ProgramID: 10, DirectAction: true}},
		FlannelRule:    reconcile.OwnedRule{Identity: "ONCACHE/oncache:dev", Fingerprint: "marker-fp"},
		InstallationID: "install-a", NodeUID: "node-a", SchemaVersion: 1,
	}
	actual := reconcile.ActualState{
		Programs:    map[string]reconcile.ProgramState{"tc_init_e": {ID: 10}},
		Maps:        map[string]reconcile.MapState{"control_map": {ID: 20}},
		Attachments: []reconcile.AttachmentState{{Link: link, Hook: string(datapath.HookEgress), Program: "tc_init_e", Priority: datapath.FixedTCPriority, Handle: 0x100, ProgramID: 10, DirectAction: true}},
	}
	plan := BuildPlan(state, actual, reconcile.RuleState{Present: true, Identity: "ONCACHE/oncache:dev", Fingerprint: "marker-fp"}, "ONCACHE/oncache:dev", nil)
	if len(plan.Blocked) != 0 || len(plan.Actions) != 5 {
		t.Fatalf("unexpected safe cleanup plan: actions=%+v blocked=%+v", plan.Actions, plan.Blocked)
	}
	actual.Maps["control_map"] = reconcile.MapState{ID: 99}
	plan = BuildPlan(state, actual, reconcile.RuleState{Present: true, Identity: "ONCACHE/oncache:dev", Fingerprint: "marker-fp"}, "ONCACHE/oncache:dev", nil)
	if len(plan.Blocked) == 0 {
		t.Fatal("Map identity mismatch was not blocked")
	}
}

func TestBuildPlanBlocksNonDirectActionFilter(t *testing.T) {
	link := resolver.LinkIdentity{IfIndex: 7}
	owned := reconcile.AttachmentState{Link: link, Hook: string(datapath.HookEgress), Program: "tc_init_e", Priority: datapath.FixedTCPriority, Handle: 0x100, ProgramID: 10, DirectAction: true}
	actual := owned
	actual.DirectAction = false
	plan := BuildPlan(
		reconcile.OwnershipState{SchemaVersion: 1, InstallationID: "install-a", NodeUID: "node-a", Programs: map[string]reconcile.ProgramState{"tc_init_e": {ID: 10}}, Attachments: []reconcile.AttachmentState{owned}},
		reconcile.ActualState{Attachments: []reconcile.AttachmentState{actual}},
		reconcile.RuleState{}, "", nil,
	)
	if len(plan.Actions) != 1 || plan.Actions[0].Kind != ActionState || len(plan.Blocked) != 1 || plan.Blocked[0].Kind != ActionTC {
		t.Fatalf("non-direct-action filter was not blocked: %+v", plan)
	}
}

func TestCleanupPlanDryRunHasNoSideEffects(t *testing.T) {
	executor := &fakeExecutor{}
	plan := Plan{Actions: []Action{{Kind: ActionState, Identity: "state.json"}}}
	if err := plan.Execute(context.Background(), executor, true); err != nil {
		t.Fatal(err)
	}
	if len(executor.calls) != 0 {
		t.Fatalf("dry-run invoked cleanup actions: %v", executor.calls)
	}
	if err := plan.Execute(context.Background(), executor, false); err != nil {
		t.Fatal(err)
	}
	if len(executor.calls) != 2 || executor.calls[0] != "disable" || executor.calls[1] != ActionState {
		t.Fatalf("unexpected cleanup order: %v", executor.calls)
	}
}

func TestBuildPlanSkipsUnresolvedNetNSAttachment(t *testing.T) {
	attachment := reconcile.AttachmentState{Link: resolver.LinkIdentity{NetNSInode: 42, IfIndex: 7}, Program: "tc_init_in", ProgramID: 11, Hook: string(datapath.HookIngress), Priority: datapath.FixedTCPriority, Handle: 0x201}
	plan := BuildPlan(reconcile.OwnershipState{}, reconcile.ActualState{}, reconcile.RuleState{}, "ONCACHE/oncache:dev", []reconcile.AttachmentState{attachment})
	if len(plan.Blocked) != 0 || len(plan.Actions) != 1 || plan.Actions[0].Kind != ActionState {
		t.Fatalf("unresolved netns attachment was not skipped safely: %+v", plan)
	}
}

func TestBlockedPlanDoesNotExecute(t *testing.T) {
	executor := &fakeExecutor{}
	plan := Plan{Blocked: []Action{{Kind: ActionMap, Identity: "maps/control_map"}}}
	if err := plan.Execute(context.Background(), executor, false); err == nil {
		t.Fatal("blocked cleanup plan executed")
	}
	if len(executor.calls) != 0 {
		t.Fatalf("blocked cleanup plan caused side effects: %v", executor.calls)
	}
}
