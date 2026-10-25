package cleanup

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/cat-cc-Lcos/FNCache/internal/controlplane"
	"github.com/cat-cc-Lcos/FNCache/internal/datapath"
	"github.com/cat-cc-Lcos/FNCache/internal/endpoint"
	"github.com/cat-cc-Lcos/FNCache/internal/hostnet/flannel"
	"github.com/cat-cc-Lcos/FNCache/internal/ownership"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

const (
	ActionTC      = "tc-filter"
	ActionMarker  = "marker-rule"
	ActionMap     = "map-pin"
	ActionProgram = "program-pin"
	ActionState   = "ownership-state"
)

type Options struct {
	PinRoot, StatePath, InstallationID string
	MarkerChain, MarkerComment         string
	MapCapacities                      datapath.MapCapacities
}

type Action struct {
	Kind       string   `json:"kind"`
	Identity   string   `json:"identity"`
	Evidence   []string `json:"evidence"`
	attachment *reconcile.AttachmentState
	marker     *reconcile.OwnedRule
	name       string
	id         uint32
}

type Plan struct {
	Actions []Action `json:"actions"`
	Blocked []Action `json:"blocked"`
}

type Executor interface {
	Disable(context.Context) error
	RemoveAttachment(context.Context, reconcile.AttachmentState) error
	RemoveMarker(context.Context, reconcile.OwnedRule) error
	RemoveMap(context.Context, string, uint32) error
	RemoveProgram(context.Context, string, uint32) error
	RemoveState(context.Context) error
}

func (p Plan) Execute(ctx context.Context, executor Executor, dryRun bool) error {
	if executor == nil {
		return fmt.Errorf("cleanup executor is required")
	}
	if dryRun {
		return nil
	}
	if len(p.Blocked) != 0 {
		return fmt.Errorf("cleanup blocked by %d ownership conflicts", len(p.Blocked))
	}
	if err := executor.Disable(ctx); err != nil {
		return fmt.Errorf("disable before cleanup: %w", err)
	}
	for _, action := range p.Actions {
		var err error
		switch action.Kind {
		case ActionTC:
			err = executor.RemoveAttachment(ctx, *action.attachment)
		case ActionMarker:
			err = executor.RemoveMarker(ctx, *action.marker)
		case ActionMap:
			err = executor.RemoveMap(ctx, action.name, action.id)
		case ActionProgram:
			err = executor.RemoveProgram(ctx, action.name, action.id)
		case ActionState:
			err = executor.RemoveState(ctx)
		default:
			err = fmt.Errorf("unknown cleanup action %q", action.Kind)
		}
		if err != nil {
			return fmt.Errorf("cleanup %s %s: %w", action.Kind, action.Identity, err)
		}
	}
	return nil
}

type nodeExecutor struct {
	control *datapath.ControlWriter
	remover *controlplane.EndpointRemover
	manager *datapath.Manager
	marker  *flannel.MarkerRuleManager
	store   *ownership.Store
	pinRoot string
}

func (e *nodeExecutor) Disable(ctx context.Context) error {
	if _, err := os.Stat(filepath.Join(e.pinRoot, "maps", "control_map")); os.IsNotExist(err) {
		return nil
	}
	return e.control.Disable(ctx)
}
func (e *nodeExecutor) RemoveAttachment(ctx context.Context, a reconcile.AttachmentState) error {
	return e.remover.RemoveOwnedAttachment(ctx, a)
}
func (e *nodeExecutor) RemoveMarker(ctx context.Context, r reconcile.OwnedRule) error {
	return e.marker.Remove(ctx, r)
}
func (e *nodeExecutor) RemoveMap(ctx context.Context, name string, id uint32) error {
	return e.manager.RemovePinnedMap(ctx, name, id)
}
func (e *nodeExecutor) RemoveProgram(ctx context.Context, name string, id uint32) error {
	return e.manager.RemovePinnedProgram(ctx, name, id)
}
func (e *nodeExecutor) RemoveState(ctx context.Context) error { return e.store.Remove(ctx) }

func Run(ctx context.Context, options Options, dryRun bool) (Plan, error) {
	if options.PinRoot == "" || options.StatePath == "" || options.InstallationID == "" || options.MarkerChain == "" || options.MarkerComment == "" {
		return Plan{}, fmt.Errorf("cleanup options are incomplete")
	}
	if options.MapCapacities == (datapath.MapCapacities{}) {
		options.MapCapacities = datapath.DefaultMapCapacities()
	}
	if err := options.MapCapacities.Validate(); err != nil {
		return Plan{}, err
	}
	store, err := ownership.NewStore(options.StatePath)
	if err != nil {
		return Plan{}, err
	}
	state, err := store.Load(ctx)
	if err != nil {
		return Plan{}, fmt.Errorf("load ownership for cleanup: %w", err)
	}
	if state.InstallationID != options.InstallationID || state.ABI != reconcile.BPFABIVersion {
		return Plan{}, fmt.Errorf("ownership identity or BPF ABI does not match cleanup configuration")
	}
	pins, err := datapath.NewPinScannerWithSchema(options.PinRoot, datapath.V1SchemaWithCapacities(options.MapCapacities))
	if err != nil {
		return Plan{}, err
	}
	actual, err := pins.Scan(ctx)
	if err != nil {
		return Plan{}, fmt.Errorf("scan pinned objects: %w", err)
	}
	unresolved := make([]reconcile.AttachmentState, 0)
	scanState := state
	scanState.Attachments = append([]reconcile.AttachmentState(nil), state.Attachments...)
	links := make([]endpoint.LinkIdentity, 0)
	seen := make(map[string]struct{})
	for index, attachment := range scanState.Attachments {
		if attachment.Link.NetNSInode != 0 {
			path, ok := netNSPath(attachment.Link.NetNSInode)
			if !ok {
				unresolved = append(unresolved, attachment)
				continue
			}
			attachment.Link.NetNSPath = path
			scanState.Attachments[index] = attachment
		}
		key := fmt.Sprintf("%d/%d", attachment.Link.NetNSInode, attachment.Link.IfIndex)
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			links = append(links, attachment.Link)
		}
	}
	tcBackend, err := datapath.NewLinuxTCBackend(options.PinRoot)
	if err != nil {
		return Plan{}, err
	}
	tc, err := datapath.NewTCManagerWithNetNS(tcBackend, datapath.NewNetNSManager())
	if err != nil {
		return Plan{}, err
	}
	tcScanner, err := datapath.NewTCScanner(tc)
	if err != nil {
		return Plan{}, err
	}
	tcActual, err := tcScanner.Scan(ctx, links)
	if err != nil {
		return Plan{}, fmt.Errorf("scan TC objects: %w", err)
	}
	actual.Attachments = tcActual.Attachments
	marker, err := flannel.NewRuleScanner(nil).Scan(ctx, flannel.MarkerRuleSpec{Chain: options.MarkerChain, Comment: options.MarkerComment})
	if err != nil {
		return Plan{}, fmt.Errorf("scan marker rule: %w", err)
	}
	plan := BuildPlan(scanState, actual, marker, options.MarkerChain+"/"+options.MarkerComment, unresolved)
	if dryRun {
		return plan, nil
	}
	if len(plan.Blocked) != 0 {
		return plan, fmt.Errorf("cleanup blocked by %d ownership conflicts", len(plan.Blocked))
	}
	mapWriter, err := datapath.NewMapWriter(options.PinRoot)
	if err != nil {
		return plan, err
	}
	remover, err := controlplane.NewEndpointRemover(mapWriter, tc)
	if err != nil {
		return plan, err
	}
	control, err := datapath.NewControlWriter(options.PinRoot)
	if err != nil {
		return plan, err
	}
	manager, err := datapath.NewManager(options.PinRoot)
	if err != nil {
		return plan, err
	}
	executor := &nodeExecutor{control: control, remover: remover, manager: manager, marker: flannel.NewMarkerRuleManager(nil), store: store, pinRoot: options.PinRoot}
	return plan, plan.Execute(ctx, executor, false)
}

func netNSPath(inode uint64) (string, bool) {
	paths, _ := filepath.Glob("/proc/[0-9]*/ns/net")
	want := fmt.Sprintf("net:[%d]", inode)
	for _, path := range paths {
		target, err := os.Readlink(path)
		if err == nil && target == want {
			return path, true
		}
	}
	return "", false
}

func BuildPlan(state reconcile.OwnershipState, actual reconcile.ActualState, marker reconcile.RuleState, markerIdentity string, unresolvedNetNS []reconcile.AttachmentState) Plan {
	plan := Plan{}
	// An unresolved netns has already disappeared, so there is no live TC
	// object to remove. Keep it out of Actions and continue cleaning objects
	// whose ownership can still be verified.
	for _, owned := range state.Attachments {
		if hasAttachment(unresolvedNetNS, owned) || state.Programs[owned.Program].ID != owned.ProgramID {
			continue
		}
		if !owned.DirectAction {
			plan.Blocked = append(plan.Blocked, Action{Kind: ActionTC, Identity: attachmentIdentity(owned), Evidence: []string{"persisted TC identity is not direct-action"}})
			continue
		}
		if _, err := datapath.NewFixedFilter(owned.Link, owned.Program, owned.ProgramID, true); err != nil {
			plan.Blocked = append(plan.Blocked, Action{Kind: ActionTC, Identity: attachmentIdentity(owned), Evidence: []string{"persisted TC identity is invalid"}})
			continue
		}
		found, slotConflict := findAttachment(actual.Attachments, owned)
		if found {
			copy := owned
			plan.Actions = append(plan.Actions, Action{Kind: ActionTC, Identity: attachmentIdentity(owned), Evidence: []string{"link identity", "program ID", "fixed handle", "direct-action=true"}, attachment: &copy})
		} else if slotConflict {
			plan.Blocked = append(plan.Blocked, Action{Kind: ActionTC, Identity: attachmentIdentity(owned), Evidence: []string{"TC slot is occupied by a different program"}})
		}
	}
	if state.FlannelRule.Identity != "" {
		if state.FlannelRule.Identity != markerIdentity {
			plan.Blocked = append(plan.Blocked, Action{Kind: ActionMarker, Identity: state.FlannelRule.Identity, Evidence: []string{"configured marker identity differs"}})
		} else if marker.Present && marker.Fingerprint == state.FlannelRule.Fingerprint {
			owned := state.FlannelRule
			plan.Actions = append(plan.Actions, Action{Kind: ActionMarker, Identity: owned.Identity, Evidence: []string{"marker fingerprint"}, marker: &owned})
		} else if marker.Present {
			plan.Blocked = append(plan.Blocked, Action{Kind: ActionMarker, Identity: state.FlannelRule.Identity, Evidence: []string{"marker fingerprint changed"}})
		}
	}
	mapNames := make([]string, 0, len(state.Maps))
	for name := range state.Maps {
		mapNames = append(mapNames, name)
	}
	sort.Strings(mapNames)
	for _, name := range mapNames {
		owned, ok := state.Maps[name]
		if !ok {
			continue
		}
		actualMap, present := actual.Maps[name]
		if !present {
			continue
		}
		if actualMap.ID != owned.ID {
			plan.Blocked = append(plan.Blocked, Action{Kind: ActionMap, Identity: "maps/" + name, Evidence: []string{"Map ID changed"}})
			continue
		}
		plan.Actions = append(plan.Actions, Action{Kind: ActionMap, Identity: "maps/" + name, Evidence: []string{"Map ID"}, name: name, id: owned.ID})
	}
	programNames := make([]string, 0, len(state.Programs))
	for name := range state.Programs {
		programNames = append(programNames, name)
	}
	sort.Strings(programNames)
	for _, name := range programNames {
		owned := state.Programs[name]
		actualProgram, present := actual.Programs[name]
		if !present {
			continue
		}
		if actualProgram.ID != owned.ID {
			plan.Blocked = append(plan.Blocked, Action{Kind: ActionProgram, Identity: "programs/" + name, Evidence: []string{"program ID changed"}})
			continue
		}
		plan.Actions = append(plan.Actions, Action{Kind: ActionProgram, Identity: "programs/" + name, Evidence: []string{"program ID"}, name: name, id: owned.ID})
	}
	plan.Actions = append(plan.Actions, Action{Kind: ActionState, Identity: "state.json", Evidence: []string{"validated ownership state"}})
	return plan
}

func hasAttachment(list []reconcile.AttachmentState, wanted reconcile.AttachmentState) bool {
	for _, item := range list {
		if attachmentIdentity(item) == attachmentIdentity(wanted) {
			return true
		}
	}
	return false
}

func findAttachment(list []reconcile.AttachmentState, wanted reconcile.AttachmentState) (bool, bool) {
	conflict := false
	for _, item := range list {
		if item.Link.NetNSInode != wanted.Link.NetNSInode || item.Link.IfIndex != wanted.Link.IfIndex || item.Hook != wanted.Hook || item.Priority != wanted.Priority || item.Handle != wanted.Handle {
			continue
		}
		if attachmentIdentity(item) == attachmentIdentity(wanted) {
			return true, false
		}
		conflict = true
	}
	return false, conflict
}

func attachmentIdentity(a reconcile.AttachmentState) string {
	return fmt.Sprintf("%d/%d/%s/%d/%d/%s/%d/direct=%t", a.Link.NetNSInode, a.Link.IfIndex, a.Hook, a.Priority, a.Handle, a.Program, a.ProgramID, a.DirectAction)
}
