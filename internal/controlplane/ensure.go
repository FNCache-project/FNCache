package controlplane

import (
	"context"
	"fmt"

	"github.com/cat-cc-Lcos/FNCache/internal/datapath"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

type BaseEnsurer struct {
	tc *datapath.TCManager
}

func NewBaseEnsurer(tc *datapath.TCManager) (*BaseEnsurer, error) {
	if tc == nil {
		return nil, fmt.Errorf("TC manager is required")
	}
	return &BaseEnsurer{tc: tc}, nil
}

func (e *BaseEnsurer) EnsureBase(ctx context.Context, desired reconcile.DesiredState, actual reconcile.ActualState) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if !desired.Enabled {
		return false, nil
	}

	programs := make(map[string]uint32, 2)
	for _, name := range []string{"tc_init_e", "tc_restore"} {
		program, ok := actual.Programs[name]
		if !ok || program.ID == 0 {
			return false, fmt.Errorf("required base program is unavailable: %s", name)
		}
		if program.Name != "" && program.Name != name {
			return false, fmt.Errorf("base program identity mismatch: got %q want %q", program.Name, name)
		}
		programs[name] = program.ID
	}

	changed := false
	for _, name := range []string{"tc_init_e", "tc_restore"} {
		spec, err := datapath.NewFixedFilter(desired.Flannel.UnderlayLink, name, programs[name], true)
		if err != nil {
			return changed, fmt.Errorf("build base filter %s: %w", name, err)
		}
		if !hasAttachment(actual.Attachments, spec) {
			changed = true
		}
		if _, err := e.tc.EnsureFilter(ctx, spec); err != nil {
			return changed, fmt.Errorf("ensure base filter %s: %w", name, err)
		}
	}
	return changed, nil
}

func hasAttachment(attachments []reconcile.AttachmentState, expected datapath.TCFilterSpec) bool {
	for _, attachment := range attachments {
		if attachment.Link.NetNSInode == expected.Link.NetNSInode &&
			attachment.Link.IfIndex == expected.Link.IfIndex &&
			attachment.Hook == string(expected.Hook) &&
			attachment.Program == expected.Program &&
			attachment.ProgramID == expected.ProgramID &&
			attachment.Priority == expected.Priority &&
			attachment.Handle == expected.Handle &&
			attachment.DirectAction == expected.DirectAction {
			return true
		}
	}
	return false
}
