//go:build linux

package datapath

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cat-cc-Lcos/FNCache/internal/endpoint"
	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type kernelQdisc struct {
	LinkIndex      int
	Handle, Parent uint32
	Kind           string
}
type kernelFilter struct {
	LinkIndex      int
	Parent, Handle uint32
	Priority       uint16
	Kind, Program  string
	ProgramID      uint32
	DirectAction   bool
	FD             int
}
type tcNetlinkAPI interface {
	listQdiscs(context.Context, endpoint.LinkIdentity) ([]kernelQdisc, error)
	addQdisc(context.Context, endpoint.LinkIdentity, kernelQdisc) error
	listFilters(context.Context, endpoint.LinkIdentity, uint32) ([]kernelFilter, error)
	addFilter(context.Context, endpoint.LinkIdentity, kernelFilter) error
	deleteFilter(context.Context, endpoint.LinkIdentity, kernelFilter) error
}
type tcProgram interface {
	FD() int
	ProgramID() (uint32, error)
	Close() error
}
type tcProgramLoader interface {
	Load(string) (tcProgram, error)
}
type linuxTCBackend struct {
	pinRoot string
	api     tcNetlinkAPI
	loader  tcProgramLoader
}

func NewLinuxTCBackend(pinRoot string) (TCBackend, error) {
	return newLinuxTCBackend(pinRoot, netlinkTCAPI{}, ebpfTCProgramLoader{})
}
func newLinuxTCBackend(pinRoot string, api tcNetlinkAPI, loader tcProgramLoader) (TCBackend, error) {
	if pinRoot == "" || !filepath.IsAbs(pinRoot) || filepath.Clean(pinRoot) == string(filepath.Separator) {
		return nil, fmt.Errorf("TC pin root must be a dedicated absolute directory")
	}
	if api == nil || loader == nil {
		return nil, fmt.Errorf("TC backend dependencies are required")
	}
	return &linuxTCBackend{pinRoot: filepath.Clean(pinRoot), api: api, loader: loader}, nil
}
func (b *linuxTCBackend) EnsureClsact(ctx context.Context, link endpoint.LinkIdentity) (TCQdiscState, error) {
	if err := validateLink(link); err != nil {
		return TCQdiscState{}, err
	}
	if err := ctx.Err(); err != nil {
		return TCQdiscState{}, err
	}
	qdiscs, err := b.api.listQdiscs(ctx, link)
	if err != nil {
		return TCQdiscState{}, fmt.Errorf("list qdiscs: %w", err)
	}
	if hasClsact(qdiscs) {
		return TCQdiscState{Link: link, Exists: true}, nil
	}
	qdisc := kernelQdisc{LinkIndex: link.IfIndex, Handle: netlink.MakeHandle(0xffff, 0), Parent: netlink.HANDLE_CLSACT, Kind: "clsact"}
	if err := b.api.addQdisc(ctx, link, qdisc); err != nil {
		qdiscs, listErr := b.api.listQdiscs(ctx, link)
		if listErr == nil && hasClsact(qdiscs) {
			return TCQdiscState{Link: link, Exists: true}, nil
		}
		return TCQdiscState{}, fmt.Errorf("add clsact: %w", err)
	}
	return TCQdiscState{Link: link, Exists: true, CreatedByOncache: true}, nil
}
func (b *linuxTCBackend) ListFilters(ctx context.Context, link endpoint.LinkIdentity) ([]TCFilterState, error) {
	if err := validateLink(link); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var result []TCFilterState
	for _, direction := range []struct {
		hook   TCHook
		parent uint32
	}{
		{hook: HookIngress, parent: netlink.HANDLE_MIN_INGRESS},
		{hook: HookEgress, parent: netlink.HANDLE_MIN_EGRESS},
	} {
		filters, err := b.api.listFilters(ctx, link, direction.parent)
		if err != nil {
			return nil, fmt.Errorf("list %s filters: %w", direction.hook, err)
		}
		for _, filter := range filters {
			result = append(result, TCFilterState{
				Link: link, Hook: direction.hook, Program: filter.Program, ProgramID: filter.ProgramID,
				Priority: filter.Priority, Handle: filter.Handle, DirectAction: filter.DirectAction,
			})
		}
	}
	return result, nil
}

func (b *linuxTCBackend) AttachFilter(ctx context.Context, spec TCFilterSpec) (TCFilterState, error) {
	if err := validateFilterSpec(spec); err != nil {
		return TCFilterState{}, err
	}
	if err := ctx.Err(); err != nil {
		return TCFilterState{}, err
	}
	program, err := b.loader.Load(filepath.Join(b.pinRoot, "programs", spec.Program))
	if err != nil {
		return TCFilterState{}, fmt.Errorf("load pinned program %s: %w", spec.Program, err)
	}
	defer program.Close()
	programID, err := program.ProgramID()
	if err != nil {
		return TCFilterState{}, fmt.Errorf("inspect pinned program %s: %w", spec.Program, err)
	}
	if programID != spec.ProgramID {
		return TCFilterState{}, fmt.Errorf("pinned program %s ID mismatch: got %d want %d", spec.Program, programID, spec.ProgramID)
	}
	parent, err := parentForHook(spec.Hook)
	if err != nil {
		return TCFilterState{}, err
	}
	filter := kernelFilter{LinkIndex: spec.Link.IfIndex, Parent: parent, Priority: spec.Priority, Handle: spec.Handle, Kind: "bpf", Program: spec.Program, ProgramID: spec.ProgramID, DirectAction: spec.DirectAction, FD: program.FD()}
	if err := b.api.addFilter(ctx, spec.Link, filter); err != nil {
		return TCFilterState{}, fmt.Errorf("add BPF filter: %w", err)
	}
	return TCFilterState{Link: spec.Link, Hook: spec.Hook, Program: spec.Program, ProgramID: spec.ProgramID, Priority: spec.Priority, Handle: spec.Handle, DirectAction: spec.DirectAction}, nil
}

func (b *linuxTCBackend) MigrateLegacyFilter(ctx context.Context, current TCFilterState, spec TCFilterSpec) (TCFilterState, bool, error) {
	legacyName, ok := legacyProgramNames[spec.Program]
	if !ok || !sameLink(current.Link, spec.Link) || current.Hook != spec.Hook ||
		current.Priority != spec.Priority || current.Handle != spec.Handle {
		return TCFilterState{}, false, nil
	}
	legacyPath := filepath.Join(b.pinRoot, "programs", legacyName)
	if _, err := os.Stat(legacyPath); err != nil {
		if os.IsNotExist(err) {
			return TCFilterState{}, false, nil
		}
		return TCFilterState{}, false, fmt.Errorf("inspect legacy program pin %s: %w", legacyName, err)
	}
	legacy, err := b.loader.Load(legacyPath)
	if err != nil {
		return TCFilterState{}, false, fmt.Errorf("load legacy pinned program %s: %w", legacyName, err)
	}
	defer legacy.Close()
	legacyID, err := legacy.ProgramID()
	if err != nil {
		return TCFilterState{}, false, fmt.Errorf("inspect legacy pinned program %s: %w", legacyName, err)
	}
	if legacyID != current.ProgramID {
		return TCFilterState{}, false, nil
	}

	currentProgram, err := b.loader.Load(filepath.Join(b.pinRoot, "programs", spec.Program))
	if err != nil {
		return TCFilterState{}, true, fmt.Errorf("load current pinned program %s: %w", spec.Program, err)
	}
	defer currentProgram.Close()
	currentID, err := currentProgram.ProgramID()
	if err != nil {
		return TCFilterState{}, true, fmt.Errorf("inspect current pinned program %s: %w", spec.Program, err)
	}
	if currentID != spec.ProgramID {
		return TCFilterState{}, true, safetyError("current pinned program identity changed during legacy migration")
	}
	parent, err := parentForHook(spec.Hook)
	if err != nil {
		return TCFilterState{}, true, err
	}
	oldFilter := kernelFilter{
		LinkIndex: current.Link.IfIndex, Parent: parent, Priority: current.Priority, Handle: current.Handle,
		Kind: "bpf", Program: current.Program, ProgramID: current.ProgramID, DirectAction: current.DirectAction, FD: -1,
	}
	if err := b.api.deleteFilter(ctx, spec.Link, oldFilter); err != nil {
		return TCFilterState{}, true, fmt.Errorf("remove legacy BPF filter %s: %w", legacyName, err)
	}
	newFilter := kernelFilter{
		LinkIndex: spec.Link.IfIndex, Parent: parent, Priority: spec.Priority, Handle: spec.Handle,
		Kind: "bpf", Program: spec.Program, ProgramID: spec.ProgramID, DirectAction: spec.DirectAction, FD: currentProgram.FD(),
	}
	if err := b.api.addFilter(ctx, spec.Link, newFilter); err != nil {
		restore := oldFilter
		restore.FD = legacy.FD()
		if restoreErr := b.api.addFilter(ctx, spec.Link, restore); restoreErr != nil {
			return TCFilterState{}, true, safetyError(fmt.Sprintf("legacy BPF filter migration failed and rollback failed: migrate=%v rollback=%v", err, restoreErr))
		}
		return TCFilterState{}, true, fmt.Errorf("attach migrated BPF filter %s: %w", spec.Program, err)
	}
	return TCFilterState{Link: spec.Link, Hook: spec.Hook, Program: spec.Program, ProgramID: spec.ProgramID, Priority: spec.Priority, Handle: spec.Handle, DirectAction: spec.DirectAction}, true, nil
}

func (b *linuxTCBackend) RemoveFilter(ctx context.Context, spec TCFilterSpec) error {
	if err := validateFilterSpec(spec); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	filters, err := b.ListFilters(ctx, spec.Link)
	if err != nil {
		return fmt.Errorf("recheck TC filters before deletion: %w", err)
	}
	found := false
	for _, current := range filters {
		if current.Hook != spec.Hook || current.Priority != spec.Priority || current.Handle != spec.Handle {
			continue
		}
		if !sameFilter(current, spec) {
			return foreignConflict("refusing to remove a filter with a different program identity")
		}
		found = true
		break
	}
	if !found {
		return nil
	}
	parent, err := parentForHook(spec.Hook)
	if err != nil {
		return err
	}
	if err := b.api.deleteFilter(ctx, spec.Link, kernelFilter{LinkIndex: spec.Link.IfIndex, Parent: parent, Priority: spec.Priority, Handle: spec.Handle, Kind: "bpf", Program: spec.Program, ProgramID: spec.ProgramID, FD: -1}); err != nil {
		return fmt.Errorf("delete BPF filter: %w", err)
	}
	return nil
}

func hasClsact(qdiscs []kernelQdisc) bool {
	for _, qdisc := range qdiscs {
		if qdisc.Kind == "clsact" && qdisc.Parent == netlink.HANDLE_CLSACT {
			return true
		}
	}
	return false
}

func parentForHook(hook TCHook) (uint32, error) {
	switch hook {
	case HookIngress:
		return netlink.HANDLE_MIN_INGRESS, nil
	case HookEgress:
		return netlink.HANDLE_MIN_EGRESS, nil
	default:
		return 0, fmt.Errorf("unsupported TC hook: %s", hook)
	}
}

type netlinkTCAPI struct{}

func (netlinkTCAPI) listQdiscs(ctx context.Context, identity endpoint.LinkIdentity) ([]kernelQdisc, error) {
	var result []kernelQdisc
	err := withNetlinkHandle(ctx, identity, func(handle *netlink.Handle) error {
		link, err := lookupLink(handle, identity)
		if err != nil {
			return err
		}
		qdiscs, err := handle.QdiscList(link)
		if err != nil {
			return err
		}
		result = make([]kernelQdisc, 0, len(qdiscs))
		for _, qdisc := range qdiscs {
			attrs := qdisc.Attrs()
			if attrs != nil {
				result = append(result, kernelQdisc{LinkIndex: attrs.LinkIndex, Handle: attrs.Handle, Parent: attrs.Parent, Kind: qdisc.Type()})
			}
		}
		return nil
	})
	return result, err
}

func (netlinkTCAPI) addQdisc(ctx context.Context, identity endpoint.LinkIdentity, qdisc kernelQdisc) error {
	return withNetlinkHandle(ctx, identity, func(handle *netlink.Handle) error {
		if _, err := lookupLink(handle, identity); err != nil {
			return err
		}
		return handle.QdiscAdd(&netlink.Clsact{QdiscAttrs: netlink.QdiscAttrs{LinkIndex: qdisc.LinkIndex, Handle: qdisc.Handle, Parent: qdisc.Parent}})
	})
}

func (netlinkTCAPI) listFilters(ctx context.Context, identity endpoint.LinkIdentity, parent uint32) ([]kernelFilter, error) {
	var result []kernelFilter
	err := withNetlinkHandle(ctx, identity, func(handle *netlink.Handle) error {
		link, err := lookupLink(handle, identity)
		if err != nil {
			return err
		}
		filters, err := handle.FilterList(link, parent)
		if err != nil {
			return err
		}
		result = make([]kernelFilter, 0, len(filters))
		for _, filter := range filters {
			attrs := filter.Attrs()
			if attrs == nil {
				continue
			}
			state := kernelFilter{LinkIndex: attrs.LinkIndex, Parent: attrs.Parent, Priority: attrs.Priority, Handle: attrs.Handle, Kind: filter.Type()}
			if bpf, ok := filter.(*netlink.BpfFilter); ok {
				state.Program = bpf.Name
				if bpf.Id > 0 {
					state.ProgramID = uint32(bpf.Id)
				}
				state.DirectAction = bpf.DirectAction
			}
			result = append(result, state)
		}
		return nil
	})
	return result, err
}

func (netlinkTCAPI) addFilter(ctx context.Context, identity endpoint.LinkIdentity, filter kernelFilter) error {
	return withNetlinkHandle(ctx, identity, func(handle *netlink.Handle) error {
		if _, err := lookupLink(handle, identity); err != nil {
			return err
		}
		return handle.FilterAdd(&netlink.BpfFilter{FilterAttrs: netlink.FilterAttrs{LinkIndex: filter.LinkIndex, Parent: filter.Parent, Priority: filter.Priority, Handle: filter.Handle, Protocol: unix.ETH_P_ALL}, Fd: filter.FD, Name: filter.Program, DirectAction: filter.DirectAction})
	})
}

func (netlinkTCAPI) deleteFilter(ctx context.Context, identity endpoint.LinkIdentity, filter kernelFilter) error {
	return withNetlinkHandle(ctx, identity, func(handle *netlink.Handle) error {
		if _, err := lookupLink(handle, identity); err != nil {
			return err
		}
		return handle.FilterDel(&netlink.BpfFilter{FilterAttrs: netlink.FilterAttrs{LinkIndex: filter.LinkIndex, Parent: filter.Parent, Priority: filter.Priority, Handle: filter.Handle, Protocol: unix.ETH_P_ALL}, Fd: -1})
	})
}

func withNetlinkHandle(ctx context.Context, identity endpoint.LinkIdentity, fn func(*netlink.Handle) error) error {
	if fn == nil {
		return fmt.Errorf("netlink callback is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	openAndRun := func(ctx context.Context) error {
		handle, err := netlink.NewHandle(unix.NETLINK_ROUTE)
		if err != nil {
			return fmt.Errorf("open netlink handle: %w", err)
		}
		defer handle.Close()
		if err := ctx.Err(); err != nil {
			return err
		}
		return fn(handle)
	}
	if identity.NetNSInode == 0 {
		return openAndRun(ctx)
	}
	if identity.NetNSPath == "" {
		return fmt.Errorf("target netns path is required for inode %d", identity.NetNSInode)
	}
	return NewNetNSManager().WithNetNS(ctx, NetNSRef{Path: identity.NetNSPath, Inode: identity.NetNSInode}, openAndRun)
}

func lookupLink(handle *netlink.Handle, identity endpoint.LinkIdentity) (netlink.Link, error) {
	link, err := handle.LinkByIndex(identity.IfIndex)
	if err != nil {
		return nil, err
	}
	attrs := link.Attrs()
	if attrs == nil || attrs.Index != identity.IfIndex {
		return nil, fmt.Errorf("TC link ifindex identity mismatch: got %d want %d", linkIndex(attrs), identity.IfIndex)
	}
	if identity.IfName != "" && attrs.Name != identity.IfName {
		return nil, fmt.Errorf("TC link name identity mismatch: got %q want %q", attrs.Name, identity.IfName)
	}
	if len(identity.MAC) != 0 && !bytes.Equal(attrs.HardwareAddr, identity.MAC) {
		return nil, fmt.Errorf("TC link MAC identity mismatch: got %s want %s", attrs.HardwareAddr, identity.MAC)
	}
	return link, nil
}

func linkIndex(attrs *netlink.LinkAttrs) int {
	if attrs == nil {
		return 0
	}
	return attrs.Index
}

type ebpfTCProgramLoader struct{}

func (ebpfTCProgramLoader) Load(path string) (tcProgram, error) {
	program, err := ebpf.LoadPinnedProgram(path, nil)
	if err != nil {
		return nil, err
	}
	return &ebpfTCProgram{program: program}, nil
}

type ebpfTCProgram struct {
	program *ebpf.Program
}

func (p *ebpfTCProgram) FD() int { return p.program.FD() }

func (p *ebpfTCProgram) ProgramID() (uint32, error) {
	info, err := p.program.Info()
	if err != nil {
		return 0, err
	}
	id, ok := info.ID()
	if !ok {
		return 0, fmt.Errorf("kernel did not provide a program ID")
	}
	return uint32(id), nil
}

func (p *ebpfTCProgram) Close() error { return p.program.Close() }
