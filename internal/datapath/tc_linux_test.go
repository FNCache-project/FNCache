//go:build linux

package datapath

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cat-cc-Lcos/FNCache/internal/endpoint"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

type fakeTCNetlinkAPI struct {
	qdiscs                               []kernelQdisc
	filters                              []kernelFilter
	qdiscAdds, filterAdds, filterDeletes int
	addFailures                          int
	addErr                               error
	onListFilters                        func(*fakeTCNetlinkAPI)
}

func (f *fakeTCNetlinkAPI) listQdiscs(context.Context, endpoint.LinkIdentity) ([]kernelQdisc, error) {
	return append([]kernelQdisc(nil), f.qdiscs...), nil
}
func (f *fakeTCNetlinkAPI) addQdisc(_ context.Context, _ endpoint.LinkIdentity, qdisc kernelQdisc) error {
	f.qdiscAdds++
	f.qdiscs = append(f.qdiscs, qdisc)
	return nil
}
func (f *fakeTCNetlinkAPI) listFilters(_ context.Context, _ endpoint.LinkIdentity, parent uint32) ([]kernelFilter, error) {
	result := make([]kernelFilter, 0)
	for _, filter := range f.filters {
		if filter.Parent == parent {
			result = append(result, filter)
		}
	}
	if f.onListFilters != nil {
		onListFilters := f.onListFilters
		f.onListFilters = nil
		onListFilters(f)
	}
	return result, nil
}
func (f *fakeTCNetlinkAPI) addFilter(_ context.Context, _ endpoint.LinkIdentity, filter kernelFilter) error {
	if f.addFailures > 0 {
		f.addFailures--
		return f.addErr
	}
	f.filters = append(f.filters, filter)
	return nil
}
func (f *fakeTCNetlinkAPI) deleteFilter(_ context.Context, _ endpoint.LinkIdentity, filter kernelFilter) error {
	f.filterDeletes++
	for i, current := range f.filters {
		if current.Parent == filter.Parent && current.Priority == filter.Priority && current.Handle == filter.Handle {
			f.filters = append(f.filters[:i], f.filters[i+1:]...)
			break
		}
	}
	return nil
}

type fakeTCProgram struct {
	fd       int
	id       uint32
	closed   bool
	pinPath  string
	unpinErr error
	unpinned bool
}

func (p *fakeTCProgram) FD() int                    { return p.fd }
func (p *fakeTCProgram) ProgramID() (uint32, error) { return p.id, nil }
func (p *fakeTCProgram) Unpin() error {
	if p.unpinErr != nil {
		return p.unpinErr
	}
	p.unpinned = true
	if p.pinPath == "" {
		return nil
	}
	return os.Remove(p.pinPath)
}
func (p *fakeTCProgram) Close() error { p.closed = true; return nil }

type fakeTCProgramLoader struct {
	program  tcProgram
	programs map[string]tcProgram
	path     string
}

func (l *fakeTCProgramLoader) Load(path string) (tcProgram, error) {
	l.path = path
	if l.programs != nil {
		program, ok := l.programs[path]
		if !ok {
			return nil, errors.New("program path not found")
		}
		return program, nil
	}
	return l.program, nil
}

func linuxTestLink() endpoint.LinkIdentity { return endpoint.LinkIdentity{IfIndex: 4, NetNSInode: 9} }

func TestLinuxTCBackendCreatesAndReusesClsact(t *testing.T) {
	api := &fakeTCNetlinkAPI{}
	backend, err := newLinuxTCBackend(t.TempDir(), api, &fakeTCProgramLoader{})
	if err != nil {
		t.Fatal(err)
	}
	link := linuxTestLink()
	first, err := backend.EnsureClsact(context.Background(), link)
	if err != nil || !first.CreatedByOncache || api.qdiscAdds != 1 {
		t.Fatalf("unexpected first clsact result: state=%+v err=%v api=%+v", first, err, api)
	}
	second, err := backend.EnsureClsact(context.Background(), link)
	if err != nil || second.CreatedByOncache || api.qdiscAdds != 1 {
		t.Fatalf("clsact was not reused: state=%+v err=%v api=%+v", second, err, api)
	}
}

func TestLinuxTCBackendRejectsTargetNamespaceWithoutPath(t *testing.T) {
	backend, err := newLinuxTCBackend(t.TempDir(), netlinkTCAPI{}, &fakeTCProgramLoader{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = backend.EnsureClsact(context.Background(), endpoint.LinkIdentity{NetNSInode: 9, IfIndex: 4})
	if err == nil {
		t.Fatal("target namespace without a path was accepted")
	}
	if got := err.Error(); !strings.Contains(got, "target netns path is required for inode 9") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLinuxTCBackendAttachesPinnedProgram(t *testing.T) {
	program := &fakeTCProgram{fd: 17, id: 10}
	loader := &fakeTCProgramLoader{program: program}
	api := &fakeTCNetlinkAPI{}
	backend, err := newLinuxTCBackend("/sys/fs/bpf/oncache/v1", api, loader)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := NewFixedFilter(linuxTestLink(), "tc_init_e", 10, true)
	if err != nil {
		t.Fatal(err)
	}
	state, err := backend.AttachFilter(context.Background(), spec)
	if err != nil || state.ProgramID != 10 || len(api.filters) != 1 || api.filters[0].Parent != 0xfffffff3 || api.filters[0].FD != 17 || !program.closed {
		t.Fatalf("unexpected attach: state=%+v err=%v api=%+v closed=%v", state, err, api, program.closed)
	}
	if loader.path != "/sys/fs/bpf/oncache/v1/programs/tc_init_e" {
		t.Fatalf("unexpected pinned program path: %s", loader.path)
	}
	program.id = 11
	if _, err := backend.AttachFilter(context.Background(), spec); err == nil || len(api.filters) != 1 || !program.closed {
		t.Fatalf("mismatched program was attached: err=%v api=%+v closed=%v", err, api, program.closed)
	}
}

func TestLinuxTCBackendMigratesLegacyFilterByPinnedProgramID(t *testing.T) {
	root := t.TempDir()
	legacyPath := filepath.Join(root, "programs", "tc_init_e_func")
	if err := os.MkdirAll(filepath.Dir(legacyPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacyPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	legacy := &fakeTCProgram{fd: 11, id: 99, pinPath: legacyPath}
	current := &fakeTCProgram{fd: 17, id: 10}
	loader := &fakeTCProgramLoader{programs: map[string]tcProgram{
		legacyPath: legacy,
		filepath.Join(root, "programs", "tc_init_e"): current,
	}}
	link := linuxTestLink()
	api := &fakeTCNetlinkAPI{filters: []kernelFilter{{
		LinkIndex: link.IfIndex, Parent: 0xfffffff3, Priority: FixedTCPriority, Handle: 0x100,
		Kind: "bpf", Program: "tc_init_e_func", ProgramID: 99, DirectAction: true,
	}}}
	backend, err := newLinuxTCBackend(root, api, loader)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := NewFixedFilter(link, "tc_init_e", 10, true)
	if err != nil {
		t.Fatal(err)
	}
	got, recognized, err := backend.(*linuxTCBackend).MigrateLegacyFilter(context.Background(), apiFilterState(link, "tc_init_e_func", 99), spec)
	if err != nil || !recognized || !sameFilter(got, spec) || api.filterDeletes != 1 || len(api.filters) != 1 || api.filters[0].Program != "tc_init_e" || !legacy.closed || !current.closed || legacy.unpinned {
		t.Fatalf("legacy filter was not migrated: got=%+v recognized=%v err=%v api=%+v", got, recognized, err, api)
	}
	if _, err := os.Stat(legacyPath); err != nil {
		t.Fatalf("legacy program pin was removed before finalization: err=%v", err)
	}
	if err := backend.(*linuxTCBackend).finalizeLegacyMigrations(context.Background(), []TCFilterState{got}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(legacyPath); !os.IsNotExist(err) {
		t.Fatalf("legacy program pin remains after finalization: err=%v", err)
	}
}

func TestLinuxTCBackendRestoresLegacyFilterWhenMigrationAttachFails(t *testing.T) {
	root := t.TempDir()
	legacyPath := filepath.Join(root, "programs", "tc_init_e_func")
	if err := os.MkdirAll(filepath.Dir(legacyPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacyPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	legacy := &fakeTCProgram{fd: 11, id: 99, pinPath: legacyPath}
	current := &fakeTCProgram{fd: 17, id: 10}
	loader := &fakeTCProgramLoader{programs: map[string]tcProgram{
		legacyPath: legacy,
		filepath.Join(root, "programs", "tc_init_e"): current,
	}}
	link := linuxTestLink()
	api := &fakeTCNetlinkAPI{
		filters:     []kernelFilter{{LinkIndex: link.IfIndex, Parent: 0xfffffff3, Priority: FixedTCPriority, Handle: 0x100, Kind: "bpf", Program: "tc_init_e_func", ProgramID: 99, DirectAction: true}},
		addFailures: 1,
		addErr:      errors.New("attach failed"),
	}
	backend, _ := newLinuxTCBackend(root, api, loader)
	spec, _ := NewFixedFilter(link, "tc_init_e", 10, true)
	_, recognized, err := backend.(*linuxTCBackend).MigrateLegacyFilter(context.Background(), apiFilterState(link, "tc_init_e_func", 99), spec)
	if err == nil || !recognized || len(api.filters) != 1 || api.filters[0].Program != "tc_init_e_func" || api.filters[0].ProgramID != 99 || legacy.unpinned {
		t.Fatalf("legacy filter was not restored after migration failure: recognized=%v err=%v api=%+v", recognized, err, api)
	}
	if _, statErr := os.Stat(legacyPath); statErr != nil {
		t.Fatalf("legacy program pin was removed after migration failure: err=%v", statErr)
	}
}

func TestLinuxTCBackendRestoresLegacyFilterWhenLegacyPinRemovalFails(t *testing.T) {
	root := t.TempDir()
	legacyPath := filepath.Join(root, "programs", "tc_init_e_func")
	if err := os.MkdirAll(filepath.Dir(legacyPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacyPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	legacy := &fakeTCProgram{fd: 11, id: 99, pinPath: legacyPath, unpinErr: errors.New("unpin failed")}
	current := &fakeTCProgram{fd: 17, id: 10}
	loader := &fakeTCProgramLoader{programs: map[string]tcProgram{
		legacyPath: legacy,
		filepath.Join(root, "programs", "tc_init_e"): current,
	}}
	link := linuxTestLink()
	api := &fakeTCNetlinkAPI{filters: []kernelFilter{{
		LinkIndex: link.IfIndex, Parent: 0xfffffff3, Priority: FixedTCPriority, Handle: 0x100,
		Kind: "bpf", Program: "tc_init_e_func", ProgramID: 99, DirectAction: true,
	}}}
	backend, err := newLinuxTCBackend(root, api, loader)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := NewFixedFilter(link, "tc_init_e", 10, true)
	if err != nil {
		t.Fatal(err)
	}
	got, recognized, err := backend.(*linuxTCBackend).MigrateLegacyFilter(context.Background(), apiFilterState(link, "tc_init_e_func", 99), spec)
	if err != nil || !recognized || !sameFilter(got, spec) || len(api.filters) != 1 || api.filters[0].Program != "tc_init_e" {
		t.Fatalf("legacy filter was not migrated before pin removal failure: recognized=%v err=%v api=%+v", recognized, err, api)
	}
	if err := backend.(*linuxTCBackend).finalizeLegacyMigrations(context.Background(), []TCFilterState{got}); err == nil {
		t.Fatal("legacy pin removal failure was not reported")
	}
	if len(api.filters) != 1 || api.filters[0].Program != "tc_init_e_func" || api.filters[0].ProgramID != 99 {
		t.Fatalf("legacy filter was not restored after pin removal failure: api=%+v", api)
	}
	if _, statErr := os.Stat(legacyPath); statErr != nil {
		t.Fatalf("legacy program pin was not preserved after pin removal failure: err=%v", statErr)
	}
}

func TestLinuxTCBackendDoesNotDeleteReplacementDuringRollback(t *testing.T) {
	root := t.TempDir()
	legacyPath := filepath.Join(root, "programs", "tc_init_e_func")
	if err := os.MkdirAll(filepath.Dir(legacyPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacyPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	legacy := &fakeTCProgram{fd: 11, id: 99, pinPath: legacyPath, unpinErr: errors.New("unpin failed")}
	current := &fakeTCProgram{fd: 17, id: 10}
	loader := &fakeTCProgramLoader{programs: map[string]tcProgram{
		legacyPath: legacy,
		filepath.Join(root, "programs", "tc_init_e"): current,
	}}
	link := linuxTestLink()
	api := &fakeTCNetlinkAPI{filters: []kernelFilter{{
		LinkIndex: link.IfIndex, Parent: 0xfffffff3, Priority: FixedTCPriority, Handle: 0x100,
		Kind: "bpf", Program: "tc_init_e_func", ProgramID: 99, DirectAction: true,
	}}}
	backend, err := newLinuxTCBackend(root, api, loader)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := NewFixedFilter(link, "tc_init_e", 10, true)
	if err != nil {
		t.Fatal(err)
	}
	got, _, err := backend.(*linuxTCBackend).MigrateLegacyFilter(context.Background(), apiFilterState(link, "tc_init_e_func", 99), spec)
	if err != nil {
		t.Fatal(err)
	}
	api.filters[0].Program = "replacement"
	api.filters[0].ProgramID = 77
	if err := backend.(*linuxTCBackend).finalizeLegacyMigrations(context.Background(), []TCFilterState{got}); err == nil {
		t.Fatal("rollback accepted a replacement filter at the same TC slot")
	}
	if api.filterDeletes != 1 || api.filters[0].Program != "replacement" || api.filters[0].ProgramID != 77 {
		t.Fatalf("replacement filter was modified during rollback: deletes=%d filters=%+v", api.filterDeletes, api.filters)
	}
}

func TestLinuxTCBackendDefersSharedLegacyPinRemoval(t *testing.T) {
	root := t.TempDir()
	legacyPath := filepath.Join(root, "programs", "tc_init_e_func")
	if err := os.MkdirAll(filepath.Dir(legacyPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacyPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	legacy := &fakeTCProgram{fd: 11, id: 99, pinPath: legacyPath}
	current := &fakeTCProgram{fd: 17, id: 10}
	loader := &fakeTCProgramLoader{programs: map[string]tcProgram{
		legacyPath: legacy,
		filepath.Join(root, "programs", "tc_init_e"): current,
	}}
	api := &fakeTCNetlinkAPI{}
	backend, err := newLinuxTCBackend(root, api, loader)
	if err != nil {
		t.Fatal(err)
	}
	linkA := linuxTestLink()
	linkB := endpoint.LinkIdentity{IfIndex: 5, NetNSInode: 10}
	specA, _ := NewFixedFilter(linkA, "tc_init_e", 10, true)
	specB, _ := NewFixedFilter(linkB, "tc_init_e", 10, true)
	legacyA := apiFilterState(linkA, "tc_init_e_func", 99)
	legacyB := apiFilterState(linkB, "tc_init_e_func", 99)
	gotA, recognized, err := backend.(*linuxTCBackend).MigrateLegacyFilter(context.Background(), legacyA, specA)
	if err != nil || !recognized {
		t.Fatalf("first shared migration failed: recognized=%v err=%v", recognized, err)
	}
	if err := backend.(*linuxTCBackend).finalizeLegacyMigrations(context.Background(), []TCFilterState{gotA, legacyB}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(legacyPath); err != nil {
		t.Fatalf("shared legacy pin was removed while another filter remained: err=%v", err)
	}
	gotB, recognized, err := backend.(*linuxTCBackend).MigrateLegacyFilter(context.Background(), legacyB, specB)
	if err != nil || !recognized {
		t.Fatalf("second shared migration failed: recognized=%v err=%v", recognized, err)
	}
	if err := backend.(*linuxTCBackend).finalizeLegacyMigrations(context.Background(), []TCFilterState{gotA, gotB}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(legacyPath); !os.IsNotExist(err) {
		t.Fatalf("shared legacy pin was not removed after all migrations: err=%v", err)
	}
}

func TestLinuxTCBackendRediscoversLegacyPinAfterRestart(t *testing.T) {
	root := t.TempDir()
	legacyPath := filepath.Join(root, "programs", "tc_init_e_func")
	currentPath := filepath.Join(root, "programs", "tc_init_e")
	if err := os.MkdirAll(filepath.Dir(legacyPath), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{legacyPath, currentPath} {
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	legacy := &fakeTCProgram{fd: 11, id: 99, pinPath: legacyPath}
	current := &fakeTCProgram{fd: 17, id: 10}
	loader := &fakeTCProgramLoader{programs: map[string]tcProgram{legacyPath: legacy, currentPath: current}}
	backend, err := newLinuxTCBackend(root, &fakeTCNetlinkAPI{}, loader)
	if err != nil {
		t.Fatal(err)
	}
	currentFilter := apiFilterState(linuxTestLink(), "tc_init_e", 10)
	if err := backend.(*linuxTCBackend).finalizeLegacyMigrations(context.Background(), []TCFilterState{currentFilter}); err != nil {
		t.Fatal(err)
	}
	if !legacy.unpinned {
		t.Fatal("stale legacy pin was not rediscovered and removed")
	}
	if _, err := os.Stat(legacyPath); !os.IsNotExist(err) {
		t.Fatalf("stale legacy pin remains after restart recovery: err=%v", err)
	}
}

func apiFilterState(link endpoint.LinkIdentity, program string, id uint32) TCFilterState {
	return TCFilterState{Link: link, Hook: HookEgress, Program: program, ProgramID: id, Priority: FixedTCPriority, Handle: 0x100, DirectAction: true}
}

func TestLinuxTCBackendListsBothHooksAndDeletesByIdentity(t *testing.T) {
	link := linuxTestLink()
	api := &fakeTCNetlinkAPI{filters: []kernelFilter{
		{LinkIndex: link.IfIndex, Parent: 0xfffffff2, Priority: FixedTCPriority, Handle: 0x201, Kind: "bpf", Program: "tc_init_in", ProgramID: 10, DirectAction: true},
	}}
	backend, _ := newLinuxTCBackend(t.TempDir(), api, &fakeTCProgramLoader{})
	filters, err := backend.ListFilters(context.Background(), link)
	if err != nil || len(filters) != 1 || filters[0].Hook != HookIngress || filters[0].ProgramID != 10 {
		t.Fatalf("unexpected filter listing: filters=%+v err=%v", filters, err)
	}
	spec, _ := NewFixedFilter(link, "tc_init_in", 10, true)
	if err := backend.RemoveFilter(context.Background(), spec); err != nil || api.filterDeletes != 1 || len(api.filters) != 0 {
		t.Fatalf("filter was not deleted: err=%v api=%+v", err, api)
	}
}

func TestTCManagerRechecksProgramIDAtLinuxBackendBoundary(t *testing.T) {
	link := linuxTestLink()
	api := &fakeTCNetlinkAPI{filters: []kernelFilter{{
		LinkIndex: link.IfIndex, Parent: 0xfffffff2, Priority: FixedTCPriority, Handle: 0x201,
		Kind: "bpf", Program: "tc_init_in", ProgramID: 10, DirectAction: true,
	}}}
	api.onListFilters = func(api *fakeTCNetlinkAPI) {
		api.filters[0].Program = "foreign"
		api.filters[0].ProgramID = 99
	}
	backend, _ := newLinuxTCBackend(t.TempDir(), api, &fakeTCProgramLoader{})
	manager, _ := NewTCManager(backend)
	spec, _ := NewFixedFilter(link, "tc_init_in", 10, true)

	err := manager.RemoveFilter(context.Background(), spec)
	var classified *reconcile.ClassifiedError
	if !errors.As(err, &classified) || classified.ReasonCode() != reconcile.ReasonTCForeignConflict ||
		api.filterDeletes != 0 || len(api.filters) != 1 || api.filters[0].ProgramID != 99 {
		t.Fatalf("foreign replacement was removed: err=%v api=%+v", err, api)
	}
}
