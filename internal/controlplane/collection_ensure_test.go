package controlplane

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/cat-cc-Lcos/FNCache/internal/datapath"
	"github.com/cat-cc-Lcos/FNCache/internal/hostnet/discovery"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

type fakeCollectionHandle struct {
	unpinCalls int
	closeCalls int
}

func (h *fakeCollectionHandle) Unpin() error { h.unpinCalls++; return nil }
func (h *fakeCollectionHandle) Close() error { h.closeCalls++; return nil }

func TestCollectionEnsurerSkipsReadyCollection(t *testing.T) {
	spec := testCollectionSpec()
	assertCollectionReadyNoop(t, spec, readyCollectionState(t, spec))
}

func TestCollectionEnsurerAcceptsSHA256ProgramTags(t *testing.T) {
	spec := testCollectionSpec()
	actual := readyCollectionStateWithHash(t, spec, sha256.New)
	assertCollectionReadyNoop(t, spec, actual)
}

func TestCollectionEnsurerUsesConfiguredMapCapacities(t *testing.T) {
	capacities := datapath.DefaultMapCapacities()
	capacities.IngressCacheMaxEntries = 2048
	capacities.DevMapMaxEntries = 16
	schema := datapath.V1SchemaWithCapacities(capacities)
	spec := testCollectionSpecWithSchema(schema)
	actual := readyCollectionStateWithSchema(t, spec, schema, sha1.New)
	elf := filepath.Join(t.TempDir(), "datapath.o")
	if err := os.WriteFile(elf, []byte("elf"), 0600); err != nil {
		t.Fatal(err)
	}
	ensurer, err := newCollectionEnsurerWithSchema(elf, filepath.Join(t.TempDir(), "bpf"), schema, func(string) (collectionOps, error) {
		return collectionOps{
			loadCollection: func(io.ReaderAt, datapath.CollectionSchema) (*ebpf.CollectionSpec, error) {
				return spec, nil
			},
			loadAndPin: func(*ebpf.CollectionSpec, datapath.CollectionSchema) (collectionHandle, error) {
				return nil, errors.New("configured collection should be ready")
			},
		}, nil
	}, func(context.Context, string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if changed, err := ensurer.EnsureCollection(context.Background(), reconcile.DesiredState{Enabled: true}, actual); err != nil || changed {
		t.Fatalf("configured collection was not treated as ready: changed=%v err=%v", changed, err)
	}
}

func TestCollectionEnsurerDoesNotSkipStaleProgram(t *testing.T) {
	elf := filepath.Join(t.TempDir(), "datapath.o")
	if err := os.WriteFile(elf, []byte("elf"), 0600); err != nil {
		t.Fatal(err)
	}
	spec := testCollectionSpec()
	handle := &fakeCollectionHandle{}
	loaded := false
	ensurer, err := newCollectionEnsurer(elf, filepath.Join(t.TempDir(), "bpf"), func(string) (collectionOps, error) {
		return collectionOps{
			loadCollection: func(io.ReaderAt, datapath.CollectionSchema) (*ebpf.CollectionSpec, error) {
				return spec, nil
			},
			loadAndPin: func(*ebpf.CollectionSpec, datapath.CollectionSchema) (collectionHandle, error) {
				loaded = true
				return handle, nil
			},
		}, nil
	}, func(context.Context, string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	actual := readyCollectionState(t, spec)
	staleProgram := actual.Programs["tc_masq"]
	staleProgram.Tag = "stale-program-tag"
	actual.Programs["tc_masq"] = staleProgram
	if changed, err := ensurer.EnsureCollection(context.Background(), reconcile.DesiredState{Enabled: true}, actual); err != nil || !changed || !loaded || handle.closeCalls != 1 {
		t.Fatalf("stale program was incorrectly treated as ready: changed=%v err=%v loaded=%v handle=%+v", changed, err, loaded, handle)
	}
}

func TestCollectionEnsurerLoadsPinsAndInitializesControl(t *testing.T) {
	elf := filepath.Join(t.TempDir(), "datapath.o")
	if err := os.WriteFile(elf, []byte("elf"), 0600); err != nil {
		t.Fatal(err)
	}
	handle := &fakeCollectionHandle{}
	loaded := false
	initialized := false
	ensurer, err := newCollectionEnsurer(elf, filepath.Join(t.TempDir(), "bpf"), func(string) (collectionOps, error) {
		return collectionOps{
			loadCollection: func(io.ReaderAt, datapath.CollectionSchema) (*ebpf.CollectionSpec, error) {
				return &ebpf.CollectionSpec{}, nil
			},
			loadAndPin: func(*ebpf.CollectionSpec, datapath.CollectionSchema) (collectionHandle, error) {
				loaded = true
				return handle, nil
			},
		}, nil
	}, func(context.Context, string) error {
		initialized = true
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	changed, err := ensurer.EnsureCollection(context.Background(), reconcile.DesiredState{Enabled: true}, reconcile.ActualState{})
	if err != nil || !changed || !loaded || !initialized || handle.closeCalls != 1 || handle.unpinCalls != 0 {
		t.Fatalf("collection was not ensured: changed=%v err=%v loaded=%v initialized=%v handle=%+v", changed, err, loaded, initialized, handle)
	}
}

func TestCollectionEnsurerRollsBackWhenControlInitializationFails(t *testing.T) {
	elf := filepath.Join(t.TempDir(), "datapath.o")
	if err := os.WriteFile(elf, []byte("elf"), 0600); err != nil {
		t.Fatal(err)
	}
	handle := &fakeCollectionHandle{}
	want := errors.New("control init failed")
	ensurer, err := newCollectionEnsurer(elf, filepath.Join(t.TempDir(), "bpf"), func(string) (collectionOps, error) {
		return collectionOps{
			loadCollection: func(io.ReaderAt, datapath.CollectionSchema) (*ebpf.CollectionSpec, error) {
				return &ebpf.CollectionSpec{}, nil
			},
			loadAndPin: func(*ebpf.CollectionSpec, datapath.CollectionSchema) (collectionHandle, error) { return handle, nil },
		}, nil
	}, func(context.Context, string) error { return want })
	if err != nil {
		t.Fatal(err)
	}
	if changed, err := ensurer.EnsureCollection(context.Background(), reconcile.DesiredState{Enabled: true}, reconcile.ActualState{}); err == nil || !errors.Is(err, want) || changed || handle.unpinCalls != 1 || handle.closeCalls != 1 {
		t.Fatalf("control failure was not rolled back: changed=%v err=%v handle=%+v", changed, err, handle)
	}
}

func assertCollectionReadyNoop(t *testing.T, spec *ebpf.CollectionSpec, actual reconcile.ActualState) {
	t.Helper()
	elf := filepath.Join(t.TempDir(), "datapath.o")
	if err := os.WriteFile(elf, []byte("elf"), 0600); err != nil {
		t.Fatal(err)
	}
	loaded := false
	ensurer, err := newCollectionEnsurer(elf, "/sys/fs/bpf/oncache/v1", func(string) (collectionOps, error) {
		return collectionOps{
			loadCollection: func(io.ReaderAt, datapath.CollectionSchema) (*ebpf.CollectionSpec, error) {
				return spec, nil
			},
			loadAndPin: func(*ebpf.CollectionSpec, datapath.CollectionSchema) (collectionHandle, error) {
				loaded = true
				return nil, errors.New("ready collection should not be loaded")
			},
		}, nil
	}, func(context.Context, string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if changed, err := ensurer.EnsureCollection(context.Background(), reconcile.DesiredState{Enabled: true}, actual); err != nil || changed || loaded {
		t.Fatalf("ready collection was not a no-op: changed=%v err=%v loaded=%v", changed, err, loaded)
	}
}

func TestCollectionEnsurerRepairsMissingControlPin(t *testing.T) {
	elf := filepath.Join(t.TempDir(), "datapath.o")
	if err := os.WriteFile(elf, []byte("elf"), 0600); err != nil {
		t.Fatal(err)
	}
	ensured := false
	loaded := &fakeCollectionHandle{}
	ensurer, err := newCollectionEnsurer(elf, filepath.Join(t.TempDir(), "bpf"), func(string) (collectionOps, error) {
		return collectionOps{
			loadCollection: func(io.ReaderAt, datapath.CollectionSchema) (*ebpf.CollectionSpec, error) {
				return &ebpf.CollectionSpec{}, nil
			},
			ensureControl: func(context.Context) error { ensured = true; return nil },
			loadAndPin:    func(*ebpf.CollectionSpec, datapath.CollectionSchema) (collectionHandle, error) { return loaded, nil },
		}, nil
	}, func(context.Context, string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	actual := readyCollectionState(t, testCollectionSpec())
	delete(actual.Maps, "control_map")
	if changed, err := ensurer.EnsureCollection(context.Background(), reconcile.DesiredState{Enabled: true}, actual); err != nil || !changed || !ensured || loaded.closeCalls != 0 {
		t.Fatalf("partial collection was not repaired: changed=%v err=%v ensured=%v handle=%+v", changed, err, ensured, loaded)
	}
}

func TestCollectionEnsurerRecoversPartialProgramPins(t *testing.T) {
	elf := filepath.Join(t.TempDir(), "datapath.o")
	if err := os.WriteFile(elf, []byte("elf"), 0600); err != nil {
		t.Fatal(err)
	}
	spec := testCollectionSpec()
	handle := &fakeCollectionHandle{}
	removed := make([]string, 0)
	loaded := false
	initialized := false
	ensurer, err := newCollectionEnsurer(elf, filepath.Join(t.TempDir(), "bpf"), func(string) (collectionOps, error) {
		return collectionOps{
			loadCollection: func(io.ReaderAt, datapath.CollectionSchema) (*ebpf.CollectionSpec, error) {
				return spec, nil
			},
			loadAndPin: func(*ebpf.CollectionSpec, datapath.CollectionSchema) (collectionHandle, error) {
				loaded = true
				return handle, nil
			},
			removeProgram: func(_ context.Context, name string, id uint32) error {
				if id != 1 {
					t.Fatalf("program %s was removed with ID %d, want 1", name, id)
				}
				removed = append(removed, name)
				return nil
			},
		}, nil
	}, func(context.Context, string) error {
		initialized = true
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	actual := readyCollectionState(t, spec)
	delete(actual.Programs, "tc_restore")
	actual.Control = reconcile.ControlState{Verified: true}

	changed, err := ensurer.EnsureCollection(context.Background(), reconcile.DesiredState{Enabled: true}, actual)
	wantRemoved := []string{"tc_init_e", "tc_init_in", "tc_masq"}
	if err != nil || !changed || !loaded || !initialized || handle.closeCalls != 1 || len(removed) != len(wantRemoved) {
		t.Fatalf("partial program pins were not recovered: changed=%v err=%v loaded=%v initialized=%v removed=%v handle=%+v", changed, err, loaded, initialized, removed, handle)
	}
	for index, name := range wantRemoved {
		if removed[index] != name {
			t.Fatalf("removed program %d = %q, want %q", index, removed[index], name)
		}
	}
}

func TestCollectionEnsurerRefusesUnsafePartialProgramRecovery(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*reconcile.ActualState)
	}{
		{name: "attached", mutate: func(actual *reconcile.ActualState) {
			actual.Attachments = []reconcile.AttachmentState{{Program: "tc_init_e", ProgramID: 1}}
		}},
		{name: "enabled", mutate: func(actual *reconcile.ActualState) {
			actual.Control.Enabled = true
		}},
		{name: "TC conflict", mutate: func(actual *reconcile.ActualState) {
			actual.Conflicts = []discovery.Conflict{{Kind: "tc-filter", Identity: "foreign"}}
		}},
		{name: "stale program", mutate: func(actual *reconcile.ActualState) {
			program := actual.Programs["tc_init_e"]
			program.Tag = "stale-program-tag"
			actual.Programs["tc_init_e"] = program
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			elf := filepath.Join(t.TempDir(), "datapath.o")
			if err := os.WriteFile(elf, []byte("elf"), 0600); err != nil {
				t.Fatal(err)
			}
			spec := testCollectionSpec()
			removed := 0
			loaded := false
			ensurer, err := newCollectionEnsurer(elf, filepath.Join(t.TempDir(), "bpf"), func(string) (collectionOps, error) {
				return collectionOps{
					loadCollection: func(io.ReaderAt, datapath.CollectionSchema) (*ebpf.CollectionSpec, error) {
						return spec, nil
					},
					loadAndPin: func(*ebpf.CollectionSpec, datapath.CollectionSchema) (collectionHandle, error) {
						loaded = true
						return &fakeCollectionHandle{}, nil
					},
					removeProgram: func(context.Context, string, uint32) error {
						removed++
						return nil
					},
				}, nil
			}, func(context.Context, string) error { return nil })
			if err != nil {
				t.Fatal(err)
			}
			actual := readyCollectionState(t, spec)
			delete(actual.Programs, "tc_restore")
			actual.Control = reconcile.ControlState{Verified: true}
			tt.mutate(&actual)

			if changed, err := ensurer.EnsureCollection(context.Background(), reconcile.DesiredState{Enabled: true}, actual); err == nil || changed || loaded || removed != 0 {
				t.Fatalf("unsafe partial recovery was not rejected: changed=%v err=%v loaded=%v removed=%d", changed, err, loaded, removed)
			}
		})
	}
}

func TestCollectionEnsurerDoesNotRecoverProgramPinOrphan(t *testing.T) {
	elf := filepath.Join(t.TempDir(), "datapath.o")
	if err := os.WriteFile(elf, []byte("elf"), 0600); err != nil {
		t.Fatal(err)
	}
	spec := testCollectionSpec()
	wantErr := errors.New("existing program pin")
	loaded := false
	removed := 0
	ensurer, err := newCollectionEnsurer(elf, filepath.Join(t.TempDir(), "bpf"), func(string) (collectionOps, error) {
		return collectionOps{
			loadCollection: func(io.ReaderAt, datapath.CollectionSchema) (*ebpf.CollectionSpec, error) {
				return spec, nil
			},
			loadAndPin: func(*ebpf.CollectionSpec, datapath.CollectionSchema) (collectionHandle, error) {
				loaded = true
				return nil, wantErr
			},
			removeProgram: func(context.Context, string, uint32) error {
				removed++
				return nil
			},
		}, nil
	}, func(context.Context, string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	actual := readyCollectionState(t, spec)
	delete(actual.Programs, "tc_restore")
	actual.Control = reconcile.ControlState{Verified: true}
	actual.Orphans = []reconcile.OwnedObject{{Kind: "program-pin", Identity: "/sys/fs/bpf/oncache/v1/programs/foreign"}}

	changed, err := ensurer.EnsureCollection(context.Background(), reconcile.DesiredState{Enabled: true}, actual)
	if !errors.Is(err, wantErr) || changed || !loaded || removed != 0 {
		t.Fatalf("program-pin orphan entered recovery: changed=%v err=%v loaded=%v removed=%d", changed, err, loaded, removed)
	}
}

func readyCollectionState(t *testing.T, spec *ebpf.CollectionSpec) reconcile.ActualState {
	return readyCollectionStateWithHash(t, spec, sha1.New)
}

func readyCollectionStateWithHash(t *testing.T, spec *ebpf.CollectionSpec, digest func() hash.Hash) reconcile.ActualState {
	return readyCollectionStateWithSchema(t, spec, datapath.V1Schema(), digest)
}

func readyCollectionStateWithSchema(t *testing.T, spec *ebpf.CollectionSpec, schema datapath.CollectionSchema, digest func() hash.Hash) reconcile.ActualState {
	t.Helper()
	actual := reconcile.ActualState{Programs: make(map[string]reconcile.ProgramState), Maps: make(map[string]reconcile.MapState)}
	for _, name := range schema.Programs {
		program := spec.Programs[name]
		tag := instructionTag(t, program.Instructions, digest)
		actual.Programs[name] = reconcile.ProgramState{ID: 1, Name: name, Tag: tag}
	}
	for _, expected := range schema.Maps {
		actual.Maps[expected.Name] = reconcile.MapState{ID: 1, Name: expected.Name, KeySize: expected.KeySize, ValueSize: expected.ValueSize, MaxEntries: expected.MaxEntries}
	}
	return actual
}

func instructionTag(t *testing.T, instructions asm.Instructions, digest func() hash.Hash) string {
	t.Helper()
	h := digest()
	if err := instructions.Marshal(h, binary.LittleEndian); err != nil {
		t.Fatalf("marshal instructions for tag: %v", err)
	}
	return hex.EncodeToString(h.Sum(nil)[:8])
}

func testCollectionSpec() *ebpf.CollectionSpec {
	return testCollectionSpecWithSchema(datapath.V1Schema())
}

func testCollectionSpecWithSchema(schema datapath.CollectionSchema) *ebpf.CollectionSpec {
	spec := &ebpf.CollectionSpec{Programs: make(map[string]*ebpf.ProgramSpec), Maps: make(map[string]*ebpf.MapSpec)}
	for index, name := range schema.Programs {
		spec.Programs[name] = &ebpf.ProgramSpec{
			Name:         name,
			Instructions: asm.Instructions{asm.LoadImm(asm.R0, int64(index), asm.DWord), asm.Return()},
		}
	}
	for _, expected := range schema.Maps {
		spec.Maps[expected.Name] = &ebpf.MapSpec{
			Name: expected.Name, Type: expected.Type, KeySize: expected.KeySize,
			ValueSize: expected.ValueSize, MaxEntries: expected.MaxEntries, Flags: expected.Flags,
		}
	}
	return spec
}
