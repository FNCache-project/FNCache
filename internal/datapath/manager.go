package datapath

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/cilium/ebpf"
)

type MapSchema struct {
	Name       string
	Type       ebpf.MapType
	KeySize    uint32
	ValueSize  uint32
	MaxEntries uint32
	Flags      uint32
}

type CollectionSchema struct {
	Programs []string
	Maps     []MapSchema
}

type MapCapacities struct {
	IngressCacheMaxEntries  uint32
	EgressIPCacheMaxEntries uint32
	EgressCacheMaxEntries   uint32
	PolicyCacheMaxEntries   uint32
	DevMapMaxEntries        uint32
}

func DefaultMapCapacities() MapCapacities {
	return MapCapacities{
		IngressCacheMaxEntries:  1024,
		EgressIPCacheMaxEntries: 4096,
		EgressCacheMaxEntries:   1024,
		PolicyCacheMaxEntries:   4096,
		DevMapMaxEntries:        8,
	}
}

func (c MapCapacities) Validate() error {
	if c.IngressCacheMaxEntries == 0 || c.EgressIPCacheMaxEntries == 0 || c.EgressCacheMaxEntries == 0 || c.PolicyCacheMaxEntries == 0 || c.DevMapMaxEntries == 0 {
		return fmt.Errorf("Map capacities must be greater than zero")
	}
	return nil
}

type MapDescriptor struct {
	Type       ebpf.MapType
	KeySize    uint32
	ValueSize  uint32
	MaxEntries uint32
	Flags      uint32
}

type Manager struct {
	pinRoot string
	loader  KernelLoader
}

func NewManager(pinRoot string) (*Manager, error) {
	if pinRoot == "" || !filepath.IsAbs(pinRoot) || filepath.Clean(pinRoot) == string(filepath.Separator) {
		return nil, fmt.Errorf("BPF pin root must be a dedicated absolute directory")
	}
	return NewManagerWithLoader(pinRoot, ciliumLoader{})
}

func NewManagerWithLoader(pinRoot string, loader KernelLoader) (*Manager, error) {
	if pinRoot == "" || !filepath.IsAbs(pinRoot) || filepath.Clean(pinRoot) == string(filepath.Separator) {
		return nil, fmt.Errorf("BPF pin root must be a dedicated absolute directory")
	}
	if loader == nil {
		return nil, fmt.Errorf("BPF kernel loader is required")
	}
	return &Manager{pinRoot: filepath.Clean(pinRoot), loader: loader}, nil
}

func (m *Manager) LoadCollection(r io.ReaderAt, schema CollectionSchema) (*ebpf.CollectionSpec, error) {
	spec, err := ebpf.LoadCollectionSpecFromReader(r)
	if err != nil {
		return nil, fmt.Errorf("load BPF collection spec: %w", err)
	}
	if err := applyConfiguredMapCapacities(spec, schema); err != nil {
		return nil, err
	}
	if err := ValidateCollectionSpec(spec, schema); err != nil {
		return nil, err
	}
	return spec, nil
}

func (m *Manager) MapPinPath(name string) (string, error) {
	return m.pinPath("maps", name)
}

func (m *Manager) ProgramPinPath(name string) (string, error) {
	return m.pinPath("programs", name)
}

func (m *Manager) RemovePinnedMap(ctx context.Context, name string, expectedID uint32) error {
	path, err := m.MapPinPath(name)
	if err != nil {
		return err
	}
	return removePinnedMap(ctx, path, name, expectedID)
}

func (m *Manager) RemovePinnedProgram(ctx context.Context, name string, expectedID uint32) error {
	path, err := m.ProgramPinPath(name)
	if err != nil {
		return err
	}
	return removePinnedProgram(ctx, path, name, expectedID)
}

func (m *Manager) EnsureControlMap(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	path, err := m.MapPinPath("control_map")
	if err != nil {
		return err
	}
	descriptor, exists, err := m.loader.InspectMap(path)
	if err != nil {
		return fmt.Errorf("inspect control Map: %w", err)
	}
	expected := MapSchema{Name: "control_map", Type: ebpf.Array, KeySize: 4, ValueSize: 40, MaxEntries: 1, Flags: 0}
	if exists {
		return validateDescriptor(descriptor, expected)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create control Map directory: %w", err)
	}
	object, err := ebpf.NewMap(&ebpf.MapSpec{Name: expected.Name, Type: expected.Type, KeySize: expected.KeySize, ValueSize: expected.ValueSize, MaxEntries: expected.MaxEntries, Flags: expected.Flags})
	if err != nil {
		return fmt.Errorf("create control Map: %w", err)
	}
	defer object.Close()
	if err := object.Pin(path); err != nil {
		return fmt.Errorf("pin control Map: %w", err)
	}
	return nil
}

func removePinnedMap(ctx context.Context, path, name string, expectedID uint32) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	object, err := ebpf.LoadPinnedMap(path, nil)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	info, err := object.Info()
	object.Close()
	if err != nil {
		return err
	}
	id, ok := info.ID()
	if !ok || uint32(id) != expectedID {
		return fmt.Errorf("Map %s ID changed before cleanup", name)
	}
	return os.Remove(path)
}

func removePinnedProgram(ctx context.Context, path, name string, expectedID uint32) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	object, err := ebpf.LoadPinnedProgram(path, nil)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	info, err := object.Info()
	object.Close()
	if err != nil {
		return err
	}
	id, ok := info.ID()
	if !ok || uint32(id) != expectedID {
		return fmt.Errorf("program %s ID changed before cleanup", name)
	}
	return os.Remove(path)
}

func (m *Manager) LoadAndPin(spec *ebpf.CollectionSpec, schema CollectionSchema) (*LoadedCollection, error) {
	if spec == nil {
		return nil, fmt.Errorf("BPF collection spec is nil")
	}
	copySpec := spec.Copy()
	if err := applyConfiguredMapCapacities(copySpec, schema); err != nil {
		return nil, err
	}
	if err := ValidateCollectionSpec(copySpec, schema); err != nil {
		return nil, err
	}
	existingMaps := make(map[string]bool)
	for _, expected := range schema.Maps {
		path, _ := m.MapPinPath(expected.Name)
		descriptor, exists, err := m.loader.InspectMap(path)
		if err != nil {
			return nil, fmt.Errorf("inspect pinned Map %s: %w", expected.Name, err)
		}
		if exists {
			if err := validateDescriptor(descriptor, expected); err != nil {
				return nil, err
			}
			existingMaps[expected.Name] = true
		}
		copySpec.Maps[expected.Name].Pinning = ebpf.PinByName
	}
	mapDir, _ := filepath.Abs(filepath.Join(m.pinRoot, "maps"))
	programDir, _ := filepath.Abs(filepath.Join(m.pinRoot, "programs"))
	if err := os.MkdirAll(mapDir, 0700); err != nil {
		return nil, fmt.Errorf("create Map pin directory: %w", err)
	}
	if err := os.MkdirAll(programDir, 0700); err != nil {
		return nil, fmt.Errorf("create program pin directory: %w", err)
	}
	for name := range copySpec.Programs {
		path, _ := m.ProgramPinPath(name)
		if _, err := os.Stat(path); err == nil {
			return nil, fmt.Errorf("program pin already exists: %s", name)
		} else if !os.IsNotExist(err) {
			return nil, fmt.Errorf("inspect program pin %s: %w", name, err)
		}
	}
	handle, err := m.loader.Load(copySpec, ebpf.CollectionOptions{Maps: ebpf.MapOptions{PinPath: mapDir}})
	if err != nil {
		return nil, fmt.Errorf("load BPF collection: %w", err)
	}
	loaded := &LoadedCollection{handle: handle, ownedMaps: make(map[string]KernelObject), ownedPrograms: make(map[string]KernelObject)}
	for name, object := range handle.Maps {
		if !existingMaps[name] {
			loaded.ownedMaps[name] = object
		}
	}
	for name, object := range handle.Programs {
		path, _ := m.ProgramPinPath(name)
		if err := object.Pin(path); err != nil {
			_ = loaded.Unpin()
			_ = loaded.Close()
			return nil, fmt.Errorf("pin program %s: %w", name, err)
		}
		loaded.ownedPrograms[name] = object
	}
	return loaded, nil
}

type LoadedCollection struct {
	handle        *CollectionHandle
	ownedMaps     map[string]KernelObject
	ownedPrograms map[string]KernelObject
}

func (c *LoadedCollection) Unpin() error {
	var first error
	for _, object := range c.ownedPrograms {
		if err := object.Unpin(); err != nil && first == nil {
			first = err
		}
	}
	for _, object := range c.ownedMaps {
		if err := object.Unpin(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func (c *LoadedCollection) Close() error { return c.handle.Close() }

func (m *Manager) pinPath(kind, name string) (string, error) {
	if name == "" || filepath.Base(name) != name {
		return "", fmt.Errorf("invalid BPF %s name: %q", kind, name)
	}
	return filepath.Join(m.pinRoot, kind, name), nil
}

func ValidateCollectionSpec(spec *ebpf.CollectionSpec, schema CollectionSchema) error {
	if spec == nil {
		return fmt.Errorf("BPF collection spec is nil")
	}
	expectedPrograms := append([]string(nil), schema.Programs...)
	actualPrograms := make([]string, 0, len(spec.Programs))
	for name := range spec.Programs {
		actualPrograms = append(actualPrograms, name)
	}
	if err := compareNames("program", expectedPrograms, actualPrograms); err != nil {
		return err
	}
	expectedMaps := make(map[string]MapSchema, len(schema.Maps))
	for _, expected := range schema.Maps {
		if _, exists := expectedMaps[expected.Name]; exists || expected.Name == "" {
			return fmt.Errorf("invalid or duplicate Map schema name: %q", expected.Name)
		}
		expectedMaps[expected.Name] = expected
	}
	if len(spec.Maps) != len(expectedMaps) {
		return fmt.Errorf("BPF Map count mismatch: got %d want %d", len(spec.Maps), len(expectedMaps))
	}
	for name, expected := range expectedMaps {
		actual, ok := spec.Maps[name]
		if !ok {
			return fmt.Errorf("missing BPF Map: %s", name)
		}
		if err := validateMap(actual, expected); err != nil {
			return err
		}
	}
	return nil
}

// applyConfiguredMapCapacities replaces the baseline max_entries values from
// the checked-in ELF with deployment-specific capacities before validation and
// kernel map creation. Map type, key/value sizes, flags, and fixed Map sizes
// remain strict schema requirements.
func applyConfiguredMapCapacities(spec *ebpf.CollectionSpec, schema CollectionSchema) error {
	if spec == nil {
		return fmt.Errorf("BPF collection spec is nil")
	}
	for _, expected := range schema.Maps {
		actual, ok := spec.Maps[expected.Name]
		if !ok || !isConfigurableMap(expected.Name) {
			continue
		}
		actual.MaxEntries = expected.MaxEntries
	}
	return nil
}

func isConfigurableMap(name string) bool {
	switch name {
	case "egressip_cache", "egress_cache", "ingress_cache", "policy_cache", "devmap":
		return true
	default:
		return false
	}
}

func validateMap(actual *ebpf.MapSpec, expected MapSchema) error {
	got := MapDescriptor{Type: actual.Type, KeySize: actual.KeySize, ValueSize: actual.ValueSize, MaxEntries: actual.MaxEntries, Flags: actual.Flags}
	return validateDescriptor(got, expected)
}

func validateDescriptor(got MapDescriptor, expected MapSchema) error {
	if got != (MapDescriptor{Type: expected.Type, KeySize: expected.KeySize, ValueSize: expected.ValueSize, MaxEntries: expected.MaxEntries, Flags: expected.Flags}) {
		return fmt.Errorf("BPF Map schema mismatch for %s: got=%+v want=%+v", expected.Name, got, expected)
	}
	return nil
}

func compareNames(kind string, expected, actual []string) error {
	sort.Strings(expected)
	sort.Strings(actual)
	if len(expected) != len(actual) {
		return fmt.Errorf("BPF %s count mismatch: got %v want %v", kind, actual, expected)
	}
	for i := range expected {
		if expected[i] != actual[i] {
			return fmt.Errorf("BPF %s names mismatch: got %v want %v", kind, actual, expected)
		}
	}
	return nil
}

func V1Schema() CollectionSchema {
	return V1SchemaWithCapacities(DefaultMapCapacities())
}

func V1SchemaWithCapacities(capacities MapCapacities) CollectionSchema {
	return CollectionSchema{
		Programs: []string{"tc_init_e", "tc_init_in", "tc_masq", "tc_restore"},
		Maps: []MapSchema{
			{Name: "egressip_cache", Type: ebpf.LRUHash, KeySize: 4, ValueSize: 4, MaxEntries: capacities.EgressIPCacheMaxEntries},
			{Name: "egress_cache", Type: ebpf.LRUHash, KeySize: 4, ValueSize: 68, MaxEntries: capacities.EgressCacheMaxEntries},
			{Name: "ingress_cache", Type: ebpf.LRUHash, KeySize: 4, ValueSize: 16, MaxEntries: capacities.IngressCacheMaxEntries},
			{Name: "policy_cache", Type: ebpf.LRUHash, KeySize: 16, ValueSize: 4, MaxEntries: capacities.PolicyCacheMaxEntries},
			{Name: "devmap", Type: ebpf.LRUHash, KeySize: 4, ValueSize: 12, MaxEntries: capacities.DevMapMaxEntries},
			{Name: "control_map", Type: ebpf.Array, KeySize: 4, ValueSize: 40, MaxEntries: 1},
			{Name: "policy_lock_map", Type: ebpf.Array, KeySize: 4, ValueSize: 4, MaxEntries: 1},
			StatsMapSchema(),
		},
	}
}
