package datapath

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"

	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
	"github.com/cilium/ebpf"
)

const controlMapABIVersion uint32 = 1

type ControlV1 struct {
	ABIVersion         uint32
	Enabled            uint32
	Generation         uint64
	HeartbeatNS        uint64
	HeartbeatTimeoutNS uint64
	Flags              uint32
	Reserved           uint32
}

type controlMap interface {
	Lookup(interface{}, interface{}) error
	Update(interface{}, interface{}, ebpf.MapUpdateFlags) error
	Close() error
}

type controlMapOpener func(string) (controlMap, error)

func readControlState(control controlMap) (reconcile.ControlState, error) {
	key := uint32(0)
	var value ControlV1
	if err := control.Lookup(key, &value); err != nil {
		return reconcile.ControlState{}, fmt.Errorf("read control Map: %w", err)
	}
	if err := validateControlValue(value); err != nil {
		return reconcile.ControlState{}, err
	}
	if value.Enabled > 1 {
		return reconcile.ControlState{}, fmt.Errorf("invalid control Map enabled value: %d", value.Enabled)
	}
	return reconcile.ControlState{Verified: true, Enabled: value.Enabled == 1, Generation: value.Generation}, nil
}

type ControlWriter struct {
	pinRoot string
	open    controlMapOpener
	mu      sync.Mutex
}

func NewControlWriter(pinRoot string) (*ControlWriter, error) {
	return newControlWriter(pinRoot, openPinnedControlMap)
}

func newControlWriter(pinRoot string, open controlMapOpener) (*ControlWriter, error) {
	if pinRoot == "" || !filepath.IsAbs(pinRoot) || filepath.Clean(pinRoot) == string(filepath.Separator) {
		return nil, fmt.Errorf("BPF pin root must be a dedicated absolute directory")
	}
	if open == nil {
		return nil, fmt.Errorf("control Map opener is required")
	}
	return &ControlWriter{pinRoot: filepath.Clean(pinRoot), open: open}, nil
}

func (w *ControlWriter) Disable(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	path := filepath.Join(w.pinRoot, "maps", "control_map")
	control, err := w.open(path)
	if err != nil {
		return fmt.Errorf("open control Map: %w", err)
	}
	defer func() { _ = control.Close() }()

	key := uint32(0)
	var value ControlV1
	if err := control.Lookup(key, &value); err != nil {
		return fmt.Errorf("read control Map: %w", err)
	}
	if value.ABIVersion == 0 {
		value = ControlV1{ABIVersion: controlMapABIVersion}
	} else if err := validateControlValue(value); err != nil {
		return err
	}
	value.Enabled = 0
	if err := control.Update(key, &value, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("disable fast path: %w", err)
	}
	return nil
}

// Initialize creates a safe, disabled control value for a newly pinned Map or
// resets a compatible value before the collection is wired into TC.
func (w *ControlWriter) Initialize(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	path := filepath.Join(w.pinRoot, "maps", "control_map")
	control, err := w.open(path)
	if err != nil {
		return fmt.Errorf("open control Map: %w", err)
	}
	defer func() { _ = control.Close() }()

	key := uint32(0)
	var current ControlV1
	if err := control.Lookup(key, &current); err != nil {
		return fmt.Errorf("read control Map: %w", err)
	}
	if current.ABIVersion != 0 && current.ABIVersion != controlMapABIVersion {
		return fmt.Errorf("control Map ABI mismatch: got %d want %d", current.ABIVersion, controlMapABIVersion)
	}
	value := ControlV1{ABIVersion: controlMapABIVersion}
	if err := control.Update(key, &value, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("initialize control Map: %w", err)
	}
	return nil
}

func (w *ControlWriter) Publish(ctx context.Context, generation, heartbeatNS, heartbeatTimeoutNS uint64, flags uint32) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if heartbeatNS == 0 || heartbeatTimeoutNS == 0 {
		return fmt.Errorf("heartbeat values must be non-zero")
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	path := filepath.Join(w.pinRoot, "maps", "control_map")
	control, err := w.open(path)
	if err != nil {
		return fmt.Errorf("open control Map: %w", err)
	}
	defer func() { _ = control.Close() }()

	key := uint32(0)
	var value ControlV1
	if err := control.Lookup(key, &value); err != nil {
		return fmt.Errorf("read control Map: %w", err)
	}
	if err := validateControlValue(value); err != nil {
		return err
	}
	value.Enabled = 1
	value.Generation = generation
	value.HeartbeatNS = heartbeatNS
	value.HeartbeatTimeoutNS = heartbeatTimeoutNS
	value.Flags = flags
	value.Reserved = 0
	if err := control.Update(key, &value, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("publish fast path: %w", err)
	}
	return nil
}

func (w *ControlWriter) RefreshHeartbeat(ctx context.Context, heartbeatNS uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if heartbeatNS == 0 {
		return fmt.Errorf("heartbeat value must be non-zero")
	}
	w.mu.Lock()
	defer w.mu.Unlock()

	path := filepath.Join(w.pinRoot, "maps", "control_map")
	control, err := w.open(path)
	if err != nil {
		return fmt.Errorf("open control Map: %w", err)
	}
	defer func() { _ = control.Close() }()

	key := uint32(0)
	var value ControlV1
	if err := control.Lookup(key, &value); err != nil {
		return fmt.Errorf("read control Map: %w", err)
	}
	if err := validateControlValue(value); err != nil {
		return err
	}
	if value.Enabled != 1 {
		return nil
	}
	value.HeartbeatNS = heartbeatNS
	if err := control.Update(key, &value, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("refresh heartbeat: %w", err)
	}
	return nil
}

func validateControlValue(value ControlV1) error {
	if value.ABIVersion != controlMapABIVersion {
		return fmt.Errorf("control Map ABI mismatch: got %d want %d", value.ABIVersion, controlMapABIVersion)
	}
	return nil
}

func openPinnedControlMap(path string) (controlMap, error) {
	return ebpf.LoadPinnedMap(path, nil)
}
