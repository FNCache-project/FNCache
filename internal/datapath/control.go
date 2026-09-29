package datapath

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

const controlMapABIVersion uint32 = 1

// MinHeartbeatTimeoutNS prevents a runtime lease from becoming a busy-loop
// or expiring before a normal scheduler tick can complete.
const MinHeartbeatTimeoutNS uint64 = uint64(100 * time.Millisecond)

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
type monotonicClock func() (uint64, error)

type ControlWriter struct {
	pinRoot string
	open    controlMapOpener
	now     monotonicClock
}

func NewControlWriter(pinRoot string) (*ControlWriter, error) {
	return newControlWriter(pinRoot, openPinnedControlMap)
}

func newControlWriter(pinRoot string, open controlMapOpener) (*ControlWriter, error) {
	return newControlWriterWithClock(pinRoot, open, monotonicNowNS)
}

func newControlWriterWithClock(pinRoot string, open controlMapOpener, now monotonicClock) (*ControlWriter, error) {
	if pinRoot == "" || !filepath.IsAbs(pinRoot) || filepath.Clean(pinRoot) == string(filepath.Separator) {
		return nil, fmt.Errorf("BPF pin root must be a dedicated absolute directory")
	}
	if open == nil {
		return nil, fmt.Errorf("control Map opener is required")
	}
	if now == nil {
		return nil, fmt.Errorf("monotonic clock is required")
	}
	return &ControlWriter{pinRoot: filepath.Clean(pinRoot), open: open, now: now}, nil
}

func (w *ControlWriter) Disable(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
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

func (w *ControlWriter) Publish(ctx context.Context, generation, heartbeatTimeoutNS uint64, flags uint32) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := ValidateHeartbeatTimeoutNS(heartbeatTimeoutNS); err != nil {
		return err
	}
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
	heartbeatNS, err := w.now()
	if err != nil {
		return fmt.Errorf("read monotonic clock: %w", err)
	}
	if heartbeatNS == 0 {
		return fmt.Errorf("monotonic heartbeat must be non-zero")
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

// Renew refreshes the current control Map lease without changing its
// generation, timeout, flags, or other control state. An already expired
// lease is disabled instead of being silently revived.
func (w *ControlWriter) Renew(ctx context.Context, expectedGeneration uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
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
		return fmt.Errorf("cannot renew disabled control Map")
	}
	if value.Generation != expectedGeneration {
		return fmt.Errorf("control Map generation changed: got %d want %d", value.Generation, expectedGeneration)
	}
	if err := ValidateHeartbeatTimeoutNS(value.HeartbeatTimeoutNS); err != nil {
		return err
	}
	if value.HeartbeatNS == 0 {
		return fmt.Errorf("control Map heartbeat is invalid")
	}
	now, err := w.now()
	if err != nil {
		return fmt.Errorf("read monotonic clock: %w", err)
	}
	if now < value.HeartbeatNS {
		return fmt.Errorf("monotonic clock moved backwards")
	}
	if now-value.HeartbeatNS > value.HeartbeatTimeoutNS {
		value.Enabled = 0
		if err := control.Update(key, &value, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("disable expired fast path: %w", err)
		}
		return fmt.Errorf("heartbeat lease expired")
	}
	value.HeartbeatNS = now
	if err := control.Update(key, &value, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("renew fast path: %w", err)
	}
	return nil
}

func validateControlValue(value ControlV1) error {
	if value.ABIVersion != controlMapABIVersion {
		return fmt.Errorf("control Map ABI mismatch: got %d want %d", value.ABIVersion, controlMapABIVersion)
	}
	return nil
}

// ValidateHeartbeatTimeoutNS checks that a lease timeout leaves enough time
// for normal scheduling and renewal.
func ValidateHeartbeatTimeoutNS(timeoutNS uint64) error {
	if timeoutNS < MinHeartbeatTimeoutNS {
		return fmt.Errorf("heartbeat timeout must be at least %s", time.Duration(MinHeartbeatTimeoutNS))
	}
	return nil
}

func monotonicNowNS() (uint64, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0, err
	}
	ns := ts.Nano()
	if ns <= 0 {
		return 0, fmt.Errorf("monotonic clock returned %d", ns)
	}
	return uint64(ns), nil
}

func openPinnedControlMap(path string) (controlMap, error) {
	return ebpf.LoadPinnedMap(path, nil)
}
