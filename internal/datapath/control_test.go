package datapath

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
)

const testHeartbeatTimeoutNS uint64 = uint64(500 * time.Millisecond)

type fakeControlMap struct {
	value       ControlV1
	lookupErr   error
	updateErr   error
	closeErr    error
	updated     ControlV1
	lookupCalls int
	updateCalls int
	closeCalls  int
}

func (m *fakeControlMap) Lookup(_ interface{}, value interface{}) error {
	m.lookupCalls++
	if m.lookupErr != nil {
		return m.lookupErr
	}
	control, ok := value.(*ControlV1)
	if !ok {
		return errors.New("unexpected lookup value")
	}
	*control = m.value
	return nil
}

func (m *fakeControlMap) Update(_ interface{}, value interface{}, _ ebpf.MapUpdateFlags) error {
	m.updateCalls++
	if m.updateErr != nil {
		return m.updateErr
	}
	control, ok := value.(*ControlV1)
	if !ok {
		return errors.New("unexpected update value")
	}
	m.updated = *control
	return nil
}

func (m *fakeControlMap) Close() error {
	m.closeCalls++
	return m.closeErr
}

func TestControlWriterDisablePreservesControlState(t *testing.T) {
	mapValue := ControlV1{ABIVersion: 1, Enabled: 1, Generation: 42, HeartbeatNS: 100, HeartbeatTimeoutNS: 500, Flags: 3, Reserved: 7}
	fake := &fakeControlMap{value: mapValue}
	root := t.TempDir()
	writer, err := newControlWriter(root, func(path string) (controlMap, error) {
		want := filepath.Join(root, "maps", "control_map")
		if path != want {
			t.Fatalf("unexpected control Map path: got=%q want=%q", path, want)
		}
		return fake, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Disable(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fake.updated.Enabled != 0 || fake.updated.ABIVersion != mapValue.ABIVersion ||
		fake.updated.Generation != mapValue.Generation || fake.updated.HeartbeatNS != mapValue.HeartbeatNS ||
		fake.updated.HeartbeatTimeoutNS != mapValue.HeartbeatTimeoutNS || fake.updated.Flags != mapValue.Flags ||
		fake.updated.Reserved != mapValue.Reserved {
		t.Fatalf("disable did not preserve control state: got=%+v want=%+v", fake.updated, mapValue)
	}
	if fake.lookupCalls != 1 || fake.updateCalls != 1 || fake.closeCalls != 1 {
		t.Fatalf("unexpected Map calls: lookup=%d update=%d close=%d", fake.lookupCalls, fake.updateCalls, fake.closeCalls)
	}
}

func TestControlWriterInitializeDisablesAndResetsState(t *testing.T) {
	fake := &fakeControlMap{value: ControlV1{ABIVersion: 1, Enabled: 1, Generation: 9, HeartbeatNS: 10, HeartbeatTimeoutNS: 20, Flags: 3, Reserved: 4}}
	writer, err := newControlWriter(t.TempDir(), func(string) (controlMap, error) { return fake, nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Initialize(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fake.updated != (ControlV1{ABIVersion: 1}) {
		t.Fatalf("unexpected initialized control state: %+v", fake.updated)
	}
}

func TestControlWriterInitializeRejectsIncompatibleOrFailedMap(t *testing.T) {
	tests := []struct {
		name      string
		value     ControlV1
		lookupErr error
		updateErr error
		want      string
	}{
		{name: "ABI mismatch", value: ControlV1{ABIVersion: 2}, want: "ABI mismatch"},
		{name: "lookup failure", lookupErr: errors.New("lookup failed"), want: "read control Map"},
		{name: "update failure", updateErr: errors.New("update failed"), want: "initialize control Map"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fake := &fakeControlMap{value: test.value, lookupErr: test.lookupErr, updateErr: test.updateErr}
			writer, err := newControlWriter(t.TempDir(), func(string) (controlMap, error) { return fake, nil })
			if err != nil {
				t.Fatal(err)
			}
			if err := writer.Initialize(context.Background()); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("unexpected initialize error: %v", err)
			}
		})
	}
}

func TestControlWriterDisableRejectsInvalidOrUnavailableMap(t *testing.T) {
	tests := []struct {
		name      string
		value     ControlV1
		lookupErr error
		updateErr error
		want      string
	}{
		{name: "ABI mismatch", value: ControlV1{ABIVersion: 2}, want: "ABI mismatch"},
		{name: "lookup failure", lookupErr: errors.New("lookup failed"), want: "read control Map"},
		{name: "update failure", value: ControlV1{ABIVersion: 1}, updateErr: errors.New("update failed"), want: "disable fast path"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fake := &fakeControlMap{value: test.value, lookupErr: test.lookupErr, updateErr: test.updateErr}
			writer, err := newControlWriter(t.TempDir(), func(string) (controlMap, error) { return fake, nil })
			if err != nil {
				t.Fatal(err)
			}
			if err := writer.Disable(context.Background()); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("unexpected disable error: %v", err)
			}
		})
	}
}

func TestControlWriterPublishEnablesNewGeneration(t *testing.T) {
	fake := &fakeControlMap{value: ControlV1{ABIVersion: 1, Enabled: 0, Generation: 4, Flags: 1}}
	writer, err := newControlWriterWithClock(t.TempDir(), func(string) (controlMap, error) { return fake, nil }, func() (uint64, error) { return 100, nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Publish(context.Background(), 42, testHeartbeatTimeoutNS, 3); err != nil {
		t.Fatal(err)
	}
	if fake.updated.Enabled != 1 || fake.updated.Generation != 42 || fake.updated.HeartbeatNS != 100 ||
		fake.updated.HeartbeatTimeoutNS != testHeartbeatTimeoutNS || fake.updated.Flags != 3 || fake.updated.Reserved != 0 {
		t.Fatalf("unexpected published control state: %+v", fake.updated)
	}
}

func TestControlWriterPublishRejectsInvalidHeartbeat(t *testing.T) {
	called := false
	writer, _ := newControlWriter(t.TempDir(), func(string) (controlMap, error) {
		called = true
		return &fakeControlMap{value: ControlV1{ABIVersion: 1}}, nil
	})
	if err := writer.Publish(context.Background(), 1, 0, 0); err == nil || called {
		t.Fatalf("invalid heartbeat was accepted: err=%v called=%v", err, called)
	}
}

func TestControlWriterRenewRefreshesHeartbeat(t *testing.T) {
	fake := &fakeControlMap{value: ControlV1{ABIVersion: 1, Enabled: 1, Generation: 42, HeartbeatNS: 100, HeartbeatTimeoutNS: testHeartbeatTimeoutNS, Flags: 3, Reserved: 7}}
	writer, err := newControlWriterWithClock(t.TempDir(), func(string) (controlMap, error) { return fake, nil }, func() (uint64, error) { return 200, nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Renew(context.Background(), 42); err != nil {
		t.Fatal(err)
	}
	if fake.updated.Enabled != 1 || fake.updated.Generation != 42 || fake.updated.HeartbeatNS != 200 ||
		fake.updated.HeartbeatTimeoutNS != testHeartbeatTimeoutNS || fake.updated.Flags != 3 || fake.updated.Reserved != 7 {
		t.Fatalf("unexpected renewed control state: %+v", fake.updated)
	}
}

func TestControlWriterRenewDisablesExpiredLease(t *testing.T) {
	fake := &fakeControlMap{value: ControlV1{ABIVersion: 1, Enabled: 1, Generation: 42, HeartbeatNS: 100, HeartbeatTimeoutNS: testHeartbeatTimeoutNS}}
	writer, err := newControlWriterWithClock(t.TempDir(), func(string) (controlMap, error) { return fake, nil }, func() (uint64, error) { return testHeartbeatTimeoutNS + 1000, nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Renew(context.Background(), 42); err == nil || !strings.Contains(err.Error(), "heartbeat lease expired") {
		t.Fatalf("expired lease was accepted: %v", err)
	}
	if fake.updated.Enabled != 0 {
		t.Fatalf("expired lease remained enabled: %+v", fake.updated)
	}
}

func TestControlWriterRenewRejectsGenerationChange(t *testing.T) {
	fake := &fakeControlMap{value: ControlV1{ABIVersion: 1, Enabled: 1, Generation: 42, HeartbeatNS: 100, HeartbeatTimeoutNS: testHeartbeatTimeoutNS}}
	writer, err := newControlWriterWithClock(t.TempDir(), func(string) (controlMap, error) { return fake, nil }, func() (uint64, error) { return 200, nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Renew(context.Background(), 43); err == nil || !strings.Contains(err.Error(), "generation changed") {
		t.Fatalf("generation mismatch was accepted: %v", err)
	}
	if fake.updateCalls != 0 {
		t.Fatalf("generation mismatch updated the control Map: calls=%d", fake.updateCalls)
	}
}

func TestControlWriterDisableHonorsCancellation(t *testing.T) {
	called := false
	writer, _ := newControlWriter(t.TempDir(), func(string) (controlMap, error) {
		called = true
		return &fakeControlMap{}, nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := writer.Disable(ctx); !errors.Is(err, context.Canceled) || called {
		t.Fatalf("unexpected cancellation result: err=%v called=%v", err, called)
	}
}
