package datapath

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

type fakeStatsMap struct {
	info        statsMapInfo
	values      map[uint32][]uint64
	lookupErr   error
	lookupCalls int
	closed      bool
}

func (m *fakeStatsMap) Info() (statsMapInfo, error) { return m.info, nil }

func (m *fakeStatsMap) Lookup(key, valueOut any) error {
	m.lookupCalls++
	if m.lookupErr != nil {
		return m.lookupErr
	}
	values, ok := valueOut.(*[]uint64)
	if !ok {
		return errors.New("value output is not a per-CPU slice")
	}
	keyValue, ok := key.(uint32)
	if !ok {
		return errors.New("key is not uint32")
	}
	*values = append([]uint64(nil), m.values[keyValue]...)
	return nil
}

func (m *fakeStatsMap) Close() error {
	m.closed = true
	return nil
}

func validStatsMapInfo() statsMapInfo {
	schema := StatsMapSchema()
	return statsMapInfo{typ: schema.Type, keySize: schema.KeySize, valueSize: schema.ValueSize, maxEntries: schema.MaxEntries, flags: schema.Flags}
}

func newFakeStatsReader(t *testing.T, object statsMap) *StatsReader {
	t.Helper()
	path := filepath.Join(t.TempDir(), StatsMapName)
	reader, err := newStatsReader(path, func(string) (statsMap, error) { return object, nil })
	if err != nil {
		t.Fatal(err)
	}
	return reader
}

func TestStatsReaderAggregatesPerCPUValues(t *testing.T) {
	object := &fakeStatsMap{info: validStatsMapInfo(), values: map[uint32][]uint64{
		0: {1, 2, 3},
		1: {5, 8},
	}}
	reader := newFakeStatsReader(t, object)

	snapshot, err := reader.ReadOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !snapshot.Available || snapshot.Counters[0] != 6 || snapshot.Counters[1] != 13 {
		t.Fatalf("unexpected stats snapshot: %+v", snapshot)
	}
	if object.lookupCalls != StatsCounterCount || !object.closed {
		t.Fatalf("stats map lifecycle: lookups=%d closed=%v", object.lookupCalls, object.closed)
	}
}

func TestStatsReaderRejectsSchemaMismatch(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*statsMapInfo)
		want   string
	}{
		{name: "type", mutate: func(info *statsMapInfo) { info.typ = ebpf.Array }, want: "schema mismatch"},
		{name: "key size", mutate: func(info *statsMapInfo) { info.keySize++ }, want: "schema mismatch"},
		{name: "value size", mutate: func(info *statsMapInfo) { info.valueSize++ }, want: "schema mismatch"},
		{name: "entry count", mutate: func(info *statsMapInfo) { info.maxEntries++ }, want: "schema mismatch"},
		{name: "flags", mutate: func(info *statsMapInfo) { info.flags++ }, want: "schema mismatch"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			info := validStatsMapInfo()
			test.mutate(&info)
			reader := newFakeStatsReader(t, &fakeStatsMap{info: info})
			_, err := reader.ReadOnce(context.Background())
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("ReadOnce() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestStatsReaderHandlesMissingAndUnreadableMaps(t *testing.T) {
	path := filepath.Join(t.TempDir(), StatsMapName)
	reader, err := newStatsReader(path, func(string) (statsMap, error) { return nil, os.ErrNotExist })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.ReadOnce(context.Background()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing map error = %v", err)
	}

	readErr := errors.New("lookup failed")
	reader = newFakeStatsReader(t, &fakeStatsMap{info: validStatsMapInfo(), lookupErr: readErr})
	if _, err := reader.ReadOnce(context.Background()); !errors.Is(err, readErr) {
		t.Fatalf("lookup error = %v", err)
	}
}

func TestStatsCollectorUsesCachedValuesForPrometheus(t *testing.T) {
	object := &fakeStatsMap{info: validStatsMapInfo(), values: map[uint32][]uint64{0: {7, 9}}}
	collector := newStatsCollector(newFakeStatsReader(t, object), time.Hour)
	registry := prometheus.NewRegistry()
	if err := registry.Register(collector); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Gather(); err != nil {
		t.Fatalf("initial gather: %v", err)
	}
	if object.lookupCalls != 0 {
		t.Fatalf("Prometheus gather read the BPF map: %d lookups", object.lookupCalls)
	}

	collector.collect(context.Background())
	if object.lookupCalls != StatsCounterCount {
		t.Fatalf("background sample lookups = %d, want %d", object.lookupCalls, StatsCounterCount)
	}
	if _, err := registry.Gather(); err != nil {
		t.Fatalf("cached gather: %v", err)
	}
	if object.lookupCalls != StatsCounterCount {
		t.Fatalf("cached Prometheus gather performed new lookups: %d", object.lookupCalls)
	}
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	var counterFamily, availableFamily *dto.MetricFamily
	for _, family := range families {
		switch family.GetName() {
		case "oncache_datapath_counter_total":
			counterFamily = family
		case "oncache_datapath_counters_available":
			availableFamily = family
		}
	}
	if counterFamily == nil || counterFamily.GetType() != dto.MetricType_COUNTER || len(counterFamily.GetMetric()) != StatsCounterCount {
		t.Fatalf("unexpected counter family: %+v", counterFamily)
	}
	if availableFamily == nil || availableFamily.GetMetric()[0].GetGauge().GetValue() != 1 {
		t.Fatalf("unexpected availability family: %+v", availableFamily)
	}
}

func TestStatsCollectorKeepsLastValuesWhenReadFails(t *testing.T) {
	object := &fakeStatsMap{info: validStatsMapInfo(), values: map[uint32][]uint64{0: {11}}}
	collector := newStatsCollector(newFakeStatsReader(t, object), time.Hour)
	collector.collect(context.Background())
	if got := collector.Snapshot(); !got.Available || got.Counters[0] != 11 {
		t.Fatalf("successful snapshot = %+v", got)
	}

	object.lookupErr = errors.New("temporary read failure")
	collector.collect(context.Background())
	got := collector.Snapshot()
	if got.Available || got.Counters[0] != 11 {
		t.Fatalf("failed snapshot = %+v", got)
	}
}

func TestStatsDescriptorsMatchFixedABI(t *testing.T) {
	if len(statDescriptors) != StatsCounterCount {
		t.Fatalf("descriptor count = %d, want %d", len(statDescriptors), StatsCounterCount)
	}
	if got := StatsMapSchema().MaxEntries; got != StatsCounterCount {
		t.Fatalf("stats map entries = %d, want %d", got, StatsCounterCount)
	}
}
