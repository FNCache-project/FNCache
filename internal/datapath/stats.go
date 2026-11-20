package datapath

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	StatsMapName             = "stats_map"
	StatsCounterCount        = 14
	ControlFlagDebugCounters = uint32(1 << 1)
	statsCollectionInterval  = 10 * time.Second
)

type statDescriptor struct {
	stage  string
	reason string
}

var statDescriptors = [...]statDescriptor{
	{stage: "init_e", reason: "policy_lookup_miss"},
	{stage: "masq", reason: "policy_miss"},
	{stage: "masq", reason: "egressip_miss"},
	{stage: "masq", reason: "egress_cache_miss"},
	{stage: "masq", reason: "ingress_not_ready"},
	{stage: "masq", reason: "adjust_room_fail"},
	{stage: "restore", reason: "policy_miss"},
	{stage: "restore", reason: "devinfo_mismatch"},
	{stage: "restore", reason: "outer_ip_mismatch"},
	{stage: "restore", reason: "pod_not_ready"},
	{stage: "restore", reason: "egressip_miss"},
	{stage: "restore", reason: "adjust_room_fail"},
	{stage: "init_in", reason: "endpoint_miss"},
	{stage: "init_in", reason: "policy_lookup_miss"},
}

type statsMapInfo struct {
	typ        ebpf.MapType
	keySize    uint32
	valueSize  uint32
	maxEntries uint32
	flags      uint32
}

type statsMap interface {
	Info() (statsMapInfo, error)
	Lookup(any, any) error
	Close() error
}

type statsMapOpener func(string) (statsMap, error)

type StatsSnapshot struct {
	Available bool
	Counters  [StatsCounterCount]uint64
}

type StatsReader struct {
	path string
	open statsMapOpener
}

func NewStatsReader(pinRoot string) (*StatsReader, error) {
	if pinRoot == "" || !filepath.IsAbs(pinRoot) || filepath.Clean(pinRoot) == string(filepath.Separator) {
		return nil, fmt.Errorf("BPF pin root must be a dedicated absolute directory")
	}
	return newStatsReader(filepath.Join(filepath.Clean(pinRoot), "maps", StatsMapName), openPinnedStatsMap)
}

func newStatsReader(path string, open statsMapOpener) (*StatsReader, error) {
	if path == "" || !filepath.IsAbs(path) {
		return nil, fmt.Errorf("stats Map path must be absolute")
	}
	if open == nil {
		return nil, fmt.Errorf("stats Map opener is required")
	}
	return &StatsReader{path: filepath.Clean(path), open: open}, nil
}

func (r *StatsReader) ReadOnce(ctx context.Context) (StatsSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return StatsSnapshot{}, err
	}
	object, err := r.open(r.path)
	if err != nil {
		return StatsSnapshot{}, fmt.Errorf("open stats Map: %w", err)
	}
	defer func() { _ = object.Close() }()

	info, err := object.Info()
	if err != nil {
		return StatsSnapshot{}, fmt.Errorf("inspect stats Map: %w", err)
	}
	expected := StatsMapSchema()
	if got := (MapDescriptor{Type: info.typ, KeySize: info.keySize, ValueSize: info.valueSize, MaxEntries: info.maxEntries, Flags: info.flags}); got != (MapDescriptor{Type: expected.Type, KeySize: expected.KeySize, ValueSize: expected.ValueSize, MaxEntries: expected.MaxEntries, Flags: expected.Flags}) {
		return StatsSnapshot{}, fmt.Errorf("stats Map schema mismatch: got=%+v want=%+v", got, expected)
	}

	snapshot := StatsSnapshot{Available: true}
	for id := range statDescriptors {
		if err := ctx.Err(); err != nil {
			return StatsSnapshot{}, err
		}
		key := uint32(id)
		var perCPU []uint64
		if err := object.Lookup(key, &perCPU); err != nil {
			return StatsSnapshot{}, fmt.Errorf("read stats Map key %d: %w", id, err)
		}
		for _, value := range perCPU {
			snapshot.Counters[id] += value
		}
	}
	return snapshot, nil
}

func StatsMapSchema() MapSchema {
	return MapSchema{
		Name:       StatsMapName,
		Type:       ebpf.PerCPUArray,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: StatsCounterCount,
		Flags:      0,
	}
}

type StatsCollector struct {
	reader   *StatsReader
	interval time.Duration
	current  atomic.Pointer[StatsSnapshot]

	counterTotal *prometheus.Desc
	available    *prometheus.Desc
}

func NewStatsCollector(pinRoot string) (*StatsCollector, error) {
	reader, err := NewStatsReader(pinRoot)
	if err != nil {
		return nil, err
	}
	return newStatsCollector(reader, statsCollectionInterval), nil
}

func newStatsCollector(reader *StatsReader, interval time.Duration) *StatsCollector {
	if interval <= 0 {
		interval = statsCollectionInterval
	}
	return &StatsCollector{
		reader:   reader,
		interval: interval,
		counterTotal: prometheus.NewDesc(
			"oncache_datapath_counter_total",
			"Cumulative datapath miss and error counters read from the eBPF stats map.",
			[]string{"stage", "reason"}, nil,
		),
		available: prometheus.NewDesc(
			"oncache_datapath_counters_available",
			"Whether the latest eBPF datapath counter sample was available.",
			nil, nil,
		),
	}
}

func (c *StatsCollector) Run(ctx context.Context) {
	if c == nil || c.reader == nil {
		return
	}
	c.collect(ctx)
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.collect(ctx)
		}
	}
}

func (c *StatsCollector) collect(ctx context.Context) {
	snapshot, err := c.reader.ReadOnce(ctx)
	if err == nil {
		c.current.Store(&snapshot)
		return
	}
	previous := c.Snapshot()
	previous.Available = false
	c.current.Store(&previous)
}

func (c *StatsCollector) Snapshot() StatsSnapshot {
	if c == nil {
		return StatsSnapshot{}
	}
	current := c.current.Load()
	if current == nil {
		return StatsSnapshot{}
	}
	return *current
}

func (c *StatsCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.counterTotal
	ch <- c.available
}

func (c *StatsCollector) Collect(ch chan<- prometheus.Metric) {
	snapshot := c.Snapshot()
	available := 0.0
	if snapshot.Available {
		available = 1
	}
	ch <- prometheus.MustNewConstMetric(c.available, prometheus.GaugeValue, available)
	for id, descriptor := range statDescriptors {
		ch <- prometheus.MustNewConstMetric(
			c.counterTotal,
			prometheus.CounterValue,
			float64(snapshot.Counters[id]),
			descriptor.stage, descriptor.reason,
		)
	}
}

type pinnedStatsMap struct{ *ebpf.Map }

func (m pinnedStatsMap) Info() (statsMapInfo, error) {
	info, err := m.Map.Info()
	if err != nil {
		return statsMapInfo{}, err
	}
	return statsMapInfo{typ: info.Type, keySize: info.KeySize, valueSize: info.ValueSize, maxEntries: info.MaxEntries, flags: info.Flags}, nil
}

func openPinnedStatsMap(path string) (statsMap, error) {
	object, err := ebpf.LoadPinnedMap(path, nil)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, os.ErrNotExist
		}
		return nil, err
	}
	return pinnedStatsMap{Map: object}, nil
}
