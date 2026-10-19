package agent

import (
	"context"
	"fmt"
	"sync"
	"time"
)

type ScanLevel uint8

const (
	ScanNone ScanLevel = iota
	ScanLight
	ScanIncremental
	ScanFull
)

type ScanResult struct {
	Level              ScanLevel
	StartedAt          time.Time
	FinishedAt         time.Time
	DatapathObserved   bool
	DatapathReady      bool
	DatapathGeneration uint64
	Critical           bool
	InvalidateEpoch    bool
	Reason             string
	Err                error
}

type ScanFunc func(context.Context) ScanResult

type ScanSchedulerConfig struct {
	Light               ScanFunc
	Incremental         ScanFunc
	Full                ScanFunc
	LightInterval       time.Duration
	IncrementalInterval time.Duration
	FullInterval        time.Duration
	Now                 func() time.Time
}

type ScanScheduler struct {
	light               ScanFunc
	incremental         ScanFunc
	full                ScanFunc
	lightInterval       time.Duration
	incrementalInterval time.Duration
	fullInterval        time.Duration
	now                 func() time.Time

	mu      sync.Mutex
	pending ScanLevel
	wake    chan struct{}
}

func NewScanScheduler(config ScanSchedulerConfig) (*ScanScheduler, error) {
	if config.Light == nil || config.Incremental == nil || config.Full == nil || config.LightInterval <= 0 || config.IncrementalInterval <= 0 || config.FullInterval < config.IncrementalInterval {
		return nil, fmt.Errorf("scan scheduler dependencies and intervals are required")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &ScanScheduler{light: config.Light, incremental: config.Incremental, full: config.Full, lightInterval: config.LightInterval, incrementalInterval: config.IncrementalInterval, fullInterval: config.FullInterval, now: config.Now, wake: make(chan struct{}, 1)}, nil
}

func (s *ScanScheduler) Trigger(level ScanLevel) error {
	if level < ScanLight || level > ScanFull {
		return fmt.Errorf("invalid scan level: %d", level)
	}
	s.mu.Lock()
	if level > s.pending {
		s.pending = level
	}
	s.mu.Unlock()
	select {
	case s.wake <- struct{}{}:
	default:
	}
	return nil
}

func (s *ScanScheduler) Run(ctx context.Context) <-chan ScanResult {
	results := make(chan ScanResult, 4)
	go s.run(ctx, results)
	return results
}

func (s *ScanScheduler) run(ctx context.Context, results chan<- ScanResult) {
	defer close(results)
	incremental := time.NewTicker(s.incrementalInterval)
	full := time.NewTicker(s.fullInterval)
	light := time.NewTicker(s.lightInterval)
	defer incremental.Stop()
	defer full.Stop()
	defer light.Stop()
	for {
		if level, ok := s.takePending(); ok {
			result := s.execute(ctx, level)
			select {
			case results <- result:
			case <-ctx.Done():
				return
			}
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-s.wake:
		case <-light.C:
			_ = s.Trigger(ScanLight)
		case <-incremental.C:
			_ = s.Trigger(ScanIncremental)
		case <-full.C:
			_ = s.Trigger(ScanFull)
		}
	}
}

func (s *ScanScheduler) takePending() (ScanLevel, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	level := s.pending
	s.pending = ScanNone
	return level, level != ScanNone
}

func (s *ScanScheduler) execute(ctx context.Context, level ScanLevel) ScanResult {
	started := s.now()
	fn := s.light
	switch level {
	case ScanIncremental:
		fn = s.incremental
	case ScanFull:
		fn = s.full
	}
	result := fn(ctx)
	result.Level = level
	result.StartedAt = started
	result.FinishedAt = s.now()
	return result
}
