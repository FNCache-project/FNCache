package observability

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"
)

const defaultRateInterval = 10 * time.Second

type LoggingConfig struct {
	Level        string
	Component    string
	Node         string
	Writer       io.Writer
	RateInterval time.Duration
	Now          func() time.Time
}

type Event struct {
	Level        slog.Level
	Message      string
	RateLimitKey string
	Attrs        []any
}

type EventLogger interface {
	Error(context.Context, string, ...any)
	LogEvent(context.Context, Event)
}

type Logger struct {
	base      *slog.Logger
	component string
	limiter   *RateLimiter
}

func New(config LoggingConfig) (*Logger, error) {
	level, err := ParseLevel(config.Level)
	if err != nil {
		return nil, err
	}
	if config.Writer == nil {
		config.Writer = os.Stderr
	}
	if config.RateInterval <= 0 {
		config.RateInterval = defaultRateInterval
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	limiter, err := NewRateLimiter(config.RateInterval, config.Now)
	if err != nil {
		return nil, err
	}
	handler := slog.NewJSONHandler(config.Writer, &slog.HandlerOptions{Level: level})
	base := slog.New(handler).With("component", config.Component, "node", config.Node)
	return &Logger{base: base, component: config.Component, limiter: limiter}, nil
}

func NewFromEnvironment(component string) (*Logger, error) {
	return New(LoggingConfig{Level: os.Getenv("ONCACHE_LOG_LEVEL"), Component: component, Node: os.Getenv("ONCACHE_NODE_NAME")})
}

func NewDefault(component string) *Logger {
	logger, err := NewFromEnvironment(component)
	if err == nil {
		return logger
	}
	logger, _ = New(LoggingConfig{Level: "info", Component: component, Node: os.Getenv("ONCACHE_NODE_NAME")})
	return logger
}

func ParseLevel(value string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, fmt.Errorf("unsupported log level %q", value)
	}
}

func (l *Logger) Error(ctx context.Context, message string, attrs ...any) {
	l.base.ErrorContext(ctx, message, attrs...)
}

func (l *Logger) LogEvent(ctx context.Context, event Event) {
	if l == nil {
		return
	}
	key := event.RateLimitKey
	if key != "" {
		key = strings.Join([]string{l.component, key}, ":")
	}
	allowed, suppressed := l.limiter.Allow(key)
	if !allowed {
		return
	}
	attrs := append([]any(nil), event.Attrs...)
	if suppressed > 0 {
		attrs = append(attrs, "suppressed", suppressed)
	}
	l.base.Log(ctx, event.Level, event.Message, attrs...)
}

type RateLimiter struct {
	mu       sync.Mutex
	interval time.Duration
	now      func() time.Time
	entries  map[string]rateEntry
}

type rateEntry struct {
	last       time.Time
	suppressed uint64
}

func NewRateLimiter(interval time.Duration, now func() time.Time) (*RateLimiter, error) {
	if interval <= 0 || now == nil {
		return nil, fmt.Errorf("rate limiter interval and clock are required")
	}
	return &RateLimiter{interval: interval, now: now, entries: make(map[string]rateEntry)}, nil
}

func (r *RateLimiter) Allow(key string) (bool, uint64) {
	if key == "" {
		return true, 0
	}
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, ok := r.entries[key]
	if !ok || now.Sub(entry.last) >= r.interval {
		suppressed := entry.suppressed
		r.entries[key] = rateEntry{last: now}
		return true, suppressed
	}
	entry.suppressed++
	r.entries[key] = entry
	return false, 0
}
