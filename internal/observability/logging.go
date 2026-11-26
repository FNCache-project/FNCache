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
	handler   slog.Handler
	component string
	node      string
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
	return &Logger{base: base, handler: handler, component: config.Component, node: config.Node, limiter: limiter}, nil
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

// WithComponent returns a logger that shares the handler and rate limiter but
// adds a component scope to every record.
func (l *Logger) WithComponent(component string) *Logger {
	if l == nil {
		return nil
	}
	base := l.base
	if l.handler != nil {
		base = slog.New(l.handler).With("component", component, "node", l.node)
	} else {
		base = base.With("component", component, "node", l.node)
	}
	return &Logger{base: base, handler: l.handler, component: component, node: l.node, limiter: l.limiter}
}

// WithNode returns a logger that shares the handler and rate limiter but uses
// the supplied node identity in every record.
func (l *Logger) WithNode(node string) *Logger {
	if l == nil {
		return nil
	}
	base := l.base
	if l.handler != nil {
		base = slog.New(l.handler).With("component", l.component, "node", node)
	} else {
		base = base.With("component", l.component, "node", node)
	}
	return &Logger{base: base, handler: l.handler, component: l.component, node: node, limiter: l.limiter}
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
	l.LogEvent(ctx, Event{Level: slog.LevelError, Message: message, Attrs: attrs})
}

func (l *Logger) LogEvent(ctx context.Context, event Event) {
	if l == nil {
		return
	}
	key := event.RateLimitKey
	if key != "" {
		key = strings.Join([]string{l.component, key}, ":")
	}
	allowed, suppressed := true, uint64(0)
	if l.limiter != nil {
		allowed, suppressed = l.limiter.Allow(key)
	}
	if !allowed {
		return
	}
	attrs := sanitizeAttrs(event.Attrs)
	if suppressed > 0 {
		attrs = append(attrs, "suppressed", suppressed)
	}
	l.base.Log(ctx, event.Level, event.Message, attrs...)
}

// DurationMillis converts a duration to a JSON-friendly millisecond value.
func DurationMillis(value time.Duration) float64 {
	return float64(value) / float64(time.Millisecond)
}

var sensitiveAttrNames = map[string]struct{}{
	"apikey":        {},
	"authorization": {},
	"clientsecret":  {},
	"credential":    {},
	"password":      {},
	"privatekey":    {},
	"secret":        {},
	"token":         {},
}

func sanitizeAttrs(attrs []any) []any {
	if len(attrs) == 0 {
		return nil
	}
	result := make([]any, 0, len(attrs))
	for index := 0; index < len(attrs); {
		if key, ok := attrs[index].(string); ok && index+1 < len(attrs) {
			value := attrs[index+1]
			switch {
			case isSensitiveAttrName(key):
				value = "[REDACTED]"
			case normalizeAttrName(key) == "error":
				value = redactText(fmt.Sprint(value))
			}
			result = append(result, key, value)
			index += 2
			continue
		}
		result = append(result, attrs[index])
		index++
	}
	return result
}

func isSensitiveAttrName(name string) bool {
	_, ok := sensitiveAttrNames[normalizeAttrName(name)]
	return ok
}

func normalizeAttrName(name string) string {
	name = strings.ToLower(name)
	name = strings.ReplaceAll(name, "-", "")
	name = strings.ReplaceAll(name, "_", "")
	return name
}

func redactText(value string) string {
	for _, marker := range []struct {
		text       string
		toBoundary bool
	}{
		{text: "authorization:", toBoundary: true},
		{text: "authorization=", toBoundary: true},
		{text: "password=", toBoundary: false},
		{text: "secret=", toBoundary: false},
		{text: "token=", toBoundary: false},
	} {
		searchFrom := 0
		for searchFrom < len(value) {
			lower := strings.ToLower(value)
			relative := strings.Index(lower[searchFrom:], marker.text)
			if relative < 0 {
				break
			}
			start := searchFrom + relative + len(marker.text)
			valueStart := start
			for valueStart < len(value) && strings.ContainsRune(" \t", rune(value[valueStart])) {
				valueStart++
			}
			if strings.HasPrefix(strings.ToLower(value[valueStart:]), "[redacted]") {
				searchFrom = valueStart + len("[REDACTED]")
				continue
			}
			end := valueStart
			boundaries := " \t\r\n,;"
			if marker.toBoundary {
				boundaries = "\r\n,;"
			}
			for end < len(value) && !strings.ContainsRune(boundaries, rune(value[end])) {
				end++
			}
			if end == valueStart {
				searchFrom = start + 1
				continue
			}
			value = value[:valueStart] + "[REDACTED]" + value[end:]
			searchFrom = valueStart + len("[REDACTED]")
		}
	}
	return value
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
