package kubernetes

import (
	"errors"
	"testing"
	"time"
)

var errTestHealth = errors.New("health test error")

func TestAPIHealthFreshAtRequiresSyncAndSuccessfulProbe(t *testing.T) {
	probeAt := time.Unix(100, 0)
	tests := []struct {
		name   string
		health APIHealth
		want   bool
	}{
		{name: "fresh", health: APIHealth{Synced: true, LastProbeAt: probeAt}, want: true},
		{name: "not synced", health: APIHealth{LastProbeAt: probeAt}, want: false},
		{name: "recent probe error", health: APIHealth{Synced: true, LastProbeAt: probeAt, LastProbeErr: errTestHealth}, want: true},
		{name: "informer error", health: APIHealth{Synced: true, LastProbeAt: probeAt, InformerError: errTestHealth}, want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := test.health.FreshAt(probeAt.Add(500*time.Millisecond), time.Second); got != test.want {
				t.Fatalf("FreshAt() = %v, want %v", got, test.want)
			}
		})
	}
}
