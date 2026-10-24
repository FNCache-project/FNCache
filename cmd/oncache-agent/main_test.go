package main

import (
	"testing"

	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

func TestStaticReconcileSucceeded(t *testing.T) {
	tests := []struct {
		name  string
		state reconcile.AgentState
		want  bool
	}{
		{name: "ready", state: reconcile.AgentReady},
		{name: "disabled", state: reconcile.AgentDisabled, want: true},
		{name: "bootstrapping", state: reconcile.AgentBootstrapping},
		{name: "reconciling", state: reconcile.AgentReconciling},
		{name: "degraded", state: reconcile.AgentDegraded},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := staticReconcileSucceeded(tt.state); got != tt.want {
				t.Fatalf("staticReconcileSucceeded(%q)=%v, want %v", tt.state, got, tt.want)
			}
		})
	}
}
