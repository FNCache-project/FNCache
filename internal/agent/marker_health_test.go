package agent

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cat-cc-Lcos/FNCache/internal/hostnet/flannel"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

type fakeMarkerHealthRules struct {
	state reconcile.RuleState
	err   error
}

func (s *fakeMarkerHealthRules) Scan(context.Context, flannel.MarkerRuleSpec) (reconcile.RuleState, error) {
	return s.state, s.err
}

type fakeMarkerHealthPins struct{ state reconcile.ActualState }

func (s *fakeMarkerHealthPins) Scan(context.Context) (reconcile.ActualState, error) {
	return s.state, nil
}

func markerHealthSpec() flannel.MarkerRuleSpec {
	return flannel.MarkerRuleSpec{Chain: "ONCACHE", Comment: "oncache:test"}
}

func newMarkerHealthMonitor(t *testing.T, rules *fakeMarkerHealthRules, pins *fakeMarkerHealthPins) *MarkerHealthMonitor {
	t.Helper()
	spec := markerHealthSpec()
	monitor, err := NewMarkerHealthMonitor(MarkerHealthMonitorConfig{Source: rules, Pins: pins, Spec: spec, ExpectedFingerprint: flannel.ExpectedMarkerFingerprint(spec), Interval: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return monitor
}

func TestMarkerHealthMonitorAcceptsCanonicalRule(t *testing.T) {
	spec := markerHealthSpec()
	rules := &fakeMarkerHealthRules{state: reconcile.RuleState{Present: true, JumpsPresent: true, Identity: "ONCACHE/oncache:test", Fingerprint: flannel.ExpectedMarkerFingerprint(spec)}}
	monitor := newMarkerHealthMonitor(t, rules, &fakeMarkerHealthPins{})
	if err := monitor.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := monitor.CheckForPublish(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestMarkerHealthMonitorHandlesMissingAndDriftedRule(t *testing.T) {
	rules := &fakeMarkerHealthRules{state: reconcile.RuleState{Present: false, Identity: "ONCACHE/oncache:test"}}
	monitor := newMarkerHealthMonitor(t, rules, &fakeMarkerHealthPins{})
	if err := monitor.Check(context.Background()); err != nil {
		t.Fatalf("disabled datapath treated missing marker as failure: %v", err)
	}
	if err := monitor.CheckForPublish(context.Background()); !errors.Is(err, ErrMarkerDrift) {
		t.Fatalf("publish check error = %v, want ErrMarkerDrift", err)
	}
	rules.state.Present = true
	rules.state.JumpsPresent = true
	rules.state.Fingerprint = "changed"
	if err := monitor.Check(context.Background()); !errors.Is(err, ErrMarkerDrift) {
		t.Fatalf("error = %v, want ErrMarkerDrift", err)
	}
	rules.err = errors.New("iptables unavailable")
	if err := monitor.Check(context.Background()); !errors.Is(err, ErrMarkerUnhealthy) {
		t.Fatalf("error = %v, want ErrMarkerUnhealthy", err)
	}
}

func TestMarkerHealthMonitorReportsMissingEnabledRule(t *testing.T) {
	rules := &fakeMarkerHealthRules{state: reconcile.RuleState{Present: false, Identity: "ONCACHE/oncache:test"}}
	pins := &fakeMarkerHealthPins{state: reconcile.ActualState{Control: reconcile.ControlState{Verified: true, Enabled: true}}}
	monitor := newMarkerHealthMonitor(t, rules, pins)
	if err := monitor.Check(context.Background()); !errors.Is(err, ErrMarkerDrift) {
		t.Fatalf("error = %v, want ErrMarkerDrift", err)
	}
}
