package discovery_test

import (
	"context"
	"errors"
	"testing"

	"github.com/cat-cc-Lcos/FNCache/internal/hostnet/discovery"
)

type fakeProbe struct {
	snapshot discovery.ProbeSnapshot
	err      error
	called   bool
}

func (p *fakeProbe) Probe(_ context.Context, _ discovery.PreflightRequest) (discovery.ProbeSnapshot, error) {
	p.called = true
	return p.snapshot, p.err
}

func TestPreflightAggregatesSuccessfulChecks(t *testing.T) {
	probe := &fakeProbe{snapshot: discovery.ProbeSnapshot{
		HasBTF: true, BPFFSMounted: true, TCSupported: true,
		Checks: []discovery.ProbeCheck{
			{Name: "btf", ProbeResult: discovery.ProbeResult{Supported: true, Required: true}},
			{Name: "helper/bpf_redirect", ProbeResult: discovery.ProbeResult{Supported: true, Required: true}},
		},
	}}
	report, err := discovery.NewPreflight(probe).Check(context.Background(), discovery.PreflightRequest{})
	if err != nil || !report.Supported || len(report.Reasons) != 0 || !probe.called {
		t.Fatalf("unexpected preflight result: report=%+v err=%v", report, err)
	}
	if !report.HelperResults["bpf_redirect"].Supported {
		t.Fatal("helper result was not aggregated")
	}
}

func TestPreflightReportsRequiredFailure(t *testing.T) {
	probe := &fakeProbe{snapshot: discovery.ProbeSnapshot{Checks: []discovery.ProbeCheck{{
		Name: "tc", ProbeResult: discovery.ProbeResult{Required: true, ReasonCode: "TC_UNSUPPORTED", Detail: "clsact unavailable"},
	}}}}
	report, err := discovery.NewPreflight(probe).Check(context.Background(), discovery.PreflightRequest{})
	if err != nil || report.Supported || len(report.Reasons) != 1 {
		t.Fatalf("unexpected required failure: report=%+v err=%v", report, err)
	}
	if report.Reasons[0].Code != "TC_UNSUPPORTED" || report.Reasons[0].Retryable {
		t.Fatalf("unexpected reason: %+v", report.Reasons[0])
	}
}

func TestPreflightPreservesProbeError(t *testing.T) {
	want := errors.New("permission denied")
	probe := &fakeProbe{err: want}
	_, err := discovery.NewPreflight(probe).Check(context.Background(), discovery.PreflightRequest{})
	if !errors.Is(err, want) {
		t.Fatalf("probe error was not preserved: %v", err)
	}
}
