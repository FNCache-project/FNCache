package discovery

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/cat-cc-Lcos/FNCache/internal/endpoint"
)

type PreflightRequest struct {
	Node           endpoint.NodeIdentity
	PinRoot        string
	StateDir       string
	InstallationID string
	ELFBuildID     string
	RuntimeURI     string
	Overlay        string
	MarkerChain    string
	MarkerComment  string
}

type ProbeCheck struct {
	Name string
	ProbeResult
}

type ProbeSnapshot struct {
	KernelRelease string
	Architecture  string
	HasBTF        bool
	BPFFSMounted  bool
	TCSupported   bool
	Checks        []ProbeCheck
	Runtime       RuntimeInfo
	Overlay       OverlayInfo
	Fingerprint   string
}

// SystemProbe must only inspect the host and must not create persistent objects.
type SystemProbe interface {
	Probe(context.Context, PreflightRequest) (ProbeSnapshot, error)
}

type Preflight interface {
	Check(context.Context, PreflightRequest) (CapabilityReport, error)
}

type Checker struct {
	probe SystemProbe
}

func NewPreflight(probe SystemProbe) Preflight { return Checker{probe: probe} }

func (c Checker) Check(ctx context.Context, req PreflightRequest) (CapabilityReport, error) {
	report := CapabilityReport{Supported: false, CheckedAt: time.Now()}
	if c.probe == nil {
		return report, fmt.Errorf("preflight probe is required")
	}
	snapshot, err := c.probe.Probe(ctx, req)
	report.KernelRelease = snapshot.KernelRelease
	report.Architecture = snapshot.Architecture
	report.HasBTF = snapshot.HasBTF
	report.BPFFSMounted = snapshot.BPFFSMounted
	report.TCSupported = snapshot.TCSupported
	report.Runtime = snapshot.Runtime
	report.Overlay = snapshot.Overlay
	report.Fingerprint = snapshot.Fingerprint
	for _, check := range snapshot.Checks {
		if strings.HasPrefix(check.Name, "helper/") {
			if report.HelperResults == nil {
				report.HelperResults = make(map[string]ProbeResult)
			}
			report.HelperResults[strings.TrimPrefix(check.Name, "helper/")] = check.ProbeResult
		}
		if check.Required && !check.Supported {
			report.Reasons = append(report.Reasons, Reason{
				Code: reasonCode(check), Message: check.Detail, Retryable: check.Retryable,
			})
		}
	}
	if err != nil {
		return report, fmt.Errorf("run preflight: %w", err)
	}
	report.Supported = len(report.Reasons) == 0
	return report, nil
}

func reasonCode(check ProbeCheck) string {
	if check.ReasonCode != "" {
		return check.ReasonCode
	}
	name := strings.ToUpper(strings.NewReplacer("/", "_", "-", "_").Replace(check.Name))
	if name == "" {
		return "PREFLIGHT_CHECK_FAILED"
	}
	return "PREFLIGHT_" + name + "_FAILED"
}
