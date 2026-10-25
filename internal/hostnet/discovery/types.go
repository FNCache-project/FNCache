package discovery

import "time"

type CapabilityReport struct {
	Supported     bool
	CheckedAt     time.Time
	KernelRelease string
	Architecture  string
	HasBTF        bool
	BPFFSMounted  bool
	TCSupported   bool
	HelperResults map[string]ProbeResult
	Runtime       RuntimeInfo
	Overlay       OverlayInfo
	Conflicts     []Conflict
	Reasons       []Reason
	Fingerprint   string
}

type ProbeResult struct {
	Supported  bool
	Required   bool
	Retryable  bool
	ReasonCode string
	Detail     string
}

type RuntimeInfo struct {
	Name     string
	Endpoint string
}

type OverlayInfo struct {
	Type   string
	Device string
}

type Conflict struct {
	Kind     string
	Identity string
	Detail   string
}

type Reason struct {
	Code      string
	Message   string
	Retryable bool
}
