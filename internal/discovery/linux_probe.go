package discovery

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type LinuxProbe struct {
	root       string
	dialUnix   func(context.Context, string) (net.Conn, error)
	runCommand CommandRunner
}

func NewLinuxProbe(root string) *LinuxProbe {
	return NewLinuxProbeWithRunner(root, nil)
}

func NewLinuxProbeWithRunner(root string, runner CommandRunner) *LinuxProbe {
	if root == "" {
		root = string(filepath.Separator)
	}
	if runner == nil {
		runner = defaultCommandRunner
	}
	return &LinuxProbe{
		root:       filepath.Clean(root),
		runCommand: runner,
		dialUnix: func(ctx context.Context, path string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 250 * time.Millisecond}).DialContext(ctx, "unix", path)
		},
	}
}

func (p *LinuxProbe) Probe(ctx context.Context, req PreflightRequest) (ProbeSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return ProbeSnapshot{}, err
	}
	release, err := os.ReadFile(p.path("/proc/sys/kernel/osrelease"))
	if err != nil {
		return ProbeSnapshot{}, fmt.Errorf("read kernel release: %w", err)
	}
	if strings.TrimSpace(string(release)) == "" {
		return ProbeSnapshot{}, fmt.Errorf("kernel release is empty")
	}
	bpffs := p.checkBPFFS()
	btf := p.checkBTF()
	cri := p.checkCRI(ctx, req.RuntimeURI)
	checks := []ProbeCheck{bpffs, btf, cri}
	checks = append(checks, p.checkHelpers(ctx)...)
	tc := p.checkTC(ctx)
	checks = append(checks, tc, p.checkIPv4Forward(), p.checkRoutes(ctx), p.checkTOS(ctx, req), p.checkExternalConflicts(ctx, req))
	return ProbeSnapshot{
		KernelRelease: strings.TrimSpace(string(release)), Architecture: runtime.GOARCH,
		HasBTF: btf.Supported, BPFFSMounted: bpffs.Supported, TCSupported: tc.Supported,
		Checks:  checks,
		Runtime: RuntimeInfo{Name: "containerd", Endpoint: req.RuntimeURI},
		Overlay: OverlayInfo{Type: req.Overlay},
	}, nil
}

func (p *LinuxProbe) checkHelpers(ctx context.Context) []ProbeCheck {
	output, err := p.runCommand(ctx, "bpftool", "feature", "probe", "kernel")
	if err != nil {
		return helperChecks("BPF_HELPER_PROBE_FAILED", string(output), true, false)
	}
	checks := make([]ProbeCheck, 0, len(requiredBPFHelpers)+1)
	for _, helper := range requiredBPFHelpers {
		result := ProbeResult{Supported: hasHelper(output, helper), Required: true, ReasonCode: "BPF_HELPER_MISSING"}
		if result.Supported {
			result.ReasonCode = ""
		} else {
			result.Detail = helper + " is not reported by bpftool"
		}
		checks = append(checks, ProbeCheck{Name: "helper/" + helper, ProbeResult: result})
	}
	directAction := ProbeResult{Supported: hasDirectAction(output), Required: true, ReasonCode: "TC_DIRECT_ACTION_UNSUPPORTED"}
	if directAction.Supported {
		directAction.ReasonCode = ""
	}
	checks = append(checks, ProbeCheck{Name: "tc/direct-action", ProbeResult: directAction})
	return checks
}

func helperChecks(reason, detail string, retryable, supported bool) []ProbeCheck {
	checks := make([]ProbeCheck, 0, len(requiredBPFHelpers)+1)
	for _, helper := range requiredBPFHelpers {
		checks = append(checks, ProbeCheck{Name: "helper/" + helper, ProbeResult: ProbeResult{
			Supported: supported, Required: true, Retryable: retryable, ReasonCode: reason, Detail: detail,
		}})
	}
	checks = append(checks, ProbeCheck{Name: "tc/direct-action", ProbeResult: ProbeResult{
		Supported: supported, Required: true, Retryable: retryable, ReasonCode: reason, Detail: detail,
	}})
	return checks
}

func (p *LinuxProbe) checkTC(ctx context.Context) ProbeCheck {
	result := ProbeResult{Required: true, ReasonCode: "TC_PROBE_FAILED", Retryable: true}
	output, err := p.runCommand(ctx, "tc", "-j", "qdisc", "show")
	if err != nil {
		result.Detail = string(output)
		return ProbeCheck{Name: "tc", ProbeResult: result}
	}
	result.Supported = true
	result.ReasonCode, result.Retryable = "", false
	return ProbeCheck{Name: "tc", ProbeResult: result}
}

func (p *LinuxProbe) checkIPv4Forward() ProbeCheck {
	result := ProbeResult{Required: true, ReasonCode: "IPV4_FORWARDING_DISABLED"}
	data, err := os.ReadFile(p.path("/proc/sys/net/ipv4/ip_forward"))
	if err != nil {
		result.ReasonCode, result.Detail = "IPV4_FORWARDING_UNAVAILABLE", err.Error()
		return ProbeCheck{Name: "ipv4/forwarding", ProbeResult: result}
	}
	result.Supported = strings.TrimSpace(string(data)) == "1"
	if result.Supported {
		result.ReasonCode = ""
	} else {
		result.Detail = "net.ipv4.ip_forward is not 1"
	}
	return ProbeCheck{Name: "ipv4/forwarding", ProbeResult: result}
}

func (p *LinuxProbe) checkRoutes(ctx context.Context) ProbeCheck {
	result := ProbeResult{Required: true, ReasonCode: "ROUTE_UNAVAILABLE", Retryable: true}
	output, err := p.runCommand(ctx, "ip", "-j", "route", "show")
	if err != nil {
		result.Detail = string(output)
		return ProbeCheck{Name: "ipv4/routes", ProbeResult: result}
	}
	result.Supported = validRouteOutput(output)
	if result.Supported {
		result.ReasonCode, result.Retryable = "", false
	} else {
		result.Detail = "ip route output is empty or invalid"
	}
	return ProbeCheck{Name: "ipv4/routes", ProbeResult: result}
}

func (p *LinuxProbe) checkTOS(ctx context.Context, req PreflightRequest) ProbeCheck {
	result := ProbeResult{Required: true, ReasonCode: "IPTABLES_NFT_UNAVAILABLE"}
	output, err := p.runCommand(ctx, "iptables-nft", "-t", "mangle", "-S")
	if err != nil {
		result.Detail = string(output)
		return ProbeCheck{Name: "tos", ProbeResult: result}
	}
	result.Supported = !hasReservedTOSConflict(output, req.MarkerChain, req.MarkerComment)
	if result.Supported {
		result.ReasonCode = ""
	} else {
		result.ReasonCode = "TOS_MASK_CONFLICT"
		result.Detail = "existing mangle rules use 0x04 or 0x08"
	}
	return ProbeCheck{Name: "tos", ProbeResult: result}
}

func (p *LinuxProbe) checkExternalConflicts(ctx context.Context, req PreflightRequest) ProbeCheck {
	result := ProbeResult{Required: true, ReasonCode: "EXTERNAL_OBJECT_SCAN_FAILED", Retryable: true}
	tc, err := p.runCommand(ctx, "tc", "-j", "filter", "show")
	if err != nil {
		result.Detail = string(tc)
		return ProbeCheck{Name: "external/conflicts", ProbeResult: result}
	}
	programs, err := p.runCommand(ctx, "bpftool", "-j", "-f", "prog", "show")
	if err != nil {
		result.Detail = string(programs)
		return ProbeCheck{Name: "external/conflicts", ProbeResult: result}
	}
	maps, err := p.runCommand(ctx, "bpftool", "-j", "-f", "map", "show")
	if err != nil {
		result.Detail = string(maps)
		return ProbeCheck{Name: "external/conflicts", ProbeResult: result}
	}
	netfilter, err := p.runCommand(ctx, "iptables-nft", "-t", "mangle", "-S")
	if err != nil {
		result.Detail = string(netfilter)
		return ProbeCheck{Name: "external/conflicts", ProbeResult: result}
	}
	evidence := loadOwnershipEvidence(filepath.Join(p.path(req.StateDir), "state.json"), req.InstallationID, req.Node.UID, req.ELFBuildID)
	programPins := make(map[string]uint32, len(evidence.ProgramPins))
	for name, id := range evidence.ProgramPins {
		programPins[filepath.Join(req.PinRoot, "programs", name)] = id
	}
	mapPins := make(map[string]uint32, len(evidence.MapPins))
	for name, id := range evidence.MapPins {
		mapPins[filepath.Join(req.PinRoot, "maps", name)] = id
	}
	if hasFixedTCConflictWithOwnership(tc, evidence.TCFilters) || hasForeignPinnedObject(programs, req.PinRoot, programPins) || hasForeignPinnedObject(maps, req.PinRoot, mapPins) || hasReservedTOSConflict(netfilter, req.MarkerChain, req.MarkerComment) {
		result.ReasonCode, result.Retryable = "EXTERNAL_OBJECT_CONFLICT", false
		result.Detail = "an external object uses an ONCache identity or reserved TOS mask"
		return ProbeCheck{Name: "external/conflicts", ProbeResult: result}
	}
	result.Supported, result.ReasonCode, result.Retryable = true, "", false
	return ProbeCheck{Name: "external/conflicts", ProbeResult: result}
}

func (p *LinuxProbe) checkBPFFS() ProbeCheck {
	result := ProbeResult{Required: true, ReasonCode: "BPFFS_NOT_MOUNTED"}
	info, err := os.Stat(p.path("/sys/fs/bpf"))
	if err != nil || !info.IsDir() {
		result.Detail = "bpffs mount directory is unavailable"
		return ProbeCheck{Name: "bpffs", ProbeResult: result}
	}
	data, err := os.ReadFile(p.path("/proc/mounts"))
	if err != nil {
		result.ReasonCode = "BPFFS_MOUNT_INFO_UNAVAILABLE"
		result.Detail = err.Error()
		return ProbeCheck{Name: "bpffs", ProbeResult: result}
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[1] == "/sys/fs/bpf" && fields[2] == "bpf" {
			result.Supported = true
			result.ReasonCode = ""
			return ProbeCheck{Name: "bpffs", ProbeResult: result}
		}
	}
	result.Detail = "bpffs is not mounted at /sys/fs/bpf"
	return ProbeCheck{Name: "bpffs", ProbeResult: result}
}

func (p *LinuxProbe) checkBTF() ProbeCheck {
	result := ProbeResult{Required: true, ReasonCode: "BTF_MISSING"}
	info, err := os.Stat(p.path("/sys/kernel/btf/vmlinux"))
	if err == nil && !info.IsDir() {
		result.Supported = true
		result.ReasonCode = ""
	} else if err != nil {
		result.Detail = err.Error()
	} else {
		result.Detail = "vmlinux BTF path is a directory"
	}
	return ProbeCheck{Name: "btf", ProbeResult: result}
}

func (p *LinuxProbe) checkCRI(ctx context.Context, uri string) ProbeCheck {
	result := ProbeResult{Required: true, ReasonCode: "CRI_SOCKET_UNAVAILABLE"}
	path, err := unixSocketPath(uri)
	if err != nil {
		result.ReasonCode = "CRI_URI_INVALID"
		result.Detail = err.Error()
		return ProbeCheck{Name: "cri", ProbeResult: result}
	}
	conn, err := p.dialUnix(ctx, p.path(path))
	if err != nil {
		result.Detail = err.Error()
		return ProbeCheck{Name: "cri", ProbeResult: result}
	}
	_ = conn.Close()
	result.Supported = true
	result.ReasonCode = ""
	return ProbeCheck{Name: "cri", ProbeResult: result}
}

func (p *LinuxProbe) path(path string) string {
	return filepath.Join(p.root, strings.TrimPrefix(path, string(filepath.Separator)))
}

func unixSocketPath(uri string) (string, error) {
	const prefix = "unix://"
	if !strings.HasPrefix(uri, prefix) {
		return "", fmt.Errorf("runtime endpoint must use unix://")
	}
	path := strings.TrimPrefix(uri, prefix)
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("runtime socket path must be absolute")
	}
	return path, nil
}
