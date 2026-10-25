//go:build linux

package endpoint

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"
)

var (
	ErrEndpointNotReady = errors.New("endpoint not ready")
	ErrStaleObject      = errors.New("stale endpoint object")
	ErrUnsupported      = errors.New("unsupported runtime endpoint")
)

const criDialTimeout = 10 * time.Second

type SandboxInfo struct {
	ID         string
	PID        int
	NetNSPath  string
	NetNSInode uint64
}

type CRIRuntimeClient interface {
	ListPodSandbox(context.Context, *runtimeapi.ListPodSandboxRequest, ...grpc.CallOption) (*runtimeapi.ListPodSandboxResponse, error)
	PodSandboxStatus(context.Context, *runtimeapi.PodSandboxStatusRequest, ...grpc.CallOption) (*runtimeapi.PodSandboxStatusResponse, error)
}

type CRISandboxResolver struct {
	client CRIRuntimeClient
	stat   func(string) (uint64, error)
}

func NewCRISandboxResolver(client CRIRuntimeClient) (*CRISandboxResolver, error) {
	return newCRISandboxResolver(client, statNetNS)
}

func newCRISandboxResolver(client CRIRuntimeClient, stat func(string) (uint64, error)) (*CRISandboxResolver, error) {
	if client == nil || stat == nil {
		return nil, fmt.Errorf("CRI client and netns stat function are required")
	}
	return &CRISandboxResolver{client: client, stat: stat}, nil
}

func DialContainerdCRI(ctx context.Context, endpoint string) (*CRISandboxResolver, io.Closer, error) {
	return dialContainerdCRI(ctx, endpoint, criDialTimeout)
}

func dialContainerdCRI(ctx context.Context, endpoint string, timeout time.Duration) (*CRISandboxResolver, io.Closer, error) {
	path, err := unixSocketPath(endpoint)
	if err != nil {
		return nil, nil, err
	}
	dialer := func(ctx context.Context, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", path)
	}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := grpc.DialContext(dialCtx, "passthrough:///oncache-cri", grpc.WithContextDialer(dialer), grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	if err != nil {
		return nil, nil, fmt.Errorf("dial CRI endpoint: %w", err)
	}
	resolver, err := NewCRISandboxResolver(runtimeapi.NewRuntimeServiceClient(conn))
	if err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	return resolver, conn, nil
}

func (r *CRISandboxResolver) ResolveSandbox(ctx context.Context, pod PodIdentity) (SandboxInfo, error) {
	if pod.UID == "" || pod.Namespace == "" || pod.Name == "" {
		return SandboxInfo{}, fmt.Errorf("pod identity is incomplete")
	}
	if err := ctx.Err(); err != nil {
		return SandboxInfo{}, err
	}
	response, err := r.client.ListPodSandbox(ctx, &runtimeapi.ListPodSandboxRequest{Filter: &runtimeapi.PodSandboxFilter{
		State:         &runtimeapi.PodSandboxStateValue{State: runtimeapi.PodSandboxState_SANDBOX_READY},
		LabelSelector: map[string]string{"io.kubernetes.pod.uid": pod.UID},
	}})
	if err != nil {
		return SandboxInfo{}, fmt.Errorf("%w: list pod sandboxes: %v", ErrEndpointNotReady, err)
	}
	var match *runtimeapi.PodSandbox
	for _, sandbox := range response.GetItems() {
		if sandbox.GetMetadata().GetUid() != pod.UID || sandbox.GetMetadata().GetNamespace() != pod.Namespace || sandbox.GetMetadata().GetName() != pod.Name {
			continue
		}
		if match != nil {
			return SandboxInfo{}, fmt.Errorf("%w: multiple ready sandboxes for pod %s", ErrStaleObject, pod.UID)
		}
		match = sandbox
	}
	if match == nil {
		return SandboxInfo{}, fmt.Errorf("%w: sandbox for pod %s is not ready", ErrEndpointNotReady, pod.UID)
	}
	statusResponse, err := r.client.PodSandboxStatus(ctx, &runtimeapi.PodSandboxStatusRequest{PodSandboxId: match.GetId(), Verbose: true})
	if err != nil {
		return SandboxInfo{}, fmt.Errorf("%w: get sandbox status: %v", ErrEndpointNotReady, err)
	}
	status := statusResponse.GetStatus()
	if status == nil || status.GetId() != match.GetId() {
		return SandboxInfo{}, fmt.Errorf("%w: sandbox status identity changed", ErrStaleObject)
	}
	metadata := status.GetMetadata()
	if metadata.GetUid() != pod.UID || metadata.GetNamespace() != pod.Namespace || metadata.GetName() != pod.Name {
		return SandboxInfo{}, fmt.Errorf("%w: sandbox metadata identity changed", ErrStaleObject)
	}
	if status.GetState() != runtimeapi.PodSandboxState_SANDBOX_READY {
		return SandboxInfo{}, fmt.Errorf("%w: sandbox stopped during resolution", ErrEndpointNotReady)
	}
	pid, err := parseSandboxPID(statusResponse.GetInfo())
	if err != nil {
		return SandboxInfo{}, fmt.Errorf("%w: %v", ErrUnsupported, err)
	}
	path := fmt.Sprintf("/proc/%d/ns/net", pid)
	inode, err := r.stat(path)
	if err != nil {
		return SandboxInfo{}, fmt.Errorf("%w: stat sandbox netns: %v", ErrEndpointNotReady, err)
	}
	return SandboxInfo{ID: match.GetId(), PID: pid, NetNSPath: path, NetNSInode: inode}, nil
}

func parseSandboxPID(info map[string]string) (int, error) {
	raw, ok := info["sandboxPid"]
	if !ok {
		raw, ok = info["pid"]
	}
	if ok {
		return parseSandboxPIDValue(raw)
	}
	raw, ok = info["info"]
	if !ok {
		return 0, fmt.Errorf("CRI status does not contain sandboxPid")
	}
	var nested struct {
		SandboxPID int `json:"sandboxPid"`
		PID        int `json:"pid"`
	}
	if err := json.Unmarshal([]byte(raw), &nested); err != nil {
		return 0, fmt.Errorf("invalid nested CRI info: %w", err)
	}
	value := nested.SandboxPID
	if value == 0 {
		value = nested.PID
	}
	if value <= 0 {
		return 0, fmt.Errorf("invalid sandboxPid %d", value)
	}
	return value, nil
}

func parseSandboxPIDValue(raw string) (int, error) {
	raw = strings.Trim(strings.TrimSpace(raw), "\"")
	var value int
	if err := json.Unmarshal([]byte(raw), &value); err != nil {
		value, err = strconv.Atoi(raw)
		if err != nil {
			return 0, fmt.Errorf("invalid sandboxPid %q", raw)
		}
	}
	if value <= 0 {
		return 0, fmt.Errorf("invalid sandboxPid %d", value)
	}
	return value, nil
}

func unixSocketPath(endpoint string) (string, error) {
	path := strings.TrimPrefix(endpoint, "unix://")
	path = strings.TrimPrefix(path, "unix:")
	if path == "" || !filepath.IsAbs(path) {
		return "", fmt.Errorf("CRI endpoint must be an absolute unix socket")
	}
	return filepath.Clean(path), nil
}

func statNetNS(path string) (uint64, error) {
	var stat unix.Stat_t
	if err := unix.Stat(path, &stat); err != nil {
		return 0, err
	}
	return uint64(stat.Ino), nil
}
