//go:build linux

package endpoint

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc"
	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"
)

func TestResolveContainerdEndpointPrefersFirstValidCandidate(t *testing.T) {
	var attempts []string
	candidates := []string{
		"unix:///host/run/k3s/containerd/containerd.sock",
		"unix:///host/run/containerd/containerd.sock",
	}
	got, err := resolveContainerdEndpoint(context.Background(), RuntimeEndpointAuto, candidates, func(_ context.Context, path string) error {
		attempts = append(attempts, path)
		if strings.Contains(path, "/k3s/") {
			return errors.New("CRI service unavailable")
		}
		return nil
	})
	if err != nil || got != candidates[1] {
		t.Fatalf("resolved endpoint = %q err=%v, want %q", got, err, candidates[1])
	}
	if len(attempts) != 2 {
		t.Fatalf("probe attempts = %d, want 2", len(attempts))
	}
}

type testRuntimeService struct {
	runtimeapi.UnimplementedRuntimeServiceServer
}

func (testRuntimeService) Version(context.Context, *runtimeapi.VersionRequest) (*runtimeapi.VersionResponse, error) {
	return &runtimeapi.VersionResponse{}, nil
}

func startUnixGRPCServer(t *testing.T, register func(*grpc.Server)) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "runtime.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	if register != nil {
		register(server)
	}
	go func() {
		_ = server.Serve(listener)
	}()
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
	})
	return "unix://" + path
}

func TestResolveContainerdEndpointSkipsReachableNonCRICandidate(t *testing.T) {
	first := startUnixGRPCServer(t, nil)
	second := startUnixGRPCServer(t, func(server *grpc.Server) {
		runtimeapi.RegisterRuntimeServiceServer(server, testRuntimeService{})
	})

	got, err := resolveContainerdEndpoint(context.Background(), RuntimeEndpointAuto, []string{first, second}, probeContainerdCRI)
	if err != nil || got != second {
		t.Fatalf("resolved endpoint = %q err=%v, want %q", got, err, second)
	}
}

func TestResolveContainerdEndpointReturnsExplicitEndpoint(t *testing.T) {
	const endpoint = "unix:///host/run/containerd/containerd.sock"
	got, err := resolveContainerdEndpoint(context.Background(), endpoint, nil, nil)
	if err != nil || got != endpoint {
		t.Fatalf("resolved endpoint = %q err=%v, want %q", got, err, endpoint)
	}
}

func TestResolveContainerdEndpointReportsMissingAutoCandidates(t *testing.T) {
	_, err := resolveContainerdEndpoint(context.Background(), RuntimeEndpointAuto, []string{"unix:///missing/containerd.sock"}, func(context.Context, string) error {
		return errors.New("missing")
	})
	if err == nil || !errors.Is(err, ErrContainerdEndpointNotReady) {
		t.Fatalf("expected auto discovery error, got %v", err)
	}
}

func TestResolveContainerdEndpointHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := resolveContainerdEndpoint(ctx, RuntimeEndpointAuto, []string{"unix:///missing/containerd.sock"}, func(context.Context, string) error {
		return errors.New("missing")
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("endpoint discovery error = %v, want context canceled", err)
	}
}
