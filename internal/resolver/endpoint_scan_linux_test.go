//go:build linux

package resolver

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

type fakeEndpointResolver struct {
	endpoints map[string]Endpoint
	errors    map[string]error
	calls     int
}

func (f *fakeEndpointResolver) Resolve(_ context.Context, pod PodSnapshot) (Endpoint, error) {
	f.calls++
	if err := f.errors[pod.Identity.UID]; err != nil {
		return Endpoint{}, err
	}
	return f.endpoints[pod.Identity.UID], nil
}
func (f *fakeEndpointResolver) Validate(context.Context, Endpoint) error { return nil }

func scanPod(uid, version string) PodSnapshot {
	return PodSnapshot{Identity: PodIdentity{Namespace: "default", Name: uid, UID: uid}, NodeName: "node-a", PodIPv4: netip.MustParseAddr("10.244.1.10"), Phase: "Running", ResourceVersion: version}
}

func scanEndpoint(uid string) Endpoint {
	return Endpoint{Pod: PodIdentity{Namespace: "default", Name: uid, UID: uid}, Node: NodeIdentity{Name: "node-a"}, PodIPv4: netip.MustParseAddr("10.244.1.10"), NetNSInode: 42, PeerLink: LinkIdentity{NetNSInode: 42, IfIndex: 10, IfName: "eth0"}, HostLink: LinkIdentity{IfIndex: 20}}
}

func TestEndpointScannerCollectsReadyEndpoints(t *testing.T) {
	resolver := &fakeEndpointResolver{endpoints: map[string]Endpoint{"pod-a": scanEndpoint("pod-a"), "pod-b": scanEndpoint("pod-b")}, errors: map[string]error{}}
	scanner, err := NewEndpointScanner(resolver)
	if err != nil {
		t.Fatal(err)
	}
	result, err := scanner.Scan(context.Background(), []PodSnapshot{scanPod("pod-a", "1"), scanPod("pod-b", "1")})
	if err != nil || len(result.Endpoints) != 2 || len(result.Skipped) != 0 || resolver.calls != 2 {
		t.Fatalf("unexpected endpoint scan: result=%+v err=%v calls=%d", result, err, resolver.calls)
	}
}

func TestEndpointScannerIgnoresDeletingAndHostNetworkPods(t *testing.T) {
	deleting := scanPod("pod-deleting", "1")
	deleting.Deleting = true
	hostNetwork := scanPod("pod-host", "1")
	hostNetwork.HostNetwork = true
	succeeded := scanPod("pod-succeeded", "1")
	succeeded.Phase = "Succeeded"
	failed := scanPod("pod-failed", "1")
	failed.Phase = "Failed"
	fake := &fakeEndpointResolver{endpoints: map[string]Endpoint{}, errors: map[string]error{}}
	scanner, _ := NewEndpointScanner(fake)

	result, err := scanner.Scan(context.Background(), []PodSnapshot{deleting, hostNetwork, succeeded, failed})
	if err != nil || len(result.Endpoints) != 0 || len(result.Skipped) != 0 || fake.calls != 0 {
		t.Fatalf("ignored endpoint candidates were resolved: result=%+v err=%v calls=%d", result, err, fake.calls)
	}
}

func TestEndpointScannerSkipsNonRunningPods(t *testing.T) {
	pending := scanPod("pod-pending", "1")
	pending.Phase = "Pending"
	unknown := scanPod("pod-unknown", "1")
	unknown.Phase = "Unknown"
	fake := &fakeEndpointResolver{endpoints: map[string]Endpoint{}, errors: map[string]error{}}
	scanner, _ := NewEndpointScanner(fake)

	result, err := scanner.Scan(context.Background(), []PodSnapshot{pending, unknown})
	if err != nil || len(result.Endpoints) != 0 || len(result.Skipped) != 2 || fake.calls != 0 {
		t.Fatalf("non-running endpoint candidates were resolved: result=%+v err=%v calls=%d", result, err, fake.calls)
	}
	for _, uid := range []string{"pod-pending", "pod-unknown"} {
		if !errors.Is(result.Skipped[uid], ErrEndpointNotReady) {
			t.Fatalf("non-running Pod %s was not marked not ready: %#v", uid, result.Skipped)
		}
	}
}

func TestEndpointScannerSkipsRecoverableEndpointErrors(t *testing.T) {
	resolver := &fakeEndpointResolver{endpoints: map[string]Endpoint{"pod-a": scanEndpoint("pod-a")}, errors: map[string]error{"pod-b": ErrEndpointNotReady, "pod-c": ErrStaleObject, "pod-d": ErrUnsupported}}
	scanner, _ := NewEndpointScanner(resolver)
	result, err := scanner.Scan(context.Background(), []PodSnapshot{scanPod("pod-a", "1"), scanPod("pod-b", "1"), scanPod("pod-c", "1"), scanPod("pod-d", "1")})
	if err != nil || len(result.Endpoints) != 1 || len(result.Skipped) != 3 {
		t.Fatalf("unexpected skipped endpoint result: result=%+v err=%v", result, err)
	}
}

func TestEndpointScannerStopsOnDuplicateOrFatalError(t *testing.T) {
	resolver, _ := NewEndpointScanner(&fakeEndpointResolver{endpoints: map[string]Endpoint{}, errors: map[string]error{}})
	if _, err := resolver.Scan(context.Background(), []PodSnapshot{scanPod("pod-a", "1"), scanPod("pod-a", "2")}); err == nil {
		t.Fatal("expected duplicate snapshot error")
	}
	fatal := errors.New("netns restore failed")
	resolver, _ = NewEndpointScanner(&fakeEndpointResolver{endpoints: map[string]Endpoint{}, errors: map[string]error{"pod-a": fatal}})
	if _, err := resolver.Scan(context.Background(), []PodSnapshot{scanPod("pod-a", "1")}); !errors.Is(err, fatal) {
		t.Fatalf("expected fatal resolver error: %v", err)
	}
}

func TestEndpointScannerHonorsCancellation(t *testing.T) {
	fake := &fakeEndpointResolver{endpoints: map[string]Endpoint{}, errors: map[string]error{}}
	scanner, _ := NewEndpointScanner(fake)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := scanner.Scan(ctx, []PodSnapshot{scanPod("pod-a", "1")}); !errors.Is(err, context.Canceled) || fake.calls != 0 {
		t.Fatalf("expected cancellation before resolver: err=%v calls=%d", err, fake.calls)
	}
}
