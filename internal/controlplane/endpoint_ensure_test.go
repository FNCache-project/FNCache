package controlplane

import (
	"context"
	"net/netip"
	"testing"

	"github.com/cat-cc-Lcos/FNCache/internal/datapath"
	"github.com/cat-cc-Lcos/FNCache/internal/endpoint"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

func TestEndpointEnsurerAttachesPodFilters(t *testing.T) {
	backend := &fakeBaseTCBackend{}
	tc, _ := datapath.NewTCManager(backend)
	ensurer, _ := NewEndpointEnsurer(tc)
	resolvedEndpoint := endpointEnsureTestEndpoint()
	desired := reconcile.DesiredState{Enabled: true, LocalEndpoints: map[string]endpoint.Endpoint{resolvedEndpoint.Pod.UID: resolvedEndpoint}}
	actual := reconcile.ActualState{Programs: map[string]reconcile.ProgramState{
		"tc_init_in": {ID: 20, Name: "tc_init_in"},
		"tc_masq":    {ID: 21, Name: "tc_masq"},
	}}
	changed, err := ensurer.EnsureEndpoint(context.Background(), desired, actual, resolvedEndpoint)
	if err != nil || !changed || len(backend.attached) != 2 {
		t.Fatalf("unexpected endpoint ensure: changed=%v attached=%+v err=%v", changed, backend.attached, err)
	}
	if backend.attached[0].Program != "tc_init_in" || backend.attached[0].Link.IfIndex != resolvedEndpoint.PeerLink.IfIndex || backend.attached[0].Link.NetNSPath != resolvedEndpoint.PeerLink.NetNSPath || backend.attached[0].Handle != 0x201 ||
		backend.attached[1].Program != "tc_masq" || backend.attached[1].Link.IfIndex != resolvedEndpoint.HostLink.IfIndex || backend.attached[1].Handle != 0x200 {
		t.Fatalf("unexpected endpoint attachments: %+v", backend.attached)
	}
}

func TestEndpointEnsurerRejectsIdentityMismatchBeforeWriting(t *testing.T) {
	backend := &fakeBaseTCBackend{}
	tc, _ := datapath.NewTCManager(backend)
	ensurer, _ := NewEndpointEnsurer(tc)
	expected := endpointEnsureTestEndpoint()
	actualEndpoint := expected
	actualEndpoint.HostLink.IfIndex++
	desired := reconcile.DesiredState{Enabled: true, LocalEndpoints: map[string]endpoint.Endpoint{expected.Pod.UID: expected}}
	actual := endpointEnsureTestActualPrograms()
	if _, err := ensurer.EnsureEndpoint(context.Background(), desired, actual, actualEndpoint); err == nil || len(backend.attached) != 0 {
		t.Fatalf("identity mismatch was not rejected before writes: err=%v attached=%+v", err, backend.attached)
	}
}

func TestEndpointEnsurerValidatesProgramsBeforeWriting(t *testing.T) {
	backend := &fakeBaseTCBackend{}
	tc, _ := datapath.NewTCManager(backend)
	ensurer, _ := NewEndpointEnsurer(tc)
	resolvedEndpoint := endpointEnsureTestEndpoint()
	desired := reconcile.DesiredState{Enabled: true, LocalEndpoints: map[string]endpoint.Endpoint{resolvedEndpoint.Pod.UID: resolvedEndpoint}}
	actual := endpointEnsureTestActualPrograms()
	delete(actual.Programs, "tc_masq")
	if _, err := ensurer.EnsureEndpoint(context.Background(), desired, actual, resolvedEndpoint); err == nil || len(backend.attached) != 0 {
		t.Fatalf("missing program was not rejected before writes: err=%v attached=%+v", err, backend.attached)
	}
}

func TestEndpointEnsurerRejectsIncompleteLinkIdentityBeforeWriting(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*endpoint.Endpoint)
	}{
		{name: "empty peer MAC", mutate: func(resolved *endpoint.Endpoint) { resolved.PeerLink.MAC = nil }},
		{name: "short host MAC", mutate: func(resolved *endpoint.Endpoint) { resolved.HostLink.MAC = []byte{2, 0, 0} }},
		{name: "empty host name", mutate: func(resolved *endpoint.Endpoint) { resolved.HostLink.IfName = "" }},
		{name: "host link in non-host namespace", mutate: func(resolved *endpoint.Endpoint) { resolved.HostLink.NetNSInode = 42 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			backend := &fakeBaseTCBackend{}
			tc, _ := datapath.NewTCManager(backend)
			ensurer, _ := NewEndpointEnsurer(tc)
			resolvedEndpoint := endpointEnsureTestEndpoint()
			test.mutate(&resolvedEndpoint)
			desired := reconcile.DesiredState{Enabled: true, LocalEndpoints: map[string]endpoint.Endpoint{resolvedEndpoint.Pod.UID: resolvedEndpoint}}
			if _, err := ensurer.EnsureEndpoint(context.Background(), desired, endpointEnsureTestActualPrograms(), resolvedEndpoint); err == nil || len(backend.attached) != 0 {
				t.Fatalf("incomplete link identity was not rejected before writes: err=%v attached=%+v", err, backend.attached)
			}
		})
	}
}

func TestEndpointEnsurerDisabledIsNoOp(t *testing.T) {
	backend := &fakeBaseTCBackend{}
	tc, _ := datapath.NewTCManager(backend)
	ensurer, _ := NewEndpointEnsurer(tc)
	resolvedEndpoint := endpointEnsureTestEndpoint()
	desired := reconcile.DesiredState{Enabled: false, LocalEndpoints: map[string]endpoint.Endpoint{resolvedEndpoint.Pod.UID: resolvedEndpoint}}
	changed, err := ensurer.EnsureEndpoint(context.Background(), desired, reconcile.ActualState{}, resolvedEndpoint)
	if err != nil || changed || len(backend.attached) != 0 {
		t.Fatalf("disabled endpoint ensure changed state: changed=%v attached=%+v err=%v", changed, backend.attached, err)
	}
}

func endpointEnsureTestEndpoint() endpoint.Endpoint {
	return endpoint.Endpoint{
		Pod:  endpoint.PodIdentity{Namespace: "default", Name: "web", UID: "pod-a"},
		Node: endpoint.NodeIdentity{Name: "node-a"}, PodIPv4: netip.MustParseAddr("10.244.1.10"), NetNSInode: 42,
		PeerLink: endpoint.LinkIdentity{NetNSInode: 42, NetNSPath: "/proc/123/ns/net", IfIndex: 10, IfName: "eth0", MAC: []byte{2, 0, 0, 0, 0, 2}},
		HostLink: endpoint.LinkIdentity{IfIndex: 20, IfName: "vethweb", MAC: []byte{2, 0, 0, 0, 0, 3}},
	}
}

func endpointEnsureTestActualPrograms() reconcile.ActualState {
	return reconcile.ActualState{Programs: map[string]reconcile.ProgramState{
		"tc_init_in": {ID: 20, Name: "tc_init_in"},
		"tc_masq":    {ID: 21, Name: "tc_masq"},
	}}
}
