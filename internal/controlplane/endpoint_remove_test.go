package controlplane

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/cat-cc-Lcos/FNCache/internal/datapath"
	"github.com/cat-cc-Lcos/FNCache/internal/endpoint"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

type fakeEndpointMaps struct{ calls []string }

func (m *fakeEndpointMaps) Delete(_ context.Context, name string, _ []byte) (bool, error) {
	m.calls = append(m.calls, "delete:"+name)
	return true, nil
}
func (m *fakeEndpointMaps) Clear(_ context.Context, name string) (int, error) {
	m.calls = append(m.calls, "clear:"+name)
	return 2, nil
}

type fakeEndpointTC struct{ specs []datapath.TCFilterSpec }

func (t *fakeEndpointTC) RemoveFilter(_ context.Context, spec datapath.TCFilterSpec) error {
	t.specs = append(t.specs, spec)
	return nil
}

func ownedEndpoint() reconcile.OwnedEndpoint {
	return reconcile.OwnedEndpoint{PodUID: "pod-1", PodIPv4: netip.MustParseAddr("10.42.0.2"), NetNSInode: 42, PeerIfIndex: 7, HostIfIndex: 8}
}

func endpointAttachments() []reconcile.AttachmentState {
	return []reconcile.AttachmentState{
		{Link: endpoint.LinkIdentity{NetNSInode: 42, IfIndex: 7, NetNSPath: "/proc/1/ns/net"}, Hook: string(datapath.HookIngress), Program: "tc_init_in", Priority: datapath.FixedTCPriority, Handle: 0x201, ProgramID: 11, DirectAction: true},
		{Link: endpoint.LinkIdentity{IfIndex: 8}, Hook: string(datapath.HookIngress), Program: "tc_masq", Priority: datapath.FixedTCPriority, Handle: 0x200, ProgramID: 12, DirectAction: true},
	}
}

func emptyEndpointDesired() reconcile.DesiredState {
	return reconcile.DesiredState{LocalEndpoints: map[string]endpoint.Endpoint{}}
}

func TestEndpointRemoverInvalidatesMapsBeforeRemovingOwnedFilters(t *testing.T) {
	maps := &fakeEndpointMaps{}
	tc := &fakeEndpointTC{}
	remover, err := NewEndpointRemover(maps, tc)
	if err != nil {
		t.Fatal(err)
	}
	if err := remover.Remove(context.Background(), ownedEndpoint(), reconcile.ActualState{Attachments: endpointAttachments()}, emptyEndpointDesired()); err != nil {
		t.Fatal(err)
	}
	if len(maps.calls) != 3 || maps.calls[0] != "delete:ingress_cache" || maps.calls[1] != "delete:egressip_cache" || maps.calls[2] != "clear:policy_cache" {
		t.Fatalf("unexpected Map invalidation order: %v", maps.calls)
	}
	if len(tc.specs) != 2 || tc.specs[0].Program != "tc_init_in" || tc.specs[1].Program != "tc_masq" {
		t.Fatalf("unexpected filter removal: %+v", tc.specs)
	}
}

func TestEndpointRemoverRejectsForeignFilter(t *testing.T) {
	maps := &fakeEndpointMaps{}
	tc := &fakeEndpointTC{}
	remover, _ := NewEndpointRemover(maps, tc)
	attachments := endpointAttachments()
	attachments[0].Program = "foreign"
	err := remover.Remove(context.Background(), ownedEndpoint(), reconcile.ActualState{Attachments: attachments}, emptyEndpointDesired())
	var classified *reconcile.ClassifiedError
	if !errors.As(err, &classified) || classified.Class() != reconcile.ErrorConflict || len(tc.specs) != 0 {
		t.Fatalf("foreign filter was not rejected: err=%v specs=%+v", err, tc.specs)
	}
}

func TestEndpointRemoverRejectsNonDirectActionOwnedAttachment(t *testing.T) {
	maps := &fakeEndpointMaps{}
	tc := &fakeEndpointTC{}
	remover, _ := NewEndpointRemover(maps, tc)
	attachment := endpointAttachments()[0]
	attachment.DirectAction = false
	err := remover.RemoveOwnedAttachment(context.Background(), attachment)
	var classified *reconcile.ClassifiedError
	if !errors.As(err, &classified) || classified.Class() != reconcile.ErrorConflict || len(tc.specs) != 0 {
		t.Fatalf("non-direct-action owned filter was not rejected: err=%v specs=%+v", err, tc.specs)
	}
}

func TestEndpointRemoverIsIdempotentWhenFiltersAreMissing(t *testing.T) {
	maps := &fakeEndpointMaps{}
	tc := &fakeEndpointTC{}
	remover, _ := NewEndpointRemover(maps, tc)
	if err := remover.Remove(context.Background(), ownedEndpoint(), reconcile.ActualState{}, emptyEndpointDesired()); err != nil {
		t.Fatal(err)
	}
	if len(tc.specs) != 0 || len(maps.calls) != 3 {
		t.Fatalf("missing filters were not idempotent: maps=%v specs=%v", maps.calls, tc.specs)
	}
}

func TestEndpointRemoverProtectsReusedIPAndHostLink(t *testing.T) {
	maps := &fakeEndpointMaps{}
	tc := &fakeEndpointTC{}
	remover, _ := NewEndpointRemover(maps, tc)
	desired := reconcile.DesiredState{LocalEndpoints: map[string]endpoint.Endpoint{
		"pod-new": {
			Pod: endpoint.PodIdentity{UID: "pod-new"}, PodIPv4: netip.MustParseAddr("10.42.0.2"), NetNSInode: 99,
			PeerLink: endpoint.LinkIdentity{NetNSInode: 99, IfIndex: 9}, HostLink: endpoint.LinkIdentity{IfIndex: 8},
		},
	}}
	if err := remover.Remove(context.Background(), ownedEndpoint(), reconcile.ActualState{
		Programs: map[string]reconcile.ProgramState{"tc_init_in": {ID: 11}, "tc_masq": {ID: 12}}, Attachments: endpointAttachments(),
	}, desired); err != nil {
		t.Fatal(err)
	}
	if len(maps.calls) != 1 || maps.calls[0] != "clear:policy_cache" {
		t.Fatalf("reused IP was deleted: maps=%v", maps.calls)
	}
	if len(tc.specs) != 1 || tc.specs[0].Program != "tc_init_in" {
		t.Fatalf("reused host filter was deleted: specs=%+v", tc.specs)
	}
}

func TestEndpointRemoverDoesNotProtectOldProgramID(t *testing.T) {
	maps := &fakeEndpointMaps{}
	tc := &fakeEndpointTC{}
	remover, _ := NewEndpointRemover(maps, tc)
	desired := reconcile.DesiredState{LocalEndpoints: map[string]endpoint.Endpoint{
		"pod-new": {
			Pod: endpoint.PodIdentity{UID: "pod-new"}, PodIPv4: netip.MustParseAddr("10.42.0.2"), NetNSInode: 42,
			PeerLink: endpoint.LinkIdentity{NetNSInode: 42, IfIndex: 7}, HostLink: endpoint.LinkIdentity{IfIndex: 8},
		},
	}}
	actual := reconcile.ActualState{
		Programs:    map[string]reconcile.ProgramState{"tc_init_in": {ID: 101}, "tc_masq": {ID: 102}},
		Attachments: endpointAttachments(),
	}
	if err := remover.Remove(context.Background(), ownedEndpoint(), actual, desired); err != nil {
		t.Fatal(err)
	}
	if len(maps.calls) != 1 || maps.calls[0] != "clear:policy_cache" || len(tc.specs) != 2 {
		t.Fatalf("old program filters were protected: maps=%v specs=%+v", maps.calls, tc.specs)
	}
}
