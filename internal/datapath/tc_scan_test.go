package datapath

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cat-cc-Lcos/FNCache/internal/endpoint"
)

type scanTCBackend struct {
	filters map[int][]TCFilterState
	err     error
}

func (b *scanTCBackend) EnsureClsact(context.Context, endpoint.LinkIdentity) (TCQdiscState, error) {
	return TCQdiscState{}, nil
}
func (b *scanTCBackend) ListFilters(_ context.Context, link endpoint.LinkIdentity) ([]TCFilterState, error) {
	if b.err != nil {
		return nil, b.err
	}
	return b.filters[link.IfIndex], nil
}
func (b *scanTCBackend) AttachFilter(context.Context, TCFilterSpec) (TCFilterState, error) {
	return TCFilterState{}, nil
}
func (b *scanTCBackend) RemoveFilter(context.Context, TCFilterSpec) error { return nil }

func TestTCScannerCollectsAttachmentsAndConflicts(t *testing.T) {
	link := endpoint.LinkIdentity{IfIndex: 7, NetNSInode: 42}
	backend := &scanTCBackend{filters: map[int][]TCFilterState{7: {
		{Link: link, Hook: HookIngress, Program: "tc_masq", ProgramID: 10, Priority: FixedTCPriority, Handle: 0x200, DirectAction: true},
		{Link: link, Hook: HookIngress, Priority: 2000, Handle: 9},
	}}}
	manager, err := NewTCManager(backend)
	if err != nil {
		t.Fatal(err)
	}
	scanner, err := NewTCScanner(manager)
	if err != nil {
		t.Fatal(err)
	}
	scanner.now = func() time.Time { return time.Unix(10, 0).UTC() }
	actual, err := scanner.Scan(context.Background(), []endpoint.LinkIdentity{link, link})
	if err != nil || len(actual.Attachments) != 2 || len(actual.Conflicts) != 1 || actual.ScannedAt.Unix() != 10 {
		t.Fatalf("unexpected TC scan: actual=%+v err=%v", actual, err)
	}
	if actual.Conflicts[0].Identity != "7/42/ingress/2000/9" {
		t.Fatalf("unexpected conflict identity: %+v", actual.Conflicts[0])
	}
}

func TestTCScannerRejectsNonDirectActionFilter(t *testing.T) {
	link := endpoint.LinkIdentity{IfIndex: 7, NetNSInode: 42}
	backend := &scanTCBackend{filters: map[int][]TCFilterState{7: {
		{Link: link, Hook: HookIngress, Program: "tc_masq", ProgramID: 10, Priority: FixedTCPriority, Handle: 0x200},
	}}}
	manager, _ := NewTCManager(backend)
	scanner, _ := NewTCScanner(manager)
	actual, err := scanner.Scan(context.Background(), []endpoint.LinkIdentity{link})
	if err != nil || len(actual.Attachments) != 1 || actual.Attachments[0].DirectAction || len(actual.Conflicts) != 1 {
		t.Fatalf("non-direct-action filter was not rejected: actual=%+v err=%v", actual, err)
	}
	if actual.Conflicts[0].Detail != "TC BPF filter is not direct-action" {
		t.Fatalf("unexpected non-direct-action conflict: %+v", actual.Conflicts[0])
	}
}

func TestTCScannerPropagatesBackendError(t *testing.T) {
	want := errors.New("filter list failed")
	manager, _ := NewTCManager(&scanTCBackend{err: want})
	scanner, _ := NewTCScanner(manager)
	_, err := scanner.Scan(context.Background(), []endpoint.LinkIdentity{{IfIndex: 7}})
	if !errors.Is(err, want) {
		t.Fatalf("expected backend error: %v", err)
	}
}

func TestTCScannerHonorsCancellation(t *testing.T) {
	manager, _ := NewTCManager(&scanTCBackend{})
	scanner, _ := NewTCScanner(manager)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := scanner.Scan(ctx, []endpoint.LinkIdentity{{IfIndex: 7}}); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation: %v", err)
	}
}

func TestTCScannerAllowsEmptyLinks(t *testing.T) {
	manager, _ := NewTCManager(&scanTCBackend{})
	scanner, _ := NewTCScanner(manager)
	actual, err := scanner.Scan(context.Background(), nil)
	if err != nil || len(actual.Attachments) != 0 || len(actual.Conflicts) != 0 {
		t.Fatalf("unexpected empty scan: actual=%+v err=%v", actual, err)
	}
}
