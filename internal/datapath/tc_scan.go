package datapath

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cat-cc-Lcos/FNCache/internal/endpoint"
	"github.com/cat-cc-Lcos/FNCache/internal/hostnet/discovery"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
	"github.com/vishvananda/netlink"
)

type TCScanner struct {
	manager *TCManager
	now     func() time.Time
}

func NewTCScanner(manager *TCManager) (*TCScanner, error) {
	if manager == nil {
		return nil, fmt.Errorf("TC manager is required")
	}
	return &TCScanner{manager: manager, now: time.Now}, nil
}

func (s *TCScanner) Scan(ctx context.Context, links []endpoint.LinkIdentity) (reconcile.ActualState, error) {
	actual := reconcile.ActualState{ScannedAt: s.now()}
	seen := make(map[struct {
		ns    uint64
		index int
	}]struct{}, len(links))
	for _, link := range links {
		key := struct {
			ns    uint64
			index int
		}{link.NetNSInode, link.IfIndex}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		if err := ctx.Err(); err != nil {
			return reconcile.ActualState{}, err
		}
		filters, err := s.manager.ListFilters(ctx, link)
		if err != nil {
			var notFound netlink.LinkNotFoundError
			if errors.As(err, &notFound) {
				continue
			}
			return reconcile.ActualState{}, fmt.Errorf("scan TC filters on ifindex %d: %w", link.IfIndex, err)
		}
		for _, filter := range filters {
			actual.Attachments = append(actual.Attachments, reconcile.AttachmentState{
				Link: filter.Link, Hook: string(filter.Hook), Program: filter.Program,
				Priority: filter.Priority, Handle: filter.Handle, ProgramID: filter.ProgramID, DirectAction: filter.DirectAction,
			})
			if filter.Program == "" || filter.ProgramID == 0 {
				actual.Conflicts = append(actual.Conflicts, discovery.Conflict{
					Kind: "tc-filter", Identity: tcFilterIdentity(filter), Detail: "filter program identity is not verifiable",
				})
			} else if !filter.DirectAction && filter.Priority == FixedTCPriority && isFixedAttachment(filter) {
				actual.Conflicts = append(actual.Conflicts, discovery.Conflict{
					Kind: "tc-filter", Identity: tcFilterIdentity(filter), Detail: "TC BPF filter is not direct-action",
				})
			}
		}
	}
	return actual, nil
}

func tcFilterIdentity(filter TCFilterState) string {
	return fmt.Sprintf("%d/%d/%s/%d/%d", filter.Link.IfIndex, filter.Link.NetNSInode, filter.Hook, filter.Priority, filter.Handle)
}
