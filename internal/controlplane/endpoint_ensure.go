package controlplane

import (
	"bytes"
	"context"
	"fmt"

	"github.com/cat-cc-Lcos/FNCache/internal/datapath"
	"github.com/cat-cc-Lcos/FNCache/internal/endpoint"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

type EndpointEnsurer struct {
	tc *datapath.TCManager
}

func NewEndpointEnsurer(tc *datapath.TCManager) (*EndpointEnsurer, error) {
	if tc == nil {
		return nil, fmt.Errorf("TC manager is required")
	}
	return &EndpointEnsurer{tc: tc}, nil
}

func (e *EndpointEnsurer) EnsureEndpoint(ctx context.Context, desired reconcile.DesiredState, actual reconcile.ActualState, resolvedEndpoint endpoint.Endpoint) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if !desired.Enabled {
		return false, nil
	}
	expected, ok := desired.LocalEndpoints[resolvedEndpoint.Pod.UID]
	if !ok || !sameEndpointIdentity(expected, resolvedEndpoint) {
		return false, fmt.Errorf("endpoint is not the current desired identity: %s", resolvedEndpoint.Pod.UID)
	}
	if err := resolvedEndpoint.Validate(); err != nil {
		return false, fmt.Errorf("validate endpoint: %w", err)
	}

	programs := make(map[string]uint32, 2)
	for _, name := range []string{"tc_init_in", "tc_masq"} {
		program, ok := actual.Programs[name]
		if !ok || program.ID == 0 {
			return false, fmt.Errorf("required endpoint program is unavailable: %s", name)
		}
		if program.Name != "" && program.Name != name {
			return false, fmt.Errorf("endpoint program identity mismatch: got %q want %q", program.Name, name)
		}
		programs[name] = program.ID
	}

	attachments := []struct {
		program string
		link    endpoint.LinkIdentity
	}{
		{program: "tc_init_in", link: resolvedEndpoint.PeerLink},
		{program: "tc_masq", link: resolvedEndpoint.HostLink},
	}
	changed := false
	for _, attachment := range attachments {
		spec, err := datapath.NewFixedFilter(attachment.link, attachment.program, programs[attachment.program], true)
		if err != nil {
			return changed, fmt.Errorf("build endpoint filter %s: %w", attachment.program, err)
		}
		if !hasAttachment(actual.Attachments, spec) {
			changed = true
		}
		if _, err := e.tc.EnsureFilter(ctx, spec); err != nil {
			return changed, fmt.Errorf("ensure endpoint filter %s: %w", attachment.program, err)
		}
	}
	return changed, nil
}

func sameEndpointIdentity(expected, actual endpoint.Endpoint) bool {
	return expected.Pod == actual.Pod && expected.Node == actual.Node && expected.PodIPv4 == actual.PodIPv4 &&
		expected.NetNSInode == actual.NetNSInode && sameLinkIdentity(expected.PeerLink, actual.PeerLink) &&
		sameLinkIdentity(expected.HostLink, actual.HostLink)
}

func sameLinkIdentity(expected, actual endpoint.LinkIdentity) bool {
	return expected.NetNSInode == actual.NetNSInode && expected.IfIndex == actual.IfIndex &&
		expected.IfName == actual.IfName && bytes.Equal(expected.MAC, actual.MAC)
}
