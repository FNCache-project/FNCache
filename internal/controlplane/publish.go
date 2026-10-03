package controlplane

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/cat-cc-Lcos/FNCache/internal/datapath"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
	"github.com/cat-cc-Lcos/FNCache/internal/resolver"
)

type OwnershipCommitter interface {
	Commit(context.Context, reconcile.OwnershipState) error
}

type ControlPublisher interface {
	Publish(context.Context, uint64, uint64, uint64, uint32) error
}

type heartbeatControlPublisher interface {
	RefreshHeartbeat(context.Context, uint64) error
}

type PublishConfig struct {
	InstallationID     string
	NodeUID            string
	ELFBuildID         string
	HeartbeatNS        uint64
	HeartbeatTimeoutNS uint64
	Flags              uint32
	Now                func() time.Time
}

type Publisher struct {
	store   OwnershipCommitter
	control ControlPublisher
	config  PublishConfig
	mu      sync.Mutex
}

func NewPublisher(store OwnershipCommitter, control ControlPublisher, config PublishConfig) (*Publisher, error) {
	if store == nil || control == nil {
		return nil, fmt.Errorf("ownership store and control publisher are required")
	}
	if config.InstallationID == "" || config.NodeUID == "" || config.ELFBuildID == "" {
		return nil, fmt.Errorf("installation ID, node UID and ELF build ID are required")
	}
	if config.HeartbeatNS == 0 || config.HeartbeatTimeoutNS == 0 {
		return nil, fmt.Errorf("heartbeat values must be non-zero")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &Publisher{store: store, control: control, config: config}, nil
}

func (p *Publisher) CommitAndPublish(ctx context.Context, desired reconcile.DesiredState, actual reconcile.ActualState) error {
	if err := VerifyState(desired, actual); err != nil {
		return err
	}
	state := p.ownershipState(desired, actual)
	if err := p.store.Commit(ctx, state); err != nil {
		return fmt.Errorf("commit ownership: %w", err)
	}
	if err := p.publishControl(ctx, desired.Generation); err != nil {
		return fmt.Errorf("publish generation %d: %w", desired.Generation, err)
	}
	return nil
}

func (p *Publisher) RefreshHeartbeat(ctx context.Context, heartbeatNS uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	refresher, ok := p.control.(heartbeatControlPublisher)
	if !ok {
		return fmt.Errorf("control publisher does not support heartbeat refresh")
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if err := refresher.RefreshHeartbeat(ctx, heartbeatNS); err != nil {
		return err
	}
	p.config.HeartbeatNS = heartbeatNS
	return nil
}

func (p *Publisher) publishControl(ctx context.Context, generation uint64) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.control.Publish(ctx, generation, p.config.HeartbeatNS, p.config.HeartbeatTimeoutNS, p.config.Flags)
}

func VerifyState(desired reconcile.DesiredState, actual reconcile.ActualState) error {
	if !desired.Enabled {
		return fmt.Errorf("cannot publish disabled desired state")
	}
	if !actual.Control.Verified || actual.Control.Enabled {
		return fmt.Errorf("cannot publish while actual control Map is enabled or unverified")
	}
	if len(actual.Conflicts) != 0 {
		return fmt.Errorf("cannot publish with %d actual conflicts", len(actual.Conflicts))
	}
	programs := make(map[string]uint32, len(requiredPrograms))
	for _, name := range requiredPrograms {
		program, ok := actual.Programs[name]
		if !ok || program.ID == 0 {
			return fmt.Errorf("required program is unavailable: %s", name)
		}
		if program.Name != "" && program.Name != name {
			return fmt.Errorf("program identity mismatch: got %q want %q", program.Name, name)
		}
		programs[name] = program.ID
	}
	for _, expected := range requiredMaps {
		state, ok := actual.Maps[expected.name]
		if !ok || state.ID == 0 || state.KeySize != expected.keySize || state.ValueSize != expected.valueSize || state.MaxEntries != expected.maxEntries {
			return fmt.Errorf("required Map schema is not verified: %s", expected.name)
		}
	}
	if !actual.FlannelRule.Present {
		return fmt.Errorf("Flannel marker rule is not present")
	}
	if err := verifyAttachment(actual.Attachments, desired.Flannel.UnderlayLink, datapath.HookEgress, "tc_init_e", programs["tc_init_e"]); err != nil {
		return err
	}
	if err := verifyAttachment(actual.Attachments, desired.Flannel.UnderlayLink, datapath.HookIngress, "tc_restore", programs["tc_restore"]); err != nil {
		return err
	}
	for uid, endpoint := range desired.LocalEndpoints {
		if err := verifyAttachment(actual.Attachments, endpoint.PeerLink, datapath.HookIngress, "tc_init_in", programs["tc_init_in"]); err != nil {
			return fmt.Errorf("endpoint %s: %w", uid, err)
		}
		if err := verifyAttachment(actual.Attachments, endpoint.HostLink, datapath.HookIngress, "tc_masq", programs["tc_masq"]); err != nil {
			return fmt.Errorf("endpoint %s: %w", uid, err)
		}
	}
	return nil
}

var requiredPrograms = []string{"tc_init_e", "tc_restore", "tc_init_in", "tc_masq"}

var requiredMaps = []struct {
	name                           string
	keySize, valueSize, maxEntries uint32
}{
	{name: "egressip_cache", keySize: 4, valueSize: 4, maxEntries: 4096},
	{name: "egress_cache", keySize: 4, valueSize: 68, maxEntries: 1024},
	{name: "ingress_cache", keySize: 4, valueSize: 16, maxEntries: 1024},
	{name: "policy_cache", keySize: 16, valueSize: 4, maxEntries: 4096},
	{name: "devmap", keySize: 4, valueSize: 12, maxEntries: 8},
	{name: "control_map", keySize: 4, valueSize: 40, maxEntries: 1},
	{name: "policy_lock_map", keySize: 4, valueSize: 4, maxEntries: 1},
	{name: "stats_map", keySize: 4, valueSize: 8, maxEntries: 14},
}

func verifyAttachment(attachments []reconcile.AttachmentState, link resolver.LinkIdentity, hook datapath.TCHook, program string, programID uint32) error {
	spec, err := datapath.NewFixedFilter(link, program, programID, true)
	if err != nil {
		return fmt.Errorf("build verification filter %s: %w", program, err)
	}
	if !hasAttachment(attachments, spec) {
		return fmt.Errorf("verified TC attachment is missing: %s/%d", program, link.IfIndex)
	}
	return nil
}

func (p *Publisher) ownershipState(desired reconcile.DesiredState, actual reconcile.ActualState) reconcile.OwnershipState {
	programs := make(map[string]reconcile.ProgramState, len(actual.Programs))
	for name, state := range actual.Programs {
		programs[name] = state
	}
	maps := make(map[string]reconcile.MapState, len(actual.Maps))
	for name, state := range actual.Maps {
		maps[name] = state
	}
	attachments := append([]reconcile.AttachmentState(nil), actual.Attachments...)
	endpoints := make(map[string]reconcile.OwnedEndpoint, len(desired.LocalEndpoints))
	uids := make([]string, 0, len(desired.LocalEndpoints))
	for uid := range desired.LocalEndpoints {
		uids = append(uids, uid)
	}
	sort.Strings(uids)
	for _, uid := range uids {
		endpoint := desired.LocalEndpoints[uid]
		endpoints[uid] = reconcile.OwnedEndpoint{PodUID: uid, PodIPv4: endpoint.PodIPv4, NetNSInode: endpoint.NetNSInode, PeerIfIndex: endpoint.PeerLink.IfIndex, HostIfIndex: endpoint.HostLink.IfIndex}
	}
	return reconcile.OwnershipState{
		SchemaVersion: 1, InstallationID: p.config.InstallationID, NodeUID: p.config.NodeUID,
		Generation: desired.Generation, ELFBuildID: p.config.ELFBuildID, ABI: reconcile.BPFABIVersion,
		Programs: programs, Maps: maps, Attachments: attachments, Endpoints: endpoints,
		FlannelRule:     reconcile.OwnedRule{Identity: actual.FlannelRule.Identity, Comment: actual.FlannelRule.Identity, Fingerprint: actual.FlannelRule.Fingerprint},
		LastCommittedAt: p.config.Now(),
	}
}
