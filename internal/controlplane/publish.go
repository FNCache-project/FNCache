package controlplane

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/cat-cc-Lcos/FNCache/internal/datapath"
	"github.com/cat-cc-Lcos/FNCache/internal/endpoint"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

type OwnershipCommitter interface {
	Commit(context.Context, reconcile.OwnershipState) error
}

type ControlPublisher interface {
	Publish(context.Context, uint64, uint64, uint64, uint32, uint32, uint16) error
}

type PublishGuard func(context.Context) error

type PublishConfig struct {
	InstallationID     string
	NodeUID            string
	ELFBuildID         string
	Schema             datapath.CollectionSchema
	HeartbeatNS        uint64
	HeartbeatTimeoutNS uint64
	Flags              uint32
	Now                func() time.Time
}

type Publisher struct {
	store   OwnershipCommitter
	control ControlPublisher
	config  PublishConfig
	schema  datapath.CollectionSchema
	guard   PublishGuard
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
	if len(config.Schema.Maps) == 0 && len(config.Schema.Programs) == 0 {
		config.Schema = datapath.V1Schema()
	}
	if err := validatePublisherSchema(config.Schema); err != nil {
		return nil, err
	}
	return &Publisher{store: store, control: control, config: config, schema: config.Schema}, nil
}

// SetPublishGuard installs a freshness check before this publisher commits or
// enables a generation. It must be called before the publisher is used.
func (p *Publisher) SetPublishGuard(guard PublishGuard) { p.guard = guard }

func (p *Publisher) checkPublishGuard(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if p.guard == nil {
		return nil
	}
	if err := p.guard(ctx); err != nil {
		return fmt.Errorf("publish guard: %w", err)
	}
	return nil
}

func (p *Publisher) CommitAndPublish(ctx context.Context, desired reconcile.DesiredState, actual reconcile.ActualState) error {
	if err := p.VerifyState(desired, actual); err != nil {
		return err
	}
	if err := p.checkPublishGuard(ctx); err != nil {
		return err
	}
	state := p.ownershipState(desired, actual)
	if err := p.store.Commit(ctx, state); err != nil {
		return fmt.Errorf("commit ownership: %w", err)
	}
	if err := p.checkPublishGuard(ctx); err != nil {
		return err
	}
	if err := p.control.Publish(ctx, desired.Generation, p.config.HeartbeatNS, p.config.HeartbeatTimeoutNS, p.config.Flags,
		desired.Datapath.VXLANVNI, desired.Datapath.VXLANUDPPort); err != nil {
		return fmt.Errorf("publish generation %d: %w", desired.Generation, err)
	}
	return nil
}

func (p *Publisher) VerifyState(desired reconcile.DesiredState, actual reconcile.ActualState) error {
	return verifyState(desired, actual, p.schema)
}

func endpointScanCompletenessError(skipped map[string]string) error {
	if len(skipped) == 0 {
		return nil
	}
	return reconcile.NewClassifiedError(
		reconcile.ErrorRetryable,
		reconcile.ReasonEndpointNotReady,
		0,
		fmt.Errorf("endpoint scan incomplete: %d endpoint(s) skipped", len(skipped)),
	)
}

func validateEndpointScanCompleteness(desired reconcile.DesiredState) error {
	return endpointScanCompletenessError(desired.EndpointScanSkipped)
}

func validateActualEndpointScanCompleteness(actual reconcile.ActualState) error {
	return endpointScanCompletenessError(actual.EndpointScanSkipped)
}

func VerifyState(desired reconcile.DesiredState, actual reconcile.ActualState) error {
	return verifyState(desired, actual, datapath.V1Schema())
}

func verifyState(desired reconcile.DesiredState, actual reconcile.ActualState, schema datapath.CollectionSchema) error {
	if !desired.Enabled {
		return fmt.Errorf("cannot publish disabled desired state")
	}
	if err := validateDatapathConfig(desired); err != nil {
		return err
	}
	if err := validateEndpointScanCompleteness(desired); err != nil {
		return err
	}
	if err := validateActualEndpointScanCompleteness(actual); err != nil {
		return err
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
	for _, expected := range schema.Maps {
		state, ok := actual.Maps[expected.Name]
		if !ok || state.ID == 0 || state.KeySize != expected.KeySize || state.ValueSize != expected.ValueSize || state.MaxEntries != expected.MaxEntries {
			return fmt.Errorf("required Map schema is not verified: %s", expected.Name)
		}
	}
	if !actual.FlannelRule.Present || !actual.FlannelRule.JumpsPresent {
		return fmt.Errorf("Flannel marker rule or hook jumps are not present")
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

func validateDatapathConfig(desired reconcile.DesiredState) error {
	if desired.Datapath.VXLANVNI == 0 || desired.Datapath.VXLANVNI > 0xffffff {
		return fmt.Errorf("invalid desired VXLAN VNI: %d", desired.Datapath.VXLANVNI)
	}
	if desired.Datapath.VXLANUDPPort == 0 {
		return fmt.Errorf("invalid desired VXLAN UDP port: %d", desired.Datapath.VXLANUDPPort)
	}
	return nil
}

var requiredPrograms = []string{"tc_init_e", "tc_restore", "tc_init_in", "tc_masq"}

func validatePublisherSchema(schema datapath.CollectionSchema) error {
	if err := validateSchemaNames("program", requiredPrograms, schema.Programs); err != nil {
		return err
	}
	expectedSchema := datapath.V1Schema()
	expectedMaps := make(map[string]datapath.MapSchema, len(expectedSchema.Maps))
	for _, expected := range expectedSchema.Maps {
		expectedMaps[expected.Name] = expected
	}
	actualMaps := make(map[string]datapath.MapSchema, len(schema.Maps))
	for _, actual := range schema.Maps {
		if actual.Name == "" {
			return fmt.Errorf("publisher Map schema contains an empty name")
		}
		if _, exists := actualMaps[actual.Name]; exists {
			return fmt.Errorf("publisher Map schema contains duplicate Map: %s", actual.Name)
		}
		actualMaps[actual.Name] = actual
	}
	if len(actualMaps) != len(expectedMaps) {
		return fmt.Errorf("publisher Map schema count mismatch: got %d want %d", len(actualMaps), len(expectedMaps))
	}
	for name, expected := range expectedMaps {
		actual, ok := actualMaps[name]
		if !ok {
			return fmt.Errorf("publisher Map schema is missing: %s", name)
		}
		if actual.Type != expected.Type || actual.KeySize != expected.KeySize || actual.ValueSize != expected.ValueSize || actual.Flags != expected.Flags {
			return fmt.Errorf("publisher Map schema mismatch for %s", name)
		}
		if isPublisherCapacityMap(name) {
			if actual.MaxEntries == 0 {
				return fmt.Errorf("publisher Map capacity must be greater than zero: %s", name)
			}
		} else if actual.MaxEntries != expected.MaxEntries {
			return fmt.Errorf("publisher fixed Map capacity mismatch for %s: got %d want %d", name, actual.MaxEntries, expected.MaxEntries)
		}
	}
	return nil
}

func validateSchemaNames(kind string, expected, actual []string) error {
	expectedCopy := append([]string(nil), expected...)
	actualCopy := append([]string(nil), actual...)
	sort.Strings(expectedCopy)
	sort.Strings(actualCopy)
	if len(expectedCopy) != len(actualCopy) {
		return fmt.Errorf("publisher %s schema count mismatch: got %v want %v", kind, actualCopy, expectedCopy)
	}
	for index := range expectedCopy {
		if expectedCopy[index] != actualCopy[index] {
			return fmt.Errorf("publisher %s schema mismatch: got %v want %v", kind, actualCopy, expectedCopy)
		}
	}
	return nil
}

func isPublisherCapacityMap(name string) bool {
	switch name {
	case "egressip_cache", "egress_cache", "ingress_cache", "policy_cache", "devmap":
		return true
	default:
		return false
	}
}

func verifyAttachment(attachments []reconcile.AttachmentState, link endpoint.LinkIdentity, hook datapath.TCHook, program string, programID uint32) error {
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
