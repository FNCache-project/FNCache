package controlplane

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/cat-cc-Lcos/FNCache/internal/datapath"
	"github.com/cat-cc-Lcos/FNCache/internal/discovery"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
	"github.com/cat-cc-Lcos/FNCache/internal/resolver"
)

type fakeOwnershipCommitter struct {
	events *[]string
	state  reconcile.OwnershipState
	err    error
}

func (f *fakeOwnershipCommitter) Commit(_ context.Context, state reconcile.OwnershipState) error {
	*f.events = append(*f.events, "commit")
	if f.err != nil {
		return f.err
	}
	f.state = state
	return nil
}

type fakeControlPublisher struct {
	events              *[]string
	generation, timeout uint64
	flags               uint32
	err                 error
}

func (f *fakeControlPublisher) Publish(_ context.Context, generation, timeout uint64, flags uint32) error {
	*f.events = append(*f.events, "publish")
	f.generation, f.timeout, f.flags = generation, timeout, flags
	return f.err
}

func TestVerifyStateRequiresCompleteVerifiedObjects(t *testing.T) {
	desired := publishTestDesired()
	actual := publishTestActual(desired)
	if err := VerifyState(desired, actual); err != nil {
		t.Fatal(err)
	}
	actual.Control.Enabled = true
	if err := VerifyState(desired, actual); err == nil {
		t.Fatal("enabled control Map was accepted")
	}
	actual.Control.Enabled = false
	delete(actual.Programs, "tc_restore")
	if err := VerifyState(desired, actual); err == nil {
		t.Fatal("missing program was accepted")
	}
}

func TestPublisherCommitsOwnershipBeforePublishing(t *testing.T) {
	desired := publishTestDesired()
	actual := publishTestActual(desired)
	events := make([]string, 0, 2)
	store := &fakeOwnershipCommitter{events: &events}
	control := &fakeControlPublisher{events: &events}
	publisher, err := NewPublisher(store, control, PublishConfig{
		InstallationID: "install-a", NodeUID: "node-a", ELFBuildID: "sha256:build",
		HeartbeatTimeoutNS: uint64(500 * time.Millisecond), Flags: 3, Now: func() time.Time { return time.Unix(42, 0).UTC() },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := publisher.CommitAndPublish(context.Background(), desired, actual); err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[0] != "commit" || events[1] != "publish" {
		t.Fatalf("unexpected publish order: %v", events)
	}
	if store.state.Generation != 7 || store.state.InstallationID != "install-a" || store.state.NodeUID != "node-a" ||
		store.state.ABI != reconcile.BPFABIVersion || store.state.LastCommittedAt.Unix() != 42 || len(store.state.Endpoints) != 1 {
		t.Fatalf("unexpected ownership state: %+v", store.state)
	}
	if control.generation != 7 || control.timeout != uint64(500*time.Millisecond) || control.flags != 3 {
		t.Fatalf("unexpected control publish: generation=%d timeout=%d flags=%d", control.generation, control.timeout, control.flags)
	}
}

func TestPublisherDoesNotCommitWhenVerificationFails(t *testing.T) {
	desired := publishTestDesired()
	actual := publishTestActual(desired)
	actual.Conflicts = []discovery.Conflict{{Kind: "tc-filter", Identity: "foreign"}}
	events := []string{}
	store := &fakeOwnershipCommitter{events: &events}
	control := &fakeControlPublisher{events: &events}
	publisher, _ := NewPublisher(store, control, publishTestConfig())
	if err := publisher.CommitAndPublish(context.Background(), desired, actual); err == nil || len(events) != 0 {
		t.Fatalf("verification failure was not stopped: err=%v events=%v", err, events)
	}
}

func TestPublisherDoesNotPublishWhenCommitFails(t *testing.T) {
	desired := publishTestDesired()
	actual := publishTestActual(desired)
	events := []string{}
	store := &fakeOwnershipCommitter{events: &events, err: errors.New("state store unavailable")}
	control := &fakeControlPublisher{events: &events}
	publisher, _ := NewPublisher(store, control, publishTestConfig())
	if err := publisher.CommitAndPublish(context.Background(), desired, actual); err == nil || len(events) != 1 || events[0] != "commit" {
		t.Fatalf("commit failure did not keep publish disabled: err=%v events=%v", err, events)
	}
}

func TestPublisherKeepsFailureWhenControlPublishFails(t *testing.T) {
	desired := publishTestDesired()
	actual := publishTestActual(desired)
	events := []string{}
	store := &fakeOwnershipCommitter{events: &events}
	control := &fakeControlPublisher{events: &events, err: errors.New("control update failed")}
	publisher, _ := NewPublisher(store, control, publishTestConfig())
	if err := publisher.CommitAndPublish(context.Background(), desired, actual); err == nil || len(events) != 2 || events[1] != "publish" {
		t.Fatalf("control publish failure was not returned: err=%v events=%v", err, events)
	}
}

func publishTestConfig() PublishConfig {
	return PublishConfig{InstallationID: "install-a", NodeUID: "node-a", ELFBuildID: "sha256:build", HeartbeatTimeoutNS: uint64(500 * time.Millisecond), Now: func() time.Time { return time.Unix(42, 0).UTC() }}
}

func publishTestDesired() reconcile.DesiredState {
	endpoint := resolver.Endpoint{
		Pod: resolver.PodIdentity{Namespace: "default", Name: "web", UID: "pod-a"}, Node: resolver.NodeIdentity{Name: "node-a"},
		PodIPv4: netip.MustParseAddr("10.244.1.10"), NetNSInode: 42,
		PeerLink: resolver.LinkIdentity{NetNSInode: 42, IfIndex: 10, IfName: "eth0", MAC: []byte{2, 0, 0, 0, 0, 2}},
		HostLink: resolver.LinkIdentity{IfIndex: 20, IfName: "vethweb", MAC: []byte{2, 0, 0, 0, 0, 3}},
	}
	return reconcile.DesiredState{
		Generation: 7, Enabled: true, LocalEndpoints: map[string]resolver.Endpoint{endpoint.Pod.UID: endpoint},
		Flannel: reconcile.FlannelState{UnderlayLink: resolver.LinkIdentity{IfIndex: 2, IfName: "eth0", MAC: []byte{2, 0, 0, 0, 0, 1}}, UnderlayIPv4: netip.MustParseAddr("192.0.2.10")},
	}
}

func publishTestActual(desired reconcile.DesiredState) reconcile.ActualState {
	actual := reconcile.ActualState{Programs: map[string]reconcile.ProgramState{
		"tc_init_e": {ID: 10, Name: "tc_init_e"}, "tc_restore": {ID: 11, Name: "tc_restore"},
		"tc_init_in": {ID: 12, Name: "tc_init_in"}, "tc_masq": {ID: 13, Name: "tc_masq"},
	}, Maps: make(map[string]reconcile.MapState), FlannelRule: reconcile.RuleState{Present: true, Identity: "ONCACHE/oncache:install-a", Fingerprint: "rule-fp"}}
	for _, expected := range requiredMaps {
		actual.Maps[expected.name] = reconcile.MapState{ID: 1, Name: expected.name, KeySize: expected.keySize, ValueSize: expected.valueSize, MaxEntries: expected.maxEntries}
	}
	addPublishAttachment := func(link resolver.LinkIdentity, program string, id uint32) {
		spec, err := datapath.NewFixedFilter(link, program, id, true)
		if err != nil {
			panic(err)
		}
		actual.Attachments = append(actual.Attachments, reconcile.AttachmentState{Link: spec.Link, Hook: string(spec.Hook), Program: spec.Program, Priority: spec.Priority, Handle: spec.Handle, ProgramID: spec.ProgramID})
	}
	addPublishAttachment(desired.Flannel.UnderlayLink, "tc_init_e", 10)
	addPublishAttachment(desired.Flannel.UnderlayLink, "tc_restore", 11)
	endpoint := desired.LocalEndpoints["pod-a"]
	addPublishAttachment(endpoint.PeerLink, "tc_init_in", 12)
	addPublishAttachment(endpoint.HostLink, "tc_masq", 13)
	return actual
}
