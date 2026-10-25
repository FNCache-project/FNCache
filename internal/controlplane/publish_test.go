package controlplane

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/cat-cc-Lcos/FNCache/internal/datapath"
	"github.com/cat-cc-Lcos/FNCache/internal/endpoint"
	"github.com/cat-cc-Lcos/FNCache/internal/hostnet/discovery"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

type fakeOwnershipCommitter struct {
	events  *[]string
	state   reconcile.OwnershipState
	loadErr error
	err     error
}

func (f *fakeOwnershipCommitter) Load(context.Context) (reconcile.OwnershipState, error) {
	if f.loadErr != nil {
		return reconcile.OwnershipState{}, f.loadErr
	}
	return f.state, nil
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
	events                         *[]string
	generation, heartbeat, timeout uint64
	flags                          uint32
	vxlanVNI                       uint32
	vxlanUDPPort                   uint16
	err                            error
}

func (f *fakeControlPublisher) Publish(_ context.Context, generation, heartbeat, timeout uint64, flags uint32, vxlanVNI uint32, vxlanUDPPort uint16) error {
	*f.events = append(*f.events, "publish")
	f.generation, f.heartbeat, f.timeout, f.flags = generation, heartbeat, timeout, flags
	f.vxlanVNI, f.vxlanUDPPort = vxlanVNI, vxlanUDPPort
	return f.err
}

func TestVerifyStateRequiresCompleteVerifiedObjects(t *testing.T) {
	desired := publishTestDesired()
	actual := publishTestActual(desired)
	if err := VerifyState(desired, actual); err != nil {
		t.Fatal(err)
	}
	actual.Control.Verified = false
	if err := VerifyState(desired, actual); err == nil {
		t.Fatal("unverified control Map was accepted")
	}
	actual.Control.Verified = true
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

func TestVerifyStateRejectsNonDirectActionAttachment(t *testing.T) {
	desired := publishTestDesired()
	actual := publishTestActual(desired)
	actual.Attachments[0].DirectAction = false
	if err := VerifyState(desired, actual); err == nil {
		t.Fatal("non-direct-action attachment was accepted")
	}
}

func TestVerifyStateRequiresVXLANConfig(t *testing.T) {
	desired := publishTestDesired()
	actual := publishTestActual(desired)
	for _, test := range []struct {
		name   string
		update func(*reconcile.DesiredState)
	}{
		{name: "zero VNI", update: func(state *reconcile.DesiredState) { state.Datapath.VXLANVNI = 0 }},
		{name: "zero UDP port", update: func(state *reconcile.DesiredState) { state.Datapath.VXLANUDPPort = 0 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			invalid := desired
			test.update(&invalid)
			if err := VerifyState(invalid, actual); err == nil {
				t.Fatal("invalid VXLAN configuration was accepted")
			}
		})
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
		HeartbeatNS: 100, HeartbeatTimeoutNS: 500, Flags: 3, Now: func() time.Time { return time.Unix(42, 0).UTC() },
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
	if control.generation != 7 || control.heartbeat != 100 || control.timeout != 500 || control.flags != 3 ||
		control.vxlanVNI != 1 || control.vxlanUDPPort != 8472 {
		t.Fatalf("unexpected control publish: generation=%d heartbeat=%d timeout=%d flags=%d vni=%d port=%d", control.generation, control.heartbeat, control.timeout, control.flags, control.vxlanVNI, control.vxlanUDPPort)
	}
}

func TestPublisherBlocksWhenPublishGuardFailsBeforeCommit(t *testing.T) {
	desired := publishTestDesired()
	actual := publishTestActual(desired)
	events := []string{}
	store := &fakeOwnershipCommitter{events: &events}
	control := &fakeControlPublisher{events: &events}
	publisher, err := NewPublisher(store, control, publishTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	wantErr := errors.New("Kubernetes state is stale")
	publisher.SetPublishGuard(func(context.Context) error { return wantErr })
	if err := publisher.CommitAndPublish(context.Background(), desired, actual); !errors.Is(err, wantErr) {
		t.Fatalf("publish guard error = %v, want %v", err, wantErr)
	}
	if len(events) != 0 {
		t.Fatalf("stale state reached ownership or control publish: %v", events)
	}
}

func TestPublisherRechecksPublishGuardBeforeControlPublish(t *testing.T) {
	desired := publishTestDesired()
	actual := publishTestActual(desired)
	events := []string{}
	store := &fakeOwnershipCommitter{events: &events}
	control := &fakeControlPublisher{events: &events}
	publisher, err := NewPublisher(store, control, publishTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	wantErr := errors.New("Kubernetes state became stale")
	checks := 0
	publisher.SetPublishGuard(func(context.Context) error {
		checks++
		if checks == 2 {
			return wantErr
		}
		return nil
	})
	if err := publisher.CommitAndPublish(context.Background(), desired, actual); !errors.Is(err, wantErr) {
		t.Fatalf("publish guard error = %v, want %v", err, wantErr)
	}
	if checks != 2 || len(events) != 1 || events[0] != "commit" {
		t.Fatalf("publish guard did not stop control publish: checks=%d events=%v", checks, events)
	}
}

func TestPublisherRejectsIncompleteEndpointScanBeforeCommit(t *testing.T) {
	desired := publishTestDesired()
	desired.EndpointScanSkipped = map[string]string{"pod-skipped": endpoint.ErrEndpointNotReady.Error()}
	actual := publishTestActual(desired)
	events := []string{}
	store := &fakeOwnershipCommitter{events: &events}
	control := &fakeControlPublisher{events: &events}
	publisher, err := NewPublisher(store, control, publishTestConfig())
	if err != nil {
		t.Fatal(err)
	}

	err = publisher.CommitAndPublish(context.Background(), desired, actual)
	var classified *reconcile.ClassifiedError
	if !errors.As(err, &classified) || classified.Class() != reconcile.ErrorRetryable || classified.ReasonCode() != reconcile.ReasonEndpointNotReady {
		t.Fatalf("incomplete endpoint scan was not retryable: err=%v", err)
	}
	if len(events) != 0 {
		t.Fatalf("incomplete endpoint scan reached publication: events=%v", events)
	}
}

func TestPublisherRejectsIncompleteActualScanBeforeCommit(t *testing.T) {
	desired := publishTestDesired()
	actual := publishTestActual(desired)
	actual.EndpointScanSkipped = map[string]string{"pod-skipped": endpoint.ErrEndpointNotReady.Error()}
	events := []string{}
	store := &fakeOwnershipCommitter{events: &events}
	control := &fakeControlPublisher{events: &events}
	publisher, err := NewPublisher(store, control, publishTestConfig())
	if err != nil {
		t.Fatal(err)
	}

	err = publisher.CommitAndPublish(context.Background(), desired, actual)
	var classified *reconcile.ClassifiedError
	if !errors.As(err, &classified) || classified.Class() != reconcile.ErrorRetryable || classified.ReasonCode() != reconcile.ReasonEndpointNotReady {
		t.Fatalf("incomplete actual scan was not retryable: err=%v", err)
	}
	if len(events) != 0 {
		t.Fatalf("incomplete actual scan reached publication: events=%v", events)
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

func TestPublisherUsesConfiguredMapCapacities(t *testing.T) {
	capacities := datapath.DefaultMapCapacities()
	capacities.IngressCacheMaxEntries = 2048
	capacities.EgressIPCacheMaxEntries = 8192
	capacities.EgressCacheMaxEntries = 2048
	capacities.PolicyCacheMaxEntries = 8192
	capacities.DevMapMaxEntries = 16
	schema := datapath.V1SchemaWithCapacities(capacities)
	config := publishTestConfig()
	config.Schema = schema
	events := []string{}
	store := &fakeOwnershipCommitter{events: &events}
	control := &fakeControlPublisher{events: &events}
	publisher, err := NewPublisher(store, control, config)
	if err != nil {
		t.Fatal(err)
	}
	desired := publishTestDesired()
	if err := publisher.CommitAndPublish(context.Background(), desired, publishTestActualWithSchema(desired, schema)); err != nil {
		t.Fatalf("configured Map capacities were rejected: %v", err)
	}
}

func TestNewPublisherRejectsIncompleteMapSchema(t *testing.T) {
	for _, test := range []struct {
		name   string
		schema datapath.CollectionSchema
		want   string
	}{
		{name: "missing all Maps", schema: datapath.CollectionSchema{Programs: append([]string(nil), requiredPrograms...)}, want: "Map schema count mismatch"},
		{name: "missing one Map", schema: datapath.CollectionSchema{Programs: append([]string(nil), requiredPrograms...), Maps: datapath.V1Schema().Maps[:len(datapath.V1Schema().Maps)-1]}, want: "Map schema count mismatch"},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := publishTestConfig()
			config.Schema = test.schema
			_, err := NewPublisher(&fakeOwnershipCommitter{}, &fakeControlPublisher{}, config)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("incomplete schema error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func publishTestConfig() PublishConfig {
	return PublishConfig{InstallationID: "install-a", NodeUID: "node-a", ELFBuildID: "sha256:build", HeartbeatNS: 100, HeartbeatTimeoutNS: 500, Now: func() time.Time { return time.Unix(42, 0).UTC() }}
}

func publishTestDesired() reconcile.DesiredState {
	resolvedEndpoint := endpoint.Endpoint{
		Pod: endpoint.PodIdentity{Namespace: "default", Name: "web", UID: "pod-a"}, Node: endpoint.NodeIdentity{Name: "node-a"},
		PodIPv4: netip.MustParseAddr("10.244.1.10"), NetNSInode: 42,
		PeerLink: endpoint.LinkIdentity{NetNSInode: 42, IfIndex: 10, IfName: "eth0", MAC: []byte{2, 0, 0, 0, 0, 2}},
		HostLink: endpoint.LinkIdentity{IfIndex: 20, IfName: "vethweb", MAC: []byte{2, 0, 0, 0, 0, 3}},
	}
	return reconcile.DesiredState{
		Generation: 7, Enabled: true, LocalEndpoints: map[string]endpoint.Endpoint{resolvedEndpoint.Pod.UID: resolvedEndpoint},
		Datapath: reconcile.DatapathSpec{VXLANVNI: 1, VXLANUDPPort: 8472},
		Flannel:  reconcile.FlannelState{UnderlayLink: endpoint.LinkIdentity{IfIndex: 2, IfName: "eth0", MAC: []byte{2, 0, 0, 0, 0, 1}}, UnderlayIPv4: netip.MustParseAddr("192.0.2.10")},
	}
}

func publishTestActual(desired reconcile.DesiredState) reconcile.ActualState {
	return publishTestActualWithSchema(desired, datapath.V1Schema())
}

func publishTestActualWithSchema(desired reconcile.DesiredState, schema datapath.CollectionSchema) reconcile.ActualState {
	actual := reconcile.ActualState{Control: reconcile.ControlState{Verified: true}, Programs: map[string]reconcile.ProgramState{
		"tc_init_e": {ID: 10, Name: "tc_init_e"}, "tc_restore": {ID: 11, Name: "tc_restore"},
		"tc_init_in": {ID: 12, Name: "tc_init_in"}, "tc_masq": {ID: 13, Name: "tc_masq"},
	}, Maps: make(map[string]reconcile.MapState), FlannelRule: reconcile.RuleState{Present: true, JumpsPresent: true, Identity: "ONCACHE/oncache:install-a", Fingerprint: "rule-fp"}}
	for _, expected := range schema.Maps {
		actual.Maps[expected.Name] = reconcile.MapState{ID: 1, Name: expected.Name, KeySize: expected.KeySize, ValueSize: expected.ValueSize, MaxEntries: expected.MaxEntries}
	}
	addPublishAttachment := func(link endpoint.LinkIdentity, program string, id uint32) {
		spec, err := datapath.NewFixedFilter(link, program, id, true)
		if err != nil {
			panic(err)
		}
		actual.Attachments = append(actual.Attachments, reconcile.AttachmentState{Link: spec.Link, Hook: string(spec.Hook), Program: spec.Program, Priority: spec.Priority, Handle: spec.Handle, ProgramID: spec.ProgramID, DirectAction: spec.DirectAction})
	}
	addPublishAttachment(desired.Flannel.UnderlayLink, "tc_init_e", 10)
	addPublishAttachment(desired.Flannel.UnderlayLink, "tc_restore", 11)
	resolvedEndpoint := desired.LocalEndpoints["pod-a"]
	addPublishAttachment(resolvedEndpoint.PeerLink, "tc_init_in", 12)
	addPublishAttachment(resolvedEndpoint.HostLink, "tc_masq", 13)
	return actual
}
