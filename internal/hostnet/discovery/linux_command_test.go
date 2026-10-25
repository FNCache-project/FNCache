package discovery

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLinuxCommandParsers(t *testing.T) {
	output := []byte("bpf_map_lookup_elem bpf_spin_unlock direct_action")
	if !hasHelper(output, "bpf_map_lookup_elem") || hasHelper(output, "bpf_map_update_elem") || !hasDirectAction(output) {
		t.Fatal("helper or direct-action parser returned an unexpected result")
	}
	if !hasDirectAction([]byte("CONFIG_NET_CLS_ACT is set to y\neBPF program_type sched_cls is available")) {
		t.Fatal("kernel TC capability was not recognized as direct-action support")
	}
	if !hasDirectAction([]byte("skipping kernel config, can't open file: No such file or directory\neBPF program_type sched_cls is available")) {
		t.Fatal("sched_cls capability was rejected when kernel config was unavailable")
	}
	if !validRouteOutput([]byte(`[{"dst":"default"}]`)) || validRouteOutput([]byte("[]")) {
		t.Fatal("route parser returned an unexpected result")
	}
}

func TestLinuxConflictParsers(t *testing.T) {
	if !hasReservedTOSConflict([]byte("-A ONCACHE -m tos --set-tos 0x08"), "", "") {
		t.Fatal("TOS conflict was not detected")
	}
	if !hasFixedTCConflict([]byte(`[{"pref":1000,"handle":256}]`)) {
		t.Fatal("TC conflict was not detected")
	}
	if !hasPinnedObject([]byte(`{"pinned":"/sys/fs/bpf/oncache/v1/maps/control_map"}`), "/sys/fs/bpf/oncache/v1") {
		t.Fatal("pin conflict was not detected")
	}
	if hasPinnedObject([]byte(`{"pinned":"/sys/fs/bpf/oncache/v1-other/maps/external_map"}`), "/sys/fs/bpf/oncache/v1") {
		t.Fatal("sibling pin path was treated as a conflict")
	}
	if hasReservedTOSConflict([]byte("-A ONCACHE -j ACCEPT"), "", "") || hasFixedTCConflict([]byte("[]")) {
		t.Fatal("false conflict detected")
	}
	if hasReservedTOSConflict([]byte(`-A ONCACHE -m comment --comment "oncache:m2-local" -m conntrack --ctstate ESTABLISHED -m tos --tos 0x04/0x04 -j TOS --set-tos 0x08/0x08`), "", "") {
		t.Fatal("canonical ONCache marker was treated as a TOS conflict")
	}
	custom := []byte(`-A FNCACHE -m comment --comment "fncache:marker" -m conntrack --ctstate ESTABLISHED -m tos --tos 0x04/0x04 -j TOS --set-tos 0x08/0x08`)
	if hasReservedTOSConflict(custom, "FNCACHE", "fncache:marker") {
		t.Fatal("configured custom marker was treated as a TOS conflict")
	}
	if !hasReservedTOSConflict(custom, "OTHER", "other") {
		t.Fatal("custom marker with a different configured identity was not treated as a TOS conflict")
	}
	caseVariantChain := []byte(`-A fncache -m comment --comment "fncache:marker" -m conntrack --ctstate ESTABLISHED -m tos --tos 0x04/0x04 -j TOS --set-tos 0x08/0x08`)
	if !hasReservedTOSConflict(caseVariantChain, "FNCACHE", "fncache:marker") {
		t.Fatal("marker on a case-variant chain was not treated as a TOS conflict")
	}
	caseVariantComment := []byte(`-A FNCACHE -m comment --comment "fncache:Marker" -m conntrack --ctstate ESTABLISHED -m tos --tos 0x04/0x04 -j TOS --set-tos 0x08/0x08`)
	if !hasReservedTOSConflict(caseVariantComment, "FNCACHE", "fncache:marker") {
		t.Fatal("marker with a case-variant comment was not treated as a TOS conflict")
	}
	related := []byte(`-A FNCACHE -m comment --comment "fncache:marker" -m conntrack --ctstate ESTABLISHED,RELATED -m tos --tos 0x04/0x04 -j TOS --set-tos 0x08/0x08`)
	if !hasReservedTOSConflict(related, "FNCACHE", "fncache:marker") {
		t.Fatal("marker with RELATED state was not treated as a TOS conflict")
	}
	drifted := []byte(`-A FNCACHE -m comment --comment "fncache:marker" -m conntrack --ctstate ESTABLISHED -m tos --tos 0x04/0x04 -j TOS --set-tos 0x01/0x01`)
	if !hasReservedTOSConflict(drifted, "FNCACHE", "fncache:marker") {
		t.Fatal("drifted custom marker was not treated as a TOS conflict")
	}
}

func TestLinuxConflictParserDoesNotHideForeignNonBPFFilter(t *testing.T) {
	output := []byte(`[{"pref":1000,"kind":"flower"},{"pref":1000,"kind":"bpf","options":{"handle":"0x100","bpf_name":"tc_init_e","prog":{"id":10}}}]`)
	owned := []ownedTCFilter{{Program: "tc_init_e", Priority: 1000, Handle: 0x100, ProgramID: 10}}
	if !hasFixedTCConflictWithOwnership(output, owned) {
		t.Fatal("foreign non-BPF fixed-priority filter was not detected")
	}

	bpfDuplicate := []byte(`[{"pref":1000,"kind":"bpf"},{"pref":1000,"kind":"bpf","options":{"handle":"0x100","bpf_name":"tc_init_e","prog":{"id":10}}}]`)
	if hasFixedTCConflictWithOwnership(bpfDuplicate, owned) {
		t.Fatal("detail-less BPF duplicate was treated as a foreign conflict")
	}
}

func TestLoadOwnershipEvidenceRequiresDirectAction(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	data := []byte(`{"schemaVersion":1,"installationID":"install-a","nodeUID":"node-a","elfBuildID":"sha256:test","bpfABI":1,"attachments":[{"Program":"tc_init_e","Priority":1000,"Handle":256,"ProgramID":10,"DirectAction":false},{"Program":"tc_restore","Priority":1000,"Handle":257,"ProgramID":11,"DirectAction":true}]}`)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	evidence := loadOwnershipEvidence(path, "install-a", "node-a", "sha256:test")
	if len(evidence.TCFilters) != 1 || evidence.TCFilters[0].Program != "tc_restore" {
		t.Fatalf("non-direct-action ownership evidence was accepted: %+v", evidence.TCFilters)
	}
}
