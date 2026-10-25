package discovery

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

type CommandRunner func(context.Context, string, ...string) ([]byte, error)

func defaultCommandRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

var requiredBPFHelpers = []string{
	"bpf_map_lookup_elem", "bpf_map_update_elem", "bpf_get_hash_recalc",
	"bpf_skb_adjust_room", "bpf_skb_store_bytes", "bpf_l3_csum_replace", "bpf_spin_lock", "bpf_spin_unlock",
}

const reservedTOSMask uint32 = 0x04 | 0x08

func hasHelper(output []byte, helper string) bool {
	for _, field := range strings.Fields(string(output)) {
		if strings.Trim(field, "[](){}:,\"'") == helper {
			return true
		}
	}
	return false
}

func hasDirectAction(output []byte) bool {
	text := strings.ToLower(string(output))
	if strings.Contains(text, "direct_action") || strings.Contains(text, "direct-action") {
		return true
	}
	if strings.Contains(text, "ebpf program_type sched_cls is available") {
		return true
	}
	return strings.Contains(text, "config_net_cls_act is set to y") &&
		strings.Contains(text, "sched_cls")
}

func validRouteOutput(output []byte) bool {
	var routes []json.RawMessage
	return json.Unmarshal(bytes.TrimSpace(output), &routes) == nil && len(routes) > 0
}

func hasReservedTOSConflict(output []byte, markerChain, markerComment string) bool {
	for _, raw := range strings.Split(string(output), "\n") {
		line := strings.Join(strings.Fields(raw), " ")
		if isMarkerRule(line, markerChain, markerComment) {
			continue
		}
		if hasReservedTOSRuleValue(line) {
			return true
		}
	}
	return false
}

func hasReservedTOSRuleValue(line string) bool {
	fields := strings.Fields(strings.ToLower(line))
	for index := 0; index < len(fields); index++ {
		field := strings.Trim(fields[index], "\"'")
		option, value, inline := strings.Cut(field, "=")
		switch option {
		case "--set-dscp", "--set-dscp-class":
			if !inline {
				if index+1 >= len(fields) {
					continue
				}
				index++
			}
			// DSCP occupies the TOS bits that include both FNCache markers.
			return true
		case "--tos", "--set-tos", "--set-xmark":
			if !inline {
				if index+1 >= len(fields) {
					continue
				}
				value = fields[index+1]
				index++
			}
			if tosValueTouchesReservedBits(value) {
				return true
			}
		}
	}
	return false
}

func tosValueTouchesReservedBits(raw string) bool {
	raw = strings.TrimSpace(strings.Trim(raw, "\"'"))
	parts := strings.Split(raw, "/")
	if len(parts) > 2 {
		return false
	}
	value, ok := parseNetfilterValue(parts[0])
	if !ok {
		return false
	}
	mask := ^uint32(0)
	if len(parts) == 2 {
		mask, ok = parseNetfilterValue(parts[1])
		if !ok {
			return false
		}
	}
	return (value|mask)&reservedTOSMask != 0
}

func parseNetfilterValue(raw string) (uint32, bool) {
	raw = strings.TrimSpace(strings.Trim(raw, "\"'()[]{};,"))
	if raw == "" {
		return 0, false
	}
	base := 10
	if strings.HasPrefix(strings.ToLower(raw), "0x") {
		raw = raw[2:]
		base = 16
	}
	value, err := strconv.ParseUint(raw, base, 32)
	return uint32(value), err == nil
}

func isMarkerRule(line, markerChain, markerComment string) bool {
	if markerChain == "" || markerComment == "" {
		return isOncacheMarkerRule(line)
	}
	fields := strings.Fields(line)
	return len(fields) == 18 && fields[1] == markerChain && strings.Trim(fields[5], "\"") == markerComment && markerRuleFieldsMatch(fields)
}

func isOncacheMarkerRule(line string) bool {
	fields := strings.Fields(line)
	return len(fields) == 18 && fields[1] == "ONCACHE" && strings.HasPrefix(strings.Trim(fields[5], "\""), "oncache:") && markerRuleFieldsMatch(fields)
}

func markerRuleFieldsMatch(fields []string) bool {
	expected := []string{"-A", "", "-m", "comment", "--comment", "", "-m", "conntrack", "--ctstate", "ESTABLISHED", "-m", "tos", "--tos", "0x04/0x04", "-j", "TOS", "--set-tos", "0x08/0x08"}
	if len(fields) != len(expected) {
		return false
	}
	for index, want := range expected {
		if index == 1 || index == 5 {
			continue
		}
		if !strings.EqualFold(fields[index], want) {
			return false
		}
	}
	return true
}

type persistedObjectState struct {
	ID uint32 `json:"ID"`
}

type persistedAttachmentState struct {
	Program      string `json:"Program"`
	Priority     uint16 `json:"Priority"`
	Handle       uint32 `json:"Handle"`
	ProgramID    uint32 `json:"ProgramID"`
	DirectAction bool   `json:"DirectAction"`
}

type persistedOwnershipState struct {
	SchemaVersion  uint32                          `json:"schemaVersion"`
	InstallationID string                          `json:"installationID"`
	NodeUID        string                          `json:"nodeUID"`
	ELFBuildID     string                          `json:"elfBuildID"`
	ABI            uint32                          `json:"bpfABI"`
	Programs       map[string]persistedObjectState `json:"programs"`
	Maps           map[string]persistedObjectState `json:"maps"`
	Attachments    []persistedAttachmentState      `json:"attachments"`
}

type ownershipEvidence struct {
	ProgramPins map[string]uint32
	MapPins     map[string]uint32
	TCFilters   []ownedTCFilter
}

type ownedTCFilter struct {
	Program   string
	Priority  uint16
	Handle    uint32
	ProgramID uint32
}

func loadOwnershipEvidence(path, installationID, nodeUID, elfBuildID string) ownershipEvidence {
	evidence := ownershipEvidence{}
	if path == "" || installationID == "" || nodeUID == "" || elfBuildID == "" {
		return evidence
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return evidence
	}
	var state persistedOwnershipState
	if err := json.Unmarshal(data, &state); err != nil || state.SchemaVersion != 1 || state.InstallationID != installationID || state.NodeUID != nodeUID || state.ELFBuildID != elfBuildID || state.ABI != 1 {
		return ownershipEvidence{}
	}
	evidence.ProgramPins = make(map[string]uint32, len(state.Programs))
	for name, object := range state.Programs {
		if name != "" && object.ID != 0 {
			evidence.ProgramPins[name] = object.ID
		}
	}
	evidence.MapPins = make(map[string]uint32, len(state.Maps))
	for name, object := range state.Maps {
		if name != "" && object.ID != 0 {
			evidence.MapPins[name] = object.ID
		}
	}
	for _, attachment := range state.Attachments {
		if attachment.Program != "" && attachment.Priority != 0 && attachment.Handle != 0 && attachment.ProgramID != 0 && attachment.DirectAction {
			evidence.TCFilters = append(evidence.TCFilters, ownedTCFilter{
				Program: attachment.Program, Priority: attachment.Priority, Handle: attachment.Handle, ProgramID: attachment.ProgramID,
			})
		}
	}
	return evidence
}

func hasFixedTCConflict(output []byte) bool {
	return hasFixedTCConflictWithOwnership(output, nil)
}

type tcFilterJSON struct {
	Kind    string          `json:"kind"`
	Pref    json.RawMessage `json:"pref"`
	Handle  json.RawMessage `json:"handle"`
	Options struct {
		Handle string `json:"handle"`
		Name   string `json:"bpf_name"`
		Prog   struct {
			ID uint32 `json:"id"`
		} `json:"prog"`
	} `json:"options"`
}

func hasFixedTCConflictWithOwnership(output []byte, owned []ownedTCFilter) bool {
	var filters []tcFilterJSON
	if err := json.Unmarshal(bytes.TrimSpace(output), &filters); err == nil {
		ownedPref := make(map[uint32]bool)
		for _, filter := range filters {
			pref, prefOK := jsonUint(filter.Pref)
			handle, handleOK := jsonUint(filter.Handle)
			if filter.Options.Handle != "" {
				handle, handleOK = jsonUint([]byte(strconv.Quote(filter.Options.Handle)))
			}
			if isOwnedTCFilter(pref, prefOK, handle, handleOK, filter.Options.Name, filter.Options.Prog.ID, owned) {
				ownedPref[pref] = true
			}
		}
		for _, filter := range filters {
			pref, prefOK := jsonUint(filter.Pref)
			handle, handleOK := jsonUint(filter.Handle)
			if filter.Options.Handle != "" {
				handle, handleOK = jsonUint([]byte(strconv.Quote(filter.Options.Handle)))
			}
			if !prefOK && !handleOK {
				continue
			}
			if !isReservedTCSlot(pref, prefOK, handle, handleOK) {
				continue
			}
			if isOwnedTCFilter(pref, prefOK, handle, handleOK, filter.Options.Name, filter.Options.Prog.ID, owned) {
				continue
			}
			// iproute2 emits a second, detail-less record for a BPF filter in
			// some kernels. A matching detailed record is the ownership proof;
			// an otherwise-unidentified slot remains a conflict.
			if filter.Kind == "bpf" && prefOK && !handleOK && filter.Options.Name == "" && filter.Options.Prog.ID == 0 && ownedPref[pref] {
				continue
			}
			return true
		}
		return false
	}

	text := strings.ToLower(string(output))
	for _, marker := range []string{
		"\"pref\":1000", "\"pref\": 1000", "pref 1000",
		"\"handle\":256", "\"handle\": 256", "handle 0x100",
		"\"handle\":257", "\"handle\": 257", "handle 0x101",
		"\"handle\":512", "\"handle\": 512", "handle 0x200",
		"\"handle\":513", "\"handle\": 513", "handle 0x201",
	} {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}

func jsonUint(raw json.RawMessage) (uint32, bool) {
	if len(raw) == 0 {
		return 0, false
	}
	var number uint32
	if err := json.Unmarshal(raw, &number); err == nil {
		return number, true
	}
	var text string
	if err := json.Unmarshal(raw, &text); err != nil {
		return 0, false
	}
	text = strings.TrimSpace(text)
	base := 10
	if strings.HasPrefix(strings.ToLower(text), "0x") {
		text = text[2:]
		base = 16
	}
	value, err := strconv.ParseUint(text, base, 32)
	return uint32(value), err == nil
}

func isReservedTCSlot(pref uint32, prefOK bool, handle uint32, handleOK bool) bool {
	return (prefOK && pref == 1000) || (handleOK && (handle == 0x100 || handle == 0x101 || handle == 0x200 || handle == 0x201))
}

func isOwnedTCFilter(pref uint32, prefOK bool, handle uint32, handleOK bool, name string, programID uint32, owned []ownedTCFilter) bool {
	if !prefOK || !handleOK || name == "" || programID == 0 {
		return false
	}
	for _, filter := range owned {
		if filter.Priority == uint16(pref) && filter.Handle == handle && filter.Program == name && filter.ProgramID == programID {
			return true
		}
	}
	return false
}

func hasPinnedObject(output []byte, pinRoot string) bool {
	if pinRoot == "" {
		return false
	}
	root := filepath.Clean(pinRoot)
	text := string(output)
	return strings.Contains(text, `"`+root+`"`) ||
		strings.Contains(text, `"`+root+string(filepath.Separator))
}

type bpftoolObjectJSON struct {
	ID     uint32          `json:"id"`
	Pinned json.RawMessage `json:"pinned"`
}

func hasForeignPinnedObject(output []byte, pinRoot string, owned map[string]uint32) bool {
	var objects []bpftoolObjectJSON
	if err := json.Unmarshal(bytes.TrimSpace(output), &objects); err != nil {
		return hasPinnedObject(output, pinRoot)
	}
	root := filepath.Clean(pinRoot)
	for _, object := range objects {
		for _, path := range pinnedPaths(object.Pinned) {
			clean := filepath.Clean(path)
			if clean != root && !strings.HasPrefix(clean, root+string(filepath.Separator)) {
				continue
			}
			expectedID, ok := owned[clean]
			if !ok || expectedID != object.ID {
				return true
			}
		}
	}
	return false
}

func pinnedPaths(raw json.RawMessage) []string {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var paths []string
	if json.Unmarshal(raw, &paths) == nil {
		return paths
	}
	var path string
	if json.Unmarshal(raw, &path) == nil && path != "" {
		return []string{path}
	}
	return nil
}
