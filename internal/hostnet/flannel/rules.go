package flannel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

type MarkerRuleSpec struct {
	Chain   string
	Comment string
}

type RuleScanner struct {
	run CommandRunner
}

type MarkerRuleManager struct {
	run CommandRunner
}

type markerRuleMatch struct {
	state          reconcile.RuleState
	line           string
	lineNumber     int
	hookLineNumber int
	hookRuleCount  int
	chainExists    bool
	found          bool
	hookFound      bool
}

const (
	markerConflictReason = "NETFILTER_MARKER_CONFLICT"
	markerHookChain      = "POSTROUTING"
	markerHookSuffix     = "-hook"
)

func NewRuleScanner(run CommandRunner) *RuleScanner {
	discovery := NewDiscovery(run)
	return &RuleScanner{run: discovery.run}
}

func NewMarkerRuleManager(run CommandRunner) *MarkerRuleManager {
	discovery := NewDiscovery(run)
	return &MarkerRuleManager{run: discovery.run}
}

func (s *RuleScanner) Scan(ctx context.Context, spec MarkerRuleSpec) (reconcile.RuleState, error) {
	match, err := readMarkerRule(ctx, s.run, spec)
	if err != nil {
		return reconcile.RuleState{}, fmt.Errorf("scan Flannel marker rules: %w", err)
	}
	return match.state, nil
}

func (m *MarkerRuleManager) Ensure(ctx context.Context, spec MarkerRuleSpec) (reconcile.RuleState, bool, error) {
	if err := validateMarkerRuleSpec(spec); err != nil {
		return reconcile.RuleState{}, false, err
	}
	match, err := readMarkerRule(ctx, m.run, spec)
	if err != nil {
		return reconcile.RuleState{}, false, err
	}
	desiredLine := markerRuleLine(spec)
	if match.found && match.line == desiredLine && match.hookFound {
		return match.state, false, nil
	}

	changed := false
	if match.found {
		if match.line != desiredLine {
			args := append([]string{"-t", "mangle", "-R", spec.Chain, strconv.Itoa(match.lineNumber)}, markerRuleArgs(spec)...)
			if _, err := m.run(ctx, "iptables-nft", args...); err != nil {
				return reconcile.RuleState{}, false, fmt.Errorf("apply marker rule: %w", err)
			}
			changed = true
		}
	} else {
		if !match.chainExists {
			if _, err := m.run(ctx, "iptables-nft", "-t", "mangle", "-N", spec.Chain); err != nil {
				return reconcile.RuleState{}, false, fmt.Errorf("create marker chain: %w", err)
			}
		}
		args := append([]string{"-t", "mangle", "-A", spec.Chain}, markerRuleArgs(spec)...)
		if _, err := m.run(ctx, "iptables-nft", args...); err != nil {
			return reconcile.RuleState{}, false, fmt.Errorf("apply marker rule: %w", err)
		}
		changed = true
	}
	if !match.hookFound {
		args := append([]string{"-t", "mangle", "-A", markerHookChain}, markerHookRuleArgs(spec)...)
		if _, err := m.run(ctx, "iptables-nft", args...); err != nil {
			return reconcile.RuleState{}, false, fmt.Errorf("apply marker hook: %w", err)
		}
		changed = true
	}
	verified, err := readMarkerRule(ctx, m.run, spec)
	if err != nil {
		return reconcile.RuleState{}, false, fmt.Errorf("verify marker and hook: %w", err)
	}
	if !verified.found || verified.line != desiredLine || !verified.hookFound {
		return reconcile.RuleState{}, false, fmt.Errorf("marker rule or hook verification mismatch")
	}
	return verified.state, changed, nil
}

func (m *MarkerRuleManager) Remove(ctx context.Context, owned reconcile.OwnedRule) error {
	spec, err := markerSpecFromOwned(owned)
	if err != nil {
		return err
	}
	match, err := readMarkerRule(ctx, m.run, spec)
	if err != nil {
		return err
	}
	if !match.found {
		if !match.hookFound {
			return nil
		}
		if _, err := m.run(ctx, "iptables-nft", "-t", "mangle", "-D", markerHookChain, strconv.Itoa(match.hookLineNumber)); err != nil {
			return fmt.Errorf("remove marker hook: %w", err)
		}
		remaining, err := readMarkerRule(ctx, m.run, spec)
		if err != nil {
			return fmt.Errorf("verify marker hook removal: %w", err)
		}
		if remaining.found || remaining.hookFound {
			return fmt.Errorf("marker rule or hook remains after removal")
		}
		return nil
	}
	if owned.Fingerprint == "" || match.state.Fingerprint != owned.Fingerprint {
		return markerConflict("marker rule identity changed before removal")
	}
	if _, err := m.run(ctx, "iptables-nft", "-t", "mangle", "-D", spec.Chain, strconv.Itoa(match.lineNumber)); err != nil {
		return fmt.Errorf("remove marker rule: %w", err)
	}
	if match.hookFound {
		if _, err := m.run(ctx, "iptables-nft", "-t", "mangle", "-D", markerHookChain, strconv.Itoa(match.hookLineNumber)); err != nil {
			return fmt.Errorf("remove marker hook: %w", err)
		}
	}
	remaining, err := readMarkerRule(ctx, m.run, spec)
	if err != nil {
		return fmt.Errorf("verify marker removal: %w", err)
	}
	if remaining.found || remaining.hookFound {
		return fmt.Errorf("marker rule or hook remains after removal")
	}
	return nil
}

func readMarkerRule(ctx context.Context, run CommandRunner, spec MarkerRuleSpec) (markerRuleMatch, error) {
	if err := validateMarkerRuleSpec(spec); err != nil {
		return markerRuleMatch{}, err
	}
	if err := ctx.Err(); err != nil {
		return markerRuleMatch{}, err
	}
	output, err := run(ctx, "iptables-nft", "-t", "mangle", "-S")
	if err != nil {
		return markerRuleMatch{}, err
	}
	match := markerRuleMatch{state: reconcile.RuleState{Identity: spec.Chain + "/" + spec.Comment}}
	hookComment := markerHookComment(spec)
	for _, raw := range strings.Split(string(output), "\n") {
		line := strings.TrimSpace(raw)
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "-N" && fields[1] == spec.Chain {
			match.chainExists = true
		}
		if len(fields) < 2 || fields[0] != "-A" {
			continue
		}
		chain := fields[1]
		if chain == spec.Chain {
			match.lineNumber++
		}
		if chain == markerHookChain {
			match.hookRuleCount++
		}
		if ruleHasComment(line, hookComment) && (chain != markerHookChain || !isMarkerHookRule(line, spec)) {
			return markerRuleMatch{}, markerConflict("marker hook comment found in another rule")
		}
		if chain == markerHookChain && ruleJumpsTo(line, spec.Chain) {
			if !isMarkerHookRule(line, spec) {
				return markerRuleMatch{}, markerConflict("marker hook is owned by another rule")
			}
			if match.hookFound {
				return markerRuleMatch{}, markerConflict("marker hook comment is duplicated")
			}
			match.hookFound = true
			match.hookLineNumber = match.hookRuleCount
		}
		if !ruleHasComment(line, spec.Comment) {
			continue
		}
		if chain != spec.Chain {
			return markerRuleMatch{}, markerConflict("marker comment found in another chain")
		}
		if match.found {
			return markerRuleMatch{}, markerConflict("marker rule comment is duplicated")
		}
		match.found = true
		match.line = line
		match.state.Fingerprint = ruleFingerprint(line)
	}
	match.state.Present = match.found && match.hookFound
	match.state.JumpsPresent = match.hookFound
	return match, nil
}

func markerRuleArgs(spec MarkerRuleSpec) []string {
	return []string{"-m", "comment", "--comment", spec.Comment, "-m", "conntrack", "--ctstate", "ESTABLISHED", "-m", "tos", "--tos", "0x04/0x04", "-j", "TOS", "--set-tos", "0x08/0x08"}
}

func markerHookComment(spec MarkerRuleSpec) string {
	return spec.Comment + markerHookSuffix
}

func markerHookRuleArgs(spec MarkerRuleSpec) []string {
	return []string{"-m", "comment", "--comment", markerHookComment(spec), "-j", spec.Chain}
}

func markerRuleLine(spec MarkerRuleSpec) string {
	args := markerRuleArgs(spec)
	for i, arg := range args {
		if i == 3 {
			args[i] = strconv.Quote(arg)
		}
	}
	return strings.Join(append([]string{"-A", spec.Chain}, args...), " ")
}

func markerSpecFromOwned(owned reconcile.OwnedRule) (MarkerRuleSpec, error) {
	parts := strings.SplitN(owned.Identity, "/", 2)
	if len(parts) != 2 {
		return MarkerRuleSpec{}, fmt.Errorf("owned marker identity is invalid: %q", owned.Identity)
	}
	comment := owned.Comment
	if comment == "" || comment == owned.Identity {
		comment = parts[1]
	}
	return MarkerRuleSpec{Chain: parts[0], Comment: comment}, validateMarkerRuleSpec(MarkerRuleSpec{Chain: parts[0], Comment: comment})
}

func markerConflict(message string) error {
	return reconcile.NewClassifiedError(reconcile.ErrorConflict, markerConflictReason, 0, fmt.Errorf("%s", message))
}

func validateMarkerRuleSpec(spec MarkerRuleSpec) error {
	if strings.TrimSpace(spec.Chain) == "" || strings.ContainsAny(spec.Chain, " \t\r\n") {
		return fmt.Errorf("marker rule chain is invalid")
	}
	if spec.Comment == "" || strings.ContainsAny(spec.Comment, " \t\"\r\n/") {
		return fmt.Errorf("marker rule comment is invalid")
	}
	return nil
}

func ruleChain(line string) (string, bool) {
	fields := strings.Fields(line)
	if len(fields) < 2 || fields[0] != "-A" {
		return "", false
	}
	return fields[1], true
}

func ruleHasComment(line, comment string) bool {
	fields := strings.Fields(line)
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == "--comment" && strings.Trim(fields[i+1], "\"") == comment {
			return true
		}
	}
	return false
}

func ruleJumpsTo(line, chain string) bool {
	fields := strings.Fields(line)
	for i := 0; i+1 < len(fields); i++ {
		if (fields[i] == "-j" || fields[i] == "--jump") && strings.Trim(fields[i+1], "\"") == chain {
			return true
		}
	}
	return false
}

func isMarkerHookRule(line string, spec MarkerRuleSpec) bool {
	fields := strings.Fields(line)
	return len(fields) == 8 &&
		fields[0] == "-A" && fields[1] == markerHookChain &&
		fields[2] == "-m" && fields[3] == "comment" &&
		fields[4] == "--comment" && strings.Trim(fields[5], "\"") == markerHookComment(spec) &&
		fields[6] == "-j" && fields[7] == spec.Chain
}

func ruleFingerprint(line string) string {
	normalized := strings.Join(strings.Fields(line), " ")
	sum := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(sum[:])
}

func ExpectedMarkerFingerprint(spec MarkerRuleSpec) string {
	return ruleFingerprint(markerRuleLine(spec))
}
