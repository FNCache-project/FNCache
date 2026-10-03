package controlplane

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/cat-cc-Lcos/FNCache/internal/overlay/flannel"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

func TestFlannelMarkerEnsurerCreatesMarker(t *testing.T) {
	spec := flannel.MarkerRuleSpec{Chain: "ONCACHE", Comment: "oncache:install-a"}
	output := ""
	manager := flannel.NewMarkerRuleManager(func(_ context.Context, _ string, args ...string) ([]byte, error) {
		joined := strings.Join(args, " ")
		if strings.Contains(joined, " -S") {
			return []byte(output), nil
		}
		if strings.Contains(joined, " -N ") {
			output = "-N ONCACHE\n"
		}
		if strings.Contains(joined, " -A ONCACHE ") {
			output += "-A ONCACHE -m comment --comment \"oncache:install-a\" -m conntrack --ctstate ESTABLISHED -m tos --tos 0x04/0x04 -j TOS --set-tos 0x08/0x08\n"
		}
		if strings.Contains(joined, " -A POSTROUTING ") {
			output += "-A POSTROUTING -m comment --comment \"oncache:install-a-hook\" -j ONCACHE\n"
		}
		return nil, nil
	})
	ensurer, err := NewFlannelMarkerEnsurer(manager, spec)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := ensurer.EnsureMarker(context.Background(), validMarkerDesired())
	if err != nil || !changed {
		t.Fatalf("marker was not created: changed=%v err=%v", changed, err)
	}
}

func TestFlannelMarkerEnsurerSkipsDisabledState(t *testing.T) {
	called := false
	manager := flannel.NewMarkerRuleManager(func(context.Context, string, ...string) ([]byte, error) {
		called = true
		return nil, nil
	})
	ensurer, err := NewFlannelMarkerEnsurer(manager, flannel.MarkerRuleSpec{Chain: "ONCACHE", Comment: "oncache:install-a"})
	if err != nil {
		t.Fatal(err)
	}
	desired := validMarkerDesired()
	desired.Enabled = false
	changed, err := ensurer.EnsureMarker(context.Background(), desired)
	if err != nil || changed || called {
		t.Fatalf("disabled marker ensure was not a no-op: changed=%v err=%v called=%v", changed, err, called)
	}
}

func TestFlannelMarkerEnsurerRejectsUnsupportedState(t *testing.T) {
	manager := flannel.NewMarkerRuleManager(func(context.Context, string, ...string) ([]byte, error) {
		return nil, errors.New("runner must not be called")
	})
	ensurer, err := NewFlannelMarkerEnsurer(manager, flannel.MarkerRuleSpec{Chain: "ONCACHE", Comment: "oncache:install-a"})
	if err != nil {
		t.Fatal(err)
	}
	desired := validMarkerDesired()
	desired.Flannel.IPTablesBackend = "iptables-legacy"
	if _, err := ensurer.EnsureMarker(context.Background(), desired); err == nil {
		t.Fatal("unsupported iptables backend was accepted")
	}
}

func TestFlannelMarkerEnsurerPropagatesConflictAndCancellation(t *testing.T) {
	manager := flannel.NewMarkerRuleManager(func(context.Context, string, ...string) ([]byte, error) {
		return []byte("-A OTHER -m comment --comment \"oncache:install-a\" -j ACCEPT\n"), nil
	})
	ensurer, err := NewFlannelMarkerEnsurer(manager, flannel.MarkerRuleSpec{Chain: "ONCACHE", Comment: "oncache:install-a"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = ensurer.EnsureMarker(context.Background(), validMarkerDesired())
	var classified *reconcile.ClassifiedError
	if !errors.As(err, &classified) || classified.Class() != reconcile.ErrorConflict {
		t.Fatalf("marker conflict was not classified: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ensurer.EnsureMarker(ctx, validMarkerDesired()); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation was not propagated: %v", err)
	}
}

func validMarkerDesired() reconcile.DesiredState {
	return reconcile.DesiredState{Enabled: true, Flannel: reconcile.FlannelState{
		BackendType: "vxlan", MissMask: 0x04, EstablishedMask: 0x08, IPTablesBackend: "iptables-nft",
	}}
}
