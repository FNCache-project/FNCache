package controlplane

import (
	"context"
	"errors"
	"testing"

	"github.com/cat-cc-Lcos/FNCache/internal/endpoint"
	"github.com/cat-cc-Lcos/FNCache/internal/hostnet/discovery"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

type generationControl struct {
	events *[]string
	err    error
}

func (c *generationControl) Disable(context.Context) error {
	*c.events = append(*c.events, "disable")
	return c.err
}

type generationScanner struct {
	events *[]string
	states []reconcile.ActualState
	index  int
	err    error
}

func (s *generationScanner) Scan(context.Context) (reconcile.ActualState, error) {
	*s.events = append(*s.events, "scan")
	if s.err != nil {
		return reconcile.ActualState{}, s.err
	}
	state := s.states[s.index]
	if s.index < len(s.states)-1 {
		s.index++
	}
	return state, nil
}

func newGenerationTransaction(t *testing.T, events *[]string, states ...reconcile.ActualState) *GenerationTransaction {
	t.Helper()
	store := &fakeOwnershipCommitter{events: events}
	control := &fakeControlPublisher{events: events}
	publisher, err := NewPublisher(store, control, publishTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	transaction, err := NewGenerationTransaction(&generationControl{events: events}, &generationScanner{events: events, states: states}, publisher)
	if err != nil {
		t.Fatal(err)
	}
	return transaction
}

func TestGenerationTransactionOrdersDisableMutateVerifyAndPublish(t *testing.T) {
	desired := publishTestDesired()
	actual := publishTestActual(desired)
	events := []string{}
	transaction := newGenerationTransaction(t, &events, actual, actual)
	err := transaction.Execute(context.Background(), desired, func(_ context.Context, _ reconcile.DesiredState, _ reconcile.ActualState) error {
		events = append(events, "mutate")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"disable", "scan", "mutate", "scan", "commit", "publish"}
	if len(events) != len(want) {
		t.Fatalf("events = %v, want %v", events, want)
	}
	for i := range want {
		if events[i] != want[i] {
			t.Fatalf("events = %v, want %v", events, want)
		}
	}
}

func TestGenerationTransactionStopsBeforeMutationWhenEndpointScanIsIncomplete(t *testing.T) {
	desired := publishTestDesired()
	desired.EndpointScanSkipped = map[string]string{"pod-skipped": endpoint.ErrEndpointNotReady.Error()}
	actual := publishTestActual(desired)
	events := []string{}
	transaction := newGenerationTransaction(t, &events, actual, actual)

	err := transaction.Execute(context.Background(), desired, func(_ context.Context, _ reconcile.DesiredState, _ reconcile.ActualState) error {
		events = append(events, "mutate")
		return nil
	})
	var classified *reconcile.ClassifiedError
	if !errors.As(err, &classified) || classified.Class() != reconcile.ErrorRetryable || classified.ReasonCode() != reconcile.ReasonEndpointNotReady {
		t.Fatalf("incomplete endpoint scan was not retryable: err=%v", err)
	}
	if len(events) != 1 || events[0] != "disable" {
		t.Fatalf("incomplete endpoint scan reached mutation: events=%v", events)
	}
}

func TestGenerationTransactionStopsBeforeMutationWhenActualScanIsIncomplete(t *testing.T) {
	desired := publishTestDesired()
	before := publishTestActual(desired)
	before.EndpointScanSkipped = map[string]string{"pod-skipped": endpoint.ErrEndpointNotReady.Error()}
	events := []string{}
	transaction := newGenerationTransaction(t, &events, before, publishTestActual(desired))

	err := transaction.Execute(context.Background(), desired, func(_ context.Context, _ reconcile.DesiredState, _ reconcile.ActualState) error {
		events = append(events, "mutate")
		return nil
	})
	var classified *reconcile.ClassifiedError
	if !errors.As(err, &classified) || classified.Class() != reconcile.ErrorRetryable || classified.ReasonCode() != reconcile.ReasonEndpointNotReady {
		t.Fatalf("incomplete actual scan was not retryable: err=%v", err)
	}
	if len(events) != 2 || events[0] != "disable" || events[1] != "scan" {
		t.Fatalf("incomplete actual scan reached mutation: events=%v", events)
	}
}

func TestGenerationTransactionRejectsStaleAndMutationFailure(t *testing.T) {
	desired := publishTestDesired()
	before := publishTestActual(desired)
	before.Control.Generation = desired.Generation + 1
	events := []string{}
	transaction := newGenerationTransaction(t, &events, before, before)
	if err := transaction.Execute(context.Background(), desired, func(context.Context, reconcile.DesiredState, reconcile.ActualState) error {
		events = append(events, "mutate")
		return nil
	}); !errors.Is(err, ErrStaleGeneration) {
		t.Fatalf("error = %v, want ErrStaleGeneration", err)
	}
	if len(events) != 2 || events[0] != "disable" || events[1] != "scan" {
		t.Fatalf("stale generation continued: %v", events)
	}

	events = nil
	transaction = newGenerationTransaction(t, &events, publishTestActual(desired))
	wantErr := errors.New("mutation failed")
	if err := transaction.Execute(context.Background(), desired, func(_ context.Context, _ reconcile.DesiredState, _ reconcile.ActualState) error {
		events = append(events, "mutate")
		return wantErr
	}); !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want %v", err, wantErr)
	}
	if len(events) != 3 || events[2] != "mutate" {
		t.Fatalf("mutation failure continued: %v", events)
	}
}

func TestGenerationTransactionStopsBeforeCommitOnVerificationFailure(t *testing.T) {
	desired := publishTestDesired()
	invalid := publishTestActual(desired)
	invalid.Conflicts = []discovery.Conflict{{Kind: "tc-filter", Identity: "foreign"}}
	events := []string{}
	transaction := newGenerationTransaction(t, &events, publishTestActual(desired), invalid)
	if err := transaction.Execute(context.Background(), desired, func(context.Context, reconcile.DesiredState, reconcile.ActualState) error {
		events = append(events, "mutate")
		return nil
	}); err == nil {
		t.Fatal("verification failure was accepted")
	}
	if len(events) != 4 || events[2] != "mutate" || events[3] != "scan" {
		t.Fatalf("verification failure reached publish: %v", events)
	}
}
