package agent

import (
	"context"
	"errors"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/cat-cc-Lcos/FNCache/internal/kubernetes"
)

func bootstrapPod(ip string) *corev1.Pod {
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "default", UID: types.UID("pod-1")}, Spec: corev1.PodSpec{NodeName: "node-a"}, Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: ip}}
}

func bootstrapNode() *corev1.Node {
	return &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-a", UID: types.UID("node-1")}, Spec: corev1.NodeSpec{PodCIDR: "10.42.0.0/24"}}
}

func newBootstrap(t *testing.T, objects ...interface{}) *KubeBootstrap {
	t.Helper()
	resources := make([]interface{}, len(objects))
	copy(resources, objects)
	client := fake.NewSimpleClientset()
	for _, object := range resources {
		switch value := object.(type) {
		case *corev1.Pod:
			if _, err := client.CoreV1().Pods(value.Namespace).Create(context.Background(), value, metav1.CreateOptions{}); err != nil {
				t.Fatal(err)
			}
		case *corev1.Node:
			if _, err := client.CoreV1().Nodes().Create(context.Background(), value, metav1.CreateOptions{}); err != nil {
				t.Fatal(err)
			}
		default:
			t.Fatalf("unsupported bootstrap fixture %T", object)
		}
	}
	store := kubernetes.NewSnapshotStore()
	source, err := kubernetes.NewInformerSource(client, store, 0)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap, err := NewKubeBootstrap(source, store)
	if err != nil {
		t.Fatal(err)
	}
	return bootstrap
}

func TestKubeBootstrapReachesReadyAfterSync(t *testing.T) {
	store := kubernetes.NewSnapshotStore()
	client := fake.NewSimpleClientset(bootstrapPod("10.42.0.2"), bootstrapNode())
	source, err := kubernetes.NewInformerSource(client, store, 0)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap, err := NewKubeBootstrap(source, store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bootstrap.Snapshot(); err == nil {
		t.Fatal("snapshot was readable before bootstrap")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := bootstrap.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if bootstrap.State() != KubeBootstrapReady {
		t.Fatalf("state = %s, want Ready", bootstrap.State())
	}
	snapshot, err := bootstrap.Snapshot()
	if err != nil || len(snapshot.Pods) != 1 || len(snapshot.Nodes) != 1 {
		t.Fatalf("ready snapshot = %#v, err=%v", snapshot, err)
	}
}

func TestKubeBootstrapCancellationDisables(t *testing.T) {
	bootstrap := newBootstrap(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := bootstrap.Start(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Start error = %v, want context.Canceled", err)
	}
	if bootstrap.State() != KubeBootstrapDisabled {
		t.Fatalf("state = %s, want Disabled", bootstrap.State())
	}
}

func TestKubeBootstrapRecoversAfterInitialConversionFailure(t *testing.T) {
	invalid := bootstrapPod("2001:db8::2")
	client := fake.NewSimpleClientset(invalid, bootstrapNode())
	store := kubernetes.NewSnapshotStore()
	source, err := kubernetes.NewInformerSource(client, store, 0)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap, err := NewKubeBootstrap(source, store)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	startDone := make(chan error, 1)
	go func() { startDone <- bootstrap.Start(ctx) }()
	deadline := time.Now().Add(time.Second)
	for source.LastError() == nil && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if source.LastError() == nil {
		t.Fatal("initial conversion failure was not recorded")
	}
	select {
	case err := <-startDone:
		t.Fatalf("bootstrap returned before conversion recovery: %v", err)
	default:
	}
	recovered := invalid.DeepCopy()
	recovered.ResourceVersion, recovered.Status.PodIP = "2", "10.42.0.2"
	if _, err := client.CoreV1().Pods("default").Update(ctx, recovered, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-startDone:
		if err != nil {
			t.Fatalf("bootstrap did not recover: %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("bootstrap recovery timed out: %v", ctx.Err())
	}
	if bootstrap.State() != KubeBootstrapReady {
		t.Fatalf("state = %s, want Ready", bootstrap.State())
	}
}
