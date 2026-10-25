package kubernetes

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

func classifierPod(uid, node, ip string) *corev1.Pod {
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "web", UID: types.UID(uid)}, Spec: corev1.PodSpec{NodeName: node}, Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: ip}}
}

func classifierNode(uid, cidr, address string) *corev1.Node {
	return &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-a", UID: types.UID(uid)}, Spec: corev1.NodeSpec{PodCIDR: cidr}, Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: address}}}}
}

func TestPodClassifier(t *testing.T) {
	classifier, err := NewEventClassifier("node-a")
	if err != nil {
		t.Fatal(err)
	}
	local := classifierPod("pod-1", "node-a", "10.42.0.2")
	remote := classifierPod("pod-1", "node-b", "10.42.1.2")
	tests := []struct {
		name   string
		old    *corev1.Pod
		new    *corev1.Pod
		kind   reconcile.ReconcileKind
		reason string
		count  int
	}{
		{name: "metadata only", old: local, new: local.DeepCopy(), count: 0},
		{name: "add local", new: local, kind: reconcile.ReconcileLocalEndpoint, reason: ReasonPodAdded, count: 1},
		{name: "delete remote", old: remote, kind: reconcile.ReconcileRemoteEndpoint, reason: ReasonPodDeleted, count: 1},
		{name: "remote IP", old: remote, new: func() *corev1.Pod { p := remote.DeepCopy(); p.Status.PodIP = "10.42.1.3"; return p }(), kind: reconcile.ReconcileRemoteEndpoint, reason: ReasonPodIP, count: 1},
		{name: "unscheduled", new: classifierPod("pod-2", "", ""), count: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keys := classifier.Pod(tt.old, tt.new)
			if len(keys) != tt.count {
				t.Fatalf("got %d keys: %#v", len(keys), keys)
			}
			if tt.count > 0 && (keys[0].Kind != tt.kind || keys[0].Reason != tt.reason) {
				t.Fatalf("got %#v, want kind=%s reason=%s", keys[0], tt.kind, tt.reason)
			}
		})
	}
}

func TestPodClassifierMigrationAndRelevantFields(t *testing.T) {
	classifier, _ := NewEventClassifier("node-a")
	oldPod := classifierPod("pod-1", "node-a", "10.42.0.2")
	newPod := classifierPod("pod-1", "node-b", "10.42.1.2")
	keys := classifier.Pod(oldPod, newPod)
	if len(keys) != 2 || keys[0].Kind != reconcile.ReconcileLocalEndpoint || keys[1].Kind != reconcile.ReconcileRemoteEndpoint {
		t.Fatalf("migration keys = %#v", keys)
	}
	changed := oldPod.DeepCopy()
	changed.Spec.HostNetwork = true
	if keys := classifier.Pod(oldPod, changed); len(keys) != 1 || keys[0].Reason != ReasonPodNetworkMode {
		t.Fatalf("hostNetwork keys = %#v", keys)
	}
	changed = oldPod.DeepCopy()
	changed.Status.Phase = corev1.PodPending
	if keys := classifier.Pod(oldPod, changed); len(keys) != 1 || keys[0].Reason != ReasonPodPhase {
		t.Fatalf("phase keys = %#v", keys)
	}
}

func TestNodeClassifier(t *testing.T) {
	classifier, _ := NewEventClassifier("node-a")
	node := classifierNode("node-1", "10.42.0.0/24", "192.0.2.10")
	if keys := classifier.Node(node, node.DeepCopy()); len(keys) != 0 {
		t.Fatalf("metadata-only Node update generated keys: %#v", keys)
	}
	changed := node.DeepCopy()
	changed.Spec.PodCIDR = "10.42.2.0/24"
	keys := classifier.Node(node, changed)
	if len(keys) != 1 || keys[0].Kind != reconcile.ReconcileGlobal || keys[0].Reason != ReasonNodePodCIDR {
		t.Fatalf("PodCIDR keys = %#v", keys)
	}
	if keys := classifier.Node(nil, node); len(keys) != 1 || keys[0].Reason != ReasonNodeAdded {
		t.Fatalf("add keys = %#v", keys)
	}
	if keys := classifier.Node(node, nil); len(keys) != 1 || keys[0].Reason != ReasonNodeDeleted {
		t.Fatalf("delete keys = %#v", keys)
	}
}

func TestClassifierRejectsMissingLocalNode(t *testing.T) {
	if _, err := NewEventClassifier(""); err == nil {
		t.Fatal("empty local node was accepted")
	}
}
