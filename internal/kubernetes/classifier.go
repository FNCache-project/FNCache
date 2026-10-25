package kubernetes

import (
	"fmt"
	"sort"

	corev1 "k8s.io/api/core/v1"

	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

const (
	ReasonPodAdded       = "POD_ADDED"
	ReasonPodDeleted     = "POD_DELETED"
	ReasonPodReplaced    = "POD_REPLACED"
	ReasonPodPlacement   = "POD_PLACEMENT_CHANGED"
	ReasonPodIP          = "POD_IP_CHANGED"
	ReasonPodNetworkMode = "POD_NETWORK_MODE_CHANGED"
	ReasonPodPhase       = "POD_PHASE_CHANGED"
	ReasonPodDeletion    = "POD_DELETION_CHANGED"
	ReasonNodeAdded      = "NODE_ADDED"
	ReasonNodeDeleted    = "NODE_DELETED"
	ReasonNodeReplaced   = "NODE_REPLACED"
	ReasonNodePodCIDR    = "NODE_PODCIDR_CHANGED"
	ReasonNodeAddresses  = "NODE_ADDRESSES_CHANGED"
)

type EventClassifier struct{ localNode string }

func NewEventClassifier(localNode string) (*EventClassifier, error) {
	if localNode == "" {
		return nil, fmt.Errorf("local node name is required")
	}
	return &EventClassifier{localNode: localNode}, nil
}

func (c *EventClassifier) Pod(oldPod, newPod *corev1.Pod) []reconcile.ReconcileKey {
	if oldPod == nil && newPod == nil {
		return nil
	}
	if oldPod == nil {
		return c.podKeys(newPod, ReasonPodAdded, nil)
	}
	if newPod == nil {
		return c.podKeys(oldPod, ReasonPodDeleted, nil)
	}
	if podIdentityChanged(oldPod, newPod) {
		keys := c.podKeys(oldPod, ReasonPodReplaced, nil)
		return c.podKeys(newPod, ReasonPodReplaced, keys)
	}
	if !podRelevantChanged(oldPod, newPod) {
		return nil
	}
	reason := podChangeReason(oldPod, newPod)
	oldKind, oldOK := c.podKind(oldPod)
	newKind, newOK := c.podKind(newPod)
	if oldOK && (!newOK || oldKind != newKind) {
		keys := c.podKeys(oldPod, reason, nil)
		return c.podKeys(newPod, reason, keys)
	}
	return c.podKeys(newPod, reason, nil)
}

func (c *EventClassifier) Node(oldNode, newNode *corev1.Node) []reconcile.ReconcileKey {
	if oldNode == nil && newNode == nil {
		return nil
	}
	if oldNode == nil {
		return nodeKeys(newNode, ReasonNodeAdded, nil)
	}
	if newNode == nil {
		return nodeKeys(oldNode, ReasonNodeDeleted, nil)
	}
	if oldNode.Name != newNode.Name || oldNode.UID != newNode.UID {
		keys := nodeKeys(oldNode, ReasonNodeReplaced, nil)
		return nodeKeys(newNode, ReasonNodeReplaced, keys)
	}
	if oldNode.Spec.PodCIDR != newNode.Spec.PodCIDR {
		return nodeKeys(newNode, ReasonNodePodCIDR, nil)
	}
	if !sameNodeAddresses(oldNode, newNode) {
		return nodeKeys(newNode, ReasonNodeAddresses, nil)
	}
	return nil
}

func (c *EventClassifier) podKind(pod *corev1.Pod) (reconcile.ReconcileKind, bool) {
	if pod == nil || pod.Spec.NodeName == "" {
		return "", false
	}
	if pod.Spec.NodeName == c.localNode {
		return reconcile.ReconcileLocalEndpoint, true
	}
	return reconcile.ReconcileRemoteEndpoint, true
}

func (c *EventClassifier) podKeys(pod *corev1.Pod, reason string, keys []reconcile.ReconcileKey) []reconcile.ReconcileKey {
	kind, ok := c.podKind(pod)
	if !ok || pod.UID == "" || pod.Namespace == "" || pod.Name == "" {
		return keys
	}
	return appendKey(keys, reconcile.ReconcileKey{Kind: kind, Namespace: pod.Namespace, Name: pod.Name, UID: string(pod.UID), Reason: reason})
}

func nodeKeys(node *corev1.Node, reason string, keys []reconcile.ReconcileKey) []reconcile.ReconcileKey {
	if node == nil || node.Name == "" || node.UID == "" {
		return keys
	}
	return appendKey(keys, reconcile.ReconcileKey{Kind: reconcile.ReconcileGlobal, Name: node.Name, UID: string(node.UID), Reason: reason})
}

func appendKey(keys []reconcile.ReconcileKey, key reconcile.ReconcileKey) []reconcile.ReconcileKey {
	for _, existing := range keys {
		if existing.QueueKey() == key.QueueKey() {
			return keys
		}
	}
	return append(keys, key)
}

func podIdentityChanged(oldPod, newPod *corev1.Pod) bool {
	return oldPod.UID != newPod.UID || oldPod.Namespace != newPod.Namespace || oldPod.Name != newPod.Name
}

func podRelevantChanged(oldPod, newPod *corev1.Pod) bool {
	return oldPod.Spec.NodeName != newPod.Spec.NodeName || oldPod.Status.PodIP != newPod.Status.PodIP ||
		oldPod.Spec.HostNetwork != newPod.Spec.HostNetwork || oldPod.Status.Phase != newPod.Status.Phase ||
		deletionChanged(oldPod, newPod)
}

func deletionChanged(oldPod, newPod *corev1.Pod) bool {
	if oldPod.DeletionTimestamp == nil || newPod.DeletionTimestamp == nil {
		return oldPod.DeletionTimestamp != nil || newPod.DeletionTimestamp != nil
	}
	return !oldPod.DeletionTimestamp.Time.Equal(newPod.DeletionTimestamp.Time)
}

func podChangeReason(oldPod, newPod *corev1.Pod) string {
	switch {
	case oldPod.Spec.NodeName != newPod.Spec.NodeName:
		return ReasonPodPlacement
	case oldPod.Status.PodIP != newPod.Status.PodIP:
		return ReasonPodIP
	case oldPod.Spec.HostNetwork != newPod.Spec.HostNetwork:
		return ReasonPodNetworkMode
	case oldPod.Status.Phase != newPod.Status.Phase:
		return ReasonPodPhase
	default:
		return ReasonPodDeletion
	}
}

func sameNodeAddresses(oldNode, newNode *corev1.Node) bool {
	oldAddresses := nodeAddresses(oldNode)
	newAddresses := nodeAddresses(newNode)
	if len(oldAddresses) != len(newAddresses) {
		return false
	}
	for index := range oldAddresses {
		if oldAddresses[index] != newAddresses[index] {
			return false
		}
	}
	return true
}

func nodeAddresses(node *corev1.Node) []string {
	addresses := make([]string, 0, len(node.Status.Addresses))
	for _, address := range node.Status.Addresses {
		addresses = append(addresses, string(address.Type)+"\x00"+address.Address)
	}
	sort.Strings(addresses)
	return addresses
}
