package kubernetes

import (
	"fmt"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/cat-cc-Lcos/FNCache/internal/endpoint"
)

// NodeSnapshot contains only the Node fields needed by the control plane.
type NodeSnapshot struct {
	Identity        endpoint.NodeIdentity
	PodCIDR         netip.Prefix
	InternalIPv4    netip.Addr
	Addresses       []netip.Addr
	ResourceVersion string
}

// Snapshot is an immutable copy of the cache at one observation point.
type Snapshot struct {
	ObservedAt time.Time
	Pods       map[string]endpoint.PodSnapshot
	Nodes      map[string]NodeSnapshot
}

// SnapshotStore keeps the latest Pod and Node snapshots without retaining
// pointers to Kubernetes API objects.
type SnapshotStore struct {
	mu    sync.RWMutex
	pods  map[string]endpoint.PodSnapshot
	nodes map[string]NodeSnapshot
}

func NewSnapshotStore() *SnapshotStore {
	return &SnapshotStore{pods: make(map[string]endpoint.PodSnapshot), nodes: make(map[string]NodeSnapshot)}
}

func (s *SnapshotStore) UpsertPod(pod endpoint.PodSnapshot) error {
	if err := validatePod(pod); err != nil {
		return err
	}
	s.mu.Lock()
	s.pods[pod.Identity.UID] = pod
	s.mu.Unlock()
	return nil
}

func (s *SnapshotStore) DeletePod(uid string) bool {
	if uid == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.pods[uid]; !ok {
		return false
	}
	delete(s.pods, uid)
	return true
}

func (s *SnapshotStore) UpsertNode(node NodeSnapshot) error {
	if err := validateNode(node); err != nil {
		return err
	}
	node = cloneNode(node)
	s.mu.Lock()
	s.nodes[node.Identity.Name] = node
	s.mu.Unlock()
	return nil
}

// DeleteNode only removes the current UID, protecting a replacement with the
// same Kubernetes name from a stale delete event.
func (s *SnapshotStore) DeleteNode(name, uid string) bool {
	if name == "" || uid == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	node, ok := s.nodes[name]
	if !ok || node.Identity.UID != uid {
		return false
	}
	delete(s.nodes, name)
	return true
}

func (s *SnapshotStore) GetPod(uid string) (endpoint.PodSnapshot, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	pod, ok := s.pods[uid]
	return pod, ok
}

func (s *SnapshotStore) GetNode(name string) (NodeSnapshot, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	node, ok := s.nodes[name]
	if !ok {
		return NodeSnapshot{}, false
	}
	return cloneNode(node), true
}

func (s *SnapshotStore) Snapshot() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := Snapshot{
		ObservedAt: time.Now(),
		Pods:       make(map[string]endpoint.PodSnapshot, len(s.pods)),
		Nodes:      make(map[string]NodeSnapshot, len(s.nodes)),
	}
	for uid, pod := range s.pods {
		result.Pods[uid] = pod
	}
	for name, node := range s.nodes {
		result.Nodes[name] = cloneNode(node)
	}
	return result
}

func (s *SnapshotStore) LocalPods(nodeName string) []endpoint.PodSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	pods := make([]endpoint.PodSnapshot, 0)
	for _, pod := range s.pods {
		if pod.NodeName == nodeName {
			pods = append(pods, pod)
		}
	}
	sort.Slice(pods, func(i, j int) bool { return pods[i].Identity.UID < pods[j].Identity.UID })
	return pods
}

func validatePod(pod endpoint.PodSnapshot) error {
	if pod.Identity.Namespace == "" || pod.Identity.Name == "" || pod.Identity.UID == "" {
		return fmt.Errorf("pod snapshot identity is incomplete")
	}
	if pod.PodIPv4.IsValid() && !pod.PodIPv4.Is4() {
		return fmt.Errorf("pod snapshot must use IPv4")
	}
	return nil
}

func validateNode(node NodeSnapshot) error {
	if node.Identity.Name == "" || node.Identity.UID == "" {
		return fmt.Errorf("node snapshot identity is incomplete")
	}
	if node.PodCIDR.IsValid() && !node.PodCIDR.Addr().Is4() {
		return fmt.Errorf("node PodCIDR must use IPv4")
	}
	if node.InternalIPv4.IsValid() && !node.InternalIPv4.Is4() {
		return fmt.Errorf("node InternalIP must use IPv4")
	}
	for _, address := range node.Addresses {
		if address.IsValid() && !address.Is4() {
			return fmt.Errorf("node address must use IPv4")
		}
	}
	return nil
}

func cloneNode(node NodeSnapshot) NodeSnapshot {
	node.Addresses = append([]netip.Addr(nil), node.Addresses...)
	return node
}
