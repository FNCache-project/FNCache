package kube

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/informers"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	"github.com/cat-cc-Lcos/FNCache/internal/resolver"
)

type InformerSource struct {
	factory          informers.SharedInformerFactory
	pods             coreinformers.PodInformer
	nodes            coreinformers.NodeInformer
	client           kubernetes.Interface
	store            *SnapshotStore
	errMu            sync.RWMutex
	podErr           error
	nodeErr          error
	healthMu         sync.RWMutex
	synced           bool
	lastProbeAt      time.Time
	lastProbeErr     error
	eventMu          sync.RWMutex
	podEventHandler  func(interface{}, interface{})
	nodeEventHandler func(interface{}, interface{})
}

func NewInformerSource(client kubernetes.Interface, store *SnapshotStore, resyncPeriod time.Duration) (*InformerSource, error) {
	if client == nil || store == nil {
		return nil, fmt.Errorf("kubernetes client and snapshot store are required")
	}
	if resyncPeriod < 0 {
		return nil, fmt.Errorf("resync period cannot be negative")
	}
	factory := informers.NewSharedInformerFactory(client, resyncPeriod)
	source := &InformerSource{factory: factory, pods: factory.Core().V1().Pods(), nodes: factory.Core().V1().Nodes(), client: client, store: store}
	if _, err := source.pods.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    source.addPod,
		UpdateFunc: source.updatePod,
		DeleteFunc: source.deletePod,
	}); err != nil {
		return nil, fmt.Errorf("register Pod informer handler: %w", err)
	}
	if _, err := source.nodes.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    source.addNode,
		UpdateFunc: source.updateNode,
		DeleteFunc: source.deleteNode,
	}); err != nil {
		return nil, fmt.Errorf("register Node informer handler: %w", err)
	}
	return source, nil
}

func (s *InformerSource) attachEventHandlers(podHandler, nodeHandler func(interface{}, interface{})) error {
	if podHandler == nil || nodeHandler == nil {
		return fmt.Errorf("Pod and Node event handlers are required")
	}
	s.eventMu.Lock()
	defer s.eventMu.Unlock()
	if s.podEventHandler != nil || s.nodeEventHandler != nil {
		return fmt.Errorf("informer event handlers are already attached")
	}
	s.podEventHandler = podHandler
	s.nodeEventHandler = nodeHandler
	return nil
}

func (s *InformerSource) notifyPodEvent(oldObj, newObj interface{}) {
	s.eventMu.RLock()
	handler := s.podEventHandler
	s.eventMu.RUnlock()
	if handler != nil {
		handler(oldObj, newObj)
	}
}

func (s *InformerSource) notifyNodeEvent(oldObj, newObj interface{}) {
	s.eventMu.RLock()
	handler := s.nodeEventHandler
	s.eventMu.RUnlock()
	if handler != nil {
		handler(oldObj, newObj)
	}
}

func (s *InformerSource) Run(ctx context.Context) {
	s.factory.Start(ctx.Done())
	<-ctx.Done()
}

func (s *InformerSource) WaitForSync(ctx context.Context) error {
	if !cache.WaitForCacheSync(ctx.Done(), s.pods.Informer().HasSynced, s.nodes.Informer().HasSynced) {
		if err := ctx.Err(); err != nil {
			return err
		}
		return fmt.Errorf("Pod and Node informers did not synchronize")
	}
	if err := s.LastError(); err != nil {
		return fmt.Errorf("snapshot synchronization failed: %w", err)
	}
	s.healthMu.Lock()
	s.synced = true
	s.lastProbeAt = time.Now()
	s.lastProbeErr = nil
	s.healthMu.Unlock()
	return nil
}

func (s *InformerSource) LastError() error {
	s.errMu.RLock()
	defer s.errMu.RUnlock()
	if s.podErr != nil {
		return s.podErr
	}
	return s.nodeErr
}

func (s *InformerSource) recordError(slot *error, err error) {
	if err == nil {
		return
	}
	s.errMu.Lock()
	if *slot == nil {
		*slot = err
	}
	s.errMu.Unlock()
}

func (s *InformerSource) recordPodError(err error) {
	s.recordError(&s.podErr, err)
}

func (s *InformerSource) recordNodeError(err error) {
	s.recordError(&s.nodeErr, err)
}

func (s *InformerSource) clearError(slot *error) {
	s.errMu.Lock()
	defer s.errMu.Unlock()
	s.healthMu.RLock()
	synced := s.synced
	s.healthMu.RUnlock()
	if synced {
		*slot = nil
	}
}

func (s *InformerSource) clearPodError() {
	s.clearError(&s.podErr)
}

func (s *InformerSource) clearNodeError() {
	s.clearError(&s.nodeErr)
}

func (s *InformerSource) addPod(obj interface{}) {
	s.upsertPod(obj)
	s.notifyPodEvent(nil, obj)
}

func (s *InformerSource) updatePod(oldObj, newObj interface{}) {
	oldPod, err := podObject(oldObj)
	if err != nil {
		s.recordPodError(err)
		return
	}
	newPod, err := podObject(newObj)
	if err != nil {
		s.recordPodError(err)
		return
	}
	if oldPod.UID != newPod.UID {
		s.store.DeletePod(string(oldPod.UID))
	}
	s.upsertPod(newPod)
	s.notifyPodEvent(oldObj, newObj)
}

func (s *InformerSource) deletePod(obj interface{}) {
	pod, err := podObject(obj)
	if err != nil {
		s.recordPodError(err)
		return
	}
	s.store.DeletePod(string(pod.UID))
	s.clearPodError()
	s.notifyPodEvent(obj, nil)
}

func (s *InformerSource) upsertPod(obj interface{}) {
	pod, err := podObject(obj)
	if err == nil {
		var snapshot resolver.PodSnapshot
		snapshot, err = podSnapshot(pod)
		if err == nil {
			err = s.store.UpsertPod(snapshot)
		}
	}
	if err != nil {
		s.recordPodError(err)
		return
	}
	s.clearPodError()
}

func (s *InformerSource) addNode(obj interface{}) {
	s.upsertNode(obj)
	s.notifyNodeEvent(nil, obj)
}

func (s *InformerSource) updateNode(oldObj, newObj interface{}) {
	oldNode, err := nodeObject(oldObj)
	if err != nil {
		s.recordNodeError(err)
		return
	}
	newNode, err := nodeObject(newObj)
	if err != nil {
		s.recordNodeError(err)
		return
	}
	if oldNode.UID != newNode.UID {
		s.store.DeleteNode(oldNode.Name, string(oldNode.UID))
	}
	s.upsertNode(newNode)
	s.notifyNodeEvent(oldObj, newObj)
}

func (s *InformerSource) deleteNode(obj interface{}) {
	node, err := nodeObject(obj)
	if err != nil {
		s.recordNodeError(err)
		return
	}
	s.store.DeleteNode(node.Name, string(node.UID))
	s.clearNodeError()
	s.notifyNodeEvent(obj, nil)
}

func (s *InformerSource) upsertNode(obj interface{}) {
	node, err := nodeObject(obj)
	if err == nil {
		var snapshot NodeSnapshot
		snapshot, err = nodeSnapshot(node)
		if err == nil {
			err = s.store.UpsertNode(snapshot)
		}
	}
	if err != nil {
		s.recordNodeError(err)
		return
	}
	s.clearNodeError()
}

func podObject(obj interface{}) (*corev1.Pod, error) {
	switch value := obj.(type) {
	case *corev1.Pod:
		return value, nil
	case cache.DeletedFinalStateUnknown:
		pod, ok := value.Obj.(*corev1.Pod)
		if ok {
			return pod, nil
		}
	case *cache.DeletedFinalStateUnknown:
		if value != nil {
			pod, ok := value.Obj.(*corev1.Pod)
			if ok {
				return pod, nil
			}
		}
	}
	return nil, fmt.Errorf("unexpected Pod informer object %T", obj)
}

func nodeObject(obj interface{}) (*corev1.Node, error) {
	switch value := obj.(type) {
	case *corev1.Node:
		return value, nil
	case cache.DeletedFinalStateUnknown:
		node, ok := value.Obj.(*corev1.Node)
		if ok {
			return node, nil
		}
	case *cache.DeletedFinalStateUnknown:
		if value != nil {
			node, ok := value.Obj.(*corev1.Node)
			if ok {
				return node, nil
			}
		}
	}
	return nil, fmt.Errorf("unexpected Node informer object %T", obj)
}

func podSnapshot(pod *corev1.Pod) (resolver.PodSnapshot, error) {
	ip, err := optionalIPv4(pod.Status.PodIP, "PodIP")
	if err != nil {
		return resolver.PodSnapshot{}, err
	}
	return resolver.PodSnapshot{
		Identity: resolver.PodIdentity{Namespace: pod.Namespace, Name: pod.Name, UID: string(pod.UID)},
		NodeName: pod.Spec.NodeName, PodIPv4: ip, HostNetwork: pod.Spec.HostNetwork,
		Phase: string(pod.Status.Phase), Deleting: pod.DeletionTimestamp != nil, ResourceVersion: pod.ResourceVersion,
	}, nil
}

func nodeSnapshot(node *corev1.Node) (NodeSnapshot, error) {
	var podCIDR netip.Prefix
	var internalIPv4 netip.Addr
	if node.Spec.PodCIDR != "" {
		parsed, err := netip.ParsePrefix(node.Spec.PodCIDR)
		if err != nil {
			return NodeSnapshot{}, fmt.Errorf("parse Node PodCIDR: %w", err)
		}
		podCIDR = parsed
	}
	addresses := make([]netip.Addr, 0, len(node.Status.Addresses))
	for _, address := range node.Status.Addresses {
		if address.Type != corev1.NodeInternalIP && address.Type != corev1.NodeExternalIP {
			continue
		}
		parsed, err := netip.ParseAddr(address.Address)
		if err != nil {
			return NodeSnapshot{}, fmt.Errorf("parse Node address: %w", err)
		}
		if parsed.Is4() {
			addresses = append(addresses, parsed)
			if address.Type == corev1.NodeInternalIP {
				if internalIPv4.IsValid() && internalIPv4 != parsed {
					return NodeSnapshot{}, fmt.Errorf("Node has multiple IPv4 InternalIP addresses")
				}
				internalIPv4 = parsed
			}
		}
	}
	return NodeSnapshot{Identity: resolver.NodeIdentity{Name: node.Name, UID: string(node.UID)}, PodCIDR: podCIDR, InternalIPv4: internalIPv4, Addresses: addresses, ResourceVersion: node.ResourceVersion}, nil
}

func optionalIPv4(value, field string) (netip.Addr, error) {
	if value == "" {
		return netip.Addr{}, nil
	}
	parsed, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("parse %s: %w", field, err)
	}
	if !parsed.Is4() {
		return netip.Addr{}, fmt.Errorf("%s must be IPv4", field)
	}
	return parsed, nil
}
