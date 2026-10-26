package kubernetes

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"

	"github.com/cat-cc-Lcos/FNCache/internal/kubernetes/queue"
)

type EventDispatcher struct {
	source     *InformerSource
	classifier *EventClassifier
	queue      *queue.Queue
}

func NewEventDispatcher(source *InformerSource, classifier *EventClassifier, target *queue.Queue) (*EventDispatcher, error) {
	if source == nil || classifier == nil || target == nil {
		return nil, fmt.Errorf("informer source, classifier and queue are required")
	}
	d := &EventDispatcher{source: source, classifier: classifier, queue: target}
	if err := source.attachEventHandlers(d.dispatchPod, d.dispatchNode); err != nil {
		return nil, fmt.Errorf("attach informer event handlers: %w", err)
	}
	return d, nil
}

func (d *EventDispatcher) addPod(obj interface{})               { d.dispatchPod(nil, obj) }
func (d *EventDispatcher) updatePod(oldObj, newObj interface{}) { d.dispatchPod(oldObj, newObj) }
func (d *EventDispatcher) deletePod(obj interface{})            { d.dispatchPod(obj, nil) }

func (d *EventDispatcher) dispatchPod(oldObj, newObj interface{}) {
	oldPod, newPod, err := pairPods(oldObj, newObj)
	if err != nil {
		d.source.recordPodError(podErrorObject(oldObj, newObj), err)
		return
	}
	for _, key := range d.classifier.Pod(oldPod, newPod) {
		d.queue.Add(key)
	}
}

func (d *EventDispatcher) addNode(obj interface{})               { d.dispatchNode(nil, obj) }
func (d *EventDispatcher) updateNode(oldObj, newObj interface{}) { d.dispatchNode(oldObj, newObj) }
func (d *EventDispatcher) deleteNode(obj interface{})            { d.dispatchNode(obj, nil) }

func (d *EventDispatcher) dispatchNode(oldObj, newObj interface{}) {
	oldNode, newNode, err := pairNodes(oldObj, newObj)
	if err != nil {
		d.source.recordNodeError(nodeErrorObject(oldObj, newObj), err)
		return
	}
	for _, key := range d.classifier.Node(oldNode, newNode) {
		d.queue.Add(key)
	}
}

func podErrorObject(oldObj, newObj interface{}) interface{} {
	if oldObj != nil {
		if _, err := podObject(oldObj); err != nil {
			return oldObj
		}
	}
	return newObj
}

func nodeErrorObject(oldObj, newObj interface{}) interface{} {
	if oldObj != nil {
		if _, err := nodeObject(oldObj); err != nil {
			return oldObj
		}
	}
	return newObj
}

func pairPods(oldObj, newObj interface{}) (oldPod, newPod *corev1.Pod, err error) {
	if oldObj != nil {
		oldPod, err = podObject(oldObj)
		if err != nil {
			return nil, nil, err
		}
	}
	if newObj != nil {
		newPod, err = podObject(newObj)
	}
	return oldPod, newPod, err
}

func pairNodes(oldObj, newObj interface{}) (oldNode, newNode *corev1.Node, err error) {
	if oldObj != nil {
		oldNode, err = nodeObject(oldObj)
		if err != nil {
			return nil, nil, err
		}
	}
	if newObj != nil {
		newNode, err = nodeObject(newObj)
	}
	return oldNode, newNode, err
}
