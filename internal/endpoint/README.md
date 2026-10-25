# Endpoint lifecycle

This module owns Pod network identity and endpoint lifecycle:

- CRI sandbox and runtime endpoint resolution;
- Pod netns, veth, and link identity discovery;
- endpoint scanning and identity reuse protection;
- local, remote, and deletion lifecycle handlers under `lifecycle/`.

The resolver package provides endpoint facts. The lifecycle package consumes
control-plane interfaces and does not implement BPF or TC internals.
