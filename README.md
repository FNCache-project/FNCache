<div align="center">
  <img src="https://github.com/user-attachments/assets/0a7d797a-1782-45c7-8a50-a5fafac29a1c" width="100" height="100" alt="FNCache Logo">
  <h1>FNCache</h1>
</div>

<p align="center">
  <img src="https://img.shields.io/badge/Kubernetes-326CE5?logo=kubernetes&logoColor=white" alt="Kubernetes" />
  <img src="https://img.shields.io/badge/status-experimental-orange" alt="Status" />
  <img src="https://img.shields.io/badge/eBPF-datapath-blue" alt="eBPF" />
  <img src="https://img.shields.io/badge/Flannel-VXLAN-important" alt="Flannel VXLAN" />
  <img src="https://img.shields.io/badge/license-Apache%202.0-green" alt="License" />
</p>

---

## Introduction
FNCache is an experimental Kubernetes node agent that uses an eBPF datapath to accelerate selected cross-node IPv4 Pod traffic in Flannel VXLAN clusters. It learns the overlay and endpoint state required by eligible flows, then provides a fast path while preserving Flannel's normal path when the cache is cold or the datapath is not ready.

## Quickstart

FNCache v0.5 targets Kubernetes or K3s clusters using Flannel VXLAN, containerd, IPv4 and amd64 nodes. The node kernel and cluster security policy must provide the BPF, BTF, TC and host-network capabilities required by the agent. Unsupported nodes remain on the normal Flannel path.

Install the latest published stable chart from GHCR:

```bash
helm upgrade --install fncache \
  oci://ghcr.io/fncache-project/charts/oncache \
  --namespace fncache-system \
  --create-namespace \
  --wait
```

For a reproducible deployment or rollback, pin the Chart version explicitly:

```bash
helm upgrade --install fncache \
  oci://ghcr.io/fncache-project/charts/oncache \
  --version 0.5.0 \
  --namespace fncache-system \
  --create-namespace \
  --wait
```

Each published Chart carries the matching release image tag, so the default
image follows the selected Chart version without a separate `image.tag` value.

Check the rollout and agent readiness:

```bash
kubectl -n fncache-system get pods -o wide
kubectl -n fncache-system get daemonset
kubectl -n fncache-system logs daemonset/fncache-oncache --all-containers
```

The agent discovers the K3s or Kubernetes containerd socket and the running Flannel VXLAN parameters automatically. A node is Ready only after preflight, ownership, BPF/TC state and the initial coordination succeed. When a dependency is unavailable, FNCache stays disabled and Flannel continues to carry traffic.

To remove FNCache, use Helm. A graceful agent shutdown first disables the fast path and removes only objects proved to be owned by this installation:

```bash
helm uninstall fncache --namespace fncache-system --wait
```

The chart does not support non-containerd runtimes, non-Flannel overlays, IPv6, host-network acceleration or kernels outside the tested capability matrix.

## License

[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fareniya%2FFNCache.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2Fareniya%2FFNCache?ref=badge_large)
