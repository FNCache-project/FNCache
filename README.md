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

Install the latest stable release:

```bash
helm upgrade --install fncache \
  oci://ghcr.io/fncache-project/charts/oncache \
  --namespace fncache-system \
  --create-namespace \
  --wait
```

FNCache starts automatically after installation. See the [usage guide](USAGE.md) for details.

## License

[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fareniya%2FFNCache.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2Fareniya%2FFNCache?ref=badge_large)
