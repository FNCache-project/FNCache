# FNCache usage

## Requirements

FNCache v0.4.5 targets Kubernetes or K3s clusters using Flannel VXLAN, containerd, IPv4, and amd64 nodes. The node kernel and cluster security policy must provide the BPF, BTF, TC, and host-network capabilities required by the agent. Unsupported nodes remain on the normal Flannel path.

## Pin a chart version

For a reproducible deployment or rollback, pin the Chart version explicitly:

```bash
helm upgrade --install fncache \
  oci://ghcr.io/fncache-project/charts/oncache \
  --version 0.4.5 \
  --namespace fncache-system \
  --create-namespace \
  --wait
```

Each published Chart carries the matching release image tag, so the default image follows the selected Chart version without a separate `image.tag` value.

## Configuration

See the chart's [default values](charts/oncache/values.yaml) for supported configuration options.

## Check rollout and readiness

```bash
kubectl -n fncache-system get pods -o wide
kubectl -n fncache-system get daemonset
kubectl -n fncache-system logs daemonset/fncache-oncache --all-containers
```

The agent discovers the K3s or Kubernetes containerd socket and the running Flannel VXLAN parameters automatically. A node is Ready only after preflight, ownership, BPF/TC state, and the initial coordination succeed. When a dependency is unavailable, FNCache stays disabled and Flannel continues to carry traffic.

## Uninstall

To remove FNCache, use Helm. A graceful agent shutdown first disables the fast path and removes only objects proved to be owned by this installation:

```bash
helm uninstall fncache --namespace fncache-system --wait
```

## Limitations

The chart does not support non-containerd runtimes, non-Flannel overlays, IPv6, host-network acceleration, or kernels outside the tested capability matrix.
