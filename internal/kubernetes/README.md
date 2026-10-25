# Kubernetes integration

This module owns Kubernetes API observation and event delivery:

- Pod and Node informer snapshots;
- event classification and periodic resync;
- the coordination queue and worker;
- Kubernetes API freshness checks.

The module produces immutable snapshots and `reconcile.ReconcileKey` values. It
does not own agent lifecycle orchestration or the BPF/TC datapath.
