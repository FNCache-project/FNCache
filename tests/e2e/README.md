# M3.15 two-node Kubernetes E2E

The test is disabled unless `ONCACHE_M3_E2E=1` is set. It expects a healthy
two-node K3s/Flannel VXLAN cluster and an agent image already available to both
nodes.

Required environment:

```text
ONCACHE_M3_E2E=1
ONCACHE_M3_E2E_IMAGE=oncache-agent:m3-e2e
ONCACHE_M3_E2E_NODE_A=<node name>
ONCACHE_M3_E2E_NODE_B=<node name>
```

Optional variables:

```text
ONCACHE_M3_E2E_CHART=charts/oncache
ONCACHE_M3_E2E_EVIDENCE=/tmp/oncache-m3-e2e
ONCACHE_M3_E2E_CLEANUP=1
```

Build the image with `make -C tests build-m3-e2e-image`, import it into both
node containerd instances, and then run `make -C tests test-m3-e2e` from the
repository root. The test preserves evidence by default. It does not promise
that the current VM environment is healthy; the runner must verify both nodes
are running and Ready before executing the workload.

## M4.14 acceleration closure

Set `ONCACHE_M4_ACCEL_E2E=1` and run `make -C tests test-m4-acceleration` to
verify first-flow Flannel fallback, warm hit, heartbeat bypass and restart
recovery. The test preserves strict BPF, TC, netfilter and packet-capture
evidence in `ONCACHE_M4_ACCEL_EVIDENCE` (or a temporary directory by default).
For an already-installed agent, `ONCACHE_M4_ACCEL_REUSE=1` skips only the
initial Helm deployment and still runs the traffic and failure gates.

## M5.5 lifecycle resilience

Set `ONCACHE_M5_LIFECYCLE_E2E=1` and run `make -C tests test-m5-lifecycle` to
exercise Pod churn, bounded PodIP reuse, and a paused-agent event-loss/resync
scenario. `ONCACHE_M5_CHURN_ROUNDS` defaults to 30 and is bounded to 200.
`ONCACHE_M5_RESYNC_INTERVAL` defaults to `15s` for the local VM baseline and
can be increased for a quieter control-plane run.

## One-command install lifecycle

Set `ONCACHE_INSTALL_E2E=1` and run `make -C tests test-one-command-install`
to validate the user-facing install flow on a healthy two-node K3s/Flannel
VXLAN cluster. Set `INSTALL_E2E_WORKLOAD_IMAGE` to an image available in both
node containerd instances; the image must contain `sh`, `ping`, `tcpdump`, and
the observer tools used by the existing evidence helpers.

Required node variables are the same as the other two-node tests:

```text
ONCACHE_M3_E2E_NODE_A=<node name>
ONCACHE_M3_E2E_NODE_B=<node name>
INSTALL_E2E_WORKLOAD_IMAGE=oncache-agent:m3-e2e
```

By default the test uses the local chart and overrides only the agent image.
Set `ONCACHE_INSTALL_E2E_STRICT=1` with the published OCI chart and leave
`ONCACHE_INSTALL_E2E_IMAGE` empty to exercise the no-override Helm command.
Evidence is written to `ONCACHE_INSTALL_E2E_EVIDENCE` or a temporary directory.
