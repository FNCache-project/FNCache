# Host networking and overlay integration

This module owns host capability and overlay integration:

- Linux/BPF/TC/CRI preflight checks under `discovery/`;
- Flannel VXLAN discovery and marker-rule management under `flannel/`;
- overlay fingerprints and host-network compatibility checks.

It reports host-network facts to the agent and control plane. The protected
`internal/datapath` package remains responsible for low-level BPF/TC objects.
