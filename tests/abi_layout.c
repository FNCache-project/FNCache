#include <stddef.h>
#include <stdio.h>

#include "oncache_abi.h"
#include "common_defines.h"

_Static_assert(ONCACHE_STAT_INIT_E_POLICY_LOOKUP_MISS == 0, "stat init_e policy id");
_Static_assert(ONCACHE_STAT_MASQ_POLICY_MISS == 1, "stat masq policy id");
_Static_assert(ONCACHE_STAT_MASQ_EGRESSIP_MISS == 2, "stat masq egressip id");
_Static_assert(ONCACHE_STAT_MASQ_EGRESS_CACHE_MISS == 3, "stat masq egress cache id");
_Static_assert(ONCACHE_STAT_MASQ_INGRESS_NOT_READY == 4, "stat masq ingress id");
_Static_assert(ONCACHE_STAT_MASQ_ADJUST_ROOM_FAIL == 5, "stat masq adjust id");
_Static_assert(ONCACHE_STAT_RESTORE_POLICY_MISS == 6, "stat restore policy id");
_Static_assert(ONCACHE_STAT_RESTORE_DEVINFO_MISMATCH == 7, "stat restore devinfo id");
_Static_assert(ONCACHE_STAT_RESTORE_OUTER_IP_MISMATCH == 8, "stat restore outer ip id");
_Static_assert(ONCACHE_STAT_RESTORE_POD_NOT_READY == 9, "stat restore pod id");
_Static_assert(ONCACHE_STAT_RESTORE_EGRESSIP_MISS == 10, "stat restore egressip id");
_Static_assert(ONCACHE_STAT_RESTORE_ADJUST_ROOM_FAIL == 11, "stat restore adjust id");
_Static_assert(ONCACHE_STAT_INIT_IN_ENDPOINT_MISS == 12, "stat init_in endpoint id");
_Static_assert(ONCACHE_STAT_INIT_IN_POLICY_LOOKUP_MISS == 13, "stat init_in policy id");
_Static_assert(ONCACHE_STAT_COUNT == 14, "stat count");

_Static_assert(sizeof(struct oncache_flow_v1) == 16, "flow size");
_Static_assert(offsetof(struct oncache_flow_v1, local_addr) == 0, "flow local_addr");
_Static_assert(offsetof(struct oncache_flow_v1, remote_addr) == 4, "flow remote_addr");
_Static_assert(offsetof(struct oncache_flow_v1, local_port) == 8, "flow local_port");
_Static_assert(offsetof(struct oncache_flow_v1, remote_port) == 10, "flow remote_port");
_Static_assert(offsetof(struct oncache_flow_v1, protocol) == 12, "flow protocol");

_Static_assert(sizeof(struct oncache_egress_v1) == 68, "egress size");
_Static_assert(offsetof(struct oncache_egress_v1, outer_header) == 0, "egress outer_header");
_Static_assert(offsetof(struct oncache_egress_v1, ifindex) == 64, "egress ifindex");

_Static_assert(sizeof(struct oncache_action_v1) == 4, "action size");
_Static_assert(offsetof(struct oncache_action_v1, ingress_ready) == 0, "action ingress_ready");
_Static_assert(offsetof(struct oncache_action_v1, egress_ready) == 2, "action egress_ready");

_Static_assert(sizeof(struct oncache_device_v1) == 12, "device size");
_Static_assert(offsetof(struct oncache_device_v1, ipv4) == 0, "device ipv4");
_Static_assert(offsetof(struct oncache_device_v1, mac) == 4, "device mac");
_Static_assert(offsetof(struct oncache_device_v1, pad) == 10, "device pad");

_Static_assert(sizeof(struct oncache_ingress_v1) == 16, "ingress size");
_Static_assert(offsetof(struct oncache_ingress_v1, ifindex) == 0, "ingress ifindex");
_Static_assert(offsetof(struct oncache_ingress_v1, dst_mac) == 4, "ingress dst_mac");
_Static_assert(offsetof(struct oncache_ingress_v1, src_mac) == 10, "ingress src_mac");

_Static_assert(sizeof(struct oncache_control_v1) == 40, "control size");
_Static_assert(offsetof(struct oncache_control_v1, abi_version) == 0, "control abi_version");
_Static_assert(offsetof(struct oncache_control_v1, enabled) == 4, "control enabled");
_Static_assert(offsetof(struct oncache_control_v1, generation) == 8, "control generation");
_Static_assert(offsetof(struct oncache_control_v1, heartbeat_ns) == 16, "control heartbeat_ns");
_Static_assert(offsetof(struct oncache_control_v1, heartbeat_timeout_ns) == 24, "control heartbeat_timeout_ns");
_Static_assert(offsetof(struct oncache_control_v1, flags) == 32, "control flags");
_Static_assert(offsetof(struct oncache_control_v1, reserved) == 36, "control reserved");

int main(void) {
    printf("flow=%zu egress=%zu action=%zu device=%zu ingress=%zu control=%zu\n",
           sizeof(struct oncache_flow_v1),
           sizeof(struct oncache_egress_v1),
           sizeof(struct oncache_action_v1),
           sizeof(struct oncache_device_v1),
           sizeof(struct oncache_ingress_v1),
           sizeof(struct oncache_control_v1));
    return 0;
}
