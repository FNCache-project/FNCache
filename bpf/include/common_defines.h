#ifndef __COMMON_DEFINES_H
#define __COMMON_DEFINES_H

#include <stdbool.h>
#include <stddef.h>

#include <linux/if_ether.h>
#include <linux/types.h>
#include <linux/pkt_cls.h>
#include <linux/pkt_sched.h> /* TC_H_MAJ + TC_H_MIN */
#include <linux/if_packet.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include "linux/bpf.h"
#include "oncache_abi.h"

#define MACLEN 14
#define IPLEN 20
#define UDPLEN 8
#define TCPLEN 20
#define VXLANLEN 8
#define ONCACHE_IPV4_FRAGMENT_MASK 0x3fff
#define ONCACHE_IPV4_RESERVED_FLAG 0x8000
#define ONCACHE_VXLAN_I_FLAG 0x08
#define ONCACHE_MISS_MASK 0x04
#define ONCACHE_ESTABLISHED_MASK 0x08
#define ONCACHE_TOS_MASK (ONCACHE_MISS_MASK | ONCACHE_ESTABLISHED_MASK)
#define ONCACHE_INGRESS_READY_MASK ((__u32)1)
#define ONCACHE_EGRESS_READY_MASK ((__u32)1 << 16)

enum oncache_stat_id {
    ONCACHE_STAT_INIT_E_POLICY_LOOKUP_MISS = 0,
    ONCACHE_STAT_MASQ_POLICY_MISS = 1,
    ONCACHE_STAT_MASQ_EGRESSIP_MISS = 2,
    ONCACHE_STAT_MASQ_EGRESS_CACHE_MISS = 3,
    ONCACHE_STAT_MASQ_INGRESS_NOT_READY = 4,
    ONCACHE_STAT_MASQ_ADJUST_ROOM_FAIL = 5,
    ONCACHE_STAT_RESTORE_POLICY_MISS = 6,
    ONCACHE_STAT_RESTORE_DEVINFO_MISMATCH = 7,
    ONCACHE_STAT_RESTORE_OUTER_IP_MISMATCH = 8,
    ONCACHE_STAT_RESTORE_POD_NOT_READY = 9,
    ONCACHE_STAT_RESTORE_EGRESSIP_MISS = 10,
    ONCACHE_STAT_RESTORE_ADJUST_ROOM_FAIL = 11,
    ONCACHE_STAT_INIT_IN_ENDPOINT_MISS = 12,
    ONCACHE_STAT_INIT_IN_POLICY_LOOKUP_MISS = 13,
    ONCACHE_STAT_COUNT = 14,
};

#define MAX_IFINDEX 4096

struct oncache_policy_lock_v1 {
    struct bpf_spin_lock lock;
};

struct rule {
    struct oncache_flow_v1 flow;
    int isIngress;
};

#define PORT_AVAILABLE 1024

#define EXIT_OK   0 /* == EXIT_SUCCESS (stdlib.h) man exit(3) */
#define EXIT_FAIL  1 /* == EXIT_FAILURE (stdlib.h) man exit(3) */
#define EXIT_FAIL_OPTION 2
#define EXIT_FAIL_XDP  3
#define EXIT_FAIL_MAP  20
#define EXIT_FAIL_MAP_KEY 21
#define EXIT_FAIL_MAP_FILE 22
#define EXIT_FAIL_MAP_FS 23
#define EXIT_FAIL_IP  30
#define EXIT_FAIL_CPU  31
#define EXIT_FAIL_BPF  40
#define EXIT_FAIL_BPF_ELF 41
#define EXIT_FAIL_BPF_RELOCATE 42

#endif
