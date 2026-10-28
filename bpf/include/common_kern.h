#ifndef __COMMON_KERN_H
#define __COMMON_KERN_H

#include "common_defines.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#if defined(ONCACHE_TEST_FAIL_ADJUST_ROOM)
#define bpf_skb_adjust_room(ctx, len, mode, flags) \
    ((void)(ctx), (void)(len), (void)(mode), (void)(flags), -1)
#elif defined(ONCACHE_TEST_FAIL_STORE_BYTES)
#define bpf_skb_store_bytes(ctx, off, from, len, flags) \
    ((void)(ctx), (void)(off), (void)(from), (void)(len), (void)(flags), -1)
#elif defined(ONCACHE_TEST_FAIL_REDIRECT)
#define bpf_redirect(ifindex, flags) ((void)(ifindex), (void)(flags), TC_ACT_OK)
#endif

static __always_inline int oncache_control_allows(void) {
    __u32 key = 0;
    struct oncache_control_v1 *control = bpf_map_lookup_elem(&control_map, &key);
    if (!control || control->abi_version != ONCACHE_ABI_VERSION) return 0;
    if (control->enabled != 1) return 0;
    if (control->flags & ONCACHE_CONTROL_FLAG_FORCE_PASS) return 0;
    if (control->heartbeat_timeout_ns == 0) return 0;

    __u64 now = bpf_ktime_get_ns();
    if (now < control->heartbeat_ns) return 0;
    if (now - control->heartbeat_ns > control->heartbeat_timeout_ns) return 0;
    return 1;
}

static __always_inline int oncache_redirect_target_valid(
        __u32 target_ifindex, __u32 current_ifindex) {
    return target_ifindex != 0 && target_ifindex != current_ifindex;
}

static __always_inline void oncache_stat_inc(__u32 stat_id) {
    __u32 control_key = 0;
    struct oncache_control_v1 *control =
        bpf_map_lookup_elem(&control_map, &control_key);
    if (!control || !(control->flags & ONCACHE_CONTROL_FLAG_DEBUG_COUNTERS) ||
        stat_id >= ONCACHE_STAT_COUNT) {
        return;
    }

    __u64 *counter = bpf_map_lookup_elem(&stats_map, &stat_id);
    if (counter) (*counter)++;
}

static __always_inline int parse_ipv4_header(
        void *cursor, void *data_end, __u32 available_len,
        struct iphdr **iph_out) {
    struct iphdr *iph = cursor;
    if (data_end < (void *)(iph + 1)) return 0;
    if (iph->version != 4 || iph->ihl != 5) return 0;

    __u16 frag_off = bpf_ntohs(iph->frag_off);
    if (frag_off & (ONCACHE_IPV4_FRAGMENT_MASK | ONCACHE_IPV4_RESERVED_FLAG)) {
        return 0;
    }

    __u16 total_len = bpf_ntohs(iph->tot_len);
    if (total_len < sizeof(*iph)) return 0;
    if (total_len > available_len) return 0;

    *iph_out = iph;
    return 1;
}

static __always_inline int oncache_vxlan_header_matches_config(
        __be16 udp_dest, const __u8 *vxlan) {
    __u32 key = 0;
    struct oncache_control_v1 *control =
        bpf_map_lookup_elem(&control_map, &key);
    if (!control) return 0;

    __u16 expected_port =
        (__u16)(control->flags >> ONCACHE_CONTROL_VXLAN_UDP_SHIFT);
    __u32 expected_vni = control->reserved;
    if (expected_port == 0 || expected_vni == 0 || expected_vni > 0xffffffU) {
        return 0;
    }
    if (udp_dest != bpf_htons(expected_port)) return 0;

    if (vxlan[0] != ONCACHE_VXLAN_I_FLAG ||
        vxlan[1] != 0 || vxlan[2] != 0 || vxlan[3] != 0 || vxlan[7] != 0) {
        return 0;
    }

    __u32 packet_vni = ((__u32)vxlan[4] << 16) |
                       ((__u32)vxlan[5] << 8) |
                       (__u32)vxlan[6];
    return packet_vni == expected_vni;
}

static __always_inline int parse_vxlan_ipv4(
        struct iphdr *outer_iph,
        void *data_end,
        struct iphdr **inner_iph_out) {
    if (outer_iph->protocol != IPPROTO_UDP) return 0;

    struct udphdr *udph = (void *)(outer_iph + 1);
    if (data_end < (void *)(udph + 1)) return 0;

    __u16 outer_len = bpf_ntohs(outer_iph->tot_len);
    __u16 udp_len = bpf_ntohs(udph->len);
    if (outer_len < sizeof(*outer_iph) ||
        udp_len < sizeof(*udph) + VXLANLEN + sizeof(struct ethhdr) ||
        udp_len > outer_len - sizeof(*outer_iph)) {
        return 0;
    }

    __u32 udp_available = (__u8 *)data_end - (__u8 *)udph;
    if (udp_len > udp_available) return 0;

    __u8 *vxlan = (void *)(udph + 1);
    if (data_end < (void *)(vxlan + VXLANLEN)) return 0;
    if (!oncache_vxlan_header_matches_config(udph->dest, vxlan)) return 0;

    struct ethhdr *inner_eth = (void *)((__u8 *)udph + sizeof(*udph) + VXLANLEN);
    if (data_end < (void *)(inner_eth + 1) ||
        inner_eth->h_proto != bpf_htons(ETH_P_IP)) {
        return 0;
    }

    __u32 inner_available = udp_len - sizeof(*udph) - VXLANLEN - sizeof(*inner_eth);
    if (!parse_ipv4_header(inner_eth + 1, data_end, inner_available, inner_iph_out)) return 0;
    return 1;
}

static __always_inline int check_l4_bound(struct iphdr *iph, void *data_end) {
    void *l4hdr = (void *)(iph + 1);
    __u16 total_len = bpf_ntohs(iph->tot_len);
    if (total_len < sizeof(*iph)) return 1;

    __u16 payload_len = total_len - sizeof(*iph);
    if (iph->protocol == IPPROTO_UDP) {
        if (payload_len < sizeof(struct udphdr) ||
            data_end < l4hdr + sizeof(struct udphdr)) {
            return 1;
        }
        struct udphdr *udph = l4hdr;
        __u16 udp_len = bpf_ntohs(udph->len);
        if (udp_len < sizeof(*udph) || udp_len > payload_len) return 1;
    } else if (iph->protocol == IPPROTO_TCP) {
        if (payload_len < sizeof(struct tcphdr) ||
            data_end < l4hdr + sizeof(struct tcphdr)) {
            return 1;
        }
    }
    return 0;
}

static __always_inline void oncache_policy_mark_ready(
        struct oncache_action_v1 *action, __u32 ready_mask) {
    __u32 key = 0;
    struct oncache_policy_lock_v1 *lock =
        bpf_map_lookup_elem(&policy_lock_map, &key);
    if (!lock) return;

    bpf_spin_lock(&lock->lock);
    if (ready_mask == ONCACHE_EGRESS_READY_MASK) {
        action->egress_ready = 1;
    } else if (ready_mask == ONCACHE_INGRESS_READY_MASK) {
        action->ingress_ready = 1;
    }
    bpf_spin_unlock(&lock->lock);
}

static __always_inline
int parse_5tuple_in(struct iphdr * iph, void *data_end, struct oncache_flow_v1* tuple) {
    int proto = iph->protocol;

    if (check_l4_bound(iph, data_end)) return 1;

    tuple->remote_addr = iph->saddr;
    tuple->local_addr = iph->daddr;
    tuple->protocol = iph->protocol;
    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcphdr = (struct tcphdr *)(iph + 1);
        tuple->remote_port = tcphdr->source;
        tuple->local_port = tcphdr->dest;
    } else if (proto == IPPROTO_UDP) {
        struct udphdr *udphdr = (struct udphdr *)(iph + 1);
        tuple->remote_port = udphdr->source;
        tuple->local_port = udphdr->dest;
    } else {
        tuple->remote_port = 0;
        tuple->local_port = 0;
    }
    return 0;
}

static __always_inline
int parse_5tuple_e(struct iphdr * iph, void *data_end, struct oncache_flow_v1* tuple) {
    int proto = iph->protocol;

    if (check_l4_bound(iph, data_end)) return 1;

    tuple->local_addr = iph->saddr;
    tuple->remote_addr = iph->daddr;
    tuple->protocol = iph->protocol;
    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcphdr = (struct tcphdr *)(iph + 1);
        tuple->local_port = tcphdr->source;
        tuple->remote_port = tcphdr->dest;
    } else if (proto == IPPROTO_UDP) {
        struct udphdr *udphdr = (struct udphdr *)(iph + 1);
        tuple->local_port = udphdr->source;
        tuple->remote_port = udphdr->dest;
    } else {
        tuple->local_port = 0;
        tuple->remote_port = 0;
    }
    return 0;
}

static __always_inline void initegressinfo(struct oncache_egress_v1* ci, const void * data, int ifindex) {
    __builtin_memcpy(&(ci->outer_header), data, 64);
    ci->ifindex = ifindex;
}

#define IP_CSUM_OFF (ETH_HLEN + offsetof(struct iphdr, check))
#define IP_DST_OFF (ETH_HLEN + offsetof(struct iphdr, daddr))
#define IP_SRC_OFF (ETH_HLEN + offsetof(struct iphdr, saddr))
#define IP_TOS_OFF (ETH_HLEN + offsetof(struct iphdr, tos))
#define IP_ID_OFF (ETH_HLEN + offsetof(struct iphdr, id))
#define IP_LEN_OFF (ETH_HLEN + offsetof(struct iphdr, tot_len))
#define TCP_PORT_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, source))
#define UDP_PORT_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct udphdr, source))
#define TCP_CSUM_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, check))
#define UDP_CSUM_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct udphdr, check))
#define UDP_LEN_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct udphdr, len))
#define VXLAN_UDP_DEST_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct udphdr, dest))
#define VXLAN_HEADER_OFF (ETH_HLEN + sizeof(struct iphdr) + sizeof(struct udphdr))
#define IS_PSEUDO 0x10
#define IS_SRC 1
#define IS_DST 2

static inline int set_ip_tos(struct __sk_buff *skb, unsigned int off, __u8 tos)
{
	__u8 tos_protocol[2];
	if (bpf_skb_load_bytes(skb, off + IP_TOS_OFF, tos_protocol, sizeof(tos_protocol)) < 0) {
		return -1;
	}
	__u8 old_tos = tos_protocol[0];
	__u8 new_tos;
	__u8 set_mask = tos & ONCACHE_TOS_MASK;
    if (set_mask){
        new_tos = old_tos | set_mask;
	} else {
		new_tos = old_tos & (__u8)~ONCACHE_TOS_MASK;
	}
	if (new_tos == old_tos) return 0;
	__be16 old_word = ((__be16)tos_protocol[0] << 8) | tos_protocol[1];
	__be16 new_word = ((__be16)new_tos << 8) | tos_protocol[1];
	if (bpf_l3_csum_replace(skb, off + IP_CSUM_OFF, old_word, new_word, sizeof(new_word)) < 0) {
		return -1;
	}
	return bpf_skb_store_bytes(skb, off + IP_TOS_OFF, &new_tos, sizeof(new_tos), 0);
}

static inline void set_new_ip(
        struct __sk_buff *skb, unsigned int off,  __be32 new_ip, int is_src, unsigned char proto, bool do_l4csum) {
    unsigned int field;
    if (is_src == IS_SRC) field = off + IP_SRC_OFF;
    else field = off + IP_DST_OFF;
    __be32 old_ip;
    if (bpf_skb_load_bytes(skb, field, &old_ip, sizeof(old_ip)) < 0) return;

    if (do_l4csum) {
        if (proto == IPPROTO_TCP) {
            bpf_l4_csum_replace(skb, off + TCP_CSUM_OFF, old_ip, new_ip, IS_PSEUDO | sizeof(new_ip));
        } else if (proto == IPPROTO_UDP) {
            bpf_l4_csum_replace(skb, off + UDP_CSUM_OFF, old_ip, new_ip, IS_PSEUDO | sizeof(new_ip));
        }
    }
    bpf_l3_csum_replace(skb, off + IP_CSUM_OFF, old_ip, new_ip, sizeof(new_ip));
    bpf_skb_store_bytes(skb, field, &new_ip, sizeof(new_ip), 0);
}

static inline void set_new_ipid(struct __sk_buff *skb, unsigned int off,  __be16 new_id) {
    __be16 old_id;
    if (bpf_skb_load_bytes(skb, off + IP_ID_OFF, &old_id, sizeof(old_id)) < 0) return;
    bpf_l3_csum_replace(skb, off + IP_CSUM_OFF, old_id, new_id, sizeof(new_id));
    bpf_skb_store_bytes(skb, off + IP_ID_OFF, &new_id, sizeof(new_id), 0);
}

// The function is used to set the IP length and UDP length according to the orignal length.
static inline int set_new_length_outerhdr(struct __sk_buff *skb, unsigned int ori_len) {
    if (ori_len < MACLEN + IPLEN + UDPLEN ||
        (void *)(long)skb->data_end < (void *)(long)skb->data + MACLEN + IPLEN + UDPLEN) {
        return -1;
    }
    __u16 udp_len = bpf_htons(ori_len - MACLEN - IPLEN);
    if (bpf_skb_store_bytes(skb, UDP_LEN_OFF, &udp_len, sizeof(udp_len), 0) < 0) {
        return -1;
    }

    if ((void *)(long)skb->data_end < (void *)(long)skb->data + MACLEN + IPLEN) return -1;
    __be16 old_len;
    if (bpf_skb_load_bytes(skb, IP_LEN_OFF, &old_len, sizeof(old_len)) < 0) return -1;
    __u16 ip_len = bpf_htons(ori_len - MACLEN);
    if (bpf_l3_csum_replace(skb, IP_CSUM_OFF, old_len, ip_len, sizeof(ip_len)) < 0) {
        return -1;
    }
    if (bpf_skb_store_bytes(skb, IP_LEN_OFF, &ip_len, sizeof(ip_len), 0) < 0) {
        return -1;
    }
    return 0;
}

static __always_inline int maccmp(char* mac1, char* mac2, int len) {
    int i;
    for (i = 0; i < len; i++) {
        if (mac1[i] != mac2[i]) return 1;
    }
    return 0;
}

static __always_inline int oncache_mac_is_zero(const __u8 *mac) {
    return mac[0] == 0 && mac[1] == 0 && mac[2] == 0 &&
           mac[3] == 0 && mac[4] == 0 && mac[5] == 0;
}

#endif  // COMMON_KERN_H_
