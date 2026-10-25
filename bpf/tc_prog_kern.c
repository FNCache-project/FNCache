#include "common_defines.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __be32);
    __type(value, struct oncache_ingress_v1);
    __uint(max_entries, 1024);
} ingress_cache SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __be32);
    __type(value, __be32);
    __uint(max_entries, 4096);
} egressip_cache SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __be32);
    __type(value, struct oncache_egress_v1);
    __uint(max_entries, 1024);
} egress_cache SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct oncache_flow_v1);
    __type(value, struct oncache_action_v1);
    __uint(max_entries, 4096);
} policy_cache SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);
    __type(value, struct oncache_device_v1);
    __uint(max_entries, 8);
} devmap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct oncache_control_v1);
    __uint(max_entries, 1);
} control_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct oncache_policy_lock_v1);
    __uint(max_entries, 1);
} policy_lock_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, ONCACHE_STAT_COUNT);
} stats_map SEC(".maps");

#include "common_kern.h"

#define PORT_MIN 49152
#define PORT_MAX 65535
#define ENABLENP

SEC("tc/egress")
int tc_init_e(struct __sk_buff *skb) {
    int err;
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    if (!oncache_control_allows()) goto out;
    ////////////////// Check if the packet is a VXLAN packet ////////////////////
    if (data_end < data + sizeof(struct ethhdr)) goto out;
    struct ethhdr *outer_eth = data;

    // Check if Ethernet frame has IP packet and set IP hdr ptr
    if (outer_eth->h_proto != bpf_htons(ETH_P_IP)) goto out;
    struct iphdr *outer_iph;
    __u32 outer_available = (__u8 *)data_end - (__u8 *)(outer_eth + 1);
    if (!parse_ipv4_header(outer_eth + 1, data_end, outer_available, &outer_iph)) goto out;

    struct iphdr *inner_iph;
    if (!parse_vxlan_ipv4(outer_iph, data_end, &inner_iph)) goto out;

    // Check if Ethernet frame has IP packet and set IP hdr ptr
    // Learn only normal Flannel traffic for a known remote PodIP. Unknown
    // overlay traffic remains on the original path without cache mutation.
    if (!bpf_map_lookup_elem(&egressip_cache, &inner_iph->daddr)) goto out;
    /////////////////////////// Policy Learning ///////////////////////////
#ifdef ENABLENP
    struct oncache_flow_v1 tuple_;
    if (parse_5tuple_e(inner_iph, data_end, &tuple_)) goto out;
    struct oncache_action_v1 eaction_ = {
        .egress_ready = 1,
        .ingress_ready = 0
    };
    if(bpf_map_update_elem(&policy_cache, &tuple_, &eaction_, BPF_NOEXIST)) {
        struct oncache_action_v1* action_ = bpf_map_lookup_elem(&policy_cache, &tuple_);
        if (!action_) {
            oncache_stat_inc(ONCACHE_STAT_INIT_E_POLICY_LOOKUP_MISS);
        } else {
            oncache_policy_mark_ready(action_, ONCACHE_EGRESS_READY_MASK);
        }
    }
#endif
    ///////////////////////// Header cache learning ///////////////////////////////
    // Make sure there is elem in the map
    struct oncache_egress_v1 tmpnodeegressinfo_;
    initegressinfo(&tmpnodeegressinfo_, data, skb->ifindex);
    err = bpf_map_update_elem(&egress_cache, &outer_iph->daddr, &tmpnodeegressinfo_, BPF_NOEXIST);

    err = bpf_map_update_elem(&egressip_cache, &inner_iph->daddr, &outer_iph->daddr, BPF_NOEXIST);
out:
    return TC_ACT_OK;
}

SEC("tc/ingress")
int tc_masq(struct __sk_buff *ctx) {
    int action = TC_ACT_OK, err;
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    if (!oncache_control_allows()) goto out;

    if (data_end < data + sizeof(struct ethhdr)) goto out;
    struct ethhdr *eth = data;

    // Check if Ethernet frame has IP packet and set IP hdr ptr
    if (eth->h_proto != bpf_htons(ETH_P_IP)) goto out;
    struct iphdr *iphdr;
    __u32 ip_available = (__u8 *)data_end - (__u8 *)(eth + 1);
    if (!parse_ipv4_header(eth + 1, data_end, ip_available, &iphdr)) goto out;
    // Read for udp source port and policy check
    __u32 hash = bpf_get_hash_recalc(ctx);

    // Only mark traffic addressed to a known remote Pod. Local, gateway and
    // other unsupported IPv4 paths must remain untouched and use Flannel.
    __be32 *nodeip_ = bpf_map_lookup_elem(&egressip_cache, &iphdr->daddr);
    if (!nodeip_) {
        oncache_stat_inc(ONCACHE_STAT_MASQ_EGRESSIP_MISS);
        goto out;
    }
#ifdef ENABLENP
    ///////////////////////// Check for Policy /////////////////////////
    struct oncache_flow_v1 tuple_;
    if (parse_5tuple_e(iphdr, data_end, &tuple_)) goto out;
    struct oncache_action_v1 *action_ = bpf_map_lookup_elem(&policy_cache, &tuple_);
    // Must the ingress and egress both allow the flow, or will cause conntrack problem
    if (!action_ || !(action_->ingress_ready & action_->egress_ready)) {
        oncache_stat_inc(ONCACHE_STAT_MASQ_POLICY_MISS);
        goto out;
    }
#endif
    ///////////////////////// Check for header cache ///////////////////////////////
    // Use the nodeip to look up the egressinfo for masq
    struct oncache_egress_v1* egressinfo_ = bpf_map_lookup_elem(&egress_cache, nodeip_);
    if (!egressinfo_) {
        oncache_stat_inc(ONCACHE_STAT_MASQ_EGRESS_CACHE_MISS);
        goto out;
    }

    // Check for restore cache
    struct oncache_ingress_v1* ingressinfo_ = bpf_map_lookup_elem(&ingress_cache, &iphdr->saddr);
    if (!ingressinfo_ || oncache_mac_is_zero(ingressinfo_->src_mac)) {
        oncache_stat_inc(ONCACHE_STAT_MASQ_INGRESS_NOT_READY);
        goto out;
    }
    __be16 cached_udp_dest;
    __builtin_memcpy(&cached_udp_dest,
                     egressinfo_->outer_header + VXLAN_UDP_DEST_OFF,
                     sizeof(cached_udp_dest));
    if (!oncache_vxlan_header_matches_config(
            cached_udp_dest, egressinfo_->outer_header + VXLAN_HEADER_OFF)) {
        goto out;
    }
    if (!oncache_redirect_target_valid(egressinfo_->ifindex, (__u32)ctx->ifindex)) {
        goto out;
    }
    ///////////////////////// Start Masqurade /////////////////////////
    // Adjust the head pointer to the start of the inner IP header
    // The skb->inner protocol must be bpf_htons(ETH_P_TEB), thus we need BPF_F_ADJ_ROOM_ENCAP_L2(14)|BPF_F_ADJ_ROOM_ENCAP_L2_ETH flags.
    // The other flags are used to adjust some fild in the skb. Need kernel with d01b59c commit, at least 5.13.
    err = bpf_skb_adjust_room(ctx, 50, BPF_ADJ_ROOM_MAC, BPF_F_ADJ_ROOM_FIXED_GSO | BPF_F_ADJ_ROOM_ENCAP_L3_IPV4 | BPF_F_ADJ_ROOM_ENCAP_L4_UDP|BPF_F_ADJ_ROOM_ENCAP_L2(14)|BPF_F_ADJ_ROOM_ENCAP_L2_ETH);
    if (err) {
        oncache_stat_inc(ONCACHE_STAT_MASQ_ADJUST_ROOM_FAIL);
        goto out;
    }
    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;
    if (data_end < data + 64) {
        action = TC_ACT_SHOT;
        goto out;
    }
    // Append the outer header through the helper so TC does not add a
    // direct-write skb unclone prologue to the fallback path.
    if (bpf_skb_store_bytes(ctx, 0, egressinfo_->outer_header, 64, 0) < 0) {
        action = TC_ACT_SHOT;
        goto out;
    }
    if (set_new_length_outerhdr(ctx, ctx->len) < 0) {
        action = TC_ACT_SHOT;
        goto out;
    }
    // Set the UDP source port
    hash ^= hash << 16;
    __be16 sport = bpf_htons((((__u64) hash * (PORT_MAX - PORT_MIN)) >> 32) + PORT_MIN);
    if (bpf_skb_store_bytes(ctx, UDP_PORT_OFF, &sport, sizeof(sport), 0) < 0) {
        action = TC_ACT_SHOT;
        goto out;
    }

    ///////////////////////// Redirect to Node NIC /////////////////////////
    // action = bpf_redirect_rpeer(egressinfo_->ifindex, 0);
    action = bpf_redirect(egressinfo_->ifindex, 0);
    if (action != TC_ACT_REDIRECT) action = TC_ACT_SHOT;
    goto out;
out:
    return action;
}

SEC("tc/ingress")
int tc_restore(struct __sk_buff *ctx) {
    int action = TC_ACT_OK;
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    if (!oncache_control_allows()) goto out;

    if (data_end < data + sizeof(struct ethhdr)) goto out;
    struct ethhdr *outer_eth = data;

    // Check if Ethernet frame has IP packet and set IP hdr ptr
    if (outer_eth->h_proto != bpf_htons(ETH_P_IP)) goto out;
    struct iphdr *outer_iph;
    __u32 outer_available = (__u8 *)data_end - (__u8 *)(outer_eth + 1);
    if (!parse_ipv4_header(outer_eth + 1, data_end, outer_available, &outer_iph)) goto out;

    struct iphdr *inner_iph;
    if (!parse_vxlan_ipv4(outer_iph, data_end, &inner_iph)) goto out;

    // Check if Ethernet frame has IP packet and set IP hdr ptr
    int ifindex = ctx->ifindex;
    struct oncache_device_v1 *devinfo_ = bpf_map_lookup_elem(&devmap, &ifindex);
    if (!devinfo_ || maccmp(outer_eth->h_dest, devinfo_->mac, ETH_ALEN)) {
        oncache_stat_inc(ONCACHE_STAT_RESTORE_DEVINFO_MISMATCH);
        goto out;
    }
    if (!devinfo_ || outer_iph->daddr != devinfo_->ipv4) {
        oncache_stat_inc(ONCACHE_STAT_RESTORE_OUTER_IP_MISMATCH);
        goto out;
    }

    // Only mark traffic from a known remote Pod to a known local endpoint.
    // Unknown and unsupported flows must remain untouched for Flannel.
    if (!bpf_map_lookup_elem(&egressip_cache, &inner_iph->saddr)) {
        oncache_stat_inc(ONCACHE_STAT_RESTORE_EGRESSIP_MISS);
        goto out;
    }
    struct oncache_ingress_v1 *ingressinfo_ =
        bpf_map_lookup_elem(&ingress_cache, &inner_iph->daddr);
    if (!ingressinfo_ || oncache_mac_is_zero(ingressinfo_->src_mac)) {
        oncache_stat_inc(ONCACHE_STAT_RESTORE_POD_NOT_READY);
        goto out;
    }
    ///////////////////////// Policy Checking /////////////////////////
#ifdef ENABLENP
    struct oncache_flow_v1 tuple_;
    if (parse_5tuple_in(inner_iph, data_end, &tuple_)) goto out;
    struct oncache_action_v1 *action_ = bpf_map_lookup_elem(&policy_cache, &tuple_);
    if (!action_ || !(action_->ingress_ready & action_->egress_ready)) {
        oncache_stat_inc(ONCACHE_STAT_RESTORE_POLICY_MISS);
        goto out;
    }
#endif
    ///////////////////////// Restore the Packet /////////////////////////
    if (!oncache_redirect_target_valid(ingressinfo_->ifindex, (__u32)ctx->ifindex)) {
        goto out;
    }

    if (bpf_skb_adjust_room(ctx, -50, BPF_ADJ_ROOM_MAC, 0)) {
        oncache_stat_inc(ONCACHE_STAT_RESTORE_ADJUST_ROOM_FAIL);
        goto out;
    }
    // Check bounds
    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;
    if (data_end < data + MACLEN + IPLEN) {
        action = TC_ACT_SHOT;
        goto out;
    }
    // Change MAC to masqed MAC
    if (bpf_skb_store_bytes(ctx, 0, ingressinfo_->dst_mac, ETH_ALEN, 0) < 0 ||
        bpf_skb_store_bytes(ctx, ETH_ALEN, ingressinfo_->src_mac, ETH_ALEN, 0) < 0) {
        action = TC_ACT_SHOT;
        goto out;
    }
    action = bpf_redirect(ingressinfo_->ifindex, 0);
    if (action != TC_ACT_REDIRECT) action = TC_ACT_SHOT;
out:
    return action;
}

SEC("tc/ingress")
int tc_init_in(struct __sk_buff *ctx) {
    int action = TC_ACT_OK;
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    if (!oncache_control_allows()) goto out;

    if (data_end < data + sizeof(struct ethhdr)) goto out;
    struct ethhdr *eth = data;
    // Check if Ethernet frame has IP packet and set IP hdr ptr
    if (eth->h_proto != bpf_htons(ETH_P_IP)) goto out;
    struct iphdr *iphdr;
    __u32 ip_available = (__u8 *)data_end - (__u8 *)(eth + 1);
    if (!parse_ipv4_header(eth + 1, data_end, ip_available, &iphdr)) goto out;

    // A fallback packet carries the miss bit. Once the remote PodIP is
    // known, later packets may arrive without that marker and can still
    // complete ingress learning safely.
    if ((iphdr->tos & ONCACHE_MISS_MASK) != ONCACHE_MISS_MASK &&
        !bpf_map_lookup_elem(&egressip_cache, &iphdr->saddr)) goto out;
    ///////////////////////// Header/ifindex Learning ////////////////////
    struct oncache_ingress_v1* ingressinfo_ = bpf_map_lookup_elem(&ingress_cache, &iphdr->daddr);
    if (!ingressinfo_) {
        oncache_stat_inc(ONCACHE_STAT_INIT_IN_ENDPOINT_MISS);
        goto out;
    } else {
        __builtin_memcpy(ingressinfo_->dst_mac, eth->h_dest, ETH_ALEN);
        __builtin_memcpy(ingressinfo_->src_mac, eth->h_source, ETH_ALEN);
    }

#ifdef ENABLENP
    ///////////////////////// Policy Learning /////////////////////////
    struct oncache_flow_v1 tuple_;
    if (parse_5tuple_in(iphdr, data_end, &tuple_)) goto out;
    struct oncache_action_v1 eaction_ = {
        .egress_ready = 0,
        .ingress_ready = 1
    };
    if(bpf_map_update_elem(&policy_cache, &tuple_, &eaction_, BPF_NOEXIST)) {
        struct oncache_action_v1* action_ = bpf_map_lookup_elem(&policy_cache, &tuple_);
        if (!action_) {
            oncache_stat_inc(ONCACHE_STAT_INIT_IN_POLICY_LOOKUP_MISS);
        } else {
            oncache_policy_mark_ready(action_, ONCACHE_INGRESS_READY_MASK);
        }
    }
#endif
out:
    return action;
}

char _license[] SEC("license") = "GPL";
