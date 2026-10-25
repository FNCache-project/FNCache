#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
#include <netinet/ip.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "oncache_abi.h"

#define PACKET_MAX 512
#define IF_IN 2
#define IF_OUT 3
#define IP_A ((uint32_t)htonl(0x0a000001U))
#define IP_B ((uint32_t)htonl(0x0a000002U))
#define IP_NODE ((uint32_t)htonl(0xc0a80102U))
#define VXLAN_TEST_PORT 8472U
#define VXLAN_TEST_VNI 1U

struct env {
    struct bpf_object *obj;
    int control, policy, egressip, egress, ingress, devmap;
};

struct race_arg {
    struct bpf_program *prog;
    uint8_t packet[PACKET_MAX];
    size_t len;
    uint32_t ifindex;
    int error;
};

static int check(int condition, const char *message) {
    if (!condition) fprintf(stderr, "FAIL: %s\n", message);
    return condition ? 0 : 1;
}

static uint32_t ip4(unsigned a, unsigned b, unsigned c, unsigned d) {
    return htonl((a << 24) | (b << 16) | (c << 8) | d);
}

static void put16(uint8_t *p, uint16_t value) { memcpy(p, &value, sizeof(value)); }
static void put32(uint8_t *p, uint32_t value) { memcpy(p, &value, sizeof(value)); }

static size_t plain_packet(uint8_t *p, uint8_t tos, uint8_t proto,
                           uint32_t src, uint32_t dst) {
    memset(p, 0, 64);
    memset(p, 0x11, 6);
    memset(p + 6, 0x22, 6);
    p[12] = 0x08;
    p[13] = 0x00;
    p[14] = 0x45;
    p[15] = tos;
    put16(p + 16, htons(40));
    p[23] = proto;
    put32(p + 26, src);
    put32(p + 30, dst);
    if (proto == IPPROTO_UDP) {
        put16(p + 34, htons(1234));
        put16(p + 36, htons(4321));
        put16(p + 38, htons(20));
    } else if (proto == IPPROTO_TCP) {
        put16(p + 34, htons(1234));
        put16(p + 36, htons(4321));
    }
    return 54;
}

static size_t vxlan_packet(uint8_t *p, uint8_t tos, uint32_t src, uint32_t dst,
                           uint32_t outer_dst, uint16_t udp_port, uint32_t vni) {
    size_t n = plain_packet(p + 50, tos, IPPROTO_UDP, src, dst);
    memset(p, 0, 50);
    memset(p, 0x33, 6);
    memset(p + 6, 0x44, 6);
    p[12] = 0x08;
    p[13] = 0x00;
    p[14] = 0x45;
    put16(p + 16, htons((uint16_t)(20 + 8 + 8 + 14 + 20 + 20)));
    p[23] = IPPROTO_UDP;
    put32(p + 26, ip4(192, 168, 1, 1));
    put32(p + 30, outer_dst);
    put16(p + 34, htons(udp_port));
    put16(p + 36, htons(udp_port));
    put16(p + 38, htons((uint16_t)(8 + 8 + 14 + 20 + 20)));
    p[42] = 0x08;
    p[46] = (uint8_t)(vni >> 16);
    p[47] = (uint8_t)(vni >> 8);
    p[48] = (uint8_t)vni;
    p[50] = 0x33;
    p[56] = 0x44;
    return n + 50;
}

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static int load_env(const char *path, struct env *e) {
    memset(e, 0, sizeof(*e));
    e->obj = bpf_object__open_file(path, NULL);
    if (!e->obj || libbpf_get_error(e->obj)) return 1;
    struct bpf_program *prog;
    bpf_object__for_each_program(prog, e->obj)
        bpf_program__set_type(prog, BPF_PROG_TYPE_SCHED_CLS);
    if (bpf_object__load(e->obj)) return 1;
#define MAP_FD(name) bpf_map__fd(bpf_object__find_map_by_name(e->obj, name))
    e->control = MAP_FD("control_map");
    e->policy = MAP_FD("policy_cache");
    e->egressip = MAP_FD("egressip_cache");
    e->egress = MAP_FD("egress_cache");
    e->ingress = MAP_FD("ingress_cache");
    e->devmap = MAP_FD("devmap");
#undef MAP_FD
    return check(e->control >= 0 && e->policy >= 0 && e->egressip >= 0 &&
                 e->egress >= 0 && e->ingress >= 0 && e->devmap >= 0,
                 "required maps loaded");
}

static void close_env(struct env *e) {
    if (e->obj) bpf_object__close(e->obj);
}

static int control_with_vxlan(struct env *e, uint32_t enabled, uint32_t flags,
                              uint64_t heartbeat, uint64_t timeout,
                              uint32_t vni, uint16_t udp_port) {
    struct oncache_control_v1 value = {
        .abi_version = ONCACHE_ABI_VERSION,
        .enabled = enabled,
        .heartbeat_ns = heartbeat,
        .heartbeat_timeout_ns = timeout,
        .flags = flags | ((uint32_t)udp_port << ONCACHE_CONTROL_VXLAN_UDP_SHIFT),
        .reserved = vni,
    };
    uint32_t key = 0;
    return bpf_map_update_elem(e->control, &key, &value, BPF_ANY);
}

static int control(struct env *e, uint32_t enabled, uint32_t flags,
                   uint64_t heartbeat, uint64_t timeout) {
    return control_with_vxlan(e, enabled, flags, heartbeat, timeout,
                              VXLAN_TEST_VNI, VXLAN_TEST_PORT);
}

static struct bpf_program *program(struct env *e, const char *name) {
    struct bpf_program *prog = bpf_object__find_program_by_name(e->obj, name);
    if (!prog) fprintf(stderr, "program not found: %s\n", name);
    return prog;
}

static int run(struct bpf_program *prog, const uint8_t *packet, size_t len,
               uint32_t ifindex, uint8_t *output) {
    if (!prog) return -1;
    struct __sk_buff ctx = {.ifindex = ifindex};
    struct bpf_test_run_opts opts = {
        .sz = sizeof(opts), .data_in = packet, .data_size_in = len,
        .data_out = output, .data_size_out = PACKET_MAX,
        .repeat = 1,
        .ctx_in = &ctx, .ctx_size_in = sizeof(ctx),
    };
    int err = bpf_prog_test_run_opts(bpf_program__fd(prog), &opts);
    if (err) fprintf(stderr, "test_run: %s\n", strerror(errno));
    return err ? -1 : (int)opts.retval;
}

static int all_programs(struct env *e, const uint8_t *packet, size_t len,
                        int expected, int unchanged) {
    const char *names[] = {"tc_init_e", "tc_masq",
                           "tc_restore", "tc_init_in"};
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        uint8_t output[PACKET_MAX] = {};
        int ret = run(program(e, names[i]), packet, len, IF_IN, output);
        if (check(ret == expected, names[i])) return 1;
        if (unchanged && check(!memcmp(packet, output, len), "packet unchanged")) return 1;
    }
    return 0;
}

static int control_tests(const char *path) {
    struct env e;
    uint8_t packet[PACKET_MAX];
    size_t len = plain_packet(packet, 0xa0, IPPROTO_UDP, IP_A, IP_B);
    if (load_env(path, &e)) return 1;
    uint32_t key = 0;
    struct oncache_control_v1 zero = {};
    if (bpf_map_update_elem(e.control, &key, &zero, BPF_ANY) ||
        all_programs(&e, packet, len, TC_ACT_OK, 1)) return 1;
    if (control(&e, 0, 0, now_ns(), 1000000000ULL) || all_programs(&e, packet, len, TC_ACT_OK, 1) ||
        control(&e, 1, ONCACHE_CONTROL_FLAG_FORCE_PASS, now_ns(), 1000000000ULL) ||
        all_programs(&e, packet, len, TC_ACT_OK, 1) ||
        control(&e, 1, 0, now_ns() - 2000000000ULL, 1000000000ULL) ||
        all_programs(&e, packet, len, TC_ACT_OK, 1)) return 1;
    struct oncache_control_v1 bad = {.abi_version = 2, .enabled = 1};
    if (bpf_map_update_elem(e.control, &key, &bad, BPF_ANY) ||
        all_programs(&e, packet, len, TC_ACT_OK, 1)) return 1;
    close_env(&e);
    return 0;
}

static int malformed_tests(const char *path) {
    struct env e;
    uint8_t packet[PACKET_MAX], output[PACKET_MAX];
    size_t len = vxlan_packet(packet, 0, IP_A, IP_B, IP_NODE,
                              VXLAN_TEST_PORT, VXLAN_TEST_VNI);
    if (load_env(path, &e) || control(&e, 1, ONCACHE_CONTROL_FLAG_DEBUG_COUNTERS, 0, UINT64_MAX)) return 1;
    const char *vxlan_programs[] = {"tc_init_e", "tc_restore"};
    for (size_t p = 0; p < 2; p++) {
        for (size_t cut = 34; cut < len; cut += 7) {
            memcpy(output, packet, sizeof(output));
            int ret = run(program(&e, vxlan_programs[p]), packet, cut, IF_IN, output);
            if (ret != TC_ACT_OK || memcmp(packet, output, cut)) {
                fprintf(stderr, "FAIL: vxlan truncation cut=%zu ret=%d\n", cut, ret);
                return 1;
            }
        }
    }
    packet[14] = 0x46;
    packet[42] = 0;
    for (size_t p = 0; p < 2; p++)
        if (run(program(&e, vxlan_programs[p]), packet, len, IF_IN, output) != TC_ACT_OK) return 1;
    packet[14] = 0x45;
    packet[20] = 0x20;
    for (size_t p = 0; p < 2; p++)
        if (run(program(&e, vxlan_programs[p]), packet, len, IF_IN, output) != TC_ACT_OK) return 1;
    len = plain_packet(packet, 0, IPPROTO_UDP, IP_A, IP_B);
    const char *plain_programs[] = {"tc_masq", "tc_init_in"};
    for (size_t p = 0; p < 2; p++) {
        for (size_t cut = 34; cut < len; cut += 7) {
            memcpy(output, packet, sizeof(output));
            int ret = run(program(&e, plain_programs[p]), packet, cut, IF_IN, output);
            if (ret != TC_ACT_OK || memcmp(packet, output, cut)) {
                fprintf(stderr, "FAIL: plain truncation cut=%zu ret=%d\n", cut, ret);
                return 1;
            }
        }
    }
    close_env(&e);
    return 0;
}

static int seed_hit(struct env *e, uint32_t current, uint16_t udp_port, uint32_t vni) {
    struct oncache_flow_v1 flow = {.local_addr = IP_A, .remote_addr = IP_B,
                                   .local_port = htons(1234), .remote_port = htons(4321),
                                   .protocol = IPPROTO_UDP};
    struct oncache_action_v1 action = {.ingress_ready = 1, .egress_ready = 1};
    struct oncache_ingress_v1 ingress = {.ifindex = IF_OUT};
    struct oncache_egress_v1 egress = {.ifindex = IF_OUT};
    struct oncache_device_v1 device = {.ipv4 = IP_NODE};
    uint8_t outer[PACKET_MAX];
    memset(ingress.dst_mac, 0x55, sizeof(ingress.dst_mac));
    memset(ingress.src_mac, 0x66, sizeof(ingress.src_mac));
    vxlan_packet(outer, 0, IP_A, IP_B, IP_NODE, udp_port, vni);
    memcpy(egress.outer_header, outer, sizeof(egress.outer_header));
    memset(device.mac, 0x33, sizeof(device.mac));
    uint32_t node = IP_NODE, source = IP_A, target = IP_B;
    uint32_t local = IP_B;
    struct oncache_flow_v1 reverse = {.local_addr = IP_B, .remote_addr = IP_A,
                                      .local_port = htons(4321), .remote_port = htons(1234),
                                      .protocol = IPPROTO_UDP};
    return bpf_map_update_elem(e->policy, &flow, &action, BPF_ANY) ||
           bpf_map_update_elem(e->policy, &reverse, &action, BPF_ANY) ||
           bpf_map_update_elem(e->egressip, &target, &node, BPF_ANY) ||
           bpf_map_update_elem(e->egressip, &source, &node, BPF_ANY) ||
           bpf_map_update_elem(e->egress, &node, &egress, BPF_ANY) ||
           bpf_map_update_elem(e->ingress, &source, &ingress, BPF_ANY) ||
           bpf_map_update_elem(e->ingress, &local, &ingress, BPF_ANY) ||
           bpf_map_update_elem(e->devmap, &current, &device, BPF_ANY);
}

static int learn_hit_tests(const char *path) {
    struct env e;
    uint8_t packet[PACKET_MAX], output[PACKET_MAX];
    size_t len = vxlan_packet(packet, 0x0c, IP_A, IP_B, IP_NODE,
                              VXLAN_TEST_PORT, VXLAN_TEST_VNI);
    if (load_env(path, &e) || control(&e, 1, 0, 0, UINT64_MAX)) return 1;
    uint32_t known_remote = IP_B, known_node = IP_NODE;
    if (bpf_map_update_elem(e.egressip, &known_remote, &known_node, BPF_ANY)) return 1;
    if (run(program(&e, "tc_init_e"), packet, len, IF_IN, output) != TC_ACT_OK) return 1;
    struct oncache_flow_v1 flow = {.local_addr = IP_A, .remote_addr = IP_B,
                                   .local_port = htons(1234), .remote_port = htons(4321),
                                   .protocol = IPPROTO_UDP};
    struct oncache_action_v1 action = {};
    uint32_t node = IP_NODE, target = IP_B;
    int policy_rc = bpf_map_lookup_elem(e.policy, &flow, &action);
    int egressip_rc = bpf_map_lookup_elem(e.egressip, &target, &node);
    if (policy_rc || !action.egress_ready || egressip_rc) {
        fprintf(stderr, "FAIL: egress learning maps policy=%d egressip=%d ready=%u\n",
                policy_rc, egressip_rc, action.egress_ready);
        return 1;
    }
    len = plain_packet(packet, 0x0c, IPPROTO_UDP, IP_B, IP_A);
    struct oncache_ingress_v1 ingress = {.ifindex = IF_OUT};
    memset(ingress.dst_mac, 0x55, sizeof(ingress.dst_mac));
    memset(ingress.src_mac, 0x66, sizeof(ingress.src_mac));
    uint32_t local = IP_A;
    if (bpf_map_update_elem(e.ingress, &local, &ingress, BPF_ANY) ||
        run(program(&e, "tc_init_in"), packet, len, IF_IN, output) != TC_ACT_OK) {
        fprintf(stderr, "FAIL: ingress learning\n");
        return 1;
    }
    len = plain_packet(packet, 0xa0, IPPROTO_UDP, IP_A, IP_B);
    if (run(program(&e, "tc_masq"), packet, len, IF_IN, output) != TC_ACT_OK ||
        output[15] != 0xa0) {
        fprintf(stderr, "FAIL: fallback changed TOS\n");
        return 1;
    }
    if (seed_hit(&e, IF_IN, VXLAN_TEST_PORT, VXLAN_TEST_VNI)) {
        fprintf(stderr, "FAIL: hit map seed\n");
        return 1;
    }
    len = plain_packet(packet, 0xa0, IPPROTO_UDP, IP_A, IP_B);
    if (run(program(&e, "tc_masq"), packet, len, IF_IN, output) != TC_ACT_REDIRECT) {
        fprintf(stderr, "FAIL: masq hit\n");
        return 1;
    }
    len = vxlan_packet(packet, 0, IP_A, IP_B, IP_NODE,
                       VXLAN_TEST_PORT, VXLAN_TEST_VNI);
    int restore_ret = run(program(&e, "tc_restore"), packet, len, IF_IN, output);
    if (restore_ret != TC_ACT_REDIRECT) {
        fprintf(stderr, "FAIL: restore hit ret=%d\n", restore_ret);
        return 1;
    }
    close_env(&e);
    return 0;
}

static int leading_zero_mac_tests(const char *path) {
    struct env e;
    uint8_t packet[PACKET_MAX], output[PACKET_MAX];
    if (load_env(path, &e) || control(&e, 1, 0, 0, UINT64_MAX) ||
        seed_hit(&e, IF_IN, VXLAN_TEST_PORT, VXLAN_TEST_VNI)) return 1;

    size_t len = plain_packet(packet, 0x0c, IPPROTO_UDP, IP_B, IP_A);
    packet[6] = 0;
    if (run(program(&e, "tc_init_in"), packet, len, IF_IN, output) != TC_ACT_OK) {
        fprintf(stderr, "FAIL: leading-zero ingress learning for tc_masq\n");
        return 1;
    }
    len = plain_packet(packet, 0x0c, IPPROTO_UDP, IP_A, IP_B);
    packet[6] = 0;
    if (run(program(&e, "tc_init_in"), packet, len, IF_IN, output) != TC_ACT_OK) {
        fprintf(stderr, "FAIL: leading-zero ingress learning for tc_restore\n");
        return 1;
    }

    uint32_t keys[] = {IP_A, IP_B};
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
        struct oncache_ingress_v1 ingress = {};
        if (bpf_map_lookup_elem(e.ingress, &keys[i], &ingress) ||
            ingress.src_mac[0] != 0 || ingress.src_mac[1] == 0) {
            fprintf(stderr, "FAIL: leading-zero MAC was not learned\n");
            return 1;
        }
    }

    len = plain_packet(packet, 0xa0, IPPROTO_UDP, IP_A, IP_B);
    if (run(program(&e, "tc_masq"), packet, len, IF_IN, output) != TC_ACT_REDIRECT) {
        fprintf(stderr, "FAIL: masq rejected leading-zero MAC\n");
        return 1;
    }
    len = vxlan_packet(packet, 0, IP_A, IP_B, IP_NODE,
                       VXLAN_TEST_PORT, VXLAN_TEST_VNI);
    if (run(program(&e, "tc_restore"), packet, len, IF_IN, output) != TC_ACT_REDIRECT) {
        fprintf(stderr, "FAIL: restore rejected leading-zero MAC\n");
        return 1;
    }

    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
        struct oncache_ingress_v1 ingress = {};
        if (bpf_map_lookup_elem(e.ingress, &keys[i], &ingress)) return 1;
        memset(ingress.src_mac, 0, sizeof(ingress.src_mac));
        if (bpf_map_update_elem(e.ingress, &keys[i], &ingress, BPF_ANY)) return 1;
    }
    len = plain_packet(packet, 0, IPPROTO_UDP, IP_A, IP_B);
    memcpy(output, packet, sizeof(output));
    if (run(program(&e, "tc_masq"), packet, len, IF_IN, output) != TC_ACT_OK ||
        memcmp(packet, output, len) != 0) {
        fprintf(stderr, "FAIL: all-zero MAC did not preserve masq fallback\n");
        return 1;
    }
    len = vxlan_packet(packet, 0, IP_A, IP_B, IP_NODE,
                       VXLAN_TEST_PORT, VXLAN_TEST_VNI);
    memcpy(output, packet, sizeof(output));
    if (run(program(&e, "tc_restore"), packet, len, IF_IN, output) != TC_ACT_OK ||
        memcmp(packet, output, len) != 0) {
        fprintf(stderr, "FAIL: all-zero MAC did not preserve restore fallback\n");
        return 1;
    }

    close_env(&e);
    return 0;
}

static int vxlan_validation_tests(const char *path) {
    struct env e;
    uint8_t packet[PACKET_MAX], output[PACKET_MAX];
    uint32_t known_remote = IP_B, known_node = IP_NODE;
    uint32_t cache_key = IP_NODE;

    if (load_env(path, &e) || control(&e, 1, 0, 0, UINT64_MAX)) return 1;
    if (bpf_map_update_elem(e.egressip, &known_remote, &known_node, BPF_ANY)) return 1;

    size_t len = vxlan_packet(packet, 0, IP_A, IP_B, IP_NODE,
                              4789, VXLAN_TEST_VNI);
    if (run(program(&e, "tc_init_e"), packet, len, IF_IN, output) != TC_ACT_OK) {
        fprintf(stderr, "FAIL: wrong VXLAN port changed return action\n");
        return 1;
    }
    struct oncache_egress_v1 cached = {};
    if (bpf_map_lookup_elem(e.egress, &cache_key, &cached) == 0) {
        fprintf(stderr, "FAIL: wrong VXLAN port was learned\n");
        return 1;
    }

    len = vxlan_packet(packet, 0, IP_A, IP_B, IP_NODE,
                       VXLAN_TEST_PORT, 2);
    if (run(program(&e, "tc_init_e"), packet, len, IF_IN, output) != TC_ACT_OK ||
        bpf_map_lookup_elem(e.egress, &cache_key, &cached) == 0) {
        fprintf(stderr, "FAIL: wrong VXLAN VNI was learned\n");
        return 1;
    }

    if (seed_hit(&e, IF_IN, VXLAN_TEST_PORT, VXLAN_TEST_VNI)) return 1;
    len = vxlan_packet(packet, 0, IP_A, IP_B, IP_NODE, 4789, VXLAN_TEST_VNI);
    memcpy(output, packet, sizeof(output));
    if (run(program(&e, "tc_restore"), packet, len, IF_IN, output) != TC_ACT_OK ||
        memcmp(packet, output, len) != 0) {
        fprintf(stderr, "FAIL: wrong VXLAN port was restored\n");
        return 1;
    }

    len = vxlan_packet(packet, 0, IP_A, IP_B, IP_NODE, VXLAN_TEST_PORT, 2);
    memcpy(output, packet, sizeof(output));
    if (run(program(&e, "tc_restore"), packet, len, IF_IN, output) != TC_ACT_OK ||
        memcmp(packet, output, len) != 0) {
        fprintf(stderr, "FAIL: wrong VXLAN VNI was restored\n");
        return 1;
    }

    if (seed_hit(&e, IF_IN, 4789, VXLAN_TEST_VNI)) return 1;
    len = plain_packet(packet, 0, IPPROTO_UDP, IP_A, IP_B);
    memcpy(output, packet, sizeof(output));
    if (run(program(&e, "tc_masq"), packet, len, IF_IN, output) != TC_ACT_OK ||
        memcmp(packet, output, len) != 0) {
        fprintf(stderr, "FAIL: stale wrong-port cache was encapsulated\n");
        return 1;
    }

    close_env(&e);
    return 0;
}

static void *race_run(void *arg) {
    struct race_arg *a = arg;
    uint8_t output[PACKET_MAX];
    a->error = run(a->prog, a->packet, a->len, a->ifindex, output) < 0;
    return NULL;
}

static int ready_race(const char *path) {
    struct env e;
    if (load_env(path, &e) || control(&e, 1, 0, 0, UINT64_MAX)) return 1;
    uint32_t known_remote = IP_B, known_node = IP_NODE;
    if (bpf_map_update_elem(e.egressip, &known_remote, &known_node, BPF_ANY)) return 1;
    uint8_t egress[PACKET_MAX], ingress[PACKET_MAX];
    size_t elen = vxlan_packet(egress, 0x0c, IP_A, IP_B, IP_NODE,
                               VXLAN_TEST_PORT, VXLAN_TEST_VNI);
    size_t ilen = plain_packet(ingress, 0x0c, IPPROTO_UDP, IP_B, IP_A);
    put16(ingress + 34, htons(4321));
    put16(ingress + 36, htons(1234));
    struct oncache_ingress_v1 info = {.ifindex = IF_OUT};
    uint32_t local = IP_A;
    memset(info.dst_mac, 0x55, sizeof(info.dst_mac));
    memset(info.src_mac, 0x66, sizeof(info.src_mac));
    if (bpf_map_update_elem(e.ingress, &local, &info, BPF_ANY)) return 1;
    enum { N = 8 };
    pthread_t threads[N];
    struct race_arg args[N];
    for (int i = 0; i < N; i++) {
        args[i].prog = program(&e, i & 1 ? "tc_init_in" : "tc_init_e");
        memcpy(args[i].packet, i & 1 ? ingress : egress, PACKET_MAX);
        args[i].len = i & 1 ? ilen : elen;
        args[i].ifindex = IF_IN;
        if (pthread_create(&threads[i], NULL, race_run, &args[i])) return 1;
    }
    for (int i = 0; i < N; i++) pthread_join(threads[i], NULL);
    struct oncache_flow_v1 flow = {.local_addr = IP_A, .remote_addr = IP_B,
                                   .local_port = htons(1234), .remote_port = htons(4321),
                                   .protocol = IPPROTO_UDP};
    struct oncache_action_v1 action = {};
    int failed = 0;
    for (int i = 0; i < N; i++) failed |= args[i].error;
    failed |= bpf_map_lookup_elem(e.policy, &flow, &action);
    failed |= check(action.ingress_ready == 1 && action.egress_ready == 1,
                    "ready bits preserved under concurrency");
    close_env(&e);
    return failed;
}

static int fallback_icmp_tests(const char *path) {
    struct env e;
    uint8_t packet[PACKET_MAX], output[PACKET_MAX];
    size_t len = plain_packet(packet, 0, IPPROTO_ICMP, IP_A, IP_B);
    if (load_env(path, &e) || control(&e, 1, 0, 0, UINT64_MAX)) return 1;
    int ret = run(program(&e, "tc_masq"), packet, len, IF_IN, output);
    int failed = check(ret == TC_ACT_OK, "ICMP fallback return") ||
                 check(output[15] == 0, "ICMP fallback preserves TOS") ||
                 check(!memcmp(packet, output, len), "ICMP fallback preserves packet");
    close_env(&e);
    return failed;
}

static int fault_tests(const char *path, const char *kind) {
    struct env e;
    uint8_t packet[PACKET_MAX], output[PACKET_MAX];
    size_t len = plain_packet(packet, 0, IPPROTO_UDP, IP_A, IP_B);
    if (load_env(path, &e) || control(&e, 1, 0, 0, UINT64_MAX) ||
        seed_hit(&e, IF_IN, VXLAN_TEST_PORT, VXLAN_TEST_VNI)) return 1;
    int ret = run(program(&e, "tc_masq"), packet, len, IF_IN, output);
    int expected = !strcmp(kind, "adjust") ? TC_ACT_OK : TC_ACT_SHOT;
    int failed = check(ret == expected, kind);
    close_env(&e);
    return failed;
}

int main(int argc, char **argv) {
    if (argc != 5) {
        fprintf(stderr, "usage: %s normal adjust store redirect\n", argv[0]);
        return 2;
    }
    puts("control");
    if (control_tests(argv[1])) return 1;
    puts("malformed");
    if (malformed_tests(argv[1])) return 1;
    puts("learn-hit");
    if (learn_hit_tests(argv[1])) return 1;
    puts("leading-zero-mac");
    if (leading_zero_mac_tests(argv[1])) return 1;
    puts("vxlan-validation");
    if (vxlan_validation_tests(argv[1])) return 1;
    puts("icmp-fallback");
    if (fallback_icmp_tests(argv[1])) return 1;
    puts("ready-race");
    if (ready_race(argv[1])) return 1;
    puts("helper-faults");
    if (fault_tests(argv[2], "adjust") || fault_tests(argv[3], "store") ||
        fault_tests(argv[4], "redirect")) return 1;
    puts("M1.13 BPF behavior tests: PASS");
    return 0;
}
