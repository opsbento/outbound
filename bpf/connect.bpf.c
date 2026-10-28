// SPDX-License-Identifier: GPL-2.0-only

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define OUTBOUND_SOCK_DGRAM 2
#define MAX_RULE_PORTS 16

struct port_set {
    __u32 count; // Zero means all ports.
    __u16 ports[MAX_RULE_PORTS];
};

struct dns_permission {
    __u64 expiry;
    struct port_set ports;
};

struct dns_suffix_hash {
    __u64 first;
    __u64 second;
};

struct dns_name {
    __u64 expiry;
    __u64 observed_at;
    struct dns_suffix_hash hash;
    __u32 length;
    __u32 ambiguous;
    __u8 wire[128];
};

struct destination_key {
    __u8 family;
    __u8 protocol;
    __u16 port;
    __u8 address[16];
};

struct observation {
    __u64 timestamp;
    __u32 allowed;
    __u32 pad;
};

struct policy_control {
    __u32 enforce;
    __u32 slot;
    __u32 cover_all_udp;
};

struct ipv4_key {
    __u32 prefixlen;
    __u8 address[4];
};

struct ipv6_key {
    __u32 prefixlen;
    __u8 address[16];
};

struct dns_ipv6_key {
    __u8 address[16];
};

struct wildcard_scan {
    struct __sk_buff *skb;
    __u32 start;
    __u32 length;
    __u64 label_bits_low;
    __u64 label_bits_high;
    struct dns_suffix_hash hash;
    __u8 matched;
    struct port_set ports;
};

struct answer_scan {
    struct __sk_buff *skb;
    __u32 offset;
    struct port_set ports;
    __u32 matched;
    struct dns_name name;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, struct dns_suffix_hash);
    __type(value, struct port_set);
} dns_wildcards SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, struct dns_suffix_hash);
    __type(value, struct port_set);
} dns_exact SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, struct dns_permission);
} dns_ipv4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, struct dns_ipv6_key);
    __type(value, struct dns_permission);
} dns_ipv6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, struct dns_name);
} dns_names_ipv4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, struct dns_ipv6_key);
    __type(value, struct dns_name);
} dns_names_ipv6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, struct destination_key);
    __type(value, struct observation);
} destinations SEC(".maps");

#define POLICY_MAP(name, key_type) \
struct { \
    __uint(type, BPF_MAP_TYPE_LPM_TRIE); \
    __uint(max_entries, 4096); \
    __uint(map_flags, BPF_F_NO_PREALLOC); \
    __type(key, key_type); \
    __type(value, struct port_set); \
} name SEC(".maps")

POLICY_MAP(ipv4_policy_0, struct ipv4_key);
POLICY_MAP(ipv4_policy_1, struct ipv4_key);
POLICY_MAP(ipv6_policy_0, struct ipv6_key);
POLICY_MAP(ipv6_policy_1, struct ipv6_key);

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct policy_control);
} control SEC(".maps");

static __always_inline int port_set_allows(const struct port_set *ports, __u16 port)
{
    if (!ports) return 0;
    if (ports->count == 0) return 1;
    for (int i = 0; i < MAX_RULE_PORTS; i++) {
        if (i >= ports->count) break;
        if (ports->ports[i] == port) return 1;
    }
    return 0;
}

static __always_inline int observe(struct bpf_sock_addr *ctx, __u8 family)
{
    __u16 port = bpf_ntohs(ctx->user_port);
    __u8 protocol;
    __u32 zero = 0;
    struct policy_control *policy = bpf_map_lookup_elem(&control, &zero);
    // TCP is always covered. UDP 443 is always covered; other UDP ports are
    // covered when the operator explicitly enables them in the policy.
    if (ctx->type == OUTBOUND_SOCK_DGRAM) {
        if (port != 443 && (!policy || !policy->cover_all_udp))
            return 1;
        protocol = 17;
    } else {
        // Connect hooks also see sockets created with protocol=0. Treat any
        // non-datagram connect as TCP so an unfamiliar type cannot bypass it.
        protocol = 6;
    }

    struct destination_key key = {};
    key.family = family;
    key.protocol = protocol;
    key.port = port;
    if (family == 4)
        __builtin_memcpy(key.address, &ctx->user_ip4, 4);
    else
        __builtin_memcpy(key.address, ctx->user_ip6, 16);

    // Loopback stays on this host. In particular, the local DNS stub sends
    // replies to an ephemeral port on 127.0.0.1; blocking those replies
    // prevents the daemon from resolving its own exact-domain policy.
    if (family == 4 && key.address[0] == 127)
        return 1;
    if (family == 6) {
        int loopback = key.address[15] == 1;
#pragma unroll
        for (int i = 0; i < 15; i++)
            loopback &= key.address[i] == 0;
        if (loopback)
            return 1;
    }

    int allowed = 0;
    if (family == 4) {
        struct ipv4_key lookup = {.prefixlen = 32};
        __builtin_memcpy(lookup.address, key.address, 4);
        struct port_set *ports = policy && policy->slot == 1
            ? bpf_map_lookup_elem(&ipv4_policy_1, &lookup)
            : bpf_map_lookup_elem(&ipv4_policy_0, &lookup);
        allowed = port_set_allows(ports, port);
        if (!allowed) {
            __u32 address;
            __builtin_memcpy(&address, key.address, 4);
            struct dns_permission *dns = bpf_map_lookup_elem(&dns_ipv4, &address);
            allowed = dns && dns->expiry > bpf_ktime_get_ns() && port_set_allows(&dns->ports, port);
        }
    } else {
        struct ipv6_key lookup = {.prefixlen = 128};
        __builtin_memcpy(lookup.address, key.address, 16);
        struct port_set *ports = policy && policy->slot == 1
            ? bpf_map_lookup_elem(&ipv6_policy_1, &lookup)
            : bpf_map_lookup_elem(&ipv6_policy_0, &lookup);
        allowed = port_set_allows(ports, port);
        if (!allowed) {
            struct dns_permission *dns = bpf_map_lookup_elem(&dns_ipv6, key.address);
            allowed = dns && dns->expiry > bpf_ktime_get_ns() && port_set_allows(&dns->ports, port);
        }
    }

    struct observation event = {.timestamp = bpf_ktime_get_ns(), .allowed = allowed};
    bpf_map_update_elem(&destinations, &key, &event, BPF_ANY);
    // A missing control entry must never turn an attached hook into allow-all.
    return policy && (!policy->enforce || allowed);
}

static __always_inline int read_byte(struct __sk_buff *skb, __u32 offset, __u8 *byte)
{
    return bpf_skb_load_bytes(skb, offset, byte, 1) == 0;
}

static __always_inline int skip_dns_name(struct __sk_buff *skb, __u32 *offset)
{
    __u32 pos = *offset;
    for (int i = 0; i < 32; i++) {
        __u8 length;
        if (!read_byte(skb, pos, &length))
            return 0;
        if ((length & 0xc0) == 0xc0) {
            __u8 next;
            if (!read_byte(skb, pos + 1, &next))
                return 0;
            *offset = pos + 2;
            return 1;
        }
        if (length & 0xc0)
            return 0;
        pos++;
        if (length == 0) {
            *offset = pos;
            return 1;
        }
        if (length > 63 || pos + length > skb->len)
            return 0;
        pos += length;
    }
    return 0;
}

static long hash_suffix_byte(__u64 index, void *data)
{
    struct wildcard_scan *scan = data;
    if (index >= scan->length)
        return 1;
    __u32 relative = scan->length - index - 1;
    __u8 byte;
    if (!read_byte(scan->skb, scan->start + relative, &byte))
        return 1;
    if (byte >= 'A' && byte <= 'Z')
        byte += 'a' - 'A';
    scan->hash.first = scan->hash.first * 131 + byte;
    scan->hash.second = scan->hash.second * 137 + byte;
    // Keep hashing the full query. A later, more specific suffix may replace
    // the ports selected by an earlier wildcard match.
    if (relative == 0) {
        struct port_set *ports = bpf_map_lookup_elem(&dns_exact, &scan->hash);
        if (ports) {
            scan->ports = *ports;
            scan->matched = 1;
            return 0;
        }
    } else if (relative < 128) {
        __u64 label_bit = relative < 64
            ? (scan->label_bits_low >> relative) & 1
            : (scan->label_bits_high >> (relative - 64)) & 1;
        if (label_bit) {
            struct port_set *ports = bpf_map_lookup_elem(&dns_wildcards, &scan->hash);
            if (ports) {
                scan->ports = *ports;
                scan->matched = 1;
                return 0;
            }
        }
    }
    return 0;
}

static __always_inline int parse_question(struct answer_scan *answer, __u32 start, __u32 *end)
{
    struct __sk_buff *skb = answer->skb;
    __u32 pos = start;
    struct wildcard_scan scan = {.skb = skb, .start = start};
    __u32 count = 0;
    for (int i = 0; i < 17; i++) {
        __u8 length;
        if (!read_byte(skb, pos, &length) || (length & 0xc0))
            return 0;
        if (length == 0) {
            *end = pos + 1;
            break;
        }
        if (i == 16)
            return 0;
        if (pos - start > 127 || pos + length + 1 > skb->len)
            return 0;
        __u32 relative = pos - start;
        if (relative < 64)
            scan.label_bits_low |= 1ULL << relative;
        else
            scan.label_bits_high |= 1ULL << (relative - 64);
        count = i + 1;
        pos += length + 1;
    }
    if (count == 0 || *end <= start)
        return 0;

    __u32 qname_length = *end - start;
    if (qname_length > sizeof(answer->name.wire))
        return 0;
    // The verifier needs a bounded, non-negative scalar at the helper call.
    qname_length &= 0xff;
    if (qname_length < 2)
        return 0;
    if (bpf_skb_load_bytes(skb, start, answer->name.wire, qname_length) != 0)
        return 0;
    scan.length = qname_length;
    if (bpf_loop(scan.length, hash_suffix_byte, &scan, 0) < 0)
        return 0;
    answer->name.length = qname_length;
    answer->name.hash = scan.hash;
    answer->matched = scan.matched;
    if (scan.matched) answer->ports = scan.ports;
    return 1;
}

static __always_inline int public_ipv4(const __u8 *ip)
{
    return ip[0] != 0 && ip[0] != 10 && ip[0] != 127 &&
           !(ip[0] == 100 && (ip[1] & 0xc0) == 64) &&
           !(ip[0] == 169 && ip[1] == 254) &&
           !(ip[0] == 172 && (ip[1] & 0xf0) == 16) &&
           !(ip[0] == 192 && ip[1] == 168) && ip[0] < 224;
}

static __always_inline int public_ipv6(const __u8 *ip)
{
    return (ip[0] & 0xe0) == 0x20; // IPv6 global unicast space.
}

static long learn_answer(__u64 index, void *data)
{
    struct answer_scan *scan = data;
    struct __sk_buff *skb = scan->skb;
    __u32 offset = scan->offset;
    if (!skip_dns_name(skb, &offset))
        return 1;
    __u8 record[10];
    if (bpf_skb_load_bytes(skb, offset, record, 10) != 0)
        return 1;
    __u32 length = ((__u32)record[8] << 8) | record[9];
    __u32 payload = offset + 10;
    if (payload + length > skb->len)
        return 1;
    __u32 ttl = ((__u32)record[4] << 24) | ((__u32)record[5] << 16) |
                ((__u32)record[6] << 8) | record[7];
    if (ttl > 3600)
        ttl = 3600;
    if (ttl && record[2] == 0 && record[3] == 1) {
        scan->name.observed_at = bpf_ktime_get_ns();
        scan->name.expiry = scan->name.observed_at + (__u64)ttl * 1000000000ULL;
        struct dns_permission permission = {
            .expiry = scan->name.expiry,
            .ports = scan->ports,
        };
        if (record[0] == 0 && record[1] == 1 && length == 4) {
            __u32 address;
            if (bpf_skb_load_bytes(skb, payload, &address, 4) == 0 &&
                public_ipv4((const __u8 *)&address)) {
                struct dns_name *old = bpf_map_lookup_elem(&dns_names_ipv4, &address);
                scan->name.ambiguous = old && old->expiry > bpf_ktime_get_ns() &&
                    (old->ambiguous || old->hash.first != scan->name.hash.first ||
                     old->hash.second != scan->name.hash.second);
                bpf_map_update_elem(&dns_names_ipv4, &address, &scan->name, BPF_ANY);
                if (scan->matched)
                    bpf_map_update_elem(&dns_ipv4, &address, &permission, BPF_ANY);
            }
        } else if (record[0] == 0 && record[1] == 28 && length == 16) {
            __u8 address[16];
            if (bpf_skb_load_bytes(skb, payload, address, 16) == 0 &&
                public_ipv6(address)) {
                struct dns_name *old = bpf_map_lookup_elem(&dns_names_ipv6, address);
                scan->name.ambiguous = old && old->expiry > bpf_ktime_get_ns() &&
                    (old->ambiguous || old->hash.first != scan->name.hash.first ||
                     old->hash.second != scan->name.hash.second);
                bpf_map_update_elem(&dns_names_ipv6, address, &scan->name, BPF_ANY);
                if (scan->matched)
                    bpf_map_update_elem(&dns_ipv6, address, &permission, BPF_ANY);
            }
        }
    }
    scan->offset = payload + length;
    return 0;
}

// Runs before the DNS reply reaches the socket. The learned IP is available
// to the connect hook without a userspace scheduling race or firewall rule.
SEC("cgroup_skb/ingress")
int observe_dns_reply(struct __sk_buff *skb)
{
    __u8 ip[40] = {};
    if (bpf_skb_load_bytes(skb, 0, ip, 40) != 0)
        return 1;
    __u32 udp;
    if ((ip[0] >> 4) == 4) {
        if (ip[9] != 17 || (ip[6] & 0x1f) || ip[7] ||
            !((ip[12] == 169 && ip[13] == 254 && ip[14] == 169 && ip[15] == 254) ||
              (ip[12] == 127 && ip[13] == 0 && ip[14] == 0 && ip[15] == 53)))
            return 1;
        udp = (ip[0] & 15) * 4;
        if (udp < 20)
            return 1;
    } else if ((ip[0] >> 4) == 6) {
        if (ip[6] != 17)
            return 1;
        __u8 metadata_middle = ip[12] | ip[13] | ip[14] | ip[15] |
                               ip[16] | ip[17] | ip[18] | ip[19] |
                               ip[20] | ip[21];
        __u8 loopback_prefix = ip[8] | ip[9] | ip[10] | ip[11] |
                               metadata_middle | ip[22];
        int metadata = ip[8] == 0xfd && ip[9] == 0x20 &&
                       ip[10] == 0 && ip[11] == 0xce &&
                       metadata_middle == 0 && ip[22] == 2 && ip[23] == 0x54;
        int loopback = loopback_prefix == 0 && ip[23] == 1;
        if (!metadata && !loopback)
            return 1;
        udp = 40;
    } else {
        return 1;
    }
    __u8 udp_header[8];
    if (bpf_skb_load_bytes(skb, udp, udp_header, 8) != 0 ||
        udp_header[0] != 0 || udp_header[1] != 53)
        return 1;
    __u32 dns = udp + 8;
    __u8 header[12];
    if (bpf_skb_load_bytes(skb, dns, header, 12) != 0 ||
        !(header[2] & 0x80) || (header[2] & 0x02) ||
        header[3] & 0x0f || header[4] != 0 || header[5] != 1 || header[6] != 0)
        return 1;
    __u32 answers = header[7];
    if (answers == 0 || answers > 16)
        return 1;
    __u32 question = dns + 12;
    __u32 offset = 0;
    struct answer_scan scan = {.skb = skb};
    if (!parse_question(&scan, question, &offset))
        return 1;
    __u8 query[4];
    if (bpf_skb_load_bytes(skb, offset, query, 4) != 0 || query[2] != 0 || query[3] != 1)
        return 1;
    scan.offset = offset + 4;
    bpf_loop(answers, learn_answer, &scan, 0);
    return 1;
}

SEC("cgroup/connect4")
int egress_connect4(struct bpf_sock_addr *ctx)
{
    return observe(ctx, 4);
}

SEC("cgroup/connect6")
int egress_connect6(struct bpf_sock_addr *ctx)
{
    return observe(ctx, 6);
}

SEC("cgroup/sendmsg4")
int egress_udp_sendmsg4(struct bpf_sock_addr *ctx)
{
    return observe(ctx, 4);
}

SEC("cgroup/sendmsg6")
int egress_udp_sendmsg6(struct bpf_sock_addr *ctx)
{
    return observe(ctx, 6);
}

char LICENSE[] SEC("license") = "GPL";
