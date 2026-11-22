#include "spectre_events.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32); /* IPv4 address in network byte order */
    __type(value, __u32);
} xdp_blocklist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct spectre_xdp_rl_config);
} xdp_rl_config SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);
    __type(value, struct spectre_xdp_bucket);
} xdp_token_buckets SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, XDP_STAT_MAX);
    __type(key, __u32);
    __type(value, __u64);
} xdp_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 262144);
} xdp_events SEC(".maps");

SPECTRE_INLINE void bump_stat(__u32 idx, __u64 delta)
{
    __u64 *cnt = bpf_map_lookup_elem(&xdp_stats, &idx);
    if (cnt) {
        *cnt += delta;
    }
}

SPECTRE_INLINE void emit_xdp_drop_event(__u32 saddr, __u32 daddr, __u16 sport, __u16 dport,
                                                __u8 proto, __u8 reason, __u16 pkt_len)
{
    struct spectre_xdp_event *evt = bpf_ringbuf_reserve(&xdp_events, sizeof(*evt), 0);
    if (!evt) {
        return;
    }
    evt->ts_ns = bpf_ktime_get_ns();
    evt->src_ipv4 = saddr;
    evt->dst_ipv4 = daddr;
    evt->src_port = sport;
    evt->dst_port = dport;
    evt->proto = proto;
    evt->reason = reason;
    evt->pkt_len = pkt_len;
    bpf_ringbuf_submit(evt, 0);
}

SEC("xdp")
int xdp_spectre_fw(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u16 pkt_len = (__u16)((long)data_end - (long)data);

    bump_stat(XDP_STAT_RX_PACKETS, 1);
    bump_stat(XDP_STAT_RX_BYTES, pkt_len);

    struct spectre_ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        bump_stat(XDP_STAT_DROP_MALFORMED, 1);
        return XDP_DROP;
    }

    __u16 eth_proto = bpf_ntohs(eth->h_proto);
    void *nh = (void *)(eth + 1);

    /* Bounded 2-tag 802.1Q / 802.1ad VLAN unwrapping */
#pragma unroll
    for (int i = 0; i < 2; i++) {
        if (eth_proto == ETH_P_8021Q || eth_proto == ETH_P_8021AD) {
            struct spectre_vlan_hdr *vh = nh;
            if ((void *)(vh + 1) > data_end) {
                bump_stat(XDP_STAT_DROP_MALFORMED, 1);
                return XDP_DROP;
            }
            eth_proto = bpf_ntohs(vh->h_vlan_encapsulated_proto);
            nh = (void *)(vh + 1);
        }
    }

    __u32 saddr_key = 0;
    __u32 daddr_v4 = 0;
    __u8 l4_proto = 0;
    void *l4 = 0;

    if (eth_proto == ETH_P_IP) {
        struct spectre_iphdr *iph = nh;
        if ((void *)(iph + 1) > data_end) {
            bump_stat(XDP_STAT_DROP_MALFORMED, 1);
            return XDP_DROP;
        }
        __u32 ihl = (__u32)(iph->ihl_ver & 0x0FU) * 4U;
        if (ihl < 20U || ihl > 60U) {
            bump_stat(XDP_STAT_DROP_MALFORMED, 1);
            return XDP_DROP;
        }
        if ((void *)iph + ihl > data_end) {
            bump_stat(XDP_STAT_DROP_MALFORMED, 1);
            return XDP_DROP;
        }
        saddr_key = iph->saddr;
        daddr_v4 = iph->daddr;
        l4_proto = iph->protocol;
        l4 = (void *)iph + ihl;
    } else if (eth_proto == ETH_P_IPV6) {
        struct spectre_ipv6hdr *ip6 = nh;
        if ((void *)(ip6 + 1) > data_end) {
            bump_stat(XDP_STAT_DROP_MALFORMED, 1);
            return XDP_DROP;
        }
        /* Hash IPv6 source /64 prefix into rate-limit key */
        __u32 hi0 = 0;
        __u32 hi1 = 0;
        __builtin_memcpy(&hi0, &ip6->saddr[0], 4);
        __builtin_memcpy(&hi1, &ip6->saddr[4], 4);
        saddr_key = hi0 ^ hi1;
        l4_proto = ip6->nexthdr;
        l4 = (void *)(ip6 + 1);
    } else {
        bump_stat(XDP_STAT_PASS, 1);
        return XDP_PASS;
    }

    __u16 sport = 0;
    __u16 dport = 0;
    __u8 is_tcp_syn = 0;

    if (l4_proto == IPPROTO_TCP) {
        struct spectre_tcphdr *tcph = l4;
        if ((void *)(tcph + 1) > data_end) {
            bump_stat(XDP_STAT_DROP_MALFORMED, 1);
            return XDP_DROP;
        }
        sport = bpf_ntohs(tcph->source);
        dport = bpf_ntohs(tcph->dest);
        __u16 tcp_flags = bpf_ntohs(tcph->flags);
        /* SYN bit = 0x0002, ACK bit = 0x0010 */
        if ((tcp_flags & 0x0012U) == 0x0002U) {
            is_tcp_syn = 1;
        }
    } else if (l4_proto == IPPROTO_UDP) {
        struct spectre_udphdr *udph = l4;
        if ((void *)(udph + 1) > data_end) {
            bump_stat(XDP_STAT_DROP_MALFORMED, 1);
            return XDP_DROP;
        }
        sport = bpf_ntohs(udph->source);
        dport = bpf_ntohs(udph->dest);
    }

    /* 1. Explicit blocklist lookup */
    __u32 *blocked = bpf_map_lookup_elem(&xdp_blocklist, &saddr_key);
    if (blocked && *blocked != 0U) {
        bump_stat(XDP_STAT_DROP_BLOCKLIST, 1);
        if (*blocked == 1U) {
            *blocked = 2U; /* Emit ringbuf event on first block hit */
            emit_xdp_drop_event(saddr_key, daddr_v4, sport, dport, l4_proto, XDP_REASON_BLOCKLIST,
                                pkt_len);
        }
        return XDP_DROP;
    }

    /* 2. Per-CPU Lock-Free Token Bucket Rate Limiter */
    __u32 cfg_key = 0;
    struct spectre_xdp_rl_config *cfg = bpf_map_lookup_elem(&xdp_rl_config, &cfg_key);
    if (cfg && cfg->enabled != 0U) {
        if (cfg->syn_only == 0U || is_tcp_syn != 0U) {
            __u64 now = bpf_ktime_get_ns();
            __u64 cap_scaled = cfg->burst_tokens << 10;
            struct spectre_xdp_bucket *b = bpf_map_lookup_elem(&xdp_token_buckets, &saddr_key);
            if (!b) {
                struct spectre_xdp_bucket init_b = {
                    .tokens_scaled = cap_scaled > 1024ULL ? cap_scaled - 1024ULL : 0ULL,
                    .last_ns = now,
                    .in_drop_state = 0U,
                    ._pad = 0U,
                };
                bpf_map_update_elem(&xdp_token_buckets, &saddr_key, &init_b, BPF_ANY);
            } else {
                __u64 elapsed = now > b->last_ns ? (now - b->last_ns) : 0ULL;
                /* Cap elapsed to 4 seconds to avoid 64-bit multiplication overflow */
                if (elapsed > 4000000000ULL) {
                    elapsed = 4000000000ULL;
                }
                __u64 added = cfg->rate_tokens_per_sec <= 10000000ULL
                    ? (elapsed * cfg->rate_tokens_per_sec) / 976562ULL
                    : (elapsed / 1000ULL) * (cfg->rate_tokens_per_sec / 976ULL);
                __u64 tokens = b->tokens_scaled + added;
                if (tokens > cap_scaled) {
                    tokens = cap_scaled;
                }
                b->last_ns = now;
                if (tokens >= 1024ULL) {
                    b->tokens_scaled = tokens - 1024ULL;
                    b->in_drop_state = 0U;
                } else {
                    b->tokens_scaled = tokens;
                    bump_stat(XDP_STAT_DROP_RATELIMIT, 1);
                    if (b->in_drop_state == 0U) {
                        b->in_drop_state = 1U;
                        emit_xdp_drop_event(saddr_key, daddr_v4, sport, dport, l4_proto,
                                            XDP_REASON_RATELIMIT, pkt_len);
                    }
                    return XDP_DROP;
                }
            }
        }
    }

    bump_stat(XDP_STAT_PASS, 1);
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
