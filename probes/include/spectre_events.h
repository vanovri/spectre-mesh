#ifndef SPECTRE_EVENTS_H
#define SPECTRE_EVENTS_H

#include "spectre_vmlinux.h"

/* XDP firewall stats indices (BPF_MAP_TYPE_PERCPU_ARRAY) */
#define XDP_STAT_RX_PACKETS      0U
#define XDP_STAT_RX_BYTES        1U
#define XDP_STAT_PASS            2U
#define XDP_STAT_DROP_RATELIMIT  3U
#define XDP_STAT_DROP_BLOCKLIST  4U
#define XDP_STAT_DROP_MALFORMED  5U
#define XDP_STAT_MAX             6U

/* XDP audit event reason codes */
#define XDP_REASON_RATELIMIT     1U
#define XDP_REASON_BLOCKLIST     2U
#define XDP_REASON_MALFORMED     3U

struct spectre_xdp_rl_config {
    __u64 rate_tokens_per_sec;
    __u64 burst_tokens;
    __u32 enabled;
    __u32 syn_only;
};

struct spectre_xdp_bucket {
    __u64 tokens_scaled; /* tokens * 1024 */
    __u64 last_ns;
    __u32 in_drop_state;
    __u32 _pad;
};

struct spectre_xdp_event {
    __u64 ts_ns;
    __u32 src_ipv4;
    __u32 dst_ipv4;
    __u16 src_port;
    __u16 dst_port;
    __u8 proto;
    __u8 reason;
    __u16 pkt_len;
};

/* TCP telemetry event kinds */
#define TCP_EVT_STATE      1U
#define TCP_EVT_RETRANSMIT 2U
#define TCP_EVT_RTT        3U

struct spectre_tcp_event {
    __u64 ts_ns;
    __u64 skaddr;
    __u32 pid;
    __u32 srtt_us;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8 kind;
    __u8 old_state;
    __u8 new_state;
    __u8 _pad;
};

/* L7 / TLS plaintext capture directions & sources */
#define L7_DIR_EGRESS  0U
#define L7_DIR_INGRESS 1U

#define L7_SRC_CLEARTEXT_SOCK 0U
#define L7_SRC_OPENSSL        1U
#define L7_SRC_GO_TLS         2U

#define L7_MAX_PAYLOAD 4096U

struct spectre_l7_event {
    __u64 ts_ns;
    __u64 conn_ptr;
    __u32 pid;
    __u32 tid;
    __s32 fd;
    __u32 payload_len;
    __u8 direction;
    __u8 tls_source;
    __u16 chunk_seq;
    __u8 comm[16];
    __u8 payload[L7_MAX_PAYLOAD];
};

struct spectre_pidns_cfg {
    __u64 dev;
    __u64 ino;
    __u32 enabled;
    __u32 _pad;
};

/* Verifier-friendly RingBuf submission with zero inner size-branch state explosion.
 * Passing constant 568B when `fast_small != 0` or full `sizeof(*evt)` otherwise. */
SPECTRE_INLINE void spectre_ringbuf_emit_sized(
    void *rb,
    void *drops_map,
    struct spectre_l7_event *evt,
    int fast_small
)
{
    long rc = fast_small
        ? bpf_ringbuf_output(rb, evt, 56U + 512U, 0)
        : bpf_ringbuf_output(rb, evt, sizeof(*evt), 0);
    if (rc != 0) {
        __u32 zero = 0;
        __u64 *cnt = bpf_map_lookup_elem(drops_map, &zero);
        if (cnt) {
            __sync_fetch_and_add(cnt, 1);
        }
    }
}

/* Shared multi-chunk L7/TLS plaintext emitter:
 * - Fast single-shot 568 B RingBuf path for payloads <= 512 B (29k+ capacity per 16 MB ring)
 * - Unrolled 8-chunk DAG path (up to 32 KB per call, zero loop verifier explosion) for large payloads */
SPECTRE_INLINE void spectre_emit_l7_chunks(
    void *rb,
    void *drops_map,
    struct spectre_l7_event *evt,
    __u64 ts,
    __u64 conn_ptr,
    __u32 pid,
    __u32 tid,
    __s32 fd,
    __u64 buf_ptr,
    __u64 total_len,
    __u8 dir,
    __u8 tls_source
)
{
    if (total_len == 0ULL || buf_ptr == 0ULL) {
        return;
    }

    if (total_len <= 512ULL) {
        __u32 copy_len = (__u32)total_len;
        if (copy_len == 0U || copy_len > 512U) {
            return;
        }
        if (bpf_probe_read_user(evt->payload, copy_len, (const void *)buf_ptr) != 0) {
            return;
        }
        evt->ts_ns = ts;
        evt->conn_ptr = conn_ptr;
        evt->pid = pid;
        evt->tid = tid;
        evt->fd = fd;
        evt->payload_len = copy_len;
        evt->direction = dir;
        evt->tls_source = tls_source;
        evt->chunk_seq = 0;
        spectre_ringbuf_emit_sized(rb, drops_map, evt, 1);
        return;
    }

#pragma unroll
    for (int chunk = 0; chunk < 8; chunk++) {
        __u64 offset = (__u64)chunk * L7_MAX_PAYLOAD;
        if (offset >= total_len) {
            break;
        }
        __u64 rem = total_len - offset;
        __u32 copy_len = rem > L7_MAX_PAYLOAD ? L7_MAX_PAYLOAD : (__u32)rem;
        if (copy_len == 0U || copy_len > L7_MAX_PAYLOAD) {
            break;
        }
        if (bpf_probe_read_user(evt->payload, copy_len, (const void *)(buf_ptr + offset)) != 0) {
            break;
        }
        evt->ts_ns = ts;
        evt->conn_ptr = conn_ptr;
        evt->pid = pid;
        evt->tid = tid;
        evt->fd = fd;
        evt->payload_len = copy_len;
        evt->direction = dir;
        evt->tls_source = tls_source;
        evt->chunk_seq = (__u16)chunk;
        spectre_ringbuf_emit_sized(rb, drops_map, evt, 0);
    }
}

#endif /* SPECTRE_EVENTS_H */
