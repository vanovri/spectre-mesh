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

#endif /* SPECTRE_EVENTS_H */
