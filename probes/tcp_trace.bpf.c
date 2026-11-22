#include "spectre_events.h"
#include "spectre_pidns.h"

/* Tracepoint context layouts verified against Linux 6.18 /sys/kernel/tracing/events/.../format */
struct tp_inet_sock_set_state {
    __u64 _hdr;
    const void *skaddr;
    __s32 oldstate;
    __s32 newstate;
    __u16 sport;
    __u16 dport;
    __u16 family;
    __u16 protocol;
    __u8 saddr[4];
    __u8 daddr[4];
    __u8 saddr_v6[16];
    __u8 daddr_v6[16];
};

struct tp_tcp_retransmit_skb {
    __u64 _hdr;
    const void *skbaddr;
    const void *skaddr;
    __s32 state;
    __u16 sport;
    __u16 dport;
    __u16 family;
    __u8 saddr[4];
    __u8 daddr[4];
    __u8 saddr_v6[16];
    __u8 daddr_v6[16];
    __s32 err;
};

struct tp_sys_enter_rw {
    __u64 _hdr;
    __s32 syscall_nr;
    __u32 _pad;
    __u64 fd;
    __u64 buf;
    __u64 len;
};

struct tp_sys_exit {
    __u64 _hdr;
    __s32 syscall_nr;
    __u32 _pad;
    __s64 ret;
};

struct active_sock_info {
    __u32 pid;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u64 last_rtt_emit_ns;
};

struct pending_io_args {
    __u64 buf;
    __u64 len;
    __s32 fd;
    __u32 _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32768);
    __type(key, __u64); /* skaddr */
    __type(value, struct active_sock_info);
} active_conns SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64); /* pid_tgid */
    __type(value, struct pending_io_args);
} pending_reads SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct spectre_l7_event);
} l7_scratch SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 262144);
} tcp_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 2097152);
} l7_events SEC(".maps");

SPECTRE_INLINE __u32 copy_ipv4(const __u8 bytes[4])
{
    __u32 v = 0;
    __builtin_memcpy(&v, bytes, 4);
    return v;
}

SEC("tp/sock/inet_sock_set_state")
int tp_inet_sock_set_state(struct tp_inet_sock_set_state *ctx)
{
    if (ctx->protocol != IPPROTO_TCP) {
        return 0;
    }
    __u64 sk = (__u64)ctx->skaddr;
    __u32 pid = (__u32)(spectre_current_pid_tgid(1) >> 32);
    __u32 saddr = copy_ipv4(ctx->saddr);
    __u32 daddr = copy_ipv4(ctx->daddr);

    if (ctx->newstate == 1) { /* TCP_ESTABLISHED */
        struct active_sock_info info = {
            .pid = pid,
            .saddr = saddr,
            .daddr = daddr,
            .sport = ctx->sport,
            .dport = ctx->dport,
            .last_rtt_emit_ns = 0ULL,
        };
        bpf_map_update_elem(&active_conns, &sk, &info, BPF_ANY);
    } else if (ctx->newstate == 7) { /* TCP_CLOSE */
        bpf_map_delete_elem(&active_conns, &sk);
    }

    struct spectre_tcp_event *evt = bpf_ringbuf_reserve(&tcp_events, sizeof(*evt), 0);
    if (!evt) {
        return 0;
    }
    evt->ts_ns = bpf_ktime_get_ns();
    evt->skaddr = sk;
    evt->pid = pid;
    evt->srtt_us = 0;
    evt->saddr = saddr;
    evt->daddr = daddr;
    evt->sport = ctx->sport;
    evt->dport = ctx->dport;
    evt->kind = TCP_EVT_STATE;
    evt->old_state = (__u8)ctx->oldstate;
    evt->new_state = (__u8)ctx->newstate;
    evt->_pad = 0;
    bpf_ringbuf_submit(evt, 0);
    return 0;
}

SEC("tp/tcp/tcp_retransmit_skb")
int tp_tcp_retransmit_skb(struct tp_tcp_retransmit_skb *ctx)
{
    __u64 sk = (__u64)ctx->skaddr;
    __u32 pid = (__u32)(spectre_current_pid_tgid(1) >> 32);
    struct spectre_tcp_event *evt = bpf_ringbuf_reserve(&tcp_events, sizeof(*evt), 0);
    if (!evt) {
        return 0;
    }
    evt->ts_ns = bpf_ktime_get_ns();
    evt->skaddr = sk;
    evt->pid = pid;
    evt->srtt_us = 0;
    evt->saddr = copy_ipv4(ctx->saddr);
    evt->daddr = copy_ipv4(ctx->daddr);
    evt->sport = ctx->sport;
    evt->dport = ctx->dport;
    evt->kind = TCP_EVT_RETRANSMIT;
    evt->old_state = (__u8)ctx->state;
    evt->new_state = 0;
    evt->_pad = 0;
    bpf_ringbuf_submit(evt, 0);
    return 0;
}

SEC("kprobe/tcp_rcv_established")
int kp_tcp_rcv_established(struct pt_regs *ctx)
{
    struct sock *sk_ptr = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk_ptr) {
        return 0;
    }
    __u64 sk = (__u64)sk_ptr;
    struct active_sock_info *info = bpf_map_lookup_elem(&active_conns, &sk);
    if (!info) {
        return 0;
    }

    __u64 now = bpf_ktime_get_ns();
    /* Throttle RTT emission per socket to once every 50 ms */
    if (info->last_rtt_emit_ns != 0ULL && (now - info->last_rtt_emit_ns) < 50000000ULL) {
        return 0;
    }
    info->last_rtt_emit_ns = now;

    struct tcp_sock *tp = (struct tcp_sock *)sk_ptr;
    __u32 srtt_raw = BPF_CORE_READ(tp, srtt_us);
    __u32 srtt_us = srtt_raw >> 3;

    struct spectre_tcp_event *evt = bpf_ringbuf_reserve(&tcp_events, sizeof(*evt), 0);
    if (!evt) {
        return 0;
    }
    evt->ts_ns = now;
    evt->skaddr = sk;
    evt->pid = info->pid;
    evt->srtt_us = srtt_us;
    evt->saddr = info->saddr;
    evt->daddr = info->daddr;
    evt->sport = info->sport;
    evt->dport = info->dport;
    evt->kind = TCP_EVT_RTT;
    evt->old_state = 1;
    evt->new_state = 1;
    evt->_pad = 0;
    bpf_ringbuf_submit(evt, 0);
    return 0;
}

SPECTRE_INLINE void emit_l7_cleartext(__s32 fd, __u64 buf_addr, __u64 raw_len, __u8 dir)
{
    if (fd < 3 || raw_len == 0ULL || buf_addr == 0ULL) {
        return;
    }
    __u64 pid_tgid = spectre_current_pid_tgid(0);
    __u32 pid = (__u32)(pid_tgid >> 32);
    if (pid == 0 || !bpf_map_lookup_elem(&tracked_pids, &pid)) {
        return;
    }

    __u32 zero = 0;
    struct spectre_l7_event *evt = bpf_map_lookup_elem(&l7_scratch, &zero);
    if (!evt) {
        return;
    }

    __u64 ts = bpf_ktime_get_ns();
    __u32 tid = (__u32)pid_tgid;
    bpf_get_current_comm(evt->comm, sizeof(evt->comm));

    __u64 offset = 0;
#pragma unroll
    for (int chunk = 0; chunk < 4; chunk++) {
        if (offset >= raw_len) {
            break;
        }
        __u64 rem = raw_len - offset;
        __u32 copy_len = rem > L7_MAX_PAYLOAD ? L7_MAX_PAYLOAD : (__u32)rem;
        if (copy_len == 0 || copy_len > L7_MAX_PAYLOAD) {
            break;
        }
        if (bpf_probe_read_user(evt->payload, copy_len, (const void *)(buf_addr + offset)) != 0) {
            break;
        }
        evt->ts_ns = ts;
        evt->conn_ptr = 0;
        evt->pid = pid;
        evt->tid = tid;
        evt->fd = fd;
        evt->payload_len = copy_len;
        evt->direction = dir;
        evt->tls_source = L7_SRC_CLEARTEXT_SOCK;
        evt->chunk_seq = (__u16)chunk;
        bpf_ringbuf_output(&l7_events, evt, sizeof(*evt), 0);
        offset += copy_len;
    }
}

struct bpf_raw_tracepoint_args_local {
    __u64 args[2];
};

#if defined(__TARGET_ARCH_arm64)
#define SYS_NR_READ     63L
#define SYS_NR_WRITE    64L
#define SYS_NR_SENDTO   206L
#define SYS_NR_RECVFROM 207L
#else
#define SYS_NR_READ     0L
#define SYS_NR_WRITE    1L
#define SYS_NR_SENDTO   44L
#define SYS_NR_RECVFROM 45L
#endif

SEC("raw_tp/sys_enter")
int raw_tp_sys_enter(struct bpf_raw_tracepoint_args_local *ctx)
{
    __u64 pid_tgid = spectre_current_pid_tgid(0);
    __u32 pid = (__u32)(pid_tgid >> 32);
    if (pid == 0 || !bpf_map_lookup_elem(&tracked_pids, &pid)) {
        return 0;
    }

    __s64 id = (__s64)ctx->args[1];
    if (id != SYS_NR_READ && id != SYS_NR_WRITE && id != SYS_NR_SENDTO && id != SYS_NR_RECVFROM) {
        return 0;
    }

    struct pt_regs *regs = (struct pt_regs *)ctx->args[0];
    if (!regs) {
        return 0;
    }
    __u64 fd_u64 = BPF_CORE_READ(regs, di);
    __u64 buf_addr = BPF_CORE_READ(regs, si);
    __u64 len = BPF_CORE_READ(regs, dx);

    if (id == SYS_NR_WRITE || id == SYS_NR_SENDTO) {
        emit_l7_cleartext((__s32)fd_u64, buf_addr, len, L7_DIR_EGRESS);
    } else {
        struct pending_io_args args = {
            .buf = buf_addr,
            .len = len,
            .fd = (__s32)fd_u64,
            ._pad = 0,
        };
        bpf_map_update_elem(&pending_reads, &pid_tgid, &args, BPF_ANY);
    }
    return 0;
}

SEC("raw_tp/sys_exit")
int raw_tp_sys_exit(struct bpf_raw_tracepoint_args_local *ctx)
{
    __u64 pid_tgid = spectre_current_pid_tgid(0);
    if (pid_tgid == 0) {
        return 0;
    }
    struct pending_io_args *args = bpf_map_lookup_elem(&pending_reads, &pid_tgid);
    if (!args) {
        return 0;
    }
    struct pending_io_args saved = *args;
    bpf_map_delete_elem(&pending_reads, &pid_tgid);
    __s64 ret = (__s64)ctx->args[1];
    if (ret > 0) {
        emit_l7_cleartext(saved.fd, saved.buf, (__u64)ret, L7_DIR_INGRESS);
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
