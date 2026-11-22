#include "spectre_events.h"
#include "spectre_pidns.h"

struct openssl_pending_op {
    __u64 ssl_ptr;
    __u64 buf_ptr;
    __u64 written_ptr;
    __u64 req_len;
    __u8 direction;
    __u8 is_ex;
    __u16 _pad[3];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64); /* SSL* */
    __type(value, __s32);
} ssl_fd_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64); /* pid_tgid */
    __type(value, struct openssl_pending_op);
} active_ssl_ops SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct spectre_l7_event);
} tls_scratch SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 16777216);
} tls_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} ringbuf_drops SEC(".maps");

SPECTRE_INLINE void record_ssl_fd(__u64 ssl_ptr, __s32 fd)
{
    __u64 pid_tgid = spectre_current_pid_tgid(0);
    __u32 pid = (__u32)(pid_tgid >> 32);
    if (pid == 0 || !bpf_map_lookup_elem(&tracked_pids, &pid)) {
        return;
    }
    if (ssl_ptr == 0ULL || fd < 0) {
        return;
    }
    bpf_map_update_elem(&ssl_fd_map, &ssl_ptr, &fd, BPF_ANY);
}

SPECTRE_INLINE int stash_ssl_op(
    __u64 ssl_ptr,
    __u64 buf_ptr,
    __u64 req_len,
    __u64 written_ptr,
    __u8 dir,
    __u8 is_ex
)
{
    __u64 pid_tgid = spectre_current_pid_tgid(0);
    __u32 pid = (__u32)(pid_tgid >> 32);
    if (pid == 0 || !bpf_map_lookup_elem(&tracked_pids, &pid)) {
        return 0;
    }
    if (ssl_ptr == 0ULL || buf_ptr == 0ULL || req_len == 0ULL) {
        return 0;
    }
    struct openssl_pending_op op = {
        .ssl_ptr = ssl_ptr,
        .buf_ptr = buf_ptr,
        .written_ptr = written_ptr,
        .req_len = req_len,
        .direction = dir,
        .is_ex = is_ex,
        ._pad = {0, 0, 0},
    };
    bpf_map_update_elem(&active_ssl_ops, &pid_tgid, &op, BPF_ANY);
    return 0;
}

SPECTRE_INLINE void emit_ssl_chunks(
    __u64 pid_tgid,
    __u64 ssl_ptr,
    __u64 buf_ptr,
    __u64 total_len,
    __u8 dir
)
{
    if (total_len == 0ULL || buf_ptr == 0ULL) {
        return;
    }
    __u32 zero = 0;
    struct spectre_l7_event *evt = bpf_map_lookup_elem(&tls_scratch, &zero);
    if (!evt) {
        return;
    }

    __s32 *fd_ptr = bpf_map_lookup_elem(&ssl_fd_map, &ssl_ptr);
    __s32 fd = fd_ptr ? *fd_ptr : -1;
    __u64 ts = bpf_ktime_get_ns();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u32 tid = (__u32)pid_tgid;
    bpf_get_current_comm(evt->comm, sizeof(evt->comm));

    spectre_emit_l7_chunks(
        &tls_events,
        &ringbuf_drops,
        evt,
        ts,
        ssl_ptr,
        pid,
        tid,
        fd,
        buf_ptr,
        total_len,
        dir,
        L7_SRC_OPENSSL
    );
}

SPECTRE_INLINE int finish_ssl_op(struct pt_regs *ctx)
{
    __u64 pid_tgid = spectre_current_pid_tgid(0);
    if (pid_tgid == 0ULL) {
        return 0;
    }
    struct openssl_pending_op *op = bpf_map_lookup_elem(&active_ssl_ops, &pid_tgid);
    if (!op) {
        return 0;
    }
    struct openssl_pending_op saved = *op;
    bpf_map_delete_elem(&active_ssl_ops, &pid_tgid);

    __s32 rc = (__s32)(__s64)PT_REGS_RC(ctx);
    __u64 actual_len = 0ULL;
    if (saved.is_ex) {
        if (rc != 1) {
            return 0;
        }
        if (saved.written_ptr != 0ULL) {
            __u64 ex_len = 0ULL;
            if (bpf_probe_read_user(&ex_len, sizeof(ex_len), (const void *)saved.written_ptr) != 0) {
                return 0;
            }
            actual_len = ex_len;
        } else {
            actual_len = saved.req_len;
        }
    } else {
        if (rc <= 0) {
            return 0;
        }
        actual_len = (__u64)(__u32)rc;
    }

    if (actual_len > saved.req_len && saved.req_len > 0ULL) {
        actual_len = saved.req_len;
    }
    emit_ssl_chunks(pid_tgid, saved.ssl_ptr, saved.buf_ptr, actual_len, saved.direction);
    return 0;
}

SEC("uprobe/SSL_set_fd")
int uprobe_ssl_set_fd(struct pt_regs *ctx)
{
    record_ssl_fd(PT_REGS_PARM1(ctx), (__s32)PT_REGS_PARM2(ctx));
    return 0;
}

SEC("uprobe/SSL_set_rfd")
int uprobe_ssl_set_rfd(struct pt_regs *ctx)
{
    record_ssl_fd(PT_REGS_PARM1(ctx), (__s32)PT_REGS_PARM2(ctx));
    return 0;
}

SEC("uprobe/SSL_set_wfd")
int uprobe_ssl_set_wfd(struct pt_regs *ctx)
{
    record_ssl_fd(PT_REGS_PARM1(ctx), (__s32)PT_REGS_PARM2(ctx));
    return 0;
}

SEC("uprobe/SSL_write")
int uprobe_ssl_write(struct pt_regs *ctx)
{
    return stash_ssl_op(
        PT_REGS_PARM1(ctx),
        PT_REGS_PARM2(ctx),
        (__u64)(__u32)(__s32)PT_REGS_PARM3(ctx),
        0ULL,
        L7_DIR_EGRESS,
        0
    );
}

SEC("uretprobe/SSL_write")
int uretprobe_ssl_write(struct pt_regs *ctx)
{
    return finish_ssl_op(ctx);
}

SEC("uprobe/SSL_write_ex")
int uprobe_ssl_write_ex(struct pt_regs *ctx)
{
    return stash_ssl_op(
        PT_REGS_PARM1(ctx),
        PT_REGS_PARM2(ctx),
        PT_REGS_PARM3(ctx),
        PT_REGS_PARM4(ctx),
        L7_DIR_EGRESS,
        1
    );
}

SEC("uretprobe/SSL_write_ex")
int uretprobe_ssl_write_ex(struct pt_regs *ctx)
{
    return finish_ssl_op(ctx);
}

SEC("uprobe/SSL_read")
int uprobe_ssl_read(struct pt_regs *ctx)
{
    return stash_ssl_op(
        PT_REGS_PARM1(ctx),
        PT_REGS_PARM2(ctx),
        (__u64)(__u32)(__s32)PT_REGS_PARM3(ctx),
        0ULL,
        L7_DIR_INGRESS,
        0
    );
}

SEC("uretprobe/SSL_read")
int uretprobe_ssl_read(struct pt_regs *ctx)
{
    return finish_ssl_op(ctx);
}

SEC("uprobe/SSL_read_ex")
int uprobe_ssl_read_ex(struct pt_regs *ctx)
{
    return stash_ssl_op(
        PT_REGS_PARM1(ctx),
        PT_REGS_PARM2(ctx),
        PT_REGS_PARM3(ctx),
        PT_REGS_PARM4(ctx),
        L7_DIR_INGRESS,
        1
    );
}

SEC("uretprobe/SSL_read_ex")
int uretprobe_ssl_read_ex(struct pt_regs *ctx)
{
    return finish_ssl_op(ctx);
}

char LICENSE[] SEC("license") = "GPL";
