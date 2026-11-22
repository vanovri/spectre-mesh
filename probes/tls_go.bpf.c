#include "spectre_events.h"
#include "spectre_pidns.h"

/* Go >= 1.17 ABIInternal:
 *   x86_64 : RAX = receiver conn, RBX = buf.ptr, RCX = buf.len, R14 = g; RET n = RAX
 *   aarch64: R0  = receiver conn, R1  = buf.ptr, R2  = buf.len, R28 = g; RET n = R0
 * NEVER attach kernel uretprobes to Go functions; attach normal entry uprobes at
 * every decoded RET instruction offset and key active calls by (pid, g_ptr)!
 */
struct go_op_key {
    __u32 pid;
    __u32 _pad;
    __u64 g_ptr;
};

struct go_op_val {
    __u64 conn_ptr;
    __u64 buf_ptr;
    __u64 buf_len;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32768);
    __type(key, struct go_op_key);
    __type(value, struct go_op_val);
} active_go_write SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32768);
    __type(key, struct go_op_key);
    __type(value, struct go_op_val);
} active_go_read SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct spectre_l7_event);
} go_tls_scratch SEC(".maps");

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

SPECTRE_INLINE void read_go_abi_entry(
    struct pt_regs *ctx,
    __u64 *conn_ptr,
    __u64 *buf_ptr,
    __u64 *buf_len,
    __u64 *g_ptr
)
{
#if defined(__TARGET_ARCH_arm64)
    *conn_ptr = ctx->regs[0];
    *buf_ptr = ctx->regs[1];
    *buf_len = ctx->regs[2];
    *g_ptr = ctx->regs[28];
#else
    *conn_ptr = ctx->ax;
    *buf_ptr = ctx->bx;
    *buf_len = ctx->cx;
    *g_ptr = ctx->r14;
#endif
}

SPECTRE_INLINE void read_go_abi_ret(struct pt_regs *ctx, __s64 *ret_n, __u64 *g_ptr)
{
#if defined(__TARGET_ARCH_arm64)
    *ret_n = (__s64)ctx->regs[0];
    *g_ptr = ctx->regs[28];
#else
    *ret_n = (__s64)ctx->ax;
    *g_ptr = ctx->r14;
#endif
}

SPECTRE_INLINE int handle_go_enter(struct pt_regs *ctx, void *map)
{
    __u64 pid_tgid = spectre_current_pid_tgid(0);
    __u32 pid = (__u32)(pid_tgid >> 32);
    if (pid == 0 || !bpf_map_lookup_elem(&tracked_pids, &pid)) {
        return 0;
    }

    __u64 conn_ptr = 0;
    __u64 buf_ptr = 0;
    __u64 buf_len = 0;
    __u64 g_ptr = 0;
    read_go_abi_entry(ctx, &conn_ptr, &buf_ptr, &buf_len, &g_ptr);
    if (conn_ptr == 0ULL || buf_ptr == 0ULL || buf_len == 0ULL || g_ptr == 0ULL) {
        return 0;
    }

    struct go_op_key key = {
        .pid = pid,
        ._pad = 0,
        .g_ptr = g_ptr,
    };
    struct go_op_val val = {
        .conn_ptr = conn_ptr,
        .buf_ptr = buf_ptr,
        .buf_len = buf_len,
    };
    /* BPF_ANY safely handles runtime.morestack prologue re-entry after stack growth */
    bpf_map_update_elem(map, &key, &val, BPF_ANY);
    return 0;
}

SPECTRE_INLINE int handle_go_ret(struct pt_regs *ctx, void *map, __u8 dir)
{
    __u64 pid_tgid = spectre_current_pid_tgid(0);
    __u32 pid = (__u32)(pid_tgid >> 32);
    if (pid == 0 || !bpf_map_lookup_elem(&tracked_pids, &pid)) {
        return 0;
    }

    __s64 ret_n = 0;
    __u64 g_ptr = 0;
    read_go_abi_ret(ctx, &ret_n, &g_ptr);
    if (g_ptr == 0ULL) {
        return 0;
    }

    struct go_op_key key = {
        .pid = pid,
        ._pad = 0,
        .g_ptr = g_ptr,
    };
    struct go_op_val *val = bpf_map_lookup_elem(map, &key);
    if (!val) {
        return 0;
    }
    struct go_op_val saved = *val;
    bpf_map_delete_elem(map, &key);

    if (ret_n <= 0 || saved.buf_ptr == 0ULL) {
        return 0;
    }
    __u64 total_len = (__u64)ret_n;
    if (total_len > saved.buf_len) {
        total_len = saved.buf_len;
    }

    __u32 zero = 0;
    struct spectre_l7_event *evt = bpf_map_lookup_elem(&go_tls_scratch, &zero);
    if (!evt) {
        return 0;
    }

    __u64 ts = bpf_ktime_get_ns();
    __u32 tid = (__u32)pid_tgid;
    bpf_get_current_comm(evt->comm, sizeof(evt->comm));

    spectre_emit_l7_chunks(
        &tls_events,
        &ringbuf_drops,
        evt,
        ts,
        saved.conn_ptr,
        pid,
        tid,
        -1,
        saved.buf_ptr,
        total_len,
        dir,
        L7_SRC_GO_TLS
    );
    return 0;
}

SEC("uprobe/go_tls_write_enter")
int uprobe_go_tls_write_enter(struct pt_regs *ctx)
{
    return handle_go_enter(ctx, &active_go_write);
}

SEC("uprobe/go_tls_write_ret")
int uprobe_go_tls_write_ret(struct pt_regs *ctx)
{
    return handle_go_ret(ctx, &active_go_write, L7_DIR_EGRESS);
}

SEC("uprobe/go_tls_read_enter")
int uprobe_go_tls_read_enter(struct pt_regs *ctx)
{
    return handle_go_enter(ctx, &active_go_read);
}

SEC("uprobe/go_tls_read_ret")
int uprobe_go_tls_read_ret(struct pt_regs *ctx)
{
    return handle_go_ret(ctx, &active_go_read, L7_DIR_INGRESS);
}

char LICENSE[] SEC("license") = "GPL";
