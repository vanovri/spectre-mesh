#include "spectre_events.h"
#include "spectre_pidns.h"

#ifndef BPF_F_USER_STACK
#define BPF_F_USER_STACK (1ULL << 8)
#endif

/* Verified against Linux 6.18 /sys/kernel/tracing/events/sched/sched_switch/format */
struct tp_sched_switch {
    __u64 _hdr;
    __u8 prev_comm[16];
    __s32 prev_pid;
    __s32 prev_prio;
    __s64 prev_state;
    __u8 next_comm[16];
    __s32 next_pid;
    __s32 next_prio;
};

struct prof_stack_key {
    __u32 pid;
    __s32 kern_stack_id;
    __s32 user_stack_id;
    __u32 _pad;
    __u8 comm[16];
};

struct offcpu_pending {
    __u64 start_ns;
    __u32 ns_pid;
    __s32 kern_stack_id;
    __s32 user_stack_id;
    __u32 _pad;
    __u8 comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, 127 * sizeof(__u64));
    __uint(max_entries, 16384);
} stack_traces SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32); /* 0 = whole system, 1 = filter by tracked_pids */
} filter_cfg SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32768);
    __type(key, struct prof_stack_key);
    __type(value, __u64);
} oncpu_counts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32768);
    __type(key, __u32); /* raw init_pid_ns TID (prev_pid == next_pid) */
    __type(value, struct offcpu_pending);
} offcpu_start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32768);
    __type(key, struct prof_stack_key);
    __type(value, __u64);
} offcpu_ns SEC(".maps");

SPECTRE_INLINE int should_profile_pid(__u32 *out_ns_pid)
{
    __u32 zero = 0;
    __u32 *mode = bpf_map_lookup_elem(&filter_cfg, &zero);
    int filter_on = (mode && *mode != 0U);
    __u64 pid_tgid = spectre_current_pid_tgid(filter_on ? 0 : 1);
    __u32 pid = (__u32)(pid_tgid >> 32);
    if (filter_on) {
        if (pid == 0U || !bpf_map_lookup_elem(&tracked_pids, &pid)) {
            return 0;
        }
    }
    *out_ns_pid = pid;
    return 1;
}

SPECTRE_INLINE void accumulate_u64_map(void *map, struct prof_stack_key *key, __u64 delta)
{
    __u64 *existing = bpf_map_lookup_elem(map, key);
    if (existing) {
        __sync_fetch_and_add(existing, delta);
    } else {
        bpf_map_update_elem(map, key, &delta, BPF_ANY);
    }
}

SEC("perf_event")
int oncpu_sample(void *ctx)
{
    __u32 ns_pid = 0;
    if (!should_profile_pid(&ns_pid)) {
        return 0;
    }
    if (ns_pid == 0U) {
        return 0;
    }

    struct prof_stack_key key;
    __builtin_memset(&key, 0, sizeof(key));
    key.pid = ns_pid;
    key.kern_stack_id = (__s32)bpf_get_stackid(ctx, &stack_traces, 0);
    key.user_stack_id = (__s32)bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);
    bpf_get_current_comm(key.comm, sizeof(key.comm));

    accumulate_u64_map(&oncpu_counts, &key, 1ULL);
    return 0;
}

SEC("tp/sched/sched_switch")
int tp_sched_switch(struct tp_sched_switch *ctx)
{
    __u64 now = bpf_ktime_get_ns();

    /* 1. Outgoing blocked task (prev_state != TASK_RUNNING): stash start time & blocked stacks */
    if (ctx->prev_state != 0 && ctx->prev_pid > 0) {
        __u32 ns_pid = 0;
        if (should_profile_pid(&ns_pid) && ns_pid != 0U) {
            struct offcpu_pending pend;
            __builtin_memset(&pend, 0, sizeof(pend));
            pend.start_ns = now;
            pend.ns_pid = ns_pid;
            pend.kern_stack_id = (__s32)bpf_get_stackid(ctx, &stack_traces, 0);
            pend.user_stack_id = (__s32)bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);
            __builtin_memcpy(pend.comm, ctx->prev_comm, sizeof(pend.comm));
            __u32 raw_prev = (__u32)ctx->prev_pid;
            bpf_map_update_elem(&offcpu_start, &raw_prev, &pend, BPF_ANY);
        }
    }

    /* 2. Incoming waking task: measure blocked latency >= 100 us */
    if (ctx->next_pid > 0) {
        __u32 raw_next = (__u32)ctx->next_pid;
        struct offcpu_pending *pend = bpf_map_lookup_elem(&offcpu_start, &raw_next);
        if (pend) {
            struct offcpu_pending saved = *pend;
            bpf_map_delete_elem(&offcpu_start, &raw_next);
            if (now > saved.start_ns) {
                __u64 delta = now - saved.start_ns;
                if (delta >= 100000ULL) {
                    struct prof_stack_key key;
                    __builtin_memset(&key, 0, sizeof(key));
                    key.pid = saved.ns_pid;
                    key.kern_stack_id = saved.kern_stack_id;
                    key.user_stack_id = saved.user_stack_id;
                    __builtin_memcpy(key.comm, saved.comm, sizeof(key.comm));
                    accumulate_u64_map(&offcpu_ns, &key, delta);
                }
            }
        }
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
