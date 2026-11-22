#ifndef SPECTRE_PIDNS_H
#define SPECTRE_PIDNS_H

#include "spectre_events.h"

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct spectre_pidns_cfg);
} pidns_cfg SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u32);
} tracked_pids SEC(".maps");

/* Resolve (tgid << 32) | pid in the collector's PID namespace when configured,
 * making PID correlation work identically on host Linux, Docker, and WSL2. */
SPECTRE_INLINE __u64 spectre_current_pid_tgid(int fallback_to_init_ns)
{
    __u32 zero = 0;
    struct spectre_pidns_cfg *cfg = bpf_map_lookup_elem(&pidns_cfg, &zero);
    if (cfg && cfg->enabled) {
        struct spectre_bpf_pidns_info ns = {0, 0};
        if (bpf_get_ns_current_pid_tgid(cfg->dev, cfg->ino, &ns, sizeof(ns)) == 0) {
            return ((__u64)ns.tgid << 32) | (__u64)ns.pid;
        }
        if (!fallback_to_init_ns) {
            return 0ULL;
        }
    }
    return bpf_get_current_pid_tgid();
}

#endif /* SPECTRE_PIDNS_H */
