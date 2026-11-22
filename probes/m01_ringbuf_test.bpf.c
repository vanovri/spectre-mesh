#include <linux/bpf.h>

#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
#define SEC(NAME) __attribute__((section(NAME), used))

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static void *(*bpf_ringbuf_reserve)(void *ringbuf, __u64 size, __u64 flags) = (void *)131;
static void (*bpf_ringbuf_submit)(void *data, __u64 flags) = (void *)132;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)5;

struct m01_seq_event {
    __u64 seq;
    __u64 ts_ns;
    __u32 pkt_len;
    __u32 magic;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} seq_counter SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 524288);
} m01_events SEC(".maps");

SEC("xdp")
int m01_emit_ringbuf(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u32 zero = 0;
    __u64 *cnt = bpf_map_lookup_elem(&seq_counter, &zero);
    if (!cnt) {
        return XDP_PASS;
    }

    __u64 next = __sync_fetch_and_add(cnt, 1) + 1;
    struct m01_seq_event *evt = bpf_ringbuf_reserve(&m01_events, sizeof(*evt), 0);
    if (!evt) {
        return XDP_ABORTED;
    }

    evt->seq = next;
    evt->ts_ns = bpf_ktime_get_ns();
    evt->pkt_len = (__u32)((long)data_end - (long)data);
    evt->magic = 0x53504543U;
    bpf_ringbuf_submit(evt, 0);
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
