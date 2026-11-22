#ifndef SPECTRE_VMLINUX_H
#define SPECTRE_VMLINUX_H

#include <linux/bpf.h>

#ifndef __u8
typedef unsigned char __u8;
#endif
#ifndef __u16
typedef unsigned short __u16;
#endif
#ifndef __u32
typedef unsigned int __u32;
#endif
#ifndef __u64
typedef unsigned long long __u64;
#endif
#ifndef __s32
typedef int __s32;
#endif
#ifndef __s64
typedef long long __s64;
#endif

#define SEC(NAME) __attribute__((section(NAME), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
#define SPECTRE_INLINE static inline __attribute__((always_inline))

#ifndef bpf_htons
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define bpf_htons(x) __builtin_bswap16(x)
#define bpf_ntohs(x) __builtin_bswap16(x)
#define bpf_htonl(x) __builtin_bswap32(x)
#define bpf_ntohl(x) __builtin_bswap32(x)
#else
#define bpf_htons(x) (x)
#define bpf_ntohs(x) (x)
#define bpf_htonl(x) (x)
#define bpf_ntohl(x) (x)
#endif
#endif

#define ETH_P_IP   0x0800U
#define ETH_P_IPV6 0x86DDU
#define ETH_P_8021Q  0x8100U
#define ETH_P_8021AD 0x88A8U
#define IPPROTO_TCP 6U
#define IPPROTO_UDP 17U
#define AF_INET_VAL 2U
#define AF_INET6_VAL 10U

/* Namespace PID info struct matching <linux/bpf.h> */
struct spectre_bpf_pidns_info {
    __u32 pid;
    __u32 tgid;
};

/* BPF helper prototypes matching kernel ABI */
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *)2;
static long (*bpf_map_delete_elem)(void *map, const void *key) = (void *)3;
static long (*bpf_probe_read)(void *dst, __u32 size, const void *unsafe_ptr) = (void *)4;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)5;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *)14;
static long (*bpf_get_current_comm)(void *buf, __u32 size_of_buf) = (void *)16;
static long (*bpf_get_stackid)(void *ctx, void *map, __u64 flags) = (void *)27;
static long (*bpf_probe_read_user)(void *dst, __u32 size, const void *unsafe_ptr) = (void *)112;
static long (*bpf_probe_read_kernel)(void *dst, __u32 size, const void *unsafe_ptr) = (void *)113;
static long (*bpf_get_ns_current_pid_tgid)(__u64 dev, __u64 ino, struct spectre_bpf_pidns_info *nsdata, __u32 size) = (void *)120;
static long (*bpf_ringbuf_output)(void *ringbuf, void *data, __u64 size, __u64 flags) = (void *)130;
static void *(*bpf_ringbuf_reserve)(void *ringbuf, __u64 size, __u64 flags) = (void *)131;
static void (*bpf_ringbuf_submit)(void *data, __u64 flags) = (void *)132;
static void (*bpf_ringbuf_discard)(void *data, __u64 flags) = (void *)133;

/* Minimal CO-RE kernel structs verified against /sys/kernel/btf/vmlinux */
#define __core __attribute__((preserve_access_index))

#if defined(__TARGET_ARCH_arm64)
struct pt_regs {
    __u64 regs[31];
    __u64 sp;
    __u64 pc;
    __u64 pstate;
} __core;
#define PT_REGS_PARM1(x) ((x)->regs[0])
#define PT_REGS_PARM2(x) ((x)->regs[1])
#define PT_REGS_PARM3(x) ((x)->regs[2])
#define PT_REGS_PARM4(x) ((x)->regs[3])
#define PT_REGS_PARM5(x) ((x)->regs[4])
#define PT_REGS_RC(x) ((x)->regs[0])
#define PT_REGS_SP(x) ((x)->sp)
#else
struct pt_regs {
    __u64 r15;
    __u64 r14;
    __u64 r13;
    __u64 r12;
    __u64 bp;
    __u64 bx;
    __u64 r11;
    __u64 r10;
    __u64 r9;
    __u64 r8;
    __u64 ax;
    __u64 cx;
    __u64 dx;
    __u64 si;
    __u64 di;
    __u64 orig_ax;
    __u64 ip;
    __u64 cs;
    __u64 flags;
    __u64 sp;
    __u64 ss;
} __core;
#define PT_REGS_PARM1(x) ((x)->di)
#define PT_REGS_PARM2(x) ((x)->si)
#define PT_REGS_PARM3(x) ((x)->dx)
#define PT_REGS_PARM4(x) ((x)->cx)
#define PT_REGS_PARM5(x) ((x)->r8)
#define PT_REGS_RC(x) ((x)->ax)
#define PT_REGS_SP(x) ((x)->sp)
#endif

struct sock_common {
    union {
        struct {
            __u32 skc_daddr;
            __u32 skc_rcv_saddr;
        };
    };
    union {
        struct {
            __u16 skc_dport;
            __u16 skc_num;
        };
    };
    short unsigned int skc_family;
} __core;

struct sock {
    struct sock_common __sk_common;
} __core;

struct inet_sock {
    struct sock sk;
    __u32 inet_saddr;
    __u16 inet_sport;
} __core;

struct tcp_sock {
    __u32 srtt_us;
} __core;

#define BPF_CORE_READ(src, field)                                            \
    ({                                                                       \
        typeof((src)->field) __val = 0;                                      \
        bpf_probe_read_kernel(&__val, sizeof(__val),                         \
                              __builtin_preserve_access_index(&(src)->field)); \
        __val;                                                               \
    })

/* Network header layouts for XDP direct packet parsing */
struct spectre_ethhdr {
    __u8 h_dest[6];
    __u8 h_source[6];
    __u16 h_proto;
} __attribute__((packed));

struct spectre_vlan_hdr {
    __u16 h_vlan_TCI;
    __u16 h_vlan_encapsulated_proto;
} __attribute__((packed));

struct spectre_iphdr {
    __u8 ihl_ver;
    __u8 tos;
    __u16 tot_len;
    __u16 id;
    __u16 frag_off;
    __u8 ttl;
    __u8 protocol;
    __u16 check;
    __u32 saddr;
    __u32 daddr;
} __attribute__((packed));

struct spectre_ipv6hdr {
    __u32 ver_tc_fl;
    __u16 payload_len;
    __u8 nexthdr;
    __u8 hop_limit;
    __u8 saddr[16];
    __u8 daddr[16];
} __attribute__((packed));

struct spectre_tcphdr {
    __u16 source;
    __u16 dest;
    __u32 seq;
    __u32 ack_seq;
    __u16 flags;
    __u16 window;
    __u16 check;
    __u16 urg_ptr;
} __attribute__((packed));

struct spectre_udphdr {
    __u16 source;
    __u16 dest;
    __u16 len;
    __u16 check;
} __attribute__((packed));

#endif /* SPECTRE_VMLINUX_H */
