# M03 Design Spec — `probes/xdp_net`, `probes/tcp_trace` & `crates/spectre-xdp`

## 1. Objective
Deliver line-rate XDP L2/L3/L4 packet filtering, lock-free per-CPU token-bucket SYN/DDoS rate limiting, kernel TCP RTT/retransmit/cleartext CO-RE telemetry, and a pure-Rust `AF_NETLINK` `NETLINK_ROUTE` XDP/veth attacher without shelling out to `ip` or `tc`.

## 2. XDP Fast-Path Parser & Token Bucket (`probes/xdp_net.bpf.c`)
- **Bounds-Safe Header Parsing:**
  1. Ethernet (`14 B`) + bounded VLAN loop (`max 2` `0x8100`/`0x88A8` tags, `4 B` each).
  2. IPv4 (`>= 20 B`): validates `ihl >= 5`, computes `ihl * 4` (`20..=60`), enforces `l3_off + ihl_bytes <= data_end`, extracts `(saddr, daddr, proto)`.
  3. IPv6 (`40 B`): extracts 128-bit source/dest addresses + `nexthdr`.
  4. L4 TCP (`20 B`) / UDP (`8 B`): parses `sport`, `dport`, and TCP flags (`SYN` / `ACK` / `RST`).
- **Blocklist & Per-CPU Token Bucket:**
  - `xdp_blocklist` (`BPF_MAP_TYPE_HASH<__u32, __u32>`): instant `XDP_DROP` on blocked IPv4 address.
  - `xdp_rl_config` (`BPF_MAP_TYPE_ARRAY`, key `0`): `{ rate_tokens_per_sec: u64, burst_tokens: u64, enabled: u32, syn_only: u32 }`.
  - `xdp_token_buckets` (`BPF_MAP_TYPE_PERCPU_HASH<__u32, TokenBucket>`): tracks `(tokens_fp: u64, last_ns: u64, in_drop_state: u32)` scaled by `1024` (or `1` token = `1 << 10`) using `bpf_ktime_get_ns()`. Zero locks across CPU cores!
  - `xdp_stats` (`BPF_MAP_TYPE_PERCPU_ARRAY`): per-CPU `rx_packets`, `rx_bytes`, `xdp_pass`, `xdp_drop_ratelimit`, `xdp_drop_blocklist`, `malformed_drop`.
  - `xdp_events` (`BPF_MAP_TYPE_RINGBUF`): emits `XdpDropEvent` ONLY on `0 -> 1` drop-state transition (flood-safe backpressure protection!).

## 3. Kernel TCP & Cleartext Tracer (`probes/tcp_trace.bpf.c`)
- `tp/sock/inet_sock_set_state`: tracks active sockets `(pid, tid, saddr, daddr, sport, dport, state)` in `active_conns` and emits `TcpLifecycleEvent` (`ESTABLISHED`, `CLOSE`).
- `tp/tcp/tcp_retransmit_skb`: increments retransmit counters and emits `TcpRetransmitEvent`.
- `kprobe/tcp_rcv_established`: reads CO-RE `BPF_CORE_READ(tp, srtt_us) >> 3` smoothed RTT in microseconds and emits `TcpRttEvent`.
- `tp/syscalls/sys_enter_sendto`, `sys_enter_write`, `sys_enter_recvfrom`, `sys_exit_recvfrom`, `sys_enter_read`, `sys_exit_read`: filtered by `tracked_pids` hash map (and optional port/socket check), copies bounded chunks (`<= 4096 B`) using a `BPF_MAP_TYPE_PERCPU_ARRAY` scratch buffer (obeying the 512B BPF stack limit!) into `l7_events` `RingBuf`.

## 4. Pure-Rust Netlink Route Attacher (`crates/spectre-xdp/src/netlink.rs`)
- Quarantine for raw `AF_NETLINK`/`NETLINK_ROUTE` sockets:
  - `XdpAttachment`: prefers `BPF_LINK_CREATE(BPF_XDP)`, falls back to `RTM_SETLINK` (`IFLA_XDP` nested attribute `IFLA_XDP_FD` + `IFLA_XDP_FLAGS`), automatically detaches (`fd = -1` / `BpfLinkGuard` drop) on `Drop`.
  - `NetlinkSocket`: `create_veth_pair`, `set_link_up`, `add_ipv4_addr`, `get_ifindex`, `delete_link` (pure Netlink messages, zero `ip` command invocations).
