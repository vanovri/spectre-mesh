# SpectreMesh Architecture

**SpectreMesh (`spectre-mesh`)** is a first-principles eBPF observability engine, plaintext TLS uprobe interceptor, XDP rate-limiting packet firewall, continuous CPU/Off-CPU profiler, and WebAssembly static verifier studio implemented in pure Rust + Restricted C (`clang -target bpf -O2 -g`).

---

## 1. Crate & Probe Topology

```
probes/*.bpf.c (clang -target bpf -O2 -g -Wall -Werror)
   ├── m01_ringbuf_test.bpf.o   -> M01 live kernel RingBuf & CO-RE smoke probe
   ├── xdp_net.bpf.o            -> L2/VLAN/IPv4/IPv6/TCP/UDP XDP firewall & per-CPU token bucket
   ├── tcp_trace.bpf.o          -> CO-RE tcp_sock SRTT tracker, retransmits, sys_enter/sys_exit cleartext
   ├── tls_openssl.bpf.o        -> OpenSSL 3.x SSL_write/SSL_read/SSL_set_fd uprobes + chunked RingBuf
   ├── tls_go.bpf.o             -> Go crypto/tls.(*Conn).Write/Read RET-offset entry uprobes (g-keyed)
   └── profiler.bpf.o           -> 99Hz On-CPU perf_event + sched_switch Off-CPU stack tracer

Workspace Crates
   ├── crates/spectre-elf-btf   -> ELF64 + .gopclntab + BTF + .BTF.ext CO-RE relocator + SYS_bpf + mmap RingBuf
   ├── crates/spectre-verifier  -> Pure-Rust eBPF ISA v3 disassembler, Tnum static verifier, BpfVm
   ├── crates/spectre-xdp       -> Pure-Rust AF_NETLINK veth/XDP manager, XdpFirewall, TcpMonitor
   ├── crates/spectre-tls       -> x86_64/aarch64 RET-offset decoder + OpenSSL/Go TLS uprobe orchestrator
   ├── crates/spectre-l7        -> Zero-copy streaming HTTP/1.1, HTTP/2+HPACK+gRPC, PG v3, Redis RESP2/3
   ├── crates/spectre-profile   -> On/Off-CPU ContinuousProfiler, ASLR+kallsyms symbolizer, diff SVG flamegraphs
   ├── crates/spectre-oracle    -> Multi-service encrypted mesh ground-truth oracle (50,000 requests)
   ├── crates/spectre-daemon    -> `spectred` HTTP/Prometheus/SSE telemetry daemon + `spectre-bench`
   ├── crates/spectre-tui       -> `spectre-top` 4-panel ratatui live cockpit
   └── crates/spectre-wasm      -> wasm32+simd128 verifier, VM, L7 & flamegraph engine -> studio/ WebWorker SPA
```

---

## 2. Constitutional Safety Boundaries

1. **Zero Wrapper Crates:** No `aya`, `libbpf-rs`, `libbpf-sys`, `redbpf`, `goblin`, `object`, `btf-rs`, `httparse`, `h2`, `hpack`, `redis`, `pgwire`, `pprof`, or `inferno`, and zero runtime CLI shell-outs to `bpftool`, `tc`, `ip`, `tcpdump`, `tshark`, or `perf`.
2. **`unsafe` Quarantine:** `#![deny(unsafe_code)]` is active across `spectre-verifier`, `spectre-tls`, `spectre-l7`, `spectre-profile`, `spectre-oracle`, `spectre-daemon`, `spectre-tui`, and `spectre-wasm`. Controlled `unsafe` exists solely in `spectre-elf-btf::{syscall,ringbuf}` (validated via `cargo +nightly miri test`) and `spectre-xdp::netlink` (`AF_NETLINK` / `AF_PACKET` / `CLONE_NEWNET` sockets).
3. **Go Goroutine Stack Safety:** `spectre-tls` scans `.symtab`/`.gopclntab` + decodes machine instructions to attach **entry uprobes directly at every `RET` offset** (`x86_64` `0xC3` / `aarch64` `0xD65F03C0`), keying active calls by `(ns_pid, g_ptr)`. Kernel `uretprobe` trampolines are never attached to Go binaries.
4. **PID-Namespace Awareness:** `probes/include/spectre_pidns.h` translates kernel task IDs using `bpf_get_ns_current_pid_tgid` populated automatically from `/proc/self/ns/pid` by `BpfObjectLoader`, ensuring containerized and WSL2 child namespaces filter PIDs accurately.
5. **Dual-Domain RingBuf Chunking:** `spectre_emit_l7_chunks` commits compact `568 B` RingBuf records for `<= 512 B` payloads and unrolled 8-chunk DAGs (`32 KB` max per call) to keep `.text = 0 B` and satisfy the Linux kernel verifier's path complexity budget with `0` dropped records.
