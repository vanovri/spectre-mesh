# SpectreMesh (`spectre-mesh`) — Autonomous Engineering Progression Ledger

## Environment & Execution Harness
- **Repository Root:** `C:\Users\ardhy\.gemini\antigravity\scratch\spectre-mesh`
- **Live Linux Kernel Target:** `WSL2 Ubuntu-26.04` (`Linux 6.18.33.2-microsoft-standard-WSL2 x86_64`, `/sys/kernel/btf/vmlinux` `6,677,359` bytes, `CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y`, `CONFIG_BPF_JIT=y`, `CONFIG_UPROBES=y`, `CONFIG_PERF_EVENTS=y`, OpenSSL `3.5.5`) + `Dockerfile.linux-verify`
- **Constitutional Guardrails:** Zero wrapper crates (`aya`, `libbpf-rs`, `goblin`, `object`, `btf-rs`, `httparse`, `h2`, `hpack`, `redis`, `pgwire`, `pprof`, `inferno`), zero runtime shell-outs (`bpftool`, `tc`, `ip`, `tcpdump`, `tshark`, `perf`), mandatory RAII FD/Link guards, `#![deny(unsafe_code)]` outside `spectre-elf-btf::{syscall,ringbuf}` and `spectre-xdp::netlink`, Go `RET`-offset uprobe safety (no `uretprobe` on Go targets).

## Module Status Matrix

| Module | Crate / Directory | Status | Tests / Oracle Gate | Key Verified Metrics |
| --- | --- | --- | --- | --- |
| **M01** | `crates/spectre-elf-btf` | **PASSED** | `6/6` release + `4/4` Miri (`0` UB) | UAPI `BpfProgLoadAttr` exact offsets, `10,000` hostile ELF/BTF fuzz `0` panics, CO-RE flavor+anon union pass, `10,000/10,000` live Linux 6.18 RingBuf zero-drop & `0` FD leaks |
| **M02** | `crates/spectre-verifier` | **PASSED** | `4/4` suites (`133` programs) | `Tnum` + strict & `CAP_PERFMON` modes: `133/133` (`0` false accepts / 100% soundness) vs Linux 6.18 `BPF_PROG_LOAD`, `BpfVm` + `disasm` verified on Linux & Windows |
| **M03** | `probes/xdp_net` & `crates/spectre-xdp` | **PASSED** | `3/3` Linux kernel suites + cross-OS clippy/tests | `50,430+` frame XDP `BPF_PROG_TEST_RUN` + `BpfVm` parity, isolated `netns` `veth` AF_NETLINK ratelimit drop & detach, CO-RE RTT + PID-ns L7 cleartext capture & `0` FD leaks (`.text` = `0 B`) |
| **M04** | `probes/tls_uprobe` & `crates/spectre-tls` | **PASSED** | `5/5` tests (unit + live OpenSSL/Go TLS 1.3) | `ret_scanner` `objdump` exact parity, OpenSSL `3.5.5` `1,000` TLS 1.3 req/resp incl. `20,480 B` (`>16 KB`) 100% plaintext, Go `1.26` `64` goroutines w/ recursive stack growth (`0` crashes, `0` RingBuf drops, `0` FD leaks, `18.49s` total) |
| **M05** | `crates/spectre-l7` | **PASSED** | `4/4` release + `wasm32` check | `#![deny(unsafe_code)]`; RFC 7541 Appendix C.4/C.6 HPACK+Huffman exact pass; 1B/3B/random fragmentation parity across HTTP/1.1, HTTP/2+gRPC, PG v3 (SQL sanitizer), & Redis RESP2/3; `100,000` adversarial fuzz `0` panics (`0.82s` Linux / `0.43s` Win) |
| **M06** | `probes/profiler` & `crates/spectre-profile` | PENDING | Pending M06 gate | — |
| **M07** | `crates/spectre-oracle` | PENDING | Pending M07 gate | — |
| **M08** | `crates/spectre-daemon` & `crates/spectre-tui` | PENDING | Pending M08 gate | — |
| **M09** | `crates/spectre-wasm` & `studio/` | PENDING | Pending M09 gate | — |
