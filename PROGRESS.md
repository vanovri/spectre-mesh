# SpectreMesh (`spectre-mesh`) — Autonomous Engineering Progression Ledger

## Environment & Execution Harness
- **Repository Root:** `C:\Users\ardhy\.gemini\antigravity\scratch\spectre-mesh`
- **Live Linux Kernel Target:** `WSL2 Ubuntu-26.04` (`Linux 6.18.33.2-microsoft-standard-WSL2 x86_64`, `/sys/kernel/btf/vmlinux` `6,677,359` bytes, `CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y`, `CONFIG_BPF_JIT=y`, `CONFIG_UPROBES=y`, `CONFIG_PERF_EVENTS=y`, OpenSSL `3.5.5`) + `Dockerfile.linux-verify`
- **Constitutional Guardrails:** Zero wrapper crates (`aya`, `libbpf-rs`, `goblin`, `object`, `btf-rs`, `httparse`, `h2`, `hpack`, `redis`, `pgwire`, `pprof`, `inferno`), zero runtime shell-outs (`bpftool`, `tc`, `ip`, `tcpdump`, `tshark`, `perf`), mandatory RAII FD/Link guards, `#![deny(unsafe_code)]` outside `spectre-elf-btf::{syscall,ringbuf}` and `spectre-xdp::netlink`, Go `RET`-offset uprobe safety (no `uretprobe` on Go targets).

## Module Status Matrix

| Module | Crate / Directory | Status | Tests / Oracle Gate | Key Verified Metrics |
| --- | --- | --- | --- | --- |
| **M01** | `crates/spectre-elf-btf` | IN PROGRESS | Pending M01 gate | — |
| **M02** | `crates/spectre-verifier` | PENDING | Pending M02 gate | — |
| **M03** | `probes/xdp_net` & `crates/spectre-xdp` | PENDING | Pending M03 gate | — |
| **M04** | `probes/tls_uprobe` & `crates/spectre-tls` | PENDING | Pending M04 gate | — |
| **M05** | `crates/spectre-l7` | PENDING | Pending M05 gate | — |
| **M06** | `probes/profiler` & `crates/spectre-profile` | PENDING | Pending M06 gate | — |
| **M07** | `crates/spectre-oracle` | PENDING | Pending M07 gate | — |
| **M08** | `crates/spectre-daemon` & `crates/spectre-tui` | PENDING | Pending M08 gate | — |
| **M09** | `crates/spectre-wasm` & `studio/` | PENDING | Pending M09 gate | — |
