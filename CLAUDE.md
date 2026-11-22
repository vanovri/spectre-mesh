# CLAUDE.md — Constitutional Engineering Laws for SpectreMesh

## 1. Mission & Architectural Identity
You are building **SpectreMesh**, a production-grade eBPF Zero-Instrumentation L7 Protocol Profiler, Plaintext TLS Uprobe Mesh, XDP Packet Filter, Continuous CPU/Off-CPU Flamegraph Engine, and WebAssembly eBPF Static Verifier Studio in Rust (Edition 2021/2024) + Restricted C (`clang -target bpf -O2 -g`).

Every subsystem must embody real-world kernel observability engineering (Cilium, Pixie, Grafana Beyla, Parca):
- **Zero-Instrumentation Plaintext TLS (No MITM Proxy, No Root CA Injection):** Capture plaintext application payloads directly at userspace crypto boundaries (`SSL_write`/`SSL_read` in OpenSSL/BoringSSL and `crypto/tls.(*Conn).Write`/`Read` in Go binaries) via kernel `uprobes`, correlating them with socket 5-tuples `(src_ip, dst_ip, src_port, dst_port, pid, fd)` without touching application source code or breaking TLS 1.3 certificate pinning!
- **Go Goroutine Stack-Safety Law (NO Kernel `uretprobe` on Go Binaries!):** Go dynamically grows and relocates goroutine stacks at function prologues; attaching a standard Linux kernel `uretprobe` overwrites the goroutine stack return address with a kernel trampoline and fatally crashes Go targets when the stack moves! Therefore, for Go targets (`M04`), `SpectreMesh` MUST parse `.gopclntab`/`.symtab`, disassemble the target function instructions (`x86_64` `0xC3` `RET` / `aarch64` `0xD65F03C0` `RET`), and attach **entry `uprobes` directly at every `RET` offset** instead of kernel `uretprobe`!
- **Kernel Verifier Discipline:** Every eBPF probe in `probes/` MUST compile cleanly with `clang -target bpf -O2 -g -Wall -Werror` producing valid `.BTF` and `.BTF.ext` CO-RE sections, obey the strict 512-byte eBPF stack ceiling (using `BPF_MAP_TYPE_PERCPU_ARRAY` scratch heaps for structs > 256 bytes!), enforce explicit packet pointer bounds checks (`if (data + sizeof(*hdr) > data_end) return XDP_PASS;`), and pass BOTH our pure-Rust Static Verifier (`M02`) AND the live Linux kernel eBPF verifier!

## 2. Strictly Banned Shortcuts & Forbidden Dependencies
1. **NO eBPF Loader, ELF, or Protocol Wrapper Crates:**
   - Workspace crates MUST NOT depend on `aya`, `libbpf-rs`, `libbpf-sys`, `redbpf`, `goblin`, `object`, `btf-rs`, `httparse`, `h2`, `hpack`, `redis`, `pgwire`, `pprof`, or `inferno`.
   - **STRICTLY FORBIDDEN** to shell out via `std::process::Command` to `bpftool`, `tc`, `ip`, `tcpdump`, `tshark`, or `perf` inside runtime crates (`clang` is invoked strictly at build time in `build.rs`/`Makefile` to emit `.bpf.o` bytecode; all ELF parsing, BTF CO-RE relocation, `SYS_bpf` syscalls, perf/ringbuf `mmap`, netlink XDP/TC attachment, L7 HPACK/PG/Redis decoding, and Flamegraph generation MUST be pure Rust!).
2. **Permitted Minimal Dependencies Only:**
   - Core/Loader/L7/Profiler (`spectre-elf-btf`, `spectre-verifier`, `spectre-xdp`, `spectre-tls`, `spectre-l7`, `spectre-profile`): `libc`, `bitflags`, `thiserror`, `memchr`, `crc32c`, `serde`, `serde_json`.
   - Daemon/TUI (`spectre-daemon`, `spectre-tui`): `tokio`, `axum`/`hyper`, `clap`, `ratatui`, `crossterm`, `parking_lot`.
   - WASM (`spectre-wasm`): `wasm-bindgen`, `js-sys`, `serde-wasm-bindgen`.
3. **ZERO Incomplete Code & Resource Leaks:** `todo!()`, `unimplemented!()`, `#[ignore]`, and dangling kernel BPF links/uprobes/XDP attachments left behind after process exit are **STRICTLY FORBIDDEN**. Every BPF program/map/link MUST be wrapped in RAII `OwnedFd` / `BpfLinkGuard` (preferring `BPF_LINK_CREATE` auto-cleanup on FD close, plus explicit `uprobe` perf-event/kprobe detach on `Drop`!).
4. **`unsafe` Quarantine Policy:**
   - `#![deny(unsafe_code)]` MUST be active in `spectre-verifier`, `spectre-l7`, `spectre-daemon`, `spectre-tui`, and `spectre-wasm`!
   - Controlled `unsafe` is permitted ONLY inside `spectre-elf-btf::syscall` (`SYS_bpf`, `perf_event_open`, `ioctl`), `spectre-elf-btf::ringbuf` (lock-free `mmap` consumer/producer ring with strict `Ordering::Acquire` / `Ordering::Release` barriers), and `spectre-xdp::netlink` (XDP/TC netlink attach). Every `unsafe` block MUST have a `// SAFETY:` proof comment and pass `cargo +nightly miri test` on pure-memory parsing/ringbuf unit suites.

## 3. Dual-Mode Portability (Linux Kernel + Cross-OS `Dockerfile.linux-verify`)
- Modules `M01` (ELF/BTF parser + ringbuf mock), `M02` (eBPF Static Verifier & VM), `M05` (L7 HTTP/2 HPACK/gRPC/PG/Redis decoders), `M06` (Flamegraph & stack aggregator), and `M09` (WASM Studio) MUST compile and pass 100% of unit/fuzz tests natively on ANY OS (Linux, macOS, Windows, and `wasm32-unknown-unknown`).
- Live kernel BPF loading, XDP `veth` packet filtering, OpenSSL/Go TLS `uprobes`, and `perf_event` profiling execute directly on Linux/WSL2 (>= 5.10 with BTF `/sys/kernel/btf/vmlinux`) OR deterministically inside `Dockerfile.linux-verify` (`docker run --rm --privileged`).

## 4. Autonomous Progression Protocol (`PROGRESS.md`)
Maintain `PROGRESS.md` tracking `M01` through `M09`. Never advance from `M(k)` to `M(k+1)` until:
1. `cargo fmt --check` and `cargo clippy --workspace --all-targets -- -D warnings` pass with `0` warnings.
2. All verifier, fuzz, protocol, and live kernel leak-check gates for `M01..M(k)` pass 100%.
3. Verified metrics are appended to `PROGRESS.md` and cleanly committed (`feat(mXX): ...`).
