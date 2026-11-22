# SpectreMesh (`spectre-mesh`)

Zero-instrumentation eBPF L7 protocol profiler, plaintext TLS uprobe interceptor (OpenSSL 3.x & Go `crypto/tls`), XDP token-bucket packet filter, continuous 99 Hz On-CPU / `sched_switch` Off-CPU flamegraph engine, and WebAssembly eBPF static verifier studio — built from first principles in pure Rust + Restricted C.

---

## Core Capabilities

| Layer | Implementation | Key Engineering Proofs |
| --- | --- | --- |
| **Pure-Rust Loader & RingBuf** | `crates/spectre-elf-btf` | ELF64 + `.gopclntab` + BTF/`.BTF.ext` CO-RE relocator + raw `SYS_bpf` + double-`mmap` `BPF_MAP_TYPE_RINGBUF`; passes `cargo +nightly miri test` (`0` UB) & 10k malformed ELF fuzz (`0` panics) |
| **eBPF Verifier & VM** | `crates/spectre-verifier` | Pure-Rust (`#![deny(unsafe_code)]`) ISA v3 disassembler, `Tnum` abstract interpreter, packet bounds & DAG checker; `133/133` differential equivalence vs Linux 6.18 `BPF_PROG_LOAD` (`0` false accepts) |
| **XDP & TCP Probes** | `probes/xdp_net.bpf.c`, `probes/tcp_trace.bpf.c`, `crates/spectre-xdp` | L2/VLAN/IPv4/IPv6/TCP XDP parser + per-CPU token-bucket SYN filter via `AF_NETLINK` + `CLONE_NEWNET` `veth` tests; CO-RE `tcp_sock` SRTT & cleartext syscall capture |
| **Plaintext TLS Uprobes** | `probes/tls_openssl.bpf.c`, `probes/tls_go.bpf.c`, `crates/spectre-tls` | OpenSSL 3.5.5 TLS 1.3 recovery (`>16 KB` payloads, `0` drops) + Go 1.26 `crypto/tls` **`RET`-offset entry uprobes** (`0` goroutine stack crashes across 64 concurrent goroutines) |
| **Streaming L7 Dissectors** | `crates/spectre-l7` | `#![deny(unsafe_code)]` HTTP/1.1, HTTP/2 + full RFC 7541 HPACK/Huffman + gRPC protobuf inspector, PostgreSQL v3 (`$1/$2` SQL sanitizer), Redis RESP2/3 (`100k` fuzz `0` panics, `1094.9 k req/s`) |
| **Continuous Profiler** | `probes/profiler.bpf.c`, `crates/spectre-profile` | 99 Hz On-CPU (`78.9%` in `hot_sha256_spin`) & `sched_switch` Off-CPU (`64.3%` in `contended_mutex_wait` + kernel futex frames), ASLR + `/proc/kallsyms` symbolizer, Red/Blue differential SVG flamegraphs |
| **50,000-Req Mesh Oracle** | `crates/spectre-oracle` | Live end-to-end verification across OpenSSL HTTP/1.1, Go HTTP/2+gRPC, PG v3, Redis RESP3, and XDP flood (`50,000/50,000` recovered, `0` mismatches, `0` RingBuf drops, `0` Go crashes, `195` XDP drops, `delta_p99 <= 0.791 ms`) |
| **Daemon, Bench & TUI** | `crates/spectre-daemon`, `crates/spectre-tui` | `spectred` (`axum` Prometheus `/metrics`, `/v1/*`, SSE), `spectre-bench` (`10.10 Mpps` XDP, `+48.99 us/req` OpenSSL TLS uprobe), and `spectre-top` 4-panel `ratatui` TUI |
| **WASM Studio** | `crates/spectre-wasm`, `studio/` | `wasm32-unknown-unknown` (`+simd128` + `wasm-opt -O3`, `257 KB` WASM) inside a Dedicated WebWorker + Vite/TypeScript 3-workbench SPA |

---

## Quick Start

### Prerequisites (Linux / WSL2 Kernel >= 5.10 with BTF)
- Rust `stable` (with `rustfmt`, `clippy`, `wasm32-unknown-unknown`) + `wasm-bindgen-cli` (`0.2.130`)
- `clang`, `llvm-strip`, `gcc`, `libssl-dev`, `golang-go`, `binaryen` (`wasm-opt`), `nodejs` + `npm`
- Non-Linux hosts can verify reproducibly via [Dockerfile.linux-verify](Dockerfile.linux-verify) (`make docker-verify`).

### Build & Verify Commands

```bash
# Run the complete M01–M09 verification pipeline (requires root/CAP_BPF for live eBPF gates)
make verify-all

# Individual stages
make build-probes      # Compile all CO-RE eBPF bytecode objects -> probes/build/*.bpf.o
make check             # Format check, clippy -D warnings, and stub macro enforcement
make test              # Workspace release unit + live kernel tests
make fuzz-l7-elf       # 10k ELF/BTF fuzz + 100k L7 protocol fuzz
make mesh-oracle       # 50,000-request live encrypted multi-service oracle
make bench             # Write docs/benchmarks/ebpf_perf.{md,json} & studio telemetry summary
make wasm-studio       # Compile spectre-wasm (+simd128), run Vitest, and bundle Vite SPA

# Cross-OS portable verification (Windows / macOS)
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p spectre-verifier -p spectre-l7 -p spectre-daemon -p spectre-tui -p spectre-wasm --release
```

### Design & Benchmark Documentation
- Architecture Overview: [ARCHITECTURE.md](ARCHITECTURE.md)
- Progress Tracker: [PROGRESS.md](PROGRESS.md)
- Benchmark Report: [docs/benchmarks/ebpf_perf.md](docs/benchmarks/ebpf_perf.md)
- Module Specs: `docs/design/M01_*.md` through `docs/design/M09_*.md`
