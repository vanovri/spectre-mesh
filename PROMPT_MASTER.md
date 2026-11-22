Read `CLAUDE.md` completely and obey every kernel-safety, zero-wrapper, and verification rule. You are autonomously engineering **SpectreMesh** from an empty repository through Module M09 until `make verify-all` passes 100%.

### Environment Probe & Kernel Harness
1. Probe the environment (`uname -a`, `clang --version`, `ls /sys/kernel/btf/vmlinux`, `docker info`).
2. If running on Linux/WSL2 with BTF enabled and `clang`, compile `.bpf.o` probes and execute live kernel BPF/XDP/uprobe tests directly. If on a non-Linux host or lacking kernel BTF headers, immediately build `Dockerfile.linux-verify` so privileged Linux execution runs reproducibly via Docker while pure-Rust crates (`M01`, `M02`, `M05`, `M09`) also verify natively.

### Sequential Engineering Loop (`M01 -> M02 -> M03 -> M04 -> M05 -> M06 -> M07 -> M08 -> M09`)
For each module strictly in order:
1. **Binary & Kernel Spec:**
   - Write `docs/design/MXX_<name>.md` specifying ELF/BTF binary structs, eBPF verifier abstract domain rules, `BPF_MAP_TYPE_RINGBUF` double-mapped memory barriers, Go `RET`-offset uprobe disassembly logic, and HPACK/PG/Redis state-machine transitions.
2. **Complete First-Principles Implementation:**
   - Build every crate, Restricted-C `.bpf.c` probe, L7 decoder, profiler, TUI view, and WASM studio component with zero stubs.
3. **Adversarial Verification & Fuzz Gate:**
   - Run `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace --release`.
   - Whenever the Linux kernel verifier rejects a `.bpf.o` probe, our pure-Rust verifier disagrees with the kernel verifier, a Go target crashes under uprobe stress, or the L7/ELF fuzzer triggers a panic: capture the exact reproducer, add a permanent regression test, fix the root cause, and re-verify 100% green.
4. **Checkpoint & Advance:**
   - Log verified test counts, verifier instruction budgets, XDP pps, TLS recovery rates, and RingBuf zero-drop metrics into `PROGRESS.md`, create an atomic commit (`feat(mXX): ...`), and immediately advance to the next module through `M09`.

Initialize the Cargo workspace, `rust-toolchain.toml`, `Dockerfile.linux-verify`, `Makefile`, and `PROGRESS.md` now, then execute **M01** through **M09** using the exact specifications below.

---

## MODULE M01 SPECIFICATION: `crates/spectre-elf-btf`

### Scope & Objective
Build a completely self-contained, `libbpf`-free eBPF object loader in pure Rust: parsing ELF64 `.bpf.o` binaries, decoding `.BTF` / `.BTF.ext` and `/sys/kernel/btf/vmlinux` type graphs, applying CO-RE (Compile Once – Run Everywhere) field relocations, loading maps/programs via raw `SYS_bpf`, and consuming kernel events through a lock-free double-`mmap`ed `BPF_MAP_TYPE_RINGBUF` consumer.

### Exact Components to Implement
1. **Zero-Copy Bounds-Checked ELF64 Parser (`elf64.rs`):**
   - Parse `Elf64_Ehdr`, `Elf64_Shdr` (section headers & `.shstrtab`), `Elf64_Sym` (`.symtab`/`.strtab`), `Elf64_Rel`/`Elf64_Rela` (map FD relocation entries `R_BPF_64_64` rewriting `BPF_PSEUDO_MAP_FD` into `ld_imm64` instructions!), and special `.maps` BTF-defined map sections (`__uint(type, ...)`, `__uint(max_entries, ...)`).
   - Also parse userspace ELF dynamic/static symbols (`.dynsym`, `.symtab`, `.gopclntab` v1.18/v1.20+ header) to support `M04` TLS uprobe symbol & file-offset resolution!

2. **BTF & CO-RE Relocation Engine (`btf.rs`, `core_reloc.rs`):**
   - Decode the binary BTF header (`magic = 0xEB9F`, `hdr_len`, `type_off/len`, `str_off/len`) and all standard `BTF_KIND_*` records (`INT`, `PTR`, `ARRAY`, `STRUCT`, `UNION`, `ENUM`, `FWD`, `TYPEDEF`, `VOLATILE`, `CONST`, `RESTRICT`, `FUNC`, `FUNC_PROTO`, `VAR`, `DATASEC`).
   - Parse `.BTF.ext` CO-RE relocation records (`bpf_core_relo { insn_off, type_id, access_str_off, kind }`), resolve candidate matching kernel structs inside `/sys/kernel/btf/vmlinux` (handling struct flavor suffixes like `task_struct___old` and nested anonymous unions/bitfields!), and poison or patch `bpf_insn` immediates/offsets for:
     - `BPF_CORE_FIELD_BYTE_OFFSET`, `BPF_CORE_FIELD_BYTE_SIZE`, `BPF_CORE_FIELD_EXISTS`, `BPF_CORE_TYPE_EXISTS`, `BPF_CORE_TYPE_SIZE`.

3. **Raw `SYS_bpf` Syscall Loader & RAII Lifecycle (`loader.rs`):**
   - Direct `libc::syscall(libc::SYS_bpf, cmd, &attr, size)` wrappers (`#[repr(C)] union BpfAttr`) for:
     - `BPF_MAP_CREATE`, `BPF_MAP_LOOKUP_ELEM`, `BPF_MAP_UPDATE_ELEM`, `BPF_MAP_DELETE_ELEM`, `BPF_MAP_GET_NEXT_KEY`
     - `BPF_PROG_LOAD` (capturing full kernel verifier `log_buf` diagnostics on failure with annotated BPF disassembly!)
     - `BPF_LINK_CREATE` & `BPF_OBJ_PIN` / `BPF_OBJ_GET`
     - `BPF_PROG_TEST_RUN` (enables fast kernel-in-the-loop unit testing of XDP/TC eBPF programs directly on synthetic packet buffers!).
   - Every map FD, prog FD, and link FD is owned by RAII `OwnedBpfFd`—closing automatically on `Drop` so zero zombie hooks persist.

4. **Lock-Free Zero-Copy `BPF_MAP_TYPE_RINGBUF` Consumer (`ringbuf.rs`):**
   - Implement exact Linux kernel RingBuf memory mapping protocol:
     1. `mmap` page 0 (`PROT_READ | PROT_WRITE`, `MAP_SHARED`, offset `0`) -> `consumer_pos: *mut AtomicU64`.
     2. `mmap` page 1 + `2 * ring_size` bytes (`PROT_READ`, `MAP_SHARED`, offset `page_size`) -> `producer_pos: *const AtomicU64` + **doubly-mapped contiguous data region** so records straddling the ring wrap boundary are read as one flat `&[u8]` slice with zero copying!
   - Read header word (`len_and_flags: u32`, checking `BPF_RINGBUF_BUSY_BIT = 1 << 31` and `BPF_RINGBUF_DISCARD_BIT = 1 << 30`) via `Ordering::Acquire`, advance `consumer_pos` rounded to 8-byte alignment via `Ordering::Release`, and wait efficiently with `epoll_wait` on the ringbuf FD when idle!

### M01 Verification Gate
- `cargo +nightly miri test -p spectre-elf-btf` on ELF64, BTF, CO-RE relocation, and in-memory simulated double-mapped RingBuf tests -> 0 UB.
- **10,000 Hostile ELF64 & BTF Fuzz Inputs:** Mutated/truncated/cyclic-type-graph `.o` and `.btf` blobs -> 0 panics, 100% clean `ElfBtfError`.
- Live Linux Kernel Test: compile a minimal `.bpf.c` program emitting 10,000 structured records to `BPF_MAP_TYPE_RINGBUF` via `BPF_PROG_TEST_RUN`, load via `spectre-elf-btf`, verify all 10,000 sequence-numbered records arrive zero-copy with 0 drops and 0 leaked FDs.

---

## MODULE M02 SPECIFICATION: `crates/spectre-verifier`

### Scope & Objective
Build an offline **eBPF ISA v3 Bytecode Disassembler, Concrete Simulator, and Static Abstract-Interpretation Verifier** in 100% `#![deny(unsafe_code)]` Rust. It serves as both a rapid pre-flight oracle checking every compiled `.bpf.o` probe against kernel verifier laws AND the core engine compiled to WebAssembly in `M09` Studio!

### Exact Components to Implement
1. **Complete eBPF ISA v3 Decoder & Disassembler (`isa.rs`, `disasm.rs`):**
   - Decode 64-bit `BpfInsn { code: u8, dst_src: u8, off: i16, imm: i32 }` (and 128-bit `BPF_LD | BPF_DW | BPF_IMM` double-slot instructions) across all instruction classes: `ALU` (32-bit zero-extending!), `ALU64`, `JMP`, `JMP32`, `LDX`, `STX`, `ST`, `ATOMIC` (`BPF_ADD`, `BPF_XCHG`, `BPF_CMPXCHG`), `CALL` (BPF helper IDs + BPF-to-BPF pseudo-calls), and `EXIT`.
   - Human-readable kernel-style disassembly (`r1 = *(u32 *)(r1 + 0); if r2 > r3 goto +4;`).

2. **Abstract-Interpretation Static Verifier (`verifier.rs`):**
   - Implement exact abstract domain tracking per register `R0..R10` and 512-byte stack slots (`[-512..0]`):
     - **`Tnum` (Tristate Number — Vishwanathan et al., Kernel `kernel/bpf/tnum.c`):** `struct Tnum { value: u64, mask: u64 }` tracking known-0, known-1, and unknown bits through bitwise `AND`, `OR`, `XOR`, `LSH`, `RSH`, and `ADD`, paired with `[umin, umax]` and `[smin, smax]` interval bounds!
     - **Register Types:** `NotInit`, `ScalarValue(Bounds)`, `PtrToCtx`, `PtrToStack { off }`, `PtrToPacket { id, off, range }`, `PtrToPacketEnd`, `PtrToMapValue { map_id, off, size, nullable }`, `PtrToRingBufMem { size, nullable }`.
     - **Path-Sensitive Branch Refinement:** On conditional jump `if r2 > r3 goto L_drop` where `r2 = PtrToPacket(off=14)` and `r3 = PtrToPacketEnd`, automatically refine `r2.range = max(r2.range, 14)` on the fall-through branch—proving subsequent `*(u16 *)(r2 - 2)` is provably safe!
     - **Null-Check Tracking:** Require `if r0 == 0 goto exit` before dereferencing `PtrToMapValue { nullable: true }` or `PtrToRingBufMem { nullable: true }`!
     - **Safety & Termination Proofs:** Enforce read-only `R10` frame pointer, uninitialized stack/register read rejection, `R1..R5` caller-saved clobbering on `CALL`, strict 512-byte stack boundary, leak detection for unsubmitted/undiscarded `bpf_ringbuf_reserve` pointers on `BPF_EXIT`, and DFS cycle + state-pruning instruction counter (max `1,000,000` explored states).
   - Emit rich step-by-step **Verifier Trace Logs** (`pc`, `insn_text`, `reg_diffs`, `verdict`, `error_reason`) consumed directly by CLI diagnostics and `M09` WASM Studio!

3. **Concrete eBPF Execution Sandbox VM (`vm.rs`):**
   - Execute verified eBPF programs in pure Rust against synthetic `xdp_md` packets and mock BPF maps (`Hash`, `Array`, `PerCpuArray`, `RingBuf`)—making XDP logic testable deterministically in unit tests and inside browsers!

### M02 Verification Gate
- **Differential Kernel Verifier Equivalence Suite (120+ Hand-Crafted & Mutated Programs):** Test valid XDP parsers, missing packet-bounds checks, null-dereference map lookups, 520-byte stack overflows, leaked `ringbuf_reserve` handles, uninitialized `R4` reads, and subtle 32-bit ALU signed/unsigned truncation traps—asserting our pure-Rust Static Verifier matches the real Linux kernel `BPF_PROG_LOAD` Accept/Reject verdict with **0 false accepts (100% soundness)**!

---

## MODULE M03 SPECIFICATION: `probes/xdp_net` & `crates/spectre-xdp`

### Scope & Objective
Write production Restricted-C eBPF XDP and TC/Socket probes loaded by `M01`, delivering line-rate L3/L4 packet parsing, zero-lock per-CPU token-bucket SYN/DDoS dropping, and kernel-level TCP connection lifecycle & RTT telemetry.

### Exact Components to Implement
1. **XDP L2/L3/L4 Fast-Path Firewall (`probes/xdp_net.bpf.c`):**
   - Parse Ethernet (`802.1Q` VLAN double-tag bounded loop `max 2 tags`), IPv4 (variable `ihl * 4` validated against `data_end`!), IPv6, TCP, and UDP headers cleanly inside verifier bounds.
   - **Per-CPU Lock-Free Token Bucket (`BPF_MAP_TYPE_PERCPU_HASH`):** Keyed by source IPv4/IPv6 prefix, tracking `(tokens_scaled: u64, last_refill_ns: u64)` via `bpf_ktime_get_ns()`. Instantly returns `XDP_DROP` on SYN-flood or blacklisted CIDR hits while incrementing lock-free `BPF_MAP_TYPE_PERCPU_ARRAY` telemetry counters (`rx_packets`, `rx_bytes`, `xdp_pass`, `xdp_drop_ratelimit`, `xdp_drop_blocklist`, `malformed_drop`)!
   - Emit sampled drop audit events to `BPF_MAP_TYPE_RINGBUF` only on state transitions (preventing drop-floods from saturating the ring buffer!).

2. **Kernel TCP Connection & RTT/Retransmit Tracer (`probes/tcp_trace.bpf.c`):**
   - CO-RE `kprobe`/`fentry` + `tracepoint` hooks:
     - `sock/inet_sock_set_state` (connection open, `ESTABLISHED`, `CLOSE`, tracking `(pid, tid, cgroup_id, saddr, daddr, sport, dport)` in `active_conns` hash map).
     - `tcp/tcp_retransmit_skb` (recording retransmission bursts per 5-tuple!).
     - `kprobe/tcp_rcv_established` reading `BPF_CORE_READ(tp, srtt_us) >> 3` (smoothed kernel TCP RTT in microseconds!) and emitting periodic connection health metrics to `RingBuf`.
     - Cleartext L7 capture hooks (`kprobe/tcp_sendmsg` + `kprobe/tcp_cleanup_rbuf` or `sock_ops`/`sk_msg` for tracked PIDs/ports) streaming bounded chunks (`<= 4,096 B` via `PERCPU_ARRAY` scratch buffer!) to `M05` L7 parser.

3. **Pure-Rust Netlink XDP/TC Attacher (`crates/spectre-xdp`):**
   - Implement raw `NETLINK_ROUTE` `RTM_SETLINK` (`IFLA_XDP` -> `IFLA_XDP_FD` with `XDP_FLAGS_SKB_MODE` / `XDP_FLAGS_DRV_MODE`) and `BPF_LINK_CREATE(BPF_XDP)` without calling `ip link set`!
   - Automatic RAII XDP detachment on drop so interfaces are never left with stale XDP programs.

### M03 Verification Gate
- **BPF_PROG_TEST_RUN + Live `veth` Integration Suite:**
  1. Pass 50,000 synthetic Ethernet/VLAN/IPv4/IPv6/TCP/UDP/truncated frames through `xdp_net.bpf.o` via BOTH `M02` pure-Rust VM AND live kernel `BPF_PROG_TEST_RUN`—verify exact `XDP_PASS` vs `XDP_DROP` parity and token-bucket enforcement!
  2. Attach `xdp_net.bpf.o` to an isolated `veth` pair inside a test `netns`, fire a burst exceeding the rate limit, confirm excess packets drop in-kernel while legitimate flows pass cleanly, and assert clean detach + 0 leaked FDs.

---

## MODULE M04 SPECIFICATION: `probes/tls_uprobe` & `crates/spectre-tls`

### Scope & Objective
Implement zero-instrumentation plaintext TLS capture across both C/C++/Rust/Python/Node workloads (`OpenSSL` / `BoringSSL`) AND Go workloads (`crypto/tls`) without installing root CAs, proxies, or modifying target binaries—including Go's notorious `RET`-offset uprobe safety architecture!

### Exact Components to Implement
1. **OpenSSL 1.1 / 3.x & BoringSSL Uprobe Interception (`probes/tls_openssl.bpf.c`):**
   - Attach `uprobe/SSL_write` & `uprobe/SSL_write_ex` (capturing `ssl_ptr`, plaintext `buf`, and `len` at entry, plus `uretprobe` confirming actual `bytes_written > 0`).
   - Attach `uprobe/SSL_read` & `uprobe/SSL_read_ex` (stashing `(ssl_ptr, buf_ptr, written_ptr)` in per-TID `BPF_MAP_TYPE_HASH` at entry) + `uretprobe/SSL_read` reading exact decrypted plaintext `bytes_read` via `bpf_probe_read_user()` into a `PERCPU_ARRAY` 4 KB scratch buffer and submitting structured `TlsDataEvent { ts_ns, pid, tid, fd, direction, ssl_ptr, len, payload[...] }` to `RingBuf`!
   - **Automatic `SSL* -> Socket FD` Correlation:** Hook `SSL_set_fd` / `SSL_set_rfd` / `SSL_set_wfd` OR read BIO `fd` offset dynamically (resolved per detected OpenSSL version `1.1.1` vs `3.0` vs `3.2`!) AND correlate `(pid, tid)` with active `sys_enter_sendto`/`recvfrom`/`write`/`read` FDs so every decrypted TLS chunk maps accurately to its exact `(src_ip:port -> dst_ip:port)` 5-tuple!

2. **Go `crypto/tls` Safe `RET`-Offset Uprobe Engine (`crates/spectre-tls/src/go_abi.rs` & `probes/tls_go.bpf.c`):**
   - Parse target Go ELF binary (`M01` `.gopclntab` + `.symtab` + `runtime.buildVersion` string) to detect Go version (>= 1.17 register-based `ABIInternal` vs stack-based `ABI0`) and exact file offsets of `crypto/tls.(*Conn).Write` and `crypto/tls.(*Conn).Read`.
   - **Pure-Rust Minimal `x86_64` & `aarch64` Instruction Length Decoder (`ret_scanner.rs`):** Scan the machine code bytes of `crypto/tls.(*Conn).Read` (from `func_start` to `func_end`), locate EVERY instruction boundary ending in `RET` (`0xC3` on `x86_64`, `0xD65F03C0` on `aarch64`) without false-matching `0xC3` inside immediate operands!, and attach normal kernel **entry `uprobes`** at each `RET` offset—**100% immune to Go goroutine stack reallocation crashes!**
   - Inside `tls_go.bpf.c`: read Go slice `(conn_ptr, buf_ptr, buf_len)` directly from `PT_REGS` (`ax`, `bx`, `cx` on `x86_64` `ABIInternal`; `r0`, `r1`, `r2` on `aarch64`), read returned `n` bytes at the `RET` uprobe (`ax` on `x86_64`), and resolve the underlying `net.Conn` `fd` via discovered Go struct offsets!

3. **Userspace Target Discovery & Dynamic Attacher (`crates/spectre-tls/src/discover.rs`):**
   - Scan `/proc/<pid>/maps` to locate loaded `libssl.so*`, statically linked Rust/C binaries, and Go executables, attach via `perf_event_open(PERF_TYPE_uprobe)` / `BPF_LINK_CREATE`, and track process exit via `sched_process_exit` to clean up stale PID maps automatically.

### M04 Verification Gate
- **Live TLS 1.3 Zero-Instrumentation Proof (OpenSSL + Go):**
  1. Launch a real TLS 1.3 HTTPS server + client linked against host `libssl.so` (OpenSSL 3.x) exchanging 1,000 encrypted requests/responses with unique randomized payloads (including > 16 KB multi-frame transfers). Assert `SpectreMesh` recovers **100% of plaintext bytes** with zero MITM proxy and zero modifications to client/server!
  2. Compile and launch a real Go TLS 1.3 server + client running 64 concurrent goroutines with deep recursive stack growth (deliberately forcing Go stack moves during `tls.(*Conn).Read`!)—assert **100% plaintext recovery** AND **0 Go target crashes** (proving `RET`-offset uprobe safety!).

---

## MODULE M05 SPECIFICATION: `crates/spectre-l7`

### Scope & Objective
Build `#![deny(unsafe_code)]`, zero-panic streaming L7 protocol parsers and request-response latency matchers that reassemble arbitrary TCP/TLS byte chunks delivered from kernel `RingBuf` events into rich distributed-tracing spans (`L7Span`).

### Exact Components to Implement
1. **Per-Connection Ordered Stream Buffer (`conn_state.rs`):**
   - Keyed by `(pid, fd, conn_epoch)` maintaining independent `Ingress` and `Egress` ring byte buffers with bounded memory caps (evicting idle/stalled connections cleanly after configurable TTL so malicious slowloris flows never OOM the collector!).
   - **Automatic Protocol Classification (`classifier.rs`):** Inspects first bytes of a new connection (`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`, HTTP/1.1 verbs, PostgreSQL startup/tag framing, Redis RESP `*<n>\r\n$...`) to bind the exact state machine automatically.

2. **Four Complete Streaming Protocol Decoders (`protocols/`):**
   - **HTTP/1.1 (`http1.rs`):** Handles pipelined requests, `Content-Length`, `Transfer-Encoding: chunked`, header normalization (`Host`, `User-Agent`, `traceparent` W3C Trace Context extraction!), and precise `request_start_ns -> first_response_byte_ns -> response_complete_ns` timing.
   - **HTTP/2 & gRPC (`http2.rs`, `hpack.rs`, `grpc.rs`):**
     - Full binary 9-byte frame parser (`DATA`, `HEADERS`, `RST_STREAM`, `SETTINGS`, `PING`, `GOAWAY`, `WINDOW_UPDATE`, `CONTINUATION`) tracking multiplexed `stream_id` lifecycles concurrently!
     - **From-Scratch RFC 7541 HPACK Decoder (`hpack.rs`):** Complete 61-entry Static Table, FIFO Dynamic Table with `SETTINGS_HEADER_TABLE_SIZE` updates, integer prefix decoder (N-bit), and **canonical RFC 7541 Appendix B Huffman decoder** (lookup-table accelerated!).
     - **gRPC Frame Inspector:** Detects `content-type: application/grpc`, decodes 5-byte length-prefixed gRPC message envelopes (`compressed_flag + msg_len`), parses `:path` (`/package.Service/Method`) and `grpc-status` trailers, and inspects top-level Protobuf varint/length-delimited wire tags!
   - **PostgreSQL v3 Wire Protocol (`postgres.rs`):**
     - Decodes Frontend (`'Q'` Simple Query, `'P'` Parse, `'B'` Bind, `'E'` Execute, `'S'` Sync) and Backend (`'T'` RowDescription, `'D'` DataRow count, `'C'` CommandComplete, `'E'` ErrorResponse SQLSTATE, `'Z'` ReadyForQuery), sanitizing SQL literals into normalized query fingerprints (`SELECT * FROM orders WHERE id = $1`) while preserving per-statement execution latency!
   - **Redis RESP2 / RESP3 (`redis.rs`):**
     - Streaming parser for Simple Strings, Errors, Integers, Bulk Strings, Arrays, Maps/Sets (RESP3), matching pipelined command queues (`GET`, `SET`, `HGETALL`, `EVAL`) to exact responses and extracting key prefixes + error rates.

### M05 Verification Gate
- **100,000-Input Adversarial Fragmentation & Protocol Fuzzer:**
  1. Take real captured byte streams for HTTP/1.1, HTTP/2 + HPACK (with Huffman encoding + dynamic table eviction), gRPC, PostgreSQL Extended Query, and pipelined Redis—slice EVERY stream at arbitrary 1-byte, 3-byte, and random chunk boundaries and verify **100% bit-exact `L7Span` recovery** regardless of fragmentation!
  2. Feed 100,000 mutated, truncated, bogus-length, and Huffman-invalid byte buffers into all 4 parsers—assert **0 panics**, **0 unbounded allocations**, and clean bounded recovery.

---

## MODULE M06 SPECIFICATION: `probes/profiler` & `crates/spectre-profile`

### Scope & Objective
Build a low-overhead (< 1% CPU) continuous whole-system and per-PID **On-CPU & Off-CPU eBPF Profiler** capturing kernel+user stack traces in real time, symbolizing binaries cleanly, and generating interactive **Differential Flamegraphs** comparing baseline vs regressed runs.

### Exact Components to Implement
1. **On-CPU `perf_event` & Off-CPU `sched_switch` eBPF Probes (`probes/profiler.bpf.c`):**
   - **On-CPU Sampler (`SEC("perf_event")`):** Attached across all online CPU cores via `perf_event_open(PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CPU_CLOCK, sample_freq = 99)`! Captures `bpf_get_stackid(ctx, &stack_traces, 0)` (kernel stack) and `BPF_F_USER_STACK` (user stack) keyed by `(pid, comm, kern_stack_id, user_stack_id)` into a `BPF_MAP_TYPE_HASH` count accumulator—aggregating inside kernel memory so userspace wakes up only once per second (near-zero ringbuf traffic!).
   - **Off-CPU Latency Profiler (`SEC("tp/sched/sched_switch")`):** Records `start_ns` when a tracked thread blocks (`prev_state != TASK_RUNNING`), computes `delta_ns = now - start_ns` when scheduled back in, filters stalls > threshold (e.g., `100 µs`), and accumulates total blocked nanoseconds per `(user_stack_id, kern_stack_id)`—exposing lock contention, futex waits, and disk/network I/O stalls invisible to normal CPU profilers!

2. **Pure-Rust Userspace & Kernel Symbolizer (`symbolizer.rs`):**
   - Kernel symbols: parse `/proc/kallsyms` into a sorted address vector with O(log N) binary search.
   - Userspace ELF symbols: parse `/proc/<pid>/maps` to map virtual IP addresses to `(binary_path, file_offset)`, resolve symbols via `M01` ELF `.symtab` / `.dynsym` / `.gopclntab` + Rust/C++ symbol demangling (implement clean Rust legacy & v0 basic demangler!), caching per `(inode, mtime)` to avoid repeated disk reads!

3. **Folded Stack Tree & Interactive Differential Flamegraph Renderer (`flamegraph.rs`):**
   - Convert raw samples into merged Trie nodes (`FrameNode { symbol, self_value, total_value, children }`), emit standard Brendan Gregg `.folded` format, and render crisp standalone SVG AND compact JSON flamegraph payloads (supporting **Differential Mode**: blue = faster / fewer samples, red = regression / hotter samples!).

### M06 Verification Gate
- **Synthetic Bottleneck Attribution Proof:** Spawn a dual-workload target process compiled with frame pointers (`-C force-frame-pointers=yes`):
  - Thread A spends 80% time inside `fn hot_sha256_spin()` (CPU-bound).
  - Thread B spends 80% time blocked inside `fn contended_mutex_wait()` (Off-CPU futex stall).
  Run `SpectreMesh` profiler for 3 seconds and assert:
  1. On-CPU profile identifies `hot_sha256_spin` as top user frame (> 50% of on-CPU samples).
  2. Off-CPU profile identifies `contended_mutex_wait` + kernel futex stack as top blocked stall source (> 50% of off-CPU wait time).
  3. Generated `.folded` and SVG flamegraph artifacts parse cleanly with zero unresolved address corruption.

---

## MODULE M07 SPECIFICATION: `crates/spectre-oracle`

### Scope & Objective
Construct a self-contained, fully automated **Multi-Service Encrypted Microservice Mesh Testbed** that spawns real communicating services over isolated Linux network namespaces while `SpectreMesh` observes them with **zero instrumentation**, verifying ground-truth accuracy across 50,000 requests.

### Exact Components to Implement
1. **Isolated Live Mesh Harness (`mesh_harness.rs`):**
   - Creates a clean test topology (`veth-client <-> veth-server`) and spins up 4 real local target processes (using minimal embedded/compiled test servers with ZERO SpectreMesh SDK imports!):
     1. **TLS 1.3 HTTP/2 gRPC Service** (OpenSSL-backed + Go `crypto/tls`-backed)
     2. **PostgreSQL v3 Mock/Real Wire Server** (handling Simple + Extended queries with known injected latency profiles: `5 ms` fast vs `40 ms` slow queries)
     3. **Redis RESP3 Server** (handling pipelined `GET`/`SET` bursts)
     4. **Attacker Traffic Generator** (sending malformed packets + SYN rate-limit floods into the XDP interface).

2. **Ground-Truth Oracle Assertions (`oracle.rs`):**
   - Every synthetic client records the exact `(request_id, protocol, method/query, payload_sha256, status_code, client_measured_latency_us)` into a ground-truth ledger.
   - `SpectreMesh` observes all processes externally via eBPF (`XDP` + `uprobe` + `kprobe` + `profiler`) and exports captured `L7Span`s.
   - **Strict Differential Checks:**
     1. **Zero Blind Spots:** 100% of 50,000 encrypted HTTP/1.1, HTTP/2 gRPC, PostgreSQL, and Redis requests appear in `SpectreMesh` with exact `method`/`path`/`SQL fingerprint`/`status_code` parity!
     2. **Latency Precision:** `|ebpf_span_latency - ground_truth_latency| < 2 ms` at `p99`.
     3. **Zero Side Effects:** Target Go and OpenSSL processes complete all 50,000 requests with 0 crashes, 0 corrupted TLS handshakes, and 0 dropped ringbuf events.
     4. **XDP Shielding:** 100% of flood bursts above the configured token-bucket rate are dropped at XDP while legitimate gRPC/PG/Redis services sustain 0% error rate.

### M07 Verification Gate
- Full 50,000-request encrypted mesh verification passes end-to-end under strict RAII cleanup checks (0 residual XDP hooks, 0 leaked BPF links/FDs, 0 lingering test processes).

---

## MODULE M08 SPECIFICATION: `crates/spectre-daemon` & `crates/spectre-tui`

### Scope & Objective
Build the production observability daemon (`spectred`), execute real hardware throughput & overhead benchmarks writing verified artifacts to `docs/benchmarks/`, and build an interactive terminal mesh cockpit (`spectre-top`).

### Exact Components to Implement
1. **Mesh Collector Daemon & Exporters (`crates/spectre-daemon`):**
   - Orchestrates `M01`–`M06` across live PIDs/cgroups/interfaces, constructing a real-time **Service Dependency Graph** (`src_comm -> dst_comm` edges annotated with protocol, `RPS`, `Error %`, `p50`/`p99` ms latency, and `TCP Retransmits`).
   - Exposes HTTP endpoints:
     - `GET /metrics` (Prometheus exposition format: `spectre_l7_requests_total`, `spectre_l7_duration_seconds_bucket`, `spectre_xdp_drops_total`, `spectre_ringbuf_drops_total`)
     - `GET /v1/topology`, `GET /v1/spans/recent`, `GET /v1/flamegraph/{oncpu|offcpu}`
     - `GET /v1/stream` (SSE live tail of decoded plaintext L7 spans & XDP security events!).

2. **Hardware Overhead & Throughput Benchmark Harness (`bin/spectre-bench.rs`):**
   - Measure real `--release` performance and export verified Markdown + JSON into `docs/benchmarks/ebpf_perf.md` and `docs/benchmarks/ebpf_perf.json` (plus `studio/public/telemetry/summary.json` for `/labs/spectre`!):
     1. **XDP Packet Filter Throughput (`BPF_PROG_TEST_RUN` 10M packets):** `Mpps` (million packets/sec) & `ns/packet` for `XDP_PASS` and `XDP_DROP` paths.
     2. **L7 Parser & HPACK Decoder Throughput:** `MB/s` and `spans/sec` across HTTP/2 gRPC, PostgreSQL, and Redis streams.
     3. **Zero-Instrumentation TLS Overhead Measurement:** Compare target HTTPS server `RPS` and `p99` latency with `SpectreMesh` **OFF** vs **ON** (proving minimal < 3–5% latency overhead with 0% ringbuf drops!).
     4. **eBPF Static Verifier Speed:** Microseconds to statically verify all production `.bpf.o` probes in `M02`.

3. **Live Terminal Observability Cockpit (`crates/spectre-tui` — `spectre-top`):**
   - Supports `--attach http://127.0.0.1:9090` (live daemon) and `--demo` (replays captured encrypted mesh telemetry + live synthetic L7/XDP/Flamegraph stream!).
   - 4-Panel SRE Dashboard:
     1. **Service Topology & RED Golden Signals Table** (`Service`, `Proto`, `TLS`, `RPS`, `Err%`, `p50/p99 ms`, `TCP RTT`).
     2. **Live Plaintext L7 Stream Tap** (color-coded `gRPC /orders.Book/Place`, `PG SELECT ...`, `REDIS HGETALL ...` decrypted via uprobes!).
     3. **XDP Firewall & RingBuf Health Sparklines** (`Pass pps`, `Drop pps`, `RingBuf Utilization %`, `Lost Events: 0`).
     4. **Interactive ASCII On-CPU / Off-CPU Flamegraph Panel.**
   - Include headless `ratatui::backend::TestBackend` (`120x40`) snapshot & keypress tests.

### M08 Verification Gate
- `spectre-bench --release` completes cleanly and writes verified real telemetry into `docs/benchmarks/ebpf_perf.md` and `studio/public/telemetry/summary.json`.
- `spectre-tui` headless rendering tests pass 100%.

---

## MODULE M09 SPECIFICATION: `crates/spectre-wasm`, `studio/` & Root Proof Suite

### Scope & Objective
Compile the pure-Rust **eBPF ISA v3 Static Verifier & VM (`M02`)**, **L7 Protocol/HPACK/PG/Redis Dissectors (`M05`)**, and **Differential Flamegraph Engine (`M06`)** to `wasm32-unknown-unknown`, ship an interactive **SpectreMesh eBPF Verifier & L7 Mesh Studio** (`studio/` configured for `/labs/spectre/` Vercel Multi-Zone routing!), and lock down `make verify-all`.

### Exact Components to Implement
1. **WebAssembly Kernel Observability Bridge (`crates/spectre-wasm`):**
   - Compiles cleanly on `wasm32-unknown-unknown` with zero Linux `libc` dependencies.
   - Export `#[wasm_bindgen]` `SpectreWasmStudio`:
     - `verify_and_run_ebpf(preset_or_bytecode_json: &str, packet_hex: &str) -> JsValue`: runs the real `M02` Abstract-Interpretation Static Verifier step-by-step, returning every disassembled BPF instruction, per-PC register state (`R0..R10` types, `Tnum` known/unknown bitmasks, `PtrToPacket` valid offset range!), final `ACCEPT` / `REJECT` verdict with exact offending instruction highlighted, AND concrete VM execution verdict (`XDP_PASS` / `XDP_DROP`) on the input packet!
     - `dissect_l7_stream(protocol_hint: &str, chunks_hex_json: &str) -> JsValue`: feeds raw fragmented byte streams through `M05` decoders, returning decoded `L7Span`s, live RFC 7541 **HPACK Dynamic Table state**, gRPC Protobuf field tree, and normalized PostgreSQL/Redis commands!
     - `compute_differential_flamegraph(baseline_folded: &str, regressed_folded: &str) -> JsValue`: builds the interactive On-CPU / Off-CPU differential flamegraph tree!

2. **Interactive Web eBPF & Mesh Studio (`studio/` — TypeScript + Vite + Systems Lab Dock):**
   - Configure `studio/vite.config.ts` with `base: '/labs/spectre/'`, `outDir: 'dist/labs/spectre'`, `assetsInlineLimit: 0`, Dedicated WebWorker execution, and the unified `<systems-lab-dock active="spectre" />` bar + OpenGraph tags pointing to `/api/og/labs?engine=spectre`.
   - 3 Interactive Engineering Workbenches:
     1. **eBPF Static Verifier & Register `Tnum` Stepper:** Pick presets (*Valid XDP IPv4/TCP Parser*, *Missing `data_end` Bounds Check -> REJECT*, *Unchecked Nullable Map Dereference -> REJECT*, *520B Stack Overflow -> REJECT*, *Leaked RingBuf Reserve -> REJECT*), step forward/backward through instructions, and inspect live `R0..R10` abstract domains and packet byte bounds on a color-coded hex strip!
     2. **Zero-Instrumentation L7 & TLS Plaintext Mesh Replay:** Interactive Service Topology SVG graph + live split stream showing raw encrypted TLS ciphertext vs `uprobe`-recovered HTTP/2 HPACK dynamic table, gRPC methods, and PostgreSQL SQL spans captured from `M07`!
     3. **Interactive Canvas On-CPU vs Off-CPU Differential Flamegraph:** Click any stack frame to zoom, hover for exact sample share & delta %, search symbols (`hot_sha256_spin`, `futex_wait`), and toggle On-CPU vs Off-CPU views!
   - Include automated Vitest / Playwright headless verification testing all 3 tabs against the compiled WASM bundle.

3. **Universal Reproducibility Proof Suite (`Dockerfile.linux-verify`, `Makefile`, `.github/workflows/ci.yml`, `ARCHITECTURE.md`, `README.md`):**
   - `Dockerfile.linux-verify`: Multi-stage Debian/Ubuntu image pre-installing `clang`, `llvm`, `libssl-dev`, `golang`, `linux-headers`, `rustup` (`wasm32-unknown-unknown`), `wasm-bindgen-cli`, `binaryen`, and Node 22 so anyone on Windows PowerShell, macOS, or Linux can execute `docker build -f Dockerfile.linux-verify -t spectre-verify . && docker run --rm --privileged spectre-verify make verify-all`.
   - Root `Makefile` targets (all must exit `0`):
     - `make build-probes`: compiles all `probes/*.bpf.c` via `clang -target bpf -O2 -g -Wall -Werror`
     - `make check`: `cargo fmt --check` + `cargo clippy --workspace --all-targets -- -D warnings`
     - `make test`: full workspace unit & verifier tests
     - `make fuzz-l7-elf`: executes 100k malformed L7/HPACK + 10k malformed ELF/BTF fuzzers
     - `make mesh-oracle`: executes the 50,000-request live encrypted OpenSSL + Go TLS 1.3 + PG + Redis mesh verification (inside Linux/Docker)
     - `make bench`: runs `spectre-bench --release` and updates `docs/benchmarks/ebpf_perf.md` + `studio/public/telemetry/summary.json`
     - `make wasm-studio`: compiles `spectre-wasm` (`+simd128` + `wasm-opt -O3`), builds `studio/dist/labs/spectre`, and runs headless Studio tests
     - `make verify-all`: executes `build-probes` -> `check` -> `test` -> `fuzz-l7-elf` -> `mesh-oracle` -> `bench` -> `wasm-studio` end-to-end!
   - Write Principal-level `README.md` and `ARCHITECTURE.md` with ASCII diagrams of:
     - Double-`mmap`ed lock-free `BPF_MAP_TYPE_RINGBUF` memory barriers
     - Go `RET`-offset uprobe disassembly vs unsafe kernel `uretprobe` goroutine stack growth
     - eBPF Static Verifier `Tnum` & `PtrToPacket` bounds propagation
     - Real benchmark tables pulled strictly from `docs/benchmarks/ebpf_perf.md`.

### Final M09 Completion Gate
Execute `make verify-all` (natively on Linux/WSL2 or via `make docker-verify`) and confirm 100% pass rate across BPF probe compilation, Clippy, Miri, 120+ Verifier differential proofs, 100k L7/ELF fuzzing, 50,000-request encrypted OpenSSL+Go mesh verification, release benchmarks, headless `spectre-top` TUI, and static WASM Studio bundle. Verify `grep -rn "todo!\|unimplemented!" crates/` returns empty.
