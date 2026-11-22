# M04 Design Spec — `probes/tls_*` & `crates/spectre-tls`

## 1. Objective
Capture 100% plaintext TLS 1.3 payloads without MITM proxies or Root CA injection across both OpenSSL 1.1/3.x (`SSL_write`, `SSL_read`, `SSL_write_ex`, `SSL_read_ex`) and Go `crypto/tls` (`(*Conn).Write`, `(*Conn).Read`) binaries.

## 2. Go Goroutine Stack-Safety Law (`RET`-Offset Uprobes)
- **Why kernel `uretprobe` fatally crashes Go binaries:**
  - Go allocates small 2 KB goroutine stacks and dynamically allocates + copies (`runtime.morestack`) the stack when deeper frames exceed the stack guard, adjusting pointers inside the Go stack.
  - Linux kernel `uretprobe` replaces the return address saved on the stack with a kernel trampoline (`uretprobe_trampoline`). When Go moves the stack during `crypto/tls.(*Conn).Read`, that kernel return-address mapping becomes stale or panics the Go runtime/unwinder.
- **SpectreMesh Solution (`ret_scanner.rs`):**
  1. Parse Go ELF binary `.gopclntab` + `.symtab` + `.go.buildinfo` via `M01` (`Elf64Object`).
  2. Locate `[func_start .. func_end]` machine code bytes for `crypto/tls.(*Conn).Read` and `crypto/tls.(*Conn).Write` in `.text`.
  3. Decode every `x86_64` instruction boundary from `func_start` to `func_end` using a pure-Rust full instruction-length decoder (legacy prefixes `0x66/67/F0/F2/F3/segment`, REX `0x40..=0x4F`, VEX2/3, EVEX, `0F`/`0F 38`/`0F 3A` escape maps, ModRM + SIB + displacements + immediates) so embedded `0xC3` bytes inside immediates/displacements are NEVER misidentified! On `aarch64`, scan 4-byte aligned `0xD65F03C0` (`RET`).
  4. Attach **entry `uprobes` ONLY** (`is_retprobe = false`) at the function entry AND at every decoded `RET` file offset!

## 3. Go `ABIInternal` Register & Goroutine State Tracking (`probes/tls_go.bpf.c`)
- Go >= 1.17 `ABIInternal` on `x86_64` passes `(c *Conn, b []byte)` as:
  - `RAX`: receiver `c` (`*tls.Conn`)
  - `RBX`: slice data pointer `b.ptr`
  - `RCX`: slice length `b.len`
  - `R14`: current goroutine pointer `g` (remains invariant across goroutine stack moves and OS-thread migration!).
- Return values at `RET` (`(n int, err error)`):
  - `RAX`: `n` (bytes read/written).
- `tls_go.bpf.c` keys active calls by `(pid, r14_g_ptr)` rather than `(pid, tid)`, stashing `(conn_ptr, buf_ptr, buf_len)` at function entry and reading `n = PT_REGS_RC(ctx)` (`ax`) at the `RET` entry-uprobe, emitting up to `16 * 4096 B` (`64 KB`) bounded chunks to `RingBuf`.

## 4. OpenSSL 1.1 / 3.x Interception & FD Correlation (`probes/tls_openssl.bpf.c`)
- Hooks `SSL_set_fd`, `SSL_set_rfd`, `SSL_set_wfd` (`uprobe` entry recording `SSL* -> fd` in `ssl_to_fd` map).
- Hooks `SSL_write` (`uprobe` + `uretprobe`), `SSL_write_ex` (`uprobe` + `uretprobe`), `SSL_read` (`uprobe` + `uretprobe`), and `SSL_read_ex` (`uprobe` + `uretprobe`).
- Multi-chunk loop (`<= 16 * 4096 B` via `PERCPU_ARRAY` scratch buffer) ensures payloads `> 16 KB` recover 100% plaintext without truncation.

## 5. Target Discovery & RAII Attachment (`crates/spectre-tls/src/discover.rs`)
- `#![deny(unsafe_code)]` crate routing `perf_event_open` through `spectre-elf-btf::syscall::attach_uprobe_perf`.
- Parses `/proc/<pid>/maps` to discover loaded `libssl.so*` or Go target paths (`inode`-deduplicated) and attaches RAII `UprobeGuard`s cleaned automatically on `Drop`.
