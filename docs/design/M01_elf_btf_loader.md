# M01 Design Spec — `crates/spectre-elf-btf`

## 1. Objective
Implement a pure-Rust, `libbpf`-free eBPF ELF64 + BTF + CO-RE loader, raw `SYS_bpf` / `SYS_perf_event_open` RAII wrapper layer, and lock-free zero-copy double-`mmap`ed `BPF_MAP_TYPE_RINGBUF` consumer.

## 2. Binary & Kernel Layouts

### 2.1 ELF64 Parser (`elf64.rs`)
- Validates `e_ident[0..4] == [0x7F, b'E', b'L', b'F']`, `EI_CLASS == ELFCLASS64 (2)`, `EI_DATA == ELFDATA2LSB (1)`.
- Bounds-checks `e_shoff + e_shnum * e_shentsize` and `e_phoff + e_phnum * e_phentsize` with checked arithmetic (`checked_mul`/`checked_add`) so malformed/truncated inputs return `ElfBtfError` cleanly without panics or out-of-bounds slicing.
- Extracts:
  - `.shstrtab`, `.strtab`, `.symtab`, `.dynstr`, `.dynsym`, `PT_LOAD` segments (`vaddr -> file_offset` mapping for userspace uprobe/symbol resolution).
  - `.BTF`, `.BTF.ext`, `.maps`, `.rodata`, `.data`, `.bss`, `license`, `version`, and executable BPF program sections (`SHF_EXECINSTR`).
  - `SHT_REL` / `SHT_RELA` relocations (`R_BPF_64_64 = 1`, `R_BPF_64_32 = 10`).
  - Go runtime symbol tables (`.gopclntab` v1.18 `0xFFFFFFF0` and v1.20+ `0xFFFFFFF1` headers + `runtime.buildVersion`) for M04 `crypto/tls` resolution.

### 2.2 BTF & `.BTF.ext` CO-RE Relocation (`btf.rs`, `core_reloc.rs`)
- BTF Header (`0xEB9F`, `version = 1`): `hdr_len`, `type_off`, `type_len`, `str_off`, `str_len`.
- Supports all kernel BTF kinds `0..=19`: `UNKN`, `INT`, `PTR`, `ARRAY`, `STRUCT`, `UNION`, `ENUM`, `FWD`, `TYPEDEF`, `VOLATILE`, `CONST`, `RESTRICT`, `FUNC`, `FUNC_PROTO`, `VAR`, `DATASEC`, `FLOAT`, `DECL_TAG`, `TYPE_TAG`, `ENUM64`.
- Enforces `MAX_BTF_DEPTH = 64` + visited tracking to guard against cyclic type graphs (`TYPEDEF -> TYPEDEF` or `PTR -> ...` loops).
- `.BTF.ext` Header (`0xEB9F`, `version = 1`): `func_info`, `line_info`, and `core_relo` sub-sections formatted as `(sec_name_off, num_info, records...)`.
- CO-RE Relocator:
  - Strips `___*` flavor suffixes (`task_struct___old` -> `task_struct`).
  - Traverses access string `"0:1:2"` across nested structs and anonymous unions/structs, accumulating byte/bit offsets and bitfield sizes.
  - Resolves target type inside `/sys/kernel/btf/vmlinux` (or synthetic target BTF in unit/Miri tests) and rewrites `bpf_insn` (`off` on `LDX/STX/ST`, `imm` on `ALU/ALU64/LD_IMM64`) or marks missing fields cleanly (`FIELD_EXISTS = 0` or poisoning).

### 2.3 Raw `SYS_bpf` & `SYS_perf_event_open` RAII Layer (`syscall.rs`)
- Quarantine for OS syscalls (`#[cfg(target_os = "linux")]`).
- Exact Linux 6.18 ABI `#[repr(C, align(8))]` structures for `BpfAttr` (`map_create`, `map_elem`, `prog_load`, `obj_pin_get`, `prog_test_run`, `link_create`, `btf_load`, `obj_info`) and `PerfEventAttr`.
- RAII guards (`OwnedBpfFd`, `BpfLinkGuard`, `PerfEventFd`, `EpollGuard`) ensure deterministic `libc::close` on `Drop`, guaranteeing zero leaked FDs or zombie kernel hooks.

### 2.4 Lock-Free Double-`mmap`ed `BPF_MAP_TYPE_RINGBUF` (`ringbuf.rs`)
```
Virtual Memory Layout (ring_size = 2^k * PAGE_SIZE):
+-------------------+-------------------+-------------------+
| Page 0 (RW)       | Page 1 (RO)       | Pages 2..2N+1 (RO)|
| consumer_pos (u64)| producer_pos (u64)| data[0..ring_size)| data[0..ring_size) alias
+-------------------+-------------------+-------------------+
```
- **Producer-Consumer Synchronization:**
  - Read `producer_pos` with `Ordering::Acquire`.
  - While `cons_pos < prod_pos`:
    - Read 8-byte aligned record header (`len_and_flags: u32`) with `Ordering::Acquire` (or atomic `u32` load).
    - If `BPF_RINGBUF_BUSY_BIT (1 << 31)` is set: break and wait (kernel has not committed payload yet).
    - Compute aligned record step `8 + round_up_8(len & 0x0FFF_FFFF)`.
    - If `BPF_RINGBUF_DISCARD_BIT (1 << 30)` is NOT set: yield contiguous `&data[offset + 8 .. offset + 8 + len]` (zero-copy even across ring wrap due to double `mmap`!).
    - Advance `cons_pos += step` and store to `consumer_pos` with `Ordering::Release`.
- **Portable Test Harness (`SimulatedRingBuf`):** Provides identical double-mapped contiguous buffer semantics in safe/Miri-verifiable heap memory so `cargo +nightly miri test` validates every wrap-around, busy-bit, discard-bit, and Acquire/Release invariant.
