# M02 Design Spec — `crates/spectre-verifier`

## 1. Objective
Implement a pure-Rust, `#![deny(unsafe_code)]` **eBPF ISA v3 Disassembler, Abstract-Interpretation Static Verifier, and Concrete Execution VM** that runs identically across Linux, Windows, macOS, and `wasm32-unknown-unknown`.

## 2. eBPF ISA v3 Instruction Layout (`isa.rs`, `disasm.rs`)
Each 64-bit `BpfInsn` has:
- `code: u8` (`class = code & 0x07`, `size/source/op = code >> 3`)
- `dst_reg: u8` (`regs & 0x0F`, `0..=10`)
- `src_reg: u8` (`(regs >> 4) & 0x0F`, `0..=10`)
- `off: i16`
- `imm: i32`
128-bit double-slot instructions (`BPF_LD | BPF_DW | BPF_IMM == 0x18`) occupy `insns[pc]` and `insns[pc + 1]` (`val64 = (imm0 as u32 as u64) | ((imm1 as u32 as u64) << 32)`).

## 3. Abstract Interpretation Domain (`tnum.rs`, `verifier.rs`)

### 3.1 `Tnum` (Tristate Numbers)
Each 64-bit scalar register tracks `(value: u64, mask: u64)` where invariant `value & mask == 0`:
- `mask` bit `1` => bit is unknown (`?`); `mask` bit `0` => bit is statically known equal to `value` bit (`0` or `1`).
- Exact bit-level transfer functions (`tnum_add`, `tnum_sub`, `tnum_and`, `tnum_or`, `tnum_xor`, `tnum_lshift`, `tnum_rshift`, `tnum_arshift`, `tnum_cast`) match Linux `kernel/bpf/tnum.c`.
- Synchronized with signed/unsigned intervals `[umin, umax]`, `[smin, smax]` (and 32-bit subregister views `[u32_min, u32_max]`, `[s32_min, s32_max]`).
- **32-bit ALU Zero Extension Law:** Writing to `wX` (`BPF_ALU`) zero-extends bit `0..31` to `64` bits, setting upper 32 bits of `tnum.value` and `tnum.mask` to `0`!

### 3.2 Pointer & Scalar Register Lattice
- `NotInit` — reading triggers immediate `UninitializedRegister` rejection.
- `Scalar(ScalarBounds)` — tracked by `Tnum` + intervals.
- `PtrToCtx(BpfProgType)` — context access bounds checked (`xdp_md` 0..24B 4-byte aligned, etc.).
- `PtrToStack { off, var_off }` — offset must stay strictly within `[-512..0]`. Reading uninitialized stack bytes (`StackSlotKind::Misc`/`Invalid`) is rejected; spilled pointers preserve exact `RegState` across `STX`/`LDX` (`BPF_DW`).
- `PtrToPacket { id, off, range }` & `PtrToPacketEnd` — loading `ctx->data` yields `PtrToPacket(off=0, range=0)` with unique `id`; `ctx->data_end` yields `PtrToPacketEnd`.
  - Adding scalar `k` (constant or bounded `[umin, umax]`) updates `off`/`var_off`.
  - Conditional comparisons (`if r2 > r3 goto L_drop` where `r2` is `PtrToPacket(id, off)` and `r3` is `PtrToPacketEnd`) refine `range = max(range, off)` for ALL registers sharing `id` on the fall-through (`r2 <= r3`) branch!
  - Dereferencing `*(u8/u16/u32/u64 *)(r2 + mem_off)` requires `off + mem_off >= 0` AND `off + mem_off + access_size <= range`!
- `PtrToMapValue { map_id, off, size, nullable, ref_id }` & `PtrToRingBufMem { ref_id, off, size, nullable }`:
  - `bpf_map_lookup_elem` returns `PtrToMapValue { nullable: true }`.
  - `bpf_ringbuf_reserve` returns `PtrToRingBufMem { nullable: true, ref_id }`, registering an active `ref_id` that MUST be passed to `bpf_ringbuf_submit` / `bpf_ringbuf_discard` on every non-NULL exit path!
  - Conditional `if r0 == 0 goto exit` clears `nullable` across matching `ref_id` on the non-null branch. Dereferencing while `nullable == true` is rejected!

### 3.3 Safety & Termination Rules
1. `R10` (`FP`) is strictly read-only (`WriteToReadOnlyR10` on modification).
2. `CALL` clobbers caller-saved `R1..=R5` (`NotInit`), validates argument types against helper prototype signatures, and sets `R0`.
3. `DIV`/`MOD` by constant `0` or potentially-zero scalar register (`umin == 0 && smax >= 0 && smin <= 0`) rejected (`PossibleDivByZero`).
4. Cycle detection along current DFS path + state subsumption pruning + `MAX_VERIFIER_STATES = 1_000_000` bound ensures guaranteed termination and parity with the Linux kernel verifier.
