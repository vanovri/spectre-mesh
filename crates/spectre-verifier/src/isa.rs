use serde::{Deserialize, Serialize};
use thiserror::Error;

// Instruction classes (bits 0..=2 of `code`)
pub const BPF_LD: u8 = 0x00;
pub const BPF_LDX: u8 = 0x01;
pub const BPF_ST: u8 = 0x02;
pub const BPF_STX: u8 = 0x03;
pub const BPF_ALU: u8 = 0x04;
pub const BPF_JMP: u8 = 0x05;
pub const BPF_JMP32: u8 = 0x06;
pub const BPF_ALU64: u8 = 0x07;

// Size modifiers for LD/LDX/ST/STX (bits 3..=4)
pub const BPF_W: u8 = 0x00;
pub const BPF_H: u8 = 0x08;
pub const BPF_B: u8 = 0x10;
pub const BPF_DW: u8 = 0x18;

// Mode modifiers for LD/LDX/ST/STX (bits 5..=7)
pub const BPF_IMM: u8 = 0x00;
pub const BPF_ABS: u8 = 0x20;
pub const BPF_IND: u8 = 0x40;
pub const BPF_MEM: u8 = 0x60;
pub const BPF_MEMSX: u8 = 0x80;
pub const BPF_ATOMIC: u8 = 0xC0;

// Source operand modifier (bit 3)
pub const BPF_K: u8 = 0x00;
pub const BPF_X: u8 = 0x08;

// ALU / ALU64 operations (bits 4..=7)
pub const BPF_ADD: u8 = 0x00;
pub const BPF_SUB: u8 = 0x10;
pub const BPF_MUL: u8 = 0x20;
pub const BPF_DIV: u8 = 0x30;
pub const BPF_OR: u8 = 0x40;
pub const BPF_AND: u8 = 0x50;
pub const BPF_LSH: u8 = 0x60;
pub const BPF_RSH: u8 = 0x70;
pub const BPF_NEG: u8 = 0x80;
pub const BPF_MOD: u8 = 0x90;
pub const BPF_XOR: u8 = 0xA0;
pub const BPF_MOV: u8 = 0xB0;
pub const BPF_ARSH: u8 = 0xC0;
pub const BPF_END: u8 = 0xD0;

// JMP / JMP32 operations (bits 4..=7)
pub const BPF_JA: u8 = 0x00;
pub const BPF_JEQ: u8 = 0x10;
pub const BPF_JGT: u8 = 0x20;
pub const BPF_JGE: u8 = 0x30;
pub const BPF_JSET: u8 = 0x40;
pub const BPF_JNE: u8 = 0x50;
pub const BPF_JSGT: u8 = 0x60;
pub const BPF_JSGE: u8 = 0x70;
pub const BPF_CALL: u8 = 0x80;
pub const BPF_EXIT: u8 = 0x90;
pub const BPF_JLT: u8 = 0xA0;
pub const BPF_JLE: u8 = 0xB0;
pub const BPF_JSLT: u8 = 0xC0;
pub const BPF_JSLE: u8 = 0xD0;

// Atomic immediate ops (`imm` field for `BPF_STX | BPF_ATOMIC`)
pub const BPF_ATOMIC_ADD: i32 = 0x00;
pub const BPF_ATOMIC_OR: i32 = 0x40;
pub const BPF_ATOMIC_AND: i32 = 0x50;
pub const BPF_ATOMIC_XOR: i32 = 0xA0;
pub const BPF_ATOMIC_FETCH: i32 = 0x01;
pub const BPF_ATOMIC_XCHG: i32 = 0xE1;
pub const BPF_ATOMIC_CMPXCHG: i32 = 0xF1;

// Pseudo src_reg tags on LD_IMM64 / CALL
pub const BPF_PSEUDO_MAP_FD: u8 = 1;
pub const BPF_PSEUDO_MAP_VALUE: u8 = 2;
pub const BPF_PSEUDO_CALL: u8 = 1;

// Standard BPF Helper IDs
pub const HELPER_MAP_LOOKUP_ELEM: i32 = 1;
pub const HELPER_MAP_UPDATE_ELEM: i32 = 2;
pub const HELPER_MAP_DELETE_ELEM: i32 = 3;
pub const HELPER_PROBE_READ: i32 = 4;
pub const HELPER_KTIME_GET_NS: i32 = 5;
pub const HELPER_TRACE_PRINTK: i32 = 6;
pub const HELPER_GET_PRANDOM_U32: i32 = 7;
pub const HELPER_GET_SMP_PROCESSOR_ID: i32 = 8;
pub const HELPER_GET_CURRENT_PID_TGID: i32 = 14;
pub const HELPER_GET_CURRENT_UID_GID: i32 = 15;
pub const HELPER_GET_CURRENT_COMM: i32 = 16;
pub const HELPER_GET_STACKID: i32 = 27;
pub const HELPER_PROBE_READ_USER: i32 = 112;
pub const HELPER_PROBE_READ_KERNEL: i32 = 113;
pub const HELPER_GET_NS_CURRENT_PID_TGID: i32 = 120;
pub const HELPER_RINGBUF_OUTPUT: i32 = 130;
pub const HELPER_RINGBUF_RESERVE: i32 = 131;
pub const HELPER_RINGBUF_SUBMIT: i32 = 132;
pub const HELPER_RINGBUF_DISCARD: i32 = 133;
pub const HELPER_RINGBUF_QUERY: i32 = 134;

// XDP action return codes
pub const XDP_ABORTED: u64 = 0;
pub const XDP_DROP: u64 = 1;
pub const XDP_PASS: u64 = 2;
pub const XDP_TX: u64 = 3;
pub const XDP_REDIRECT: u64 = 4;

#[derive(Debug, Error)]
pub enum IsaError {
    #[error("program byte length {0} is not a multiple of 8")]
    UnalignedLength(usize),
    #[error("empty eBPF instruction stream")]
    EmptyProgram,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BpfProgType {
    Xdp,
    Kprobe,
    Tracepoint,
    PerfEvent,
    RawTracepoint,
    SocketFilter,
}

impl BpfProgType {
    #[must_use]
    pub const fn ctx_size(self) -> i32 {
        match self {
            Self::Xdp => 24, // struct xdp_md: data, data_end, data_meta, ingress_ifindex, rx_queue_index, egress_ifindex
            Self::SocketFilter => 64, // __sk_buff subset
            Self::Kprobe | Self::Tracepoint | Self::PerfEvent | Self::RawTracepoint => 256,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BpfMapSpec {
    pub id: u32,
    pub name: String,
    pub map_type: u32,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
}

/// Decoded 64-bit eBPF ISA v3 instruction (`struct bpf_insn`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BpfInsn {
    pub code: u8,
    pub dst_reg: u8,
    pub src_reg: u8,
    pub off: i16,
    pub imm: i32,
}

impl BpfInsn {
    #[must_use]
    pub const fn new(code: u8, dst_reg: u8, src_reg: u8, off: i16, imm: i32) -> Self {
        Self {
            code,
            dst_reg: dst_reg & 0x0F,
            src_reg: src_reg & 0x0F,
            off,
            imm,
        }
    }

    #[must_use]
    pub const fn from_raw(raw: u64) -> Self {
        let bytes = raw.to_le_bytes();
        Self {
            code: bytes[0],
            dst_reg: bytes[1] & 0x0F,
            src_reg: (bytes[1] >> 4) & 0x0F,
            off: i16::from_le_bytes([bytes[2], bytes[3]]),
            imm: i32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        }
    }

    #[must_use]
    pub const fn to_raw(self) -> u64 {
        let regs = (self.dst_reg & 0x0F) | ((self.src_reg & 0x0F) << 4);
        let off = self.off.to_le_bytes();
        let imm = self.imm.to_le_bytes();
        u64::from_le_bytes([
            self.code, regs, off[0], off[1], imm[0], imm[1], imm[2], imm[3],
        ])
    }

    #[must_use]
    pub const fn class(self) -> u8 {
        self.code & 0x07
    }

    #[must_use]
    pub const fn src(self) -> u8 {
        self.code & 0x08
    }

    #[must_use]
    pub const fn op(self) -> u8 {
        self.code & 0xF0
    }

    #[must_use]
    pub const fn size(self) -> u8 {
        self.code & 0x18
    }

    #[must_use]
    pub const fn mode(self) -> u8 {
        self.code & 0xE0
    }

    #[must_use]
    pub const fn is_ld_imm64(self) -> bool {
        self.code == (BPF_LD | BPF_DW | BPF_IMM)
    }

    #[must_use]
    pub const fn mem_size_bytes(self) -> i32 {
        match self.size() {
            BPF_B => 1,
            BPF_H => 2,
            BPF_W => 4,
            BPF_DW => 8,
            _ => 0,
        }
    }

    // Ergonomic constructors for building BPF instruction sequences cleanly
    #[must_use]
    pub const fn mov64_imm(dst: u8, imm: i32) -> Self {
        Self::new(BPF_ALU64 | BPF_MOV | BPF_K, dst, 0, 0, imm)
    }

    #[must_use]
    pub const fn mov64_reg(dst: u8, src: u8) -> Self {
        Self::new(BPF_ALU64 | BPF_MOV | BPF_X, dst, src, 0, 0)
    }

    #[must_use]
    pub const fn mov32_imm(dst: u8, imm: i32) -> Self {
        Self::new(BPF_ALU | BPF_MOV | BPF_K, dst, 0, 0, imm)
    }

    #[must_use]
    pub const fn mov32_reg(dst: u8, src: u8) -> Self {
        Self::new(BPF_ALU | BPF_MOV | BPF_X, dst, src, 0, 0)
    }

    #[must_use]
    pub const fn alu64_imm(op: u8, dst: u8, imm: i32) -> Self {
        Self::new(BPF_ALU64 | op | BPF_K, dst, 0, 0, imm)
    }

    #[must_use]
    pub const fn alu64_reg(op: u8, dst: u8, src: u8) -> Self {
        Self::new(BPF_ALU64 | op | BPF_X, dst, src, 0, 0)
    }

    #[must_use]
    pub const fn alu32_imm(op: u8, dst: u8, imm: i32) -> Self {
        Self::new(BPF_ALU | op | BPF_K, dst, 0, 0, imm)
    }

    #[must_use]
    pub const fn ldx_mem(size: u8, dst: u8, src: u8, off: i16) -> Self {
        Self::new(BPF_LDX | size | BPF_MEM, dst, src, off, 0)
    }

    #[must_use]
    pub const fn stx_mem(size: u8, dst: u8, src: u8, off: i16) -> Self {
        Self::new(BPF_STX | size | BPF_MEM, dst, src, off, 0)
    }

    #[must_use]
    pub const fn st_mem(size: u8, dst: u8, off: i16, imm: i32) -> Self {
        Self::new(BPF_ST | size | BPF_MEM, dst, 0, off, imm)
    }

    #[must_use]
    pub const fn ld_imm64(dst: u8, src_pseudo: u8, val: u64) -> [Self; 2] {
        let lo = (val & 0xFFFF_FFFF) as u32 as i32;
        let hi = (val >> 32) as u32 as i32;
        [
            Self::new(BPF_LD | BPF_DW | BPF_IMM, dst, src_pseudo, 0, lo),
            Self::new(0, 0, 0, 0, hi),
        ]
    }

    #[must_use]
    pub const fn jmp_imm(op: u8, dst: u8, imm: i32, off: i16) -> Self {
        Self::new(BPF_JMP | op | BPF_K, dst, 0, off, imm)
    }

    #[must_use]
    pub const fn jmp_reg(op: u8, dst: u8, src: u8, off: i16) -> Self {
        Self::new(BPF_JMP | op | BPF_X, dst, src, off, 0)
    }

    #[must_use]
    pub const fn ja(off: i16) -> Self {
        Self::new(BPF_JMP | BPF_JA, 0, 0, off, 0)
    }

    #[must_use]
    pub const fn call(helper_id: i32) -> Self {
        Self::new(BPF_JMP | BPF_CALL, 0, 0, 0, helper_id)
    }

    #[must_use]
    pub const fn exit() -> Self {
        Self::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0)
    }
}

pub fn decode_raw_insns(raw: &[u64]) -> Vec<BpfInsn> {
    raw.iter().copied().map(BpfInsn::from_raw).collect()
}

pub fn decode_bytes(bytes: &[u8]) -> Result<Vec<BpfInsn>, IsaError> {
    if bytes.is_empty() {
        return Err(IsaError::EmptyProgram);
    }
    if !bytes.len().is_multiple_of(8) {
        return Err(IsaError::UnalignedLength(bytes.len()));
    }
    Ok(bytes
        .as_chunks::<8>()
        .0
        .iter()
        .map(|chunk| BpfInsn::from_raw(u64::from_le_bytes(*chunk)))
        .collect())
}

pub fn encode_raw(insns: &[BpfInsn]) -> Vec<u64> {
    insns.iter().map(|i| i.to_raw()).collect()
}

#[must_use]
pub const fn helper_name(id: i32) -> &'static str {
    match id {
        HELPER_MAP_LOOKUP_ELEM => "bpf_map_lookup_elem",
        HELPER_MAP_UPDATE_ELEM => "bpf_map_update_elem",
        HELPER_MAP_DELETE_ELEM => "bpf_map_delete_elem",
        HELPER_PROBE_READ => "bpf_probe_read",
        HELPER_KTIME_GET_NS => "bpf_ktime_get_ns",
        HELPER_TRACE_PRINTK => "bpf_trace_printk",
        HELPER_GET_PRANDOM_U32 => "bpf_get_prandom_u32",
        HELPER_GET_SMP_PROCESSOR_ID => "bpf_get_smp_processor_id",
        HELPER_GET_CURRENT_PID_TGID => "bpf_get_current_pid_tgid",
        HELPER_GET_CURRENT_UID_GID => "bpf_get_current_uid_gid",
        HELPER_GET_CURRENT_COMM => "bpf_get_current_comm",
        HELPER_GET_STACKID => "bpf_get_stackid",
        HELPER_PROBE_READ_USER => "bpf_probe_read_user",
        HELPER_PROBE_READ_KERNEL => "bpf_probe_read_kernel",
        HELPER_GET_NS_CURRENT_PID_TGID => "bpf_get_ns_current_pid_tgid",
        HELPER_RINGBUF_OUTPUT => "bpf_ringbuf_output",
        HELPER_RINGBUF_RESERVE => "bpf_ringbuf_reserve",
        HELPER_RINGBUF_SUBMIT => "bpf_ringbuf_submit",
        HELPER_RINGBUF_DISCARD => "bpf_ringbuf_discard",
        HELPER_RINGBUF_QUERY => "bpf_ringbuf_query",
        _ => "bpf_helper_unknown",
    }
}
