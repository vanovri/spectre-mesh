use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::disasm::disassemble_insn;
use crate::isa::{
    BpfInsn, BpfMapSpec, BpfProgType, BPF_ADD, BPF_ALU, BPF_ALU64, BPF_AND, BPF_ARSH, BPF_ATOMIC,
    BPF_CALL, BPF_DIV, BPF_END, BPF_EXIT, BPF_JA, BPF_JEQ, BPF_JGE, BPF_JGT, BPF_JLE, BPF_JLT,
    BPF_JMP, BPF_JMP32, BPF_JNE, BPF_JSET, BPF_JSGE, BPF_JSGT, BPF_JSLE, BPF_JSLT, BPF_LDX,
    BPF_LSH, BPF_MEM, BPF_MOD, BPF_MOV, BPF_MUL, BPF_NEG, BPF_OR, BPF_PSEUDO_CALL,
    BPF_PSEUDO_MAP_FD, BPF_PSEUDO_MAP_VALUE, BPF_RSH, BPF_ST, BPF_STX, BPF_SUB, BPF_X, BPF_XOR,
    HELPER_GET_CURRENT_COMM, HELPER_GET_CURRENT_PID_TGID, HELPER_GET_CURRENT_UID_GID,
    HELPER_GET_NS_CURRENT_PID_TGID, HELPER_GET_PRANDOM_U32, HELPER_GET_SMP_PROCESSOR_ID,
    HELPER_GET_STACKID, HELPER_KTIME_GET_NS, HELPER_MAP_DELETE_ELEM, HELPER_MAP_LOOKUP_ELEM,
    HELPER_MAP_UPDATE_ELEM, HELPER_PROBE_READ, HELPER_PROBE_READ_KERNEL, HELPER_PROBE_READ_USER,
    HELPER_RINGBUF_DISCARD, HELPER_RINGBUF_OUTPUT, HELPER_RINGBUF_QUERY, HELPER_RINGBUF_RESERVE,
    HELPER_RINGBUF_SUBMIT, HELPER_TRACE_PRINTK,
};
use crate::tnum::Tnum;

pub const MAX_BPF_STACK: i32 = 512;
pub const MAX_PACKET_OFF: i32 = 0xFFFF;
pub const MAX_VERIFIER_STATES: usize = 1_000_000;

#[derive(Debug, Error, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerifierError {
    #[error("empty instruction stream")]
    EmptyProgram,
    #[error("program exceeds verifier complexity budget ({0} insns processed)")]
    ComplexityLimitExceeded(usize),
    #[error("jump target pc={0} out of program bounds or lands inside 128-bit instruction")]
    JumpOutOfBounds(isize),
    #[error("execution falls off end of program without BPF_EXIT")]
    FallthroughWithoutExit,
    #[error("infinite loop / back-edge cycle detected at pc={0}")]
    BackEdgeLoopDetected(usize),
    #[error("read from uninitialized register r{0} at pc={1}")]
    UninitializedRegister(u8, usize),
    #[error("read from uninitialized stack offset {0}..{1} at pc={2}")]
    UninitializedStackRead(i32, i32, usize),
    #[error("stack out of bounds access [{0}..{1}) (allowed [-512..0]) at pc={2}")]
    StackOutOfBounds(i32, i32, usize),
    #[error("write to read-only frame pointer r10 at pc={0}")]
    WriteToReadOnlyR10(usize),
    #[error("invalid register index {0} at pc={1}")]
    InvalidRegister(u8, usize),
    #[error("dereferencing non-pointer register r{0} ({1}) at pc={2}")]
    InvalidPointerDereference(u8, String, usize),
    #[error("dereferencing potentially NULL pointer r{0} without null check at pc={1}")]
    NullPointerDereference(u8, usize),
    #[error("invalid packet access [{0}..{1}) outside proven packet range [0..{2}) at pc={3}")]
    PacketOutOfBounds(i32, i32, i32, usize),
    #[error("out-of-bounds map value access [{0}..{1}) (map value_size={2}) at pc={3}")]
    MapValueOutOfBounds(i32, i32, u32, usize),
    #[error("out-of-bounds ringbuf access [{0}..{1}) (reserved size={2}) at pc={3}")]
    RingBufOutOfBounds(i32, i32, u32, usize),
    #[error("context access offset {0} size {1} out of bounds or disallowed write at pc={2}")]
    InvalidContextAccess(i32, i32, usize),
    #[error("unbounded scalar added to packet pointer at pc={0}")]
    UnboundedPacketOffset(usize),
    #[error("invalid pointer arithmetic on {0} at pc={1}")]
    InvalidPointerArithmetic(String, usize),
    #[error("possible division or modulo by zero at pc={0}")]
    PossibleDivByZero(usize),
    #[error("invalid helper call #{0} or wrong argument types: {1} at pc={2}")]
    InvalidHelperCall(i32, String, usize),
    #[error("unreleased ringbuf reference id={0} on BPF_EXIT at pc={1}")]
    UnreleasedReference(u32, usize),
    #[error("unsupported or invalid opcode {0:#04x} at pc={1}")]
    InvalidOpcode(u8, usize),
    #[error("unreachable instruction at pc={0}")]
    UnreachableInsn(usize),
    #[error("map id {0} not registered in verifier environment")]
    UnknownMap(u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ScalarBounds {
    pub tnum: Tnum,
    pub umin: u64,
    pub umax: u64,
    pub smin: i64,
    pub smax: i64,
}

impl ScalarBounds {
    #[must_use]
    pub const fn from_const(v: u64) -> Self {
        Self {
            tnum: Tnum::from_const(v),
            umin: v,
            umax: v,
            smin: v as i64,
            smax: v as i64,
        }
    }

    #[must_use]
    pub const fn unknown() -> Self {
        Self {
            tnum: Tnum::UNKNOWN,
            umin: 0,
            umax: u64::MAX,
            smin: i64::MIN,
            smax: i64::MAX,
        }
    }

    #[must_use]
    pub const fn u32_unknown() -> Self {
        Self {
            tnum: Tnum::new(0, 0xFFFF_FFFF),
            umin: 0,
            umax: u32::MAX as u64,
            smin: 0,
            smax: u32::MAX as i64,
        }
    }

    #[must_use]
    pub const fn range(umin: u64, umax: u64) -> Self {
        let smin = if umax <= i64::MAX as u64 {
            umin as i64
        } else {
            i64::MIN
        };
        let smax = if umax <= i64::MAX as u64 {
            umax as i64
        } else {
            i64::MAX
        };
        Self {
            tnum: Tnum::from_range(umin, umax),
            umin,
            umax,
            smin,
            smax,
        }
    }

    #[must_use]
    pub const fn is_const(self) -> Option<u64> {
        if self.umin == self.umax {
            Some(self.umin)
        } else if self.tnum.is_const() {
            Some(self.tnum.value)
        } else {
            None
        }
    }

    pub fn sync_bounds(&mut self) {
        self.umin = self.umin.max(self.tnum.umin());
        self.umax = self.umax.min(self.tnum.umax());
        if self.umin > self.umax {
            self.umin = self.tnum.umin();
            self.umax = self.tnum.umax();
        }
        if self.umin == self.umax {
            self.tnum = Tnum::from_const(self.umin);
            self.smin = self.umin as i64;
            self.smax = self.umin as i64;
        }
        if self.smin >= 0 && (self.smax as u64) <= i64::MAX as u64 {
            self.umin = self.umin.max(self.smin as u64);
            self.umax = self.umax.min(self.smax as u64);
        }
    }

    #[must_use]
    pub fn zero_extend_32(self) -> Self {
        let t = self.tnum.subreg();
        let (umin, umax) = if self.umax <= u32::MAX as u64 {
            (self.umin, self.umax)
        } else {
            (t.umin(), t.umax())
        };
        Self {
            tnum: t,
            umin,
            umax,
            smin: umin as i64,
            smax: umax as i64,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RegState {
    NotInit,
    Scalar(ScalarBounds),
    PtrToCtx(BpfProgType),
    PtrToStack {
        off: i32,
        var_off: Tnum,
    },
    PtrToPacket {
        id: u32,
        off: i32,
        range: i32,
    },
    PtrToPacketEnd,
    PtrToMapValue {
        map_id: u32,
        off: i32,
        value_size: u32,
        nullable: bool,
        ref_id: u32,
    },
    PtrToRingBufMem {
        ref_id: u32,
        off: i32,
        size: u32,
        nullable: bool,
    },
    ConstPtrToMap {
        map_id: u32,
    },
}

impl RegState {
    #[must_use]
    pub fn summary(&self) -> String {
        match self {
            Self::NotInit => "not_init".to_owned(),
            Self::Scalar(b) => {
                if let Some(c) = b.is_const() {
                    format!("inv({c})")
                } else {
                    format!(
                        "inv(umin={}, umax={}, tnum={})",
                        b.umin,
                        b.umax,
                        b.tnum.format_bits()
                    )
                }
            }
            Self::PtrToCtx(_) => "ctx()".to_owned(),
            Self::PtrToStack { off, .. } => format!("fp({off})"),
            Self::PtrToPacket { id, off, range } => format!("pkt(id={id},off={off},r={range})"),
            Self::PtrToPacketEnd => "pkt_end()".to_owned(),
            Self::PtrToMapValue {
                map_id,
                off,
                value_size,
                nullable,
                ..
            } => format!(
                "map_value{}(id={},off={},sz={})",
                if *nullable { "_or_null" } else { "" },
                map_id,
                off,
                value_size
            ),
            Self::PtrToRingBufMem {
                ref_id,
                off,
                size,
                nullable,
            } => format!(
                "ringbuf_mem{}(ref={},off={},sz={})",
                if *nullable { "_or_null" } else { "" },
                ref_id,
                off,
                size
            ),
            Self::ConstPtrToMap { map_id } => format!("map_ptr(id={map_id})"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum StackSlot {
    Invalid,
    Misc,
    Spill {
        spill_id: u32,
        byte_idx: u8,
        reg: Option<Box<RegState>>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct VerifierState {
    regs: [RegState; 11],
    stack: Vec<StackSlot>, // 512 bytes: index 0 -> fp-512, index 511 -> fp-1
    active_refs: Vec<u32>,
    next_id: u32,
}

impl VerifierState {
    fn entry(prog_type: BpfProgType) -> Self {
        let mut regs = std::array::from_fn(|_| RegState::NotInit);
        regs[1] = RegState::PtrToCtx(prog_type);
        regs[10] = RegState::PtrToStack {
            off: 0,
            var_off: Tnum::ZERO,
        };
        Self {
            regs,
            stack: vec![StackSlot::Invalid; MAX_BPF_STACK as usize],
            active_refs: Vec::new(),
            next_id: 1,
        }
    }

    fn alloc_id(&mut self) -> u32 {
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        id
    }

    fn mark_packet_range(&mut self, pkt_id: u32, new_range: i32) {
        for r in &mut self.regs {
            if let RegState::PtrToPacket { id, range, .. } = r {
                if *id == pkt_id {
                    *range = (*range).max(new_range);
                }
            }
        }
        for slot in &mut self.stack {
            if let StackSlot::Spill {
                reg: Some(boxed), ..
            } = slot
            {
                if let RegState::PtrToPacket { id, range, .. } = boxed.as_mut() {
                    if *id == pkt_id {
                        *range = (*range).max(new_range);
                    }
                }
            }
        }
    }

    fn mark_ptr_non_null(&mut self, target_ref: u32) {
        for r in &mut self.regs {
            match r {
                RegState::PtrToMapValue {
                    ref_id, nullable, ..
                }
                | RegState::PtrToRingBufMem {
                    ref_id, nullable, ..
                } if *ref_id == target_ref => {
                    *nullable = false;
                }
                _ => {}
            }
        }
        for slot in &mut self.stack {
            if let StackSlot::Spill {
                reg: Some(boxed), ..
            } = slot
            {
                match boxed.as_mut() {
                    RegState::PtrToMapValue {
                        ref_id, nullable, ..
                    }
                    | RegState::PtrToRingBufMem {
                        ref_id, nullable, ..
                    } if *ref_id == target_ref => {
                        *nullable = false;
                    }
                    _ => {}
                }
            }
        }
    }

    fn clear_null_ref(&mut self, target_ref: u32) {
        self.active_refs.retain(|&id| id != target_ref);
    }

    fn max_stack_depth(&self) -> usize {
        for (idx, slot) in self.stack.iter().enumerate() {
            if *slot != StackSlot::Invalid {
                return (MAX_BPF_STACK as usize) - idx;
            }
        }
        0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceStep {
    pub pc: usize,
    pub insn_text: String,
    pub regs: [String; 11],
    pub stack_depth: usize,
    pub note: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    Accept,
    Reject,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationReport {
    pub verdict: Verdict,
    pub insns_processed: usize,
    pub max_stack_depth: usize,
    pub trace: Vec<TraceStep>,
    pub error: Option<VerifierError>,
}

#[derive(Debug, Clone)]
pub struct VerifierConfig {
    pub prog_type: BpfProgType,
    pub maps: HashMap<u32, BpfMapSpec>,
    pub max_trace_steps: usize,
    pub strict_stack_alignment: bool,
    /// Matches Linux `CAP_PERFMON` root mode (`allow_ptr_leaks`), which permits scalar
    /// loads from uninitialized stack slots within `[-512..0]`.
    pub allow_privileged_uninit_stack_read: bool,
    /// Matches Linux BPF JIT runtime `div/mod` by 0 returning 0 (only statically known
    /// constant 0 divisors are rejected by the kernel verifier).
    pub allow_runtime_div_by_zero: bool,
}

impl Default for VerifierConfig {
    fn default() -> Self {
        Self {
            prog_type: BpfProgType::Xdp,
            maps: HashMap::new(),
            max_trace_steps: 2048,
            strict_stack_alignment: false,
            allow_privileged_uninit_stack_read: false,
            allow_runtime_div_by_zero: false,
        }
    }
}

impl VerifierConfig {
    /// Configuration matching live Linux 6.x privileged (`CAP_BPF`/`CAP_PERFMON`) kernel verifier.
    #[must_use]
    pub fn linux_privileged(prog_type: BpfProgType, maps: HashMap<u32, BpfMapSpec>) -> Self {
        Self {
            prog_type,
            maps,
            max_trace_steps: 2048,
            strict_stack_alignment: false,
            allow_privileged_uninit_stack_read: true,
            allow_runtime_div_by_zero: true,
        }
    }
}

pub fn verify_program(insns: &[BpfInsn], cfg: &VerifierConfig) -> VerificationReport {
    if insns.is_empty() {
        return VerificationReport {
            verdict: Verdict::Reject,
            insns_processed: 0,
            max_stack_depth: 0,
            trace: Vec::new(),
            error: Some(VerifierError::EmptyProgram),
        };
    }

    let mut runner = VerifierRunner {
        insns,
        cfg,
        insns_processed: 0,
        max_stack_depth: 0,
        trace: Vec::new(),
        visited_at_pc: HashMap::new(),
        visited_pcs: vec![false; insns.len()],
    };

    let init = VerifierState::entry(cfg.prog_type);
    let mut dfs_stack: HashMap<usize, HashSet<VerifierState>> = HashMap::new();
    let mut active_pc_visits: HashMap<usize, usize> = HashMap::new();
    match runner.explore(0, init, &mut dfs_stack, &mut active_pc_visits) {
        Ok(()) => {
            // Check for unreachable instructions (matching Linux kernel verifier check_cfg)
            let mut pc = 0usize;
            while pc < insns.len() {
                if !runner.visited_pcs[pc] {
                    return VerificationReport {
                        verdict: Verdict::Reject,
                        insns_processed: runner.insns_processed,
                        max_stack_depth: runner.max_stack_depth,
                        trace: runner.trace,
                        error: Some(VerifierError::UnreachableInsn(pc)),
                    };
                }
                pc += if insns[pc].is_ld_imm64() { 2 } else { 1 };
            }
            VerificationReport {
                verdict: Verdict::Accept,
                insns_processed: runner.insns_processed,
                max_stack_depth: runner.max_stack_depth,
                trace: runner.trace,
                error: None,
            }
        }
        Err(err) => VerificationReport {
            verdict: Verdict::Reject,
            insns_processed: runner.insns_processed,
            max_stack_depth: runner.max_stack_depth,
            trace: runner.trace,
            error: Some(err),
        },
    }
}

struct VerifierRunner<'a> {
    insns: &'a [BpfInsn],
    cfg: &'a VerifierConfig,
    insns_processed: usize,
    max_stack_depth: usize,
    trace: Vec<TraceStep>,
    visited_at_pc: HashMap<usize, HashSet<VerifierState>>,
    visited_pcs: Vec<bool>,
}

impl<'a> VerifierRunner<'a> {
    fn record_step(&mut self, pc: usize, state: &VerifierState, note: &str) {
        if self.trace.len() < self.cfg.max_trace_steps {
            let (insn_text, _) = disassemble_insn(self.insns, pc);
            let regs = std::array::from_fn(|i| state.regs[i].summary());
            self.trace.push(TraceStep {
                pc,
                insn_text,
                regs,
                stack_depth: state.max_stack_depth(),
                note: note.to_owned(),
            });
        }
    }

    fn explore(
        &mut self,
        mut pc: usize,
        mut state: VerifierState,
        active_dfs: &mut HashMap<usize, HashSet<VerifierState>>,
        active_pc_visits: &mut HashMap<usize, usize>,
    ) -> Result<(), VerifierError> {
        // Track states inserted onto active DFS path so we pop them cleanly on return.
        let mut pushed_dfs: Vec<(usize, VerifierState)> = Vec::new();
        let mut pushed_pcs: Vec<usize> = Vec::new();

        let res: Result<(), VerifierError> = (|| {
            loop {
                if pc >= self.insns.len() {
                    return Err(VerifierError::FallthroughWithoutExit);
                }

                // Cycle & unbounded loop check on active DFS path
                let visits = active_pc_visits.entry(pc).or_insert(0);
                if *visits >= 64 || active_dfs.get(&pc).is_some_and(|set| set.contains(&state)) {
                    return Err(VerifierError::BackEdgeLoopDetected(pc));
                }

                // Subsumption/explored pruning across completed branches
                if self
                    .visited_at_pc
                    .get(&pc)
                    .is_some_and(|set| set.contains(&state))
                {
                    return Ok(());
                }

                if self.insns_processed >= MAX_VERIFIER_STATES {
                    return Err(VerifierError::ComplexityLimitExceeded(self.insns_processed));
                }
                self.insns_processed += 1;
                self.visited_pcs[pc] = true;
                self.max_stack_depth = self.max_stack_depth.max(state.max_stack_depth());

                *visits += 1;
                pushed_pcs.push(pc);
                let snapshot_for_dfs = state.clone();
                active_dfs
                    .entry(pc)
                    .or_default()
                    .insert(snapshot_for_dfs.clone());
                pushed_dfs.push((pc, snapshot_for_dfs));

                let insn = self.insns[pc];
                if insn.dst_reg > 10 || insn.src_reg > 10 {
                    return Err(VerifierError::InvalidRegister(
                        insn.dst_reg.max(insn.src_reg),
                        pc,
                    ));
                }

                if insn.is_ld_imm64() {
                    if pc + 1 >= self.insns.len() {
                        return Err(VerifierError::InvalidOpcode(insn.code, pc));
                    }
                    if insn.dst_reg == 10 {
                        return Err(VerifierError::WriteToReadOnlyR10(pc));
                    }
                    let hi = self.insns[pc + 1];
                    match insn.src_reg {
                        BPF_PSEUDO_MAP_FD => {
                            let map_id = insn.imm as u32;
                            if !self.cfg.maps.contains_key(&map_id) {
                                return Err(VerifierError::UnknownMap(map_id));
                            }
                            state.regs[insn.dst_reg as usize] = RegState::ConstPtrToMap { map_id };
                        }
                        BPF_PSEUDO_MAP_VALUE => {
                            let map_id = insn.imm as u32;
                            let spec = self
                                .cfg
                                .maps
                                .get(&map_id)
                                .ok_or(VerifierError::UnknownMap(map_id))?;
                            let off = hi.imm;
                            let ref_id = state.alloc_id();
                            state.regs[insn.dst_reg as usize] = RegState::PtrToMapValue {
                                map_id,
                                off,
                                value_size: spec.value_size,
                                nullable: false,
                                ref_id,
                            };
                        }
                        0 => {
                            let val = (insn.imm as u32 as u64) | ((hi.imm as u32 as u64) << 32);
                            state.regs[insn.dst_reg as usize] =
                                RegState::Scalar(ScalarBounds::from_const(val));
                        }
                        _ => return Err(VerifierError::InvalidOpcode(insn.code, pc)),
                    }
                    self.record_step(pc, &state, "ld_imm64");
                    pc += 2;
                    continue;
                }

                match insn.class() {
                    BPF_LDX => {
                        self.check_load(pc, insn, &mut state)?;
                        self.record_step(pc, &state, "ldx");
                        pc += 1;
                    }
                    BPF_ST => {
                        self.check_store_imm(pc, insn, &mut state)?;
                        self.record_step(pc, &state, "st");
                        pc += 1;
                    }
                    BPF_STX => {
                        self.check_store_reg(pc, insn, &mut state)?;
                        self.record_step(pc, &state, "stx");
                        pc += 1;
                    }
                    BPF_ALU | BPF_ALU64 => {
                        self.check_alu(pc, insn, &mut state)?;
                        self.record_step(pc, &state, "alu");
                        pc += 1;
                    }
                    BPF_JMP | BPF_JMP32 => {
                        match insn.op() {
                            BPF_EXIT => {
                                if matches!(state.regs[0], RegState::NotInit) {
                                    return Err(VerifierError::UninitializedRegister(0, pc));
                                }
                                if let Some(&leaked) = state.active_refs.first() {
                                    return Err(VerifierError::UnreleasedReference(leaked, pc));
                                }
                                self.record_step(pc, &state, "exit");
                                return Ok(());
                            }
                            BPF_JA => {
                                self.record_step(pc, &state, "ja");
                                let next = self.compute_jump_target(pc, insn.off)?;
                                pc = next;
                            }
                            BPF_CALL => {
                                self.check_call(pc, insn, &mut state)?;
                                self.record_step(pc, &state, "call");
                                if insn.src_reg == BPF_PSEUDO_CALL {
                                    let target = self.compute_jump_target(pc, insn.imm as i16)?;
                                    self.explore(
                                        target,
                                        state.clone(),
                                        active_dfs,
                                        active_pc_visits,
                                    )?;
                                }
                                pc += 1;
                            }
                            op => {
                                // Conditional jump: explore taken branch recursively, refine fall-through
                                let target = self.compute_jump_target(pc, insn.off)?;
                                let (fallthrough_state, taken_state) =
                                    self.split_conditional(pc, insn, op, &state)?;
                                self.record_step(pc, &state, "jcc");
                                if let Some(t_state) = taken_state {
                                    self.explore(target, t_state, active_dfs, active_pc_visits)?;
                                }
                                if let Some(f_state) = fallthrough_state {
                                    state = f_state;
                                    pc += 1;
                                } else {
                                    return Ok(());
                                }
                            }
                        }
                    }
                    _ => return Err(VerifierError::InvalidOpcode(insn.code, pc)),
                }
            }
        })();

        for p_pc in pushed_pcs {
            if let Some(cnt) = active_pc_visits.get_mut(&p_pc) {
                *cnt = cnt.saturating_sub(1);
            }
        }
        for (p_pc, p_state) in pushed_dfs {
            if let Some(set) = active_dfs.get_mut(&p_pc) {
                set.remove(&p_state);
            }
            if res.is_ok() {
                let entry = self.visited_at_pc.entry(p_pc).or_default();
                if entry.len() < 64 {
                    entry.insert(p_state);
                }
            }
        }
        res
    }

    fn compute_jump_target(&self, pc: usize, off: i16) -> Result<usize, VerifierError> {
        let target = (pc as isize) + 1 + (off as isize);
        if target < 0 || (target as usize) >= self.insns.len() {
            return Err(VerifierError::JumpOutOfBounds(target));
        }
        let target_usize = target as usize;
        if target_usize > 0 && self.insns[target_usize - 1].is_ld_imm64() {
            return Err(VerifierError::JumpOutOfBounds(target));
        }
        Ok(target_usize)
    }

    fn check_load(
        &self,
        pc: usize,
        insn: BpfInsn,
        state: &mut VerifierState,
    ) -> Result<(), VerifierError> {
        if insn.mode() != BPF_MEM {
            return Err(VerifierError::InvalidOpcode(insn.code, pc));
        }
        if insn.dst_reg == 10 {
            return Err(VerifierError::WriteToReadOnlyR10(pc));
        }
        let size = insn.mem_size_bytes();
        if size == 0 {
            return Err(VerifierError::InvalidOpcode(insn.code, pc));
        }
        let src_reg = state.regs[insn.src_reg as usize].clone();
        let loaded = match src_reg {
            RegState::NotInit => {
                return Err(VerifierError::UninitializedRegister(insn.src_reg, pc))
            }
            RegState::PtrToCtx(prog_type) => {
                self.check_ctx_load(pc, prog_type, i32::from(insn.off), size)?
            }
            RegState::PtrToStack { off, var_off } => {
                if !var_off.is_const() {
                    return Err(VerifierError::StackOutOfBounds(-MAX_BPF_STACK, 0, pc));
                }
                let eff = off + i32::from(insn.off);
                self.read_stack(pc, state, eff, size)?
            }
            RegState::PtrToPacket { off, range, .. } => {
                let start = off + i32::from(insn.off);
                let end = start + size;
                if start < 0 || end > range {
                    return Err(VerifierError::PacketOutOfBounds(start, end, range, pc));
                }
                Self::scalar_for_size(size)
            }
            RegState::PtrToMapValue {
                off,
                value_size,
                nullable,
                ..
            } => {
                if nullable {
                    return Err(VerifierError::NullPointerDereference(insn.src_reg, pc));
                }
                let start = off + i32::from(insn.off);
                let end = start + size;
                if start < 0 || end as u32 > value_size {
                    return Err(VerifierError::MapValueOutOfBounds(
                        start, end, value_size, pc,
                    ));
                }
                Self::scalar_for_size(size)
            }
            RegState::PtrToRingBufMem {
                off,
                size: rb_sz,
                nullable,
                ..
            } => {
                if nullable {
                    return Err(VerifierError::NullPointerDereference(insn.src_reg, pc));
                }
                let start = off + i32::from(insn.off);
                let end = start + size;
                if start < 0 || end as u32 > rb_sz {
                    return Err(VerifierError::RingBufOutOfBounds(start, end, rb_sz, pc));
                }
                Self::scalar_for_size(size)
            }
            other => {
                return Err(VerifierError::InvalidPointerDereference(
                    insn.src_reg,
                    other.summary(),
                    pc,
                ));
            }
        };
        state.regs[insn.dst_reg as usize] = loaded;
        Ok(())
    }

    fn scalar_for_size(size: i32) -> RegState {
        let bounds = match size {
            1 => ScalarBounds::range(0, u8::MAX as u64),
            2 => ScalarBounds::range(0, u16::MAX as u64),
            4 => ScalarBounds::u32_unknown(),
            _ => ScalarBounds::unknown(),
        };
        RegState::Scalar(bounds)
    }

    fn check_ctx_load(
        &self,
        pc: usize,
        prog_type: BpfProgType,
        off: i32,
        size: i32,
    ) -> Result<RegState, VerifierError> {
        let ctx_sz = prog_type.ctx_size();
        if off < 0 || off + size > ctx_sz {
            return Err(VerifierError::InvalidContextAccess(off, size, pc));
        }
        match prog_type {
            BpfProgType::Xdp => {
                if size != 4 || off % 4 != 0 {
                    return Err(VerifierError::InvalidContextAccess(off, size, pc));
                }
                match off {
                    0 => Ok(RegState::PtrToPacket {
                        id: 0,
                        off: 0,
                        range: 0,
                    }),
                    4 => Ok(RegState::PtrToPacketEnd),
                    _ => Ok(RegState::Scalar(ScalarBounds::u32_unknown())),
                }
            }
            _ => Ok(RegState::Scalar(ScalarBounds::unknown())),
        }
    }

    fn check_store_imm(
        &self,
        pc: usize,
        insn: BpfInsn,
        state: &mut VerifierState,
    ) -> Result<(), VerifierError> {
        if insn.mode() != BPF_MEM {
            return Err(VerifierError::InvalidOpcode(insn.code, pc));
        }
        let reg = state.regs[insn.dst_reg as usize].clone();
        self.check_mem_write(
            pc,
            insn.dst_reg,
            &reg,
            i32::from(insn.off),
            insn.mem_size_bytes(),
            &RegState::Scalar(ScalarBounds::from_const(insn.imm as i64 as u64)),
            state,
        )
    }

    fn check_store_reg(
        &self,
        pc: usize,
        insn: BpfInsn,
        state: &mut VerifierState,
    ) -> Result<(), VerifierError> {
        if insn.mode() != BPF_MEM && insn.mode() != BPF_ATOMIC {
            return Err(VerifierError::InvalidOpcode(insn.code, pc));
        }
        let val_reg = state.regs[insn.src_reg as usize].clone();
        if matches!(val_reg, RegState::NotInit) {
            return Err(VerifierError::UninitializedRegister(insn.src_reg, pc));
        }
        let dst = state.regs[insn.dst_reg as usize].clone();
        if insn.mode() == BPF_ATOMIC {
            // Atomic RMWs allowed on MapValue / Stack (scalars only)
            if !matches!(val_reg, RegState::Scalar(_)) {
                return Err(VerifierError::InvalidPointerArithmetic(
                    "atomic non-scalar value".to_owned(),
                    pc,
                ));
            }
        }
        self.check_mem_write(
            pc,
            insn.dst_reg,
            &dst,
            i32::from(insn.off),
            insn.mem_size_bytes(),
            &val_reg,
            state,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn check_mem_write(
        &self,
        pc: usize,
        reg_idx: u8,
        dst: &RegState,
        mem_off: i32,
        size: i32,
        val: &RegState,
        state: &mut VerifierState,
    ) -> Result<(), VerifierError> {
        if size == 0 {
            return Err(VerifierError::InvalidContextAccess(mem_off, size, pc));
        }
        match dst {
            RegState::NotInit => Err(VerifierError::UninitializedRegister(reg_idx, pc)),
            RegState::PtrToCtx(_) => Err(VerifierError::InvalidContextAccess(mem_off, size, pc)),
            RegState::PtrToStack { off, var_off } => {
                if !var_off.is_const() {
                    return Err(VerifierError::StackOutOfBounds(-MAX_BPF_STACK, 0, pc));
                }
                let eff = off + mem_off;
                self.write_stack(pc, state, eff, size, val)
            }
            RegState::PtrToPacket { off, range, .. } => {
                let start = off + mem_off;
                let end = start + size;
                if start < 0 || end > *range {
                    return Err(VerifierError::PacketOutOfBounds(start, end, *range, pc));
                }
                Ok(())
            }
            RegState::PtrToMapValue {
                off,
                value_size,
                nullable,
                ..
            } => {
                if *nullable {
                    return Err(VerifierError::NullPointerDereference(reg_idx, pc));
                }
                let start = off + mem_off;
                let end = start + size;
                if start < 0 || end as u32 > *value_size {
                    return Err(VerifierError::MapValueOutOfBounds(
                        start,
                        end,
                        *value_size,
                        pc,
                    ));
                }
                Ok(())
            }
            RegState::PtrToRingBufMem {
                off,
                size: rb_sz,
                nullable,
                ..
            } => {
                if *nullable {
                    return Err(VerifierError::NullPointerDereference(reg_idx, pc));
                }
                let start = off + mem_off;
                let end = start + size;
                if start < 0 || end as u32 > *rb_sz {
                    return Err(VerifierError::RingBufOutOfBounds(start, end, *rb_sz, pc));
                }
                Ok(())
            }
            other => Err(VerifierError::InvalidPointerDereference(
                reg_idx,
                other.summary(),
                pc,
            )),
        }
    }

    fn read_stack(
        &self,
        pc: usize,
        state: &VerifierState,
        eff_off: i32,
        size: i32,
    ) -> Result<RegState, VerifierError> {
        let end_off = eff_off + size;
        if eff_off < -MAX_BPF_STACK || end_off > 0 {
            return Err(VerifierError::StackOutOfBounds(eff_off, end_off, pc));
        }
        let start_idx = (MAX_BPF_STACK + eff_off) as usize;
        let end_idx = (MAX_BPF_STACK + end_off) as usize;

        if !self.cfg.allow_privileged_uninit_stack_read {
            for slot in &state.stack[start_idx..end_idx] {
                if *slot == StackSlot::Invalid {
                    return Err(VerifierError::UninitializedStackRead(eff_off, end_off, pc));
                }
            }
        }

        if size == 8 {
            if let StackSlot::Spill {
                spill_id,
                byte_idx: 0,
                reg: Some(ref boxed),
            } = state.stack[start_idx]
            {
                let intact = (0..8u8).all(|k| {
                    matches!(
                        state.stack[start_idx + k as usize],
                        StackSlot::Spill {
                            spill_id: sid,
                            byte_idx,
                            ..
                        } if sid == spill_id && byte_idx == k
                    )
                });
                if intact {
                    return Ok((**boxed).clone());
                }
            }
        }
        Ok(Self::scalar_for_size(size))
    }

    fn write_stack(
        &self,
        pc: usize,
        state: &mut VerifierState,
        eff_off: i32,
        size: i32,
        val: &RegState,
    ) -> Result<(), VerifierError> {
        let end_off = eff_off + size;
        if eff_off < -MAX_BPF_STACK || end_off > 0 {
            return Err(VerifierError::StackOutOfBounds(eff_off, end_off, pc));
        }
        let start_idx = (MAX_BPF_STACK + eff_off) as usize;
        let end_idx = (MAX_BPF_STACK + end_off) as usize;

        if size == 8 && eff_off % 8 == 0 {
            let spill_id = state.alloc_id();
            for (k, slot) in state.stack[start_idx..end_idx].iter_mut().enumerate() {
                *slot = StackSlot::Spill {
                    spill_id,
                    byte_idx: k as u8,
                    reg: if k == 0 {
                        Some(Box::new(val.clone()))
                    } else {
                        None
                    },
                };
            }
        } else {
            for slot in &mut state.stack[start_idx..end_idx] {
                *slot = StackSlot::Misc;
            }
        }
        Ok(())
    }

    fn check_alu(
        &self,
        pc: usize,
        insn: BpfInsn,
        state: &mut VerifierState,
    ) -> Result<(), VerifierError> {
        if insn.dst_reg == 10 {
            return Err(VerifierError::WriteToReadOnlyR10(pc));
        }
        let is_64 = insn.class() == BPF_ALU64;
        let op = insn.op();

        if op == BPF_MOV {
            let src_val = if insn.src() == BPF_X {
                let s = state.regs[insn.src_reg as usize].clone();
                if matches!(s, RegState::NotInit) {
                    return Err(VerifierError::UninitializedRegister(insn.src_reg, pc));
                }
                if !is_64 {
                    match s {
                        RegState::Scalar(b) => RegState::Scalar(b.zero_extend_32()),
                        _ => RegState::Scalar(ScalarBounds::u32_unknown()),
                    }
                } else {
                    s
                }
            } else {
                let v = if is_64 {
                    insn.imm as i64 as u64
                } else {
                    u64::from(insn.imm as u32)
                };
                RegState::Scalar(ScalarBounds::from_const(v))
            };
            state.regs[insn.dst_reg as usize] = src_val;
            return Ok(());
        }

        if op == BPF_NEG {
            let d = state.regs[insn.dst_reg as usize].clone();
            let RegState::Scalar(b) = d else {
                return Err(VerifierError::InvalidPointerArithmetic(d.summary(), pc));
            };
            let next = if let Some(c) = b.is_const() {
                let v = if is_64 {
                    (c as i64).wrapping_neg() as u64
                } else {
                    u64::from((c as i32).wrapping_neg() as u32)
                };
                ScalarBounds::from_const(v)
            } else if is_64 {
                ScalarBounds::unknown()
            } else {
                ScalarBounds::u32_unknown()
            };
            state.regs[insn.dst_reg as usize] = RegState::Scalar(next);
            return Ok(());
        }

        if op == BPF_END {
            let d = state.regs[insn.dst_reg as usize].clone();
            let RegState::Scalar(b) = d else {
                return Err(VerifierError::InvalidPointerArithmetic(d.summary(), pc));
            };
            let next = match insn.imm {
                16 => ScalarBounds {
                    tnum: b.tnum.cast_u16(),
                    umin: 0,
                    umax: u16::MAX as u64,
                    smin: 0,
                    smax: u16::MAX as i64,
                },
                32 => ScalarBounds::u32_unknown(),
                _ => ScalarBounds::unknown(),
            };
            state.regs[insn.dst_reg as usize] = RegState::Scalar(next);
            return Ok(());
        }

        let dst = state.regs[insn.dst_reg as usize].clone();
        if matches!(dst, RegState::NotInit) {
            return Err(VerifierError::UninitializedRegister(insn.dst_reg, pc));
        }

        let rhs = if insn.src() == BPF_X {
            let s = state.regs[insn.src_reg as usize].clone();
            if matches!(s, RegState::NotInit) {
                return Err(VerifierError::UninitializedRegister(insn.src_reg, pc));
            }
            s
        } else {
            let v = if is_64 {
                insn.imm as i64 as u64
            } else {
                u64::from(insn.imm as u32)
            };
            RegState::Scalar(ScalarBounds::from_const(v))
        };

        // Pointer +/- Scalar or Pointer - Pointer arithmetic
        match (&dst, &rhs, op) {
            (RegState::PtrToStack { off, var_off }, RegState::Scalar(sb), BPF_ADD | BPF_SUB)
                if is_64 =>
            {
                if let Some(c) = sb.is_const() {
                    let delta = i32::try_from(c as i64)
                        .map_err(|_| VerifierError::StackOutOfBounds(i32::MIN, i32::MAX, pc))?;
                    let new_off = if op == BPF_ADD {
                        off.saturating_add(delta)
                    } else {
                        off.saturating_sub(delta)
                    };
                    if !(-MAX_BPF_STACK..=0).contains(&new_off) {
                        return Err(VerifierError::StackOutOfBounds(new_off, new_off, pc));
                    }
                    state.regs[insn.dst_reg as usize] = RegState::PtrToStack {
                        off: new_off,
                        var_off: *var_off,
                    };
                    return Ok(());
                }
                return Err(VerifierError::InvalidPointerArithmetic(dst.summary(), pc));
            }
            (RegState::PtrToPacket { id, off, range }, RegState::Scalar(sb), BPF_ADD) if is_64 => {
                if let Some(c) = sb.is_const() {
                    let delta = i32::try_from(c as i64)
                        .map_err(|_| VerifierError::UnboundedPacketOffset(pc))?;
                    if !(0..=MAX_PACKET_OFF).contains(&delta) {
                        return Err(VerifierError::UnboundedPacketOffset(pc));
                    }
                    let new_off = off.saturating_add(delta);
                    if new_off > MAX_PACKET_OFF {
                        return Err(VerifierError::UnboundedPacketOffset(pc));
                    }
                    state.regs[insn.dst_reg as usize] = RegState::PtrToPacket {
                        id: *id,
                        off: new_off,
                        range: *range,
                    };
                    return Ok(());
                }
                if sb.smin < 0 || sb.umax > MAX_PACKET_OFF as u64 {
                    return Err(VerifierError::UnboundedPacketOffset(pc));
                }
                let new_id = state.alloc_id();
                state.regs[insn.dst_reg as usize] = RegState::PtrToPacket {
                    id: new_id,
                    off: 0,
                    range: 0,
                };
                return Ok(());
            }
            (
                RegState::PtrToMapValue {
                    map_id,
                    off,
                    value_size,
                    nullable,
                    ref_id,
                },
                RegState::Scalar(sb),
                BPF_ADD,
            ) if is_64 && !*nullable => {
                let Some(c) = sb.is_const() else {
                    return Err(VerifierError::InvalidPointerArithmetic(dst.summary(), pc));
                };
                let delta = i32::try_from(c as i64).map_err(|_| {
                    VerifierError::MapValueOutOfBounds(*off, i32::MAX, *value_size, pc)
                })?;
                state.regs[insn.dst_reg as usize] = RegState::PtrToMapValue {
                    map_id: *map_id,
                    off: off.saturating_add(delta),
                    value_size: *value_size,
                    nullable: false,
                    ref_id: *ref_id,
                };
                return Ok(());
            }
            (RegState::PtrToPacketEnd, RegState::PtrToPacket { .. }, BPF_SUB)
            | (RegState::PtrToPacket { .. }, RegState::PtrToPacket { .. }, BPF_SUB)
                if is_64 =>
            {
                state.regs[insn.dst_reg as usize] =
                    RegState::Scalar(ScalarBounds::range(0, MAX_PACKET_OFF as u64));
                return Ok(());
            }
            (RegState::Scalar(lb), RegState::Scalar(rb), _) => {
                let res = self.eval_scalar_alu(pc, op, is_64, *lb, *rb)?;
                state.regs[insn.dst_reg as usize] = RegState::Scalar(res);
                return Ok(());
            }
            _ => {}
        }

        Err(VerifierError::InvalidPointerArithmetic(
            format!("{} op {}", dst.summary(), rhs.summary()),
            pc,
        ))
    }

    fn eval_scalar_alu(
        &self,
        pc: usize,
        op: u8,
        is_64: bool,
        mut a: ScalarBounds,
        mut b: ScalarBounds,
    ) -> Result<ScalarBounds, VerifierError> {
        if !is_64 {
            a = a.zero_extend_32();
            b = b.zero_extend_32();
        }
        if matches!(op, BPF_DIV | BPF_MOD) {
            let reject_div = if self.cfg.allow_runtime_div_by_zero {
                b.is_const() == Some(0)
            } else {
                b.umin == 0
            };
            if reject_div {
                return Err(VerifierError::PossibleDivByZero(pc));
            }
        }

        let mut res = match (a.is_const(), b.is_const()) {
            (Some(x), Some(y)) => {
                let v = if is_64 {
                    match op {
                        BPF_ADD => x.wrapping_add(y),
                        BPF_SUB => x.wrapping_sub(y),
                        BPF_MUL => x.wrapping_mul(y),
                        BPF_DIV => x / y,
                        BPF_MOD => x % y,
                        BPF_OR => x | y,
                        BPF_AND => x & y,
                        BPF_XOR => x ^ y,
                        BPF_LSH => x.wrapping_shl((y & 63) as u32),
                        BPF_RSH => x.wrapping_shr((y & 63) as u32),
                        BPF_ARSH => ((x as i64).wrapping_shr((y & 63) as u32)) as u64,
                        _ => return Err(VerifierError::InvalidOpcode(op, pc)),
                    }
                } else {
                    let x32 = x as u32;
                    let y32 = y as u32;
                    let r32 = match op {
                        BPF_ADD => x32.wrapping_add(y32),
                        BPF_SUB => x32.wrapping_sub(y32),
                        BPF_MUL => x32.wrapping_mul(y32),
                        BPF_DIV => x32 / y32,
                        BPF_MOD => x32 % y32,
                        BPF_OR => x32 | y32,
                        BPF_AND => x32 & y32,
                        BPF_XOR => x32 ^ y32,
                        BPF_LSH => x32.wrapping_shl(y32 & 31),
                        BPF_RSH => x32.wrapping_shr(y32 & 31),
                        BPF_ARSH => ((x32 as i32).wrapping_shr(y32 & 31)) as u32,
                        _ => return Err(VerifierError::InvalidOpcode(op, pc)),
                    };
                    u64::from(r32)
                };
                ScalarBounds::from_const(v)
            }
            _ => match op {
                BPF_ADD => {
                    let tnum = a.tnum.add(b.tnum);
                    let umin = a.umin.saturating_add(b.umin);
                    let umax = a.umax.saturating_add(b.umax);
                    let mut out = ScalarBounds {
                        tnum,
                        umin: umin.max(tnum.umin()),
                        umax: umax.min(tnum.umax()),
                        smin: a.smin.saturating_add(b.smin),
                        smax: a.smax.saturating_add(b.smax),
                    };
                    out.sync_bounds();
                    out
                }
                BPF_SUB => {
                    let tnum = a.tnum.sub(b.tnum);
                    let mut out = ScalarBounds {
                        tnum,
                        umin: tnum.umin(),
                        umax: tnum.umax(),
                        smin: a.smin.saturating_sub(b.smax),
                        smax: a.smax.saturating_sub(b.smin),
                    };
                    out.sync_bounds();
                    out
                }
                BPF_AND => {
                    let tnum = a.tnum.and(b.tnum);
                    let mut out = ScalarBounds {
                        tnum,
                        umin: tnum.umin(),
                        umax: tnum.umax().min(a.umax.min(b.umax)),
                        smin: i64::MIN,
                        smax: i64::MAX,
                    };
                    if out.umax <= i64::MAX as u64 {
                        out.smin = 0;
                        out.smax = out.umax as i64;
                    }
                    out.sync_bounds();
                    out
                }
                BPF_OR => {
                    let tnum = a.tnum.or(b.tnum);
                    ScalarBounds {
                        tnum,
                        umin: tnum.umin().max(a.umin.max(b.umin)),
                        umax: tnum.umax(),
                        smin: i64::MIN,
                        smax: i64::MAX,
                    }
                }
                BPF_XOR => {
                    let tnum = a.tnum.xor(b.tnum);
                    ScalarBounds {
                        tnum,
                        umin: tnum.umin(),
                        umax: tnum.umax(),
                        smin: i64::MIN,
                        smax: i64::MAX,
                    }
                }
                BPF_LSH => {
                    if let Some(sh) = b.is_const() {
                        let sh32 = sh as u32;
                        let tnum = a.tnum.lshift(sh32);
                        let umin = tnum.umin();
                        let umax = if sh32 < 64 {
                            a.umax.checked_shl(sh32).unwrap_or(u64::MAX)
                        } else {
                            u64::MAX
                        }
                        .min(tnum.umax());
                        let (smin, smax) = if umax <= i64::MAX as u64 {
                            (umin as i64, umax as i64)
                        } else {
                            (i64::MIN, i64::MAX)
                        };
                        ScalarBounds {
                            tnum,
                            umin,
                            umax,
                            smin,
                            smax,
                        }
                    } else {
                        ScalarBounds::unknown()
                    }
                }
                BPF_RSH => {
                    if let Some(sh) = b.is_const() {
                        let sh32 = sh as u32;
                        let tnum = a.tnum.rshift(sh32);
                        let umin = if sh32 < 64 { a.umin >> sh32 } else { 0 };
                        let umax = if sh32 < 64 { a.umax >> sh32 } else { 0 };
                        ScalarBounds {
                            tnum,
                            umin: umin.max(tnum.umin()),
                            umax: umax.min(tnum.umax()),
                            smin: umin as i64,
                            smax: umax as i64,
                        }
                    } else {
                        ScalarBounds::unknown()
                    }
                }
                BPF_MUL => {
                    let umax = a.umax.saturating_mul(b.umax);
                    ScalarBounds::range(a.umin.saturating_mul(b.umin), umax)
                }
                BPF_DIV => ScalarBounds::range(0, a.umax / b.umin.max(1)),
                BPF_MOD => ScalarBounds::range(0, b.umax.saturating_sub(1)),
                _ => ScalarBounds::unknown(),
            },
        };

        if !is_64 {
            res = res.zero_extend_32();
        }
        Ok(res)
    }

    fn check_call(
        &self,
        pc: usize,
        insn: BpfInsn,
        state: &mut VerifierState,
    ) -> Result<(), VerifierError> {
        if insn.src_reg == BPF_PSEUDO_CALL {
            for reg in &mut state.regs[1..=5] {
                *reg = RegState::NotInit;
            }
            state.regs[0] = RegState::Scalar(ScalarBounds::unknown());
            return Ok(());
        }

        let helper = insn.imm;
        let r1 = state.regs[1].clone();
        let r2 = state.regs[2].clone();
        let r3 = state.regs[3].clone();

        let ret_reg = match helper {
            HELPER_MAP_LOOKUP_ELEM => {
                let RegState::ConstPtrToMap { map_id } = r1 else {
                    return Err(VerifierError::InvalidHelperCall(
                        helper,
                        "r1 must be ConstPtrToMap".to_owned(),
                        pc,
                    ));
                };
                let spec = self
                    .cfg
                    .maps
                    .get(&map_id)
                    .ok_or(VerifierError::UnknownMap(map_id))?;
                self.check_mem_read_arg(pc, helper, 2, &r2, spec.key_size as i32, state)?;
                let ref_id = state.alloc_id();
                RegState::PtrToMapValue {
                    map_id,
                    off: 0,
                    value_size: spec.value_size,
                    nullable: true,
                    ref_id,
                }
            }
            HELPER_MAP_UPDATE_ELEM => {
                let RegState::ConstPtrToMap { map_id } = r1 else {
                    return Err(VerifierError::InvalidHelperCall(
                        helper,
                        "r1 must be ConstPtrToMap".to_owned(),
                        pc,
                    ));
                };
                let spec = self
                    .cfg
                    .maps
                    .get(&map_id)
                    .ok_or(VerifierError::UnknownMap(map_id))?;
                self.check_mem_read_arg(pc, helper, 2, &r2, spec.key_size as i32, state)?;
                self.check_mem_read_arg(pc, helper, 3, &r3, spec.value_size as i32, state)?;
                RegState::Scalar(ScalarBounds::unknown())
            }
            HELPER_MAP_DELETE_ELEM => {
                let RegState::ConstPtrToMap { map_id } = r1 else {
                    return Err(VerifierError::InvalidHelperCall(
                        helper,
                        "r1 must be ConstPtrToMap".to_owned(),
                        pc,
                    ));
                };
                let spec = self
                    .cfg
                    .maps
                    .get(&map_id)
                    .ok_or(VerifierError::UnknownMap(map_id))?;
                self.check_mem_read_arg(pc, helper, 2, &r2, spec.key_size as i32, state)?;
                RegState::Scalar(ScalarBounds::unknown())
            }
            HELPER_RINGBUF_RESERVE => {
                let RegState::ConstPtrToMap { map_id } = r1 else {
                    return Err(VerifierError::InvalidHelperCall(
                        helper,
                        "r1 must be ConstPtrToMap".to_owned(),
                        pc,
                    ));
                };
                if !self.cfg.maps.contains_key(&map_id) {
                    return Err(VerifierError::UnknownMap(map_id));
                }
                let RegState::Scalar(sz_b) = r2 else {
                    return Err(VerifierError::InvalidHelperCall(
                        helper,
                        "r2 must be scalar size".to_owned(),
                        pc,
                    ));
                };
                let Some(sz) = sz_b.is_const() else {
                    return Err(VerifierError::InvalidHelperCall(
                        helper,
                        "ringbuf reserve size must be constant".to_owned(),
                        pc,
                    ));
                };
                if sz == 0 || sz > 16 * 1024 * 1024 {
                    return Err(VerifierError::InvalidHelperCall(
                        helper,
                        "ringbuf reserve size out of bounds".to_owned(),
                        pc,
                    ));
                }
                let ref_id = state.alloc_id();
                state.active_refs.push(ref_id);
                RegState::PtrToRingBufMem {
                    ref_id,
                    off: 0,
                    size: sz as u32,
                    nullable: true,
                }
            }
            HELPER_RINGBUF_SUBMIT | HELPER_RINGBUF_DISCARD => {
                let RegState::PtrToRingBufMem {
                    ref_id, nullable, ..
                } = r1
                else {
                    return Err(VerifierError::InvalidHelperCall(
                        helper,
                        "r1 must be PtrToRingBufMem".to_owned(),
                        pc,
                    ));
                };
                if nullable {
                    return Err(VerifierError::NullPointerDereference(1, pc));
                }
                if !state.active_refs.contains(&ref_id) {
                    return Err(VerifierError::InvalidHelperCall(
                        helper,
                        "ringbuf reference already released".to_owned(),
                        pc,
                    ));
                }
                state.active_refs.retain(|&id| id != ref_id);
                state.regs[1] = RegState::NotInit;
                RegState::Scalar(ScalarBounds::unknown())
            }
            HELPER_RINGBUF_OUTPUT => {
                let RegState::ConstPtrToMap { map_id } = r1 else {
                    return Err(VerifierError::InvalidHelperCall(
                        helper,
                        "r1 must be ConstPtrToMap".to_owned(),
                        pc,
                    ));
                };
                if !self.cfg.maps.contains_key(&map_id) {
                    return Err(VerifierError::UnknownMap(map_id));
                }
                let RegState::Scalar(sz_b) = r3 else {
                    return Err(VerifierError::InvalidHelperCall(
                        helper,
                        "r3 must be scalar size".to_owned(),
                        pc,
                    ));
                };
                self.check_mem_read_arg(pc, helper, 2, &r2, sz_b.umax.min(4096) as i32, state)?;
                RegState::Scalar(ScalarBounds::unknown())
            }
            HELPER_KTIME_GET_NS
            | HELPER_GET_CURRENT_PID_TGID
            | HELPER_GET_CURRENT_UID_GID
            | HELPER_GET_PRANDOM_U32
            | HELPER_GET_SMP_PROCESSOR_ID
            | HELPER_RINGBUF_QUERY => RegState::Scalar(ScalarBounds::unknown()),
            HELPER_GET_NS_CURRENT_PID_TGID => {
                if let RegState::PtrToStack { off, var_off } = &r3 {
                    if var_off.is_const() {
                        self.write_stack(
                            pc,
                            state,
                            *off,
                            8,
                            &RegState::Scalar(ScalarBounds::unknown()),
                        )?;
                    }
                }
                RegState::Scalar(ScalarBounds::unknown())
            }
            HELPER_PROBE_READ
            | HELPER_PROBE_READ_USER
            | HELPER_PROBE_READ_KERNEL
            | HELPER_GET_CURRENT_COMM
            | HELPER_GET_STACKID
            | HELPER_TRACE_PRINTK => RegState::Scalar(ScalarBounds::unknown()),
            _ => {
                return Err(VerifierError::InvalidHelperCall(
                    helper,
                    "unsupported helper ID".to_owned(),
                    pc,
                ));
            }
        };

        for reg in &mut state.regs[1..=5] {
            *reg = RegState::NotInit;
        }
        state.regs[0] = ret_reg;
        Ok(())
    }

    fn check_mem_read_arg(
        &self,
        pc: usize,
        helper: i32,
        reg_idx: u8,
        reg: &RegState,
        size: i32,
        state: &VerifierState,
    ) -> Result<(), VerifierError> {
        match reg {
            RegState::PtrToStack { off, var_off } => {
                if !var_off.is_const() {
                    return Err(VerifierError::InvalidHelperCall(
                        helper,
                        format!("r{reg_idx} stack pointer has variable offset"),
                        pc,
                    ));
                }
                let _ = self.read_stack(pc, state, *off, size)?;
                Ok(())
            }
            RegState::PtrToMapValue {
                off,
                value_size,
                nullable,
                ..
            } => {
                if *nullable {
                    return Err(VerifierError::NullPointerDereference(reg_idx, pc));
                }
                if *off < 0 || (*off + size) as u32 > *value_size {
                    return Err(VerifierError::MapValueOutOfBounds(
                        *off,
                        *off + size,
                        *value_size,
                        pc,
                    ));
                }
                Ok(())
            }
            _ => Err(VerifierError::InvalidHelperCall(
                helper,
                format!("r{reg_idx} must point to stack or map value"),
                pc,
            )),
        }
    }

    fn split_conditional(
        &self,
        pc: usize,
        insn: BpfInsn,
        op: u8,
        state: &VerifierState,
    ) -> Result<(Option<VerifierState>, Option<VerifierState>), VerifierError> {
        let d_reg = state.regs[insn.dst_reg as usize].clone();
        if matches!(d_reg, RegState::NotInit) {
            return Err(VerifierError::UninitializedRegister(insn.dst_reg, pc));
        }

        let s_reg = if insn.src() == BPF_X {
            let s = state.regs[insn.src_reg as usize].clone();
            if matches!(s, RegState::NotInit) {
                return Err(VerifierError::UninitializedRegister(insn.src_reg, pc));
            }
            s
        } else {
            let imm_val = if insn.class() == BPF_JMP {
                insn.imm as i64 as u64
            } else {
                u64::from(insn.imm as u32)
            };
            RegState::Scalar(ScalarBounds::from_const(imm_val))
        };

        let mut fall = Some(state.clone());
        let mut taken = Some(state.clone());

        // 1. Packet bounds refinement: compare PtrToPacket against PtrToPacketEnd
        match (&d_reg, &s_reg, op) {
            (RegState::PtrToPacket { id, off, .. }, RegState::PtrToPacketEnd, BPF_JGT) => {
                // taken: pkt > pkt_end; fall-through: pkt <= pkt_end -> range = max(range, off)
                if let Some(ref mut f) = fall {
                    f.mark_packet_range(*id, *off);
                }
                return Ok((fall, taken));
            }
            (RegState::PtrToPacket { id, off, .. }, RegState::PtrToPacketEnd, BPF_JLE) => {
                // taken: pkt <= pkt_end -> range = max(range, off)
                if let Some(ref mut t) = taken {
                    t.mark_packet_range(*id, *off);
                }
                return Ok((fall, taken));
            }
            (RegState::PtrToPacketEnd, RegState::PtrToPacket { id, off, .. }, BPF_JLT) => {
                // taken: pkt_end < pkt; fall-through: pkt_end >= pkt -> range = max(range, off)
                if let Some(ref mut f) = fall {
                    f.mark_packet_range(*id, *off);
                }
                return Ok((fall, taken));
            }
            (RegState::PtrToPacketEnd, RegState::PtrToPacket { id, off, .. }, BPF_JGE) => {
                // taken: pkt_end >= pkt -> range = max(range, off)
                if let Some(ref mut t) = taken {
                    t.mark_packet_range(*id, *off);
                }
                return Ok((fall, taken));
            }
            _ => {}
        }

        // 2. Nullability check refinement on MapValue / RingBufMem against 0
        let is_zero = matches!(s_reg, RegState::Scalar(sb) if sb.is_const() == Some(0));
        if is_zero {
            match &d_reg {
                RegState::PtrToMapValue {
                    ref_id,
                    nullable: true,
                    ..
                }
                | RegState::PtrToRingBufMem {
                    ref_id,
                    nullable: true,
                    ..
                } => {
                    match op {
                        BPF_JEQ => {
                            // taken: ptr == NULL (clear reference + reset to const 0), fall: non-NULL!
                            if let Some(ref mut t) = taken {
                                t.clear_null_ref(*ref_id);
                                t.regs[insn.dst_reg as usize] =
                                    RegState::Scalar(ScalarBounds::from_const(0));
                            }
                            if let Some(ref mut f) = fall {
                                f.mark_ptr_non_null(*ref_id);
                            }
                            return Ok((fall, taken));
                        }
                        BPF_JNE => {
                            // taken: non-NULL!, fall: NULL (clear reference + reset to const 0)
                            if let Some(ref mut t) = taken {
                                t.mark_ptr_non_null(*ref_id);
                            }
                            if let Some(ref mut f) = fall {
                                f.clear_null_ref(*ref_id);
                                f.regs[insn.dst_reg as usize] =
                                    RegState::Scalar(ScalarBounds::from_const(0));
                            }
                            return Ok((fall, taken));
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }

        // 3. Scalar branch pruning & bound tightening (essential for bounded loops & div-by-zero guards!)
        if let (RegState::Scalar(lb), RegState::Scalar(rb)) = (d_reg, s_reg) {
            let (f_b, t_b) = refine_scalar_branch(op, insn.class() == BPF_JMP, lb, rb);
            match f_b {
                Some(nb) => {
                    if let Some(ref mut f) = fall {
                        f.regs[insn.dst_reg as usize] = RegState::Scalar(nb);
                    }
                }
                None => fall = None,
            }
            match t_b {
                Some(nb) => {
                    if let Some(ref mut t) = taken {
                        t.regs[insn.dst_reg as usize] = RegState::Scalar(nb);
                    }
                }
                None => taken = None,
            }
        }

        Ok((fall, taken))
    }
}

fn refine_scalar_branch(
    op: u8,
    is_64: bool,
    lb_in: ScalarBounds,
    rb_in: ScalarBounds,
) -> (Option<ScalarBounds>, Option<ScalarBounds>) {
    let mut lb = if is_64 { lb_in } else { lb_in.zero_extend_32() };
    let rb = if is_64 { rb_in } else { rb_in.zero_extend_32() };

    if let (Some(lv), Some(rv)) = (lb.is_const(), rb.is_const()) {
        let cond = match op {
            BPF_JEQ => lv == rv,
            BPF_JNE => lv != rv,
            BPF_JGT => lv > rv,
            BPF_JGE => lv >= rv,
            BPF_JLT => lv < rv,
            BPF_JLE => lv <= rv,
            BPF_JSGT => (lv as i64) > (rv as i64),
            BPF_JSGE => (lv as i64) >= (rv as i64),
            BPF_JSLT => (lv as i64) < (rv as i64),
            BPF_JSLE => (lv as i64) <= (rv as i64),
            BPF_JSET => (lv & rv) != 0,
            _ => return (Some(lb), Some(lb)),
        };
        return if cond {
            (None, Some(lb))
        } else {
            (Some(lb), None)
        };
    }

    if let Some(rv) = rb.is_const() {
        let mut fall = lb;
        let mut taken = lb;
        match op {
            BPF_JEQ => {
                taken = ScalarBounds::from_const(rv);
                if rv == 0 && fall.umin == 0 {
                    fall.umin = 1;
                }
                if rv == lb.umax && fall.umax > fall.umin {
                    fall.umax -= 1;
                }
                if rv < lb.umin || rv > lb.umax {
                    return (Some(lb), None);
                }
            }
            BPF_JNE => {
                fall = ScalarBounds::from_const(rv);
                if rv == 0 && taken.umin == 0 {
                    taken.umin = 1;
                }
                if rv < lb.umin || rv > lb.umax {
                    return (None, Some(lb));
                }
            }
            BPF_JGT => {
                if lb.umax <= rv {
                    return (Some(lb), None);
                }
                if lb.umin > rv {
                    return (None, Some(lb));
                }
                taken.umin = taken.umin.max(rv + 1);
                fall.umax = fall.umax.min(rv);
            }
            BPF_JGE => {
                if lb.umax < rv {
                    return (Some(lb), None);
                }
                if lb.umin >= rv {
                    return (None, Some(lb));
                }
                taken.umin = taken.umin.max(rv);
                fall.umax = fall.umax.min(rv.saturating_sub(1));
            }
            BPF_JLT => {
                if lb.umin >= rv {
                    return (Some(lb), None);
                }
                if lb.umax < rv {
                    return (None, Some(lb));
                }
                taken.umax = taken.umax.min(rv.saturating_sub(1));
                fall.umin = fall.umin.max(rv);
            }
            BPF_JLE => {
                if lb.umin > rv {
                    return (Some(lb), None);
                }
                if lb.umax <= rv {
                    return (None, Some(lb));
                }
                taken.umax = taken.umax.min(rv);
                fall.umin = fall.umin.max(rv.saturating_add(1));
            }
            BPF_JSGE => {
                let r_s = rv as i64;
                if lb.smax < r_s {
                    return (Some(lb), None);
                }
                if lb.smin >= r_s {
                    return (None, Some(lb));
                }
                taken.smin = taken.smin.max(r_s);
                fall.smax = fall.smax.min(r_s.saturating_sub(1));
                if r_s >= 0 {
                    taken.umin = taken.umin.max(r_s as u64);
                }
            }
            BPF_JSLT => {
                let r_s = rv as i64;
                if lb.smin >= r_s {
                    return (Some(lb), None);
                }
                if lb.smax < r_s {
                    return (None, Some(lb));
                }
                taken.smax = taken.smax.min(r_s.saturating_sub(1));
                fall.smin = fall.smin.max(r_s);
                if r_s >= 0 {
                    fall.umin = fall.umin.max(r_s as u64);
                }
            }
            _ => {}
        }
        fall.sync_bounds();
        taken.sync_bounds();
        return (Some(fall), Some(taken));
    }

    lb.sync_bounds();
    (Some(lb), Some(lb))
}
