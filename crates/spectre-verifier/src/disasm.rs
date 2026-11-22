use serde::{Deserialize, Serialize};

use crate::isa::{
    helper_name, BpfInsn, BPF_ADD, BPF_ALU, BPF_ALU64, BPF_AND, BPF_ARSH, BPF_ATOMIC,
    BPF_ATOMIC_ADD, BPF_ATOMIC_AND, BPF_ATOMIC_CMPXCHG, BPF_ATOMIC_FETCH, BPF_ATOMIC_OR,
    BPF_ATOMIC_XCHG, BPF_ATOMIC_XOR, BPF_B, BPF_CALL, BPF_DIV, BPF_DW, BPF_END, BPF_EXIT, BPF_H,
    BPF_IMM, BPF_JA, BPF_JEQ, BPF_JGE, BPF_JGT, BPF_JLE, BPF_JLT, BPF_JMP, BPF_JMP32, BPF_JNE,
    BPF_JSET, BPF_JSGE, BPF_JSGT, BPF_JSLE, BPF_JSLT, BPF_LD, BPF_LDX, BPF_LSH, BPF_MEM, BPF_MOD,
    BPF_MOV, BPF_MUL, BPF_NEG, BPF_OR, BPF_PSEUDO_CALL, BPF_PSEUDO_MAP_FD, BPF_PSEUDO_MAP_VALUE,
    BPF_RSH, BPF_ST, BPF_STX, BPF_SUB, BPF_W, BPF_X, BPF_XOR,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisasmLine {
    pub pc: usize,
    pub text: String,
    pub slots: usize,
}

#[must_use]
pub fn size_str(size: u8) -> &'static str {
    match size {
        BPF_B => "u8",
        BPF_H => "u16",
        BPF_W => "u32",
        BPF_DW => "u64",
        _ => "u?",
    }
}

#[must_use]
pub fn disassemble_insn(insns: &[BpfInsn], pc: usize) -> (String, usize) {
    let insn = insns[pc];
    let d = insn.dst_reg;
    let s = insn.src_reg;

    if insn.is_ld_imm64() {
        let hi = insns.get(pc + 1).map_or(0, |n| n.imm);
        let full = (insn.imm as u32 as u64) | ((hi as u32 as u64) << 32);
        let text = match insn.src_reg {
            BPF_PSEUDO_MAP_FD => format!("r{d} = map_fd({:#x}) ll", insn.imm),
            BPF_PSEUDO_MAP_VALUE => format!("r{d} = map_val(fd={}, off={hi}) ll", insn.imm),
            _ => format!("r{d} = {full:#x} ll"),
        };
        return (text, 2);
    }

    let text = match insn.class() {
        BPF_LDX if insn.mode() == BPF_MEM => {
            format!("r{d} = *({} *)(r{s} {:+})", size_str(insn.size()), insn.off)
        }
        BPF_ST if insn.mode() == BPF_MEM => {
            format!(
                "*({} *)(r{d} {:+}) = {}",
                size_str(insn.size()),
                insn.off,
                insn.imm
            )
        }
        BPF_STX if insn.mode() == BPF_MEM => {
            format!("*({} *)(r{d} {:+}) = r{s}", size_str(insn.size()), insn.off)
        }
        BPF_STX if insn.mode() == BPF_ATOMIC => {
            let ty = size_str(insn.size());
            match insn.imm {
                BPF_ATOMIC_ADD => format!("lock *({ty} *)(r{d} {:+}) += r{s}", insn.off),
                v if v == (BPF_ATOMIC_ADD | BPF_ATOMIC_FETCH) => {
                    format!(
                        "r{s} = atomic_fetch_add(({ty} *)(r{d} {:+}), r{s})",
                        insn.off
                    )
                }
                BPF_ATOMIC_OR => format!("lock *({ty} *)(r{d} {:+}) |= r{s}", insn.off),
                BPF_ATOMIC_AND => format!("lock *({ty} *)(r{d} {:+}) &= r{s}", insn.off),
                BPF_ATOMIC_XOR => format!("lock *({ty} *)(r{d} {:+}) ^= r{s}", insn.off),
                BPF_ATOMIC_XCHG => {
                    format!("r{s} = xchg(({ty} *)(r{d} {:+}), r{s})", insn.off)
                }
                BPF_ATOMIC_CMPXCHG => {
                    format!("r0 = cmpxchg(({ty} *)(r{d} {:+}), r0, r{s})", insn.off)
                }
                other => format!(
                    "lock *({ty} *)(r{d} {:+}) atomic_op({other:#x}) r{s}",
                    insn.off
                ),
            }
        }
        BPF_ALU | BPF_ALU64 => {
            let pfx = if insn.class() == BPF_ALU64 { 'r' } else { 'w' };
            let rhs = if insn.src() == BPF_X {
                format!("{pfx}{s}")
            } else {
                format!("{}", insn.imm)
            };
            match insn.op() {
                BPF_MOV => format!("{pfx}{d} = {rhs}"),
                BPF_ADD => format!("{pfx}{d} += {rhs}"),
                BPF_SUB => format!("{pfx}{d} -= {rhs}"),
                BPF_MUL => format!("{pfx}{d} *= {rhs}"),
                BPF_DIV => format!("{pfx}{d} /= {rhs}"),
                BPF_MOD => format!("{pfx}{d} %= {rhs}"),
                BPF_OR => format!("{pfx}{d} |= {rhs}"),
                BPF_AND => format!("{pfx}{d} &= {rhs}"),
                BPF_XOR => format!("{pfx}{d} ^= {rhs}"),
                BPF_LSH => format!("{pfx}{d} <<= {rhs}"),
                BPF_RSH => format!("{pfx}{d} >>= {rhs}"),
                BPF_ARSH => format!("{pfx}{d} s>>= {rhs}"),
                BPF_NEG => format!("{pfx}{d} = -{pfx}{d}"),
                BPF_END => {
                    let kind = if insn.src() == BPF_X { "be" } else { "le" };
                    format!("r{d} = {kind}{} r{d}", insn.imm)
                }
                op => format!("alu_unk({op:#x}) {pfx}{d}, {rhs}"),
            }
        }
        BPF_JMP | BPF_JMP32 => {
            let pfx = if insn.class() == BPF_JMP { 'r' } else { 'w' };
            let rhs = if insn.src() == BPF_X {
                format!("{pfx}{s}")
            } else {
                format!("{}", insn.imm)
            };
            let target = (pc as isize) + 1 + (insn.off as isize);
            match insn.op() {
                BPF_JA => format!("goto pc{:+}", insn.off),
                BPF_CALL => {
                    if insn.src_reg == BPF_PSEUDO_CALL {
                        format!("call pc{:+}", insn.imm)
                    } else {
                        format!("call {}#{}", helper_name(insn.imm), insn.imm)
                    }
                }
                BPF_EXIT => "exit".to_owned(),
                BPF_JEQ => format!("if {pfx}{d} == {rhs} goto pc+{target} ({:+})", insn.off),
                BPF_JNE => format!("if {pfx}{d} != {rhs} goto pc+{target} ({:+})", insn.off),
                BPF_JGT => format!("if {pfx}{d} > {rhs} goto pc+{target} ({:+})", insn.off),
                BPF_JGE => format!("if {pfx}{d} >= {rhs} goto pc+{target} ({:+})", insn.off),
                BPF_JLT => format!("if {pfx}{d} < {rhs} goto pc+{target} ({:+})", insn.off),
                BPF_JLE => format!("if {pfx}{d} <= {rhs} goto pc+{target} ({:+})", insn.off),
                BPF_JSGT => format!("if {pfx}{d} s> {rhs} goto pc+{target} ({:+})", insn.off),
                BPF_JSGE => format!("if {pfx}{d} s>= {rhs} goto pc+{target} ({:+})", insn.off),
                BPF_JSLT => format!("if {pfx}{d} s< {rhs} goto pc+{target} ({:+})", insn.off),
                BPF_JSLE => format!("if {pfx}{d} s<= {rhs} goto pc+{target} ({:+})", insn.off),
                BPF_JSET => format!("if {pfx}{d} & {rhs} goto pc+{target} ({:+})", insn.off),
                op => format!("jmp_unk({op:#x})"),
            }
        }
        _ if insn.code == (BPF_LD | BPF_IMM) => format!("ld_unk r{d}"),
        other => format!("unk({other:#04x})"),
    };

    (text, 1)
}

#[must_use]
pub fn disassemble_program(insns: &[BpfInsn]) -> Vec<DisasmLine> {
    let mut out = Vec::new();
    let mut pc = 0usize;
    while pc < insns.len() {
        let (text, slots) = disassemble_insn(insns, pc);
        out.push(DisasmLine { pc, text, slots });
        pc += slots;
    }
    out
}
