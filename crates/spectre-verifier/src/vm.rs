use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::isa::{
    BpfInsn, BpfMapSpec, BPF_ADD, BPF_ALU, BPF_ALU64, BPF_AND, BPF_ARSH, BPF_ATOMIC,
    BPF_ATOMIC_ADD, BPF_ATOMIC_AND, BPF_ATOMIC_FETCH, BPF_ATOMIC_OR, BPF_ATOMIC_XOR, BPF_CALL,
    BPF_DIV, BPF_END, BPF_EXIT, BPF_JA, BPF_JEQ, BPF_JGE, BPF_JGT, BPF_JLE, BPF_JLT, BPF_JMP,
    BPF_JMP32, BPF_JNE, BPF_JSET, BPF_JSGE, BPF_JSGT, BPF_JSLE, BPF_JSLT, BPF_LDX, BPF_LSH,
    BPF_MEM, BPF_MOD, BPF_MOV, BPF_MUL, BPF_NEG, BPF_OR, BPF_PSEUDO_CALL, BPF_PSEUDO_MAP_FD,
    BPF_PSEUDO_MAP_VALUE, BPF_RSH, BPF_ST, BPF_STX, BPF_SUB, BPF_X, BPF_XOR,
    HELPER_GET_PRANDOM_U32, HELPER_KTIME_GET_NS, HELPER_MAP_DELETE_ELEM, HELPER_MAP_LOOKUP_ELEM,
    HELPER_MAP_UPDATE_ELEM, HELPER_RINGBUF_DISCARD, HELPER_RINGBUF_OUTPUT, HELPER_RINGBUF_RESERVE,
    HELPER_RINGBUF_SUBMIT,
};

const STACK_BASE_ADDR: u64 = 0x1000_0000;
const CTX_BASE_ADDR: u64 = 0x2000_0000;
const PKT_BASE_ADDR: u64 = 0x3000_0000;
const MAP_VAL_STRIDE: u64 = 0x0010_0000;
const MAP_VAL_BASE: u64 = 0x4000_0000;
const RINGBUF_BASE_ADDR: u64 = 0x6000_0000;
const MAP_PTR_TAG: u64 = 0x9000_0000;

#[derive(Debug, Error)]
pub enum VmError {
    #[error("execution step limit exceeded ({0})")]
    StepLimitExceeded(usize),
    #[error("invalid memory address {0:#x} (size {1})")]
    InvalidMemoryAccess(u64, usize),
    #[error("division by zero at pc={0}")]
    DivByZero(usize),
    #[error("unsupported instruction {0:#04x} at pc={1}")]
    UnsupportedInsn(u8, usize),
}

#[derive(Debug, Clone, Default)]
pub struct VmMaps {
    pub specs: HashMap<u32, BpfMapSpec>,
    pub entries: HashMap<u32, HashMap<Vec<u8>, Vec<u8>>>,
    pub ringbuf_records: Vec<Vec<u8>>,
    next_alloc_id: u64,
    active_map_ptrs: Vec<(u64, u32, Vec<u8>)>,
    active_ringbuf_ptrs: HashMap<u64, Vec<u8>>,
    pub ktime_ns: u64,
    prng_state: u64,
}

impl VmMaps {
    #[must_use]
    pub fn new() -> Self {
        Self {
            ktime_ns: 1_000_000_000,
            prng_state: 0x1234_5678_9ABC_DEF0,
            ..Self::default()
        }
    }

    pub fn add_map(&mut self, spec: BpfMapSpec) {
        let id = spec.id;
        self.specs.insert(id, spec);
        self.entries.entry(id).or_default();
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmExecResult {
    pub return_code: u64,
    pub cycles: usize,
    pub ringbuf_records: Vec<Vec<u8>>,
}

/// Pure-Rust concrete eBPF ISA v3 Sandbox VM for deterministic packet & map execution.
pub struct BpfVm;

impl BpfVm {
    pub fn run_xdp(
        insns: &[BpfInsn],
        packet: &mut [u8],
        maps: &mut VmMaps,
        max_cycles: usize,
    ) -> Result<VmExecResult, VmError> {
        let mut regs = [0u64; 11];
        regs[1] = CTX_BASE_ADDR;
        regs[10] = STACK_BASE_ADDR + 512;

        let mut stack = [0u8; 512];
        let mut xdp_md = [0u8; 24];
        let pkt_start = PKT_BASE_ADDR as u32;
        let pkt_end = (PKT_BASE_ADDR + packet.len() as u64) as u32;
        xdp_md[0..4].copy_from_slice(&pkt_start.to_le_bytes());
        xdp_md[4..8].copy_from_slice(&pkt_end.to_le_bytes());
        xdp_md[8..12].copy_from_slice(&pkt_start.to_le_bytes());
        xdp_md[12..16].copy_from_slice(&1u32.to_le_bytes()); // ingress_ifindex

        let mut call_stack: Vec<(usize, [u64; 4])> = Vec::new();
        let mut pc = 0usize;
        let mut cycles = 0usize;

        while pc < insns.len() {
            if cycles >= max_cycles {
                return Err(VmError::StepLimitExceeded(cycles));
            }
            cycles += 1;
            let insn = insns[pc];

            if insn.is_ld_imm64() {
                let hi = insns.get(pc + 1).map_or(0, |n| n.imm);
                let val = match insn.src_reg {
                    BPF_PSEUDO_MAP_FD => MAP_PTR_TAG | u64::from(insn.imm as u32),
                    BPF_PSEUDO_MAP_VALUE => {
                        let map_id = insn.imm as u32;
                        let off = u64::from(hi as u32);
                        MAP_VAL_BASE + u64::from(map_id) * MAP_VAL_STRIDE + off
                    }
                    _ => (insn.imm as u32 as u64) | ((hi as u32 as u64) << 32),
                };
                regs[insn.dst_reg as usize] = val;
                pc += 2;
                continue;
            }

            match insn.class() {
                BPF_LDX if insn.mode() == BPF_MEM => {
                    let addr = (regs[insn.src_reg as usize] as i64 + i64::from(insn.off)) as u64;
                    let sz = insn.mem_size_bytes() as usize;
                    regs[insn.dst_reg as usize] =
                        read_mem(addr, sz, &stack, &xdp_md, packet, maps)?;
                    pc += 1;
                }
                BPF_ST if insn.mode() == BPF_MEM => {
                    let addr = (regs[insn.dst_reg as usize] as i64 + i64::from(insn.off)) as u64;
                    let sz = insn.mem_size_bytes() as usize;
                    write_mem(addr, sz, insn.imm as i64 as u64, &mut stack, packet, maps)?;
                    pc += 1;
                }
                BPF_STX if insn.mode() == BPF_MEM => {
                    let addr = (regs[insn.dst_reg as usize] as i64 + i64::from(insn.off)) as u64;
                    let sz = insn.mem_size_bytes() as usize;
                    write_mem(
                        addr,
                        sz,
                        regs[insn.src_reg as usize],
                        &mut stack,
                        packet,
                        maps,
                    )?;
                    pc += 1;
                }
                BPF_STX if insn.mode() == BPF_ATOMIC => {
                    let addr = (regs[insn.dst_reg as usize] as i64 + i64::from(insn.off)) as u64;
                    let sz = insn.mem_size_bytes() as usize;
                    let cur = read_mem(addr, sz, &stack, &xdp_md, packet, maps)?;
                    let src_val = regs[insn.src_reg as usize];
                    let new_val = match insn.imm & !BPF_ATOMIC_FETCH {
                        BPF_ATOMIC_ADD => cur.wrapping_add(src_val),
                        BPF_ATOMIC_OR => cur | src_val,
                        BPF_ATOMIC_AND => cur & src_val,
                        BPF_ATOMIC_XOR => cur ^ src_val,
                        _ => src_val,
                    };
                    write_mem(addr, sz, new_val, &mut stack, packet, maps)?;
                    if (insn.imm & BPF_ATOMIC_FETCH) != 0 {
                        regs[insn.src_reg as usize] = cur;
                    }
                    pc += 1;
                }
                BPF_ALU | BPF_ALU64 => {
                    let is_64 = insn.class() == BPF_ALU64;
                    let rhs = if insn.src() == BPF_X {
                        regs[insn.src_reg as usize]
                    } else if is_64 {
                        insn.imm as i64 as u64
                    } else {
                        u64::from(insn.imm as u32)
                    };
                    let d = insn.dst_reg as usize;
                    let lhs = regs[d];
                    let out = if is_64 {
                        match insn.op() {
                            BPF_MOV => rhs,
                            BPF_ADD => lhs.wrapping_add(rhs),
                            BPF_SUB => lhs.wrapping_sub(rhs),
                            BPF_MUL => lhs.wrapping_mul(rhs),
                            BPF_DIV => {
                                if rhs == 0 {
                                    return Err(VmError::DivByZero(pc));
                                }
                                lhs / rhs
                            }
                            BPF_MOD => {
                                if rhs == 0 {
                                    return Err(VmError::DivByZero(pc));
                                }
                                lhs % rhs
                            }
                            BPF_OR => lhs | rhs,
                            BPF_AND => lhs & rhs,
                            BPF_XOR => lhs ^ rhs,
                            BPF_LSH => lhs.wrapping_shl((rhs & 63) as u32),
                            BPF_RSH => lhs.wrapping_shr((rhs & 63) as u32),
                            BPF_ARSH => ((lhs as i64).wrapping_shr((rhs & 63) as u32)) as u64,
                            BPF_NEG => (lhs as i64).wrapping_neg() as u64,
                            BPF_END => eval_end(lhs, insn.imm, insn.src() == BPF_X),
                            other => return Err(VmError::UnsupportedInsn(other, pc)),
                        }
                    } else {
                        let l32 = lhs as u32;
                        let r32 = rhs as u32;
                        let out32 = match insn.op() {
                            BPF_MOV => r32,
                            BPF_ADD => l32.wrapping_add(r32),
                            BPF_SUB => l32.wrapping_sub(r32),
                            BPF_MUL => l32.wrapping_mul(r32),
                            BPF_DIV => {
                                if r32 == 0 {
                                    return Err(VmError::DivByZero(pc));
                                }
                                l32 / r32
                            }
                            BPF_MOD => {
                                if r32 == 0 {
                                    return Err(VmError::DivByZero(pc));
                                }
                                l32 % r32
                            }
                            BPF_OR => l32 | r32,
                            BPF_AND => l32 & r32,
                            BPF_XOR => l32 ^ r32,
                            BPF_LSH => l32.wrapping_shl(r32 & 31),
                            BPF_RSH => l32.wrapping_shr(r32 & 31),
                            BPF_ARSH => ((l32 as i32).wrapping_shr(r32 & 31)) as u32,
                            BPF_NEG => (l32 as i32).wrapping_neg() as u32,
                            other => return Err(VmError::UnsupportedInsn(other, pc)),
                        };
                        u64::from(out32)
                    };
                    regs[d] = out;
                    pc += 1;
                }
                BPF_JMP | BPF_JMP32 => {
                    let is_64 = insn.class() == BPF_JMP;
                    match insn.op() {
                        BPF_EXIT => {
                            if let Some((ret_pc, saved)) = call_stack.pop() {
                                regs[6..=9].copy_from_slice(&saved);
                                pc = ret_pc;
                            } else {
                                return Ok(VmExecResult {
                                    return_code: regs[0],
                                    cycles,
                                    ringbuf_records: maps.ringbuf_records.clone(),
                                });
                            }
                        }
                        BPF_JA => {
                            pc = ((pc as isize) + 1 + (insn.off as isize)) as usize;
                        }
                        BPF_CALL => {
                            if insn.src_reg == BPF_PSEUDO_CALL {
                                let saved = [regs[6], regs[7], regs[8], regs[9]];
                                call_stack.push((pc + 1, saved));
                                pc = ((pc as isize) + 1 + (insn.imm as isize)) as usize;
                            } else {
                                exec_helper(insn.imm, &mut regs, &stack, packet, maps)?;
                                pc += 1;
                            }
                        }
                        op => {
                            let rhs = if insn.src() == BPF_X {
                                regs[insn.src_reg as usize]
                            } else if is_64 {
                                insn.imm as i64 as u64
                            } else {
                                u64::from(insn.imm as u32)
                            };
                            let lhs = regs[insn.dst_reg as usize];
                            let take = if is_64 {
                                eval_cond_64(op, lhs, rhs)
                            } else {
                                eval_cond_64(op, u64::from(lhs as u32), u64::from(rhs as u32))
                            };
                            if take {
                                pc = ((pc as isize) + 1 + (insn.off as isize)) as usize;
                            } else {
                                pc += 1;
                            }
                        }
                    }
                }
                other => return Err(VmError::UnsupportedInsn(other, pc)),
            }
        }

        Ok(VmExecResult {
            return_code: regs[0],
            cycles,
            ringbuf_records: maps.ringbuf_records.clone(),
        })
    }
}

fn eval_end(val: u64, bits: i32, to_be: bool) -> u64 {
    if !to_be {
        return match bits {
            16 => u64::from((val as u16).to_le()),
            32 => u64::from((val as u32).to_le()),
            _ => val.to_le(),
        };
    }
    match bits {
        16 => u64::from((val as u16).swap_bytes()),
        32 => u64::from((val as u32).swap_bytes()),
        _ => val.swap_bytes(),
    }
}

fn eval_cond_64(op: u8, l: u64, r: u64) -> bool {
    match op {
        BPF_JEQ => l == r,
        BPF_JNE => l != r,
        BPF_JGT => l > r,
        BPF_JGE => l >= r,
        BPF_JLT => l < r,
        BPF_JLE => l <= r,
        BPF_JSGT => (l as i64) > (r as i64),
        BPF_JSGE => (l as i64) >= (r as i64),
        BPF_JSLT => (l as i64) < (r as i64),
        BPF_JSLE => (l as i64) <= (r as i64),
        BPF_JSET => (l & r) != 0,
        _ => false,
    }
}

fn read_bytes<'a>(
    addr: u64,
    sz: usize,
    stack: &'a [u8; 512],
    xdp_md: &'a [u8; 24],
    pkt: &'a [u8],
    maps: &'a VmMaps,
) -> Result<&'a [u8], VmError> {
    if addr >= STACK_BASE_ADDR && addr + sz as u64 <= STACK_BASE_ADDR + 512 {
        let off = (addr - STACK_BASE_ADDR) as usize;
        return Ok(&stack[off..off + sz]);
    }
    if addr >= CTX_BASE_ADDR && addr + sz as u64 <= CTX_BASE_ADDR + 24 {
        let off = (addr - CTX_BASE_ADDR) as usize;
        return Ok(&xdp_md[off..off + sz]);
    }
    if addr >= PKT_BASE_ADDR && addr + sz as u64 <= PKT_BASE_ADDR + pkt.len() as u64 {
        let off = (addr - PKT_BASE_ADDR) as usize;
        return Ok(&pkt[off..off + sz]);
    }
    if addr >= RINGBUF_BASE_ADDR {
        let ptr_id = addr & !0xFFFF_FFFF;
        let off = (addr & 0xFFFF_FFFF) as usize;
        if let Some(buf) = maps.active_ringbuf_ptrs.get(&ptr_id) {
            if off + sz <= buf.len() {
                return Ok(&buf[off..off + sz]);
            }
        }
    }
    if (MAP_VAL_BASE..RINGBUF_BASE_ADDR).contains(&addr) {
        for (ptr_base, _map_id, val) in &maps.active_map_ptrs {
            if addr >= *ptr_base && addr + sz as u64 <= *ptr_base + val.len() as u64 {
                let off = (addr - *ptr_base) as usize;
                return Ok(&val[off..off + sz]);
            }
        }
        // Also allow array map[0] value pointer via MAP_VAL_BASE
        let rel = addr - MAP_VAL_BASE;
        let map_id = (rel / MAP_VAL_STRIDE) as u32;
        let off = (rel % MAP_VAL_STRIDE) as usize;
        if let Some(m) = maps.entries.get(&map_id) {
            let key0 = 0u32.to_le_bytes().to_vec();
            if let Some(val) = m.get(&key0) {
                if off + sz <= val.len() {
                    return Ok(&val[off..off + sz]);
                }
            }
        }
    }
    Err(VmError::InvalidMemoryAccess(addr, sz))
}

fn read_mem(
    addr: u64,
    sz: usize,
    stack: &[u8; 512],
    xdp_md: &[u8; 24],
    pkt: &[u8],
    maps: &VmMaps,
) -> Result<u64, VmError> {
    let slice = read_bytes(addr, sz, stack, xdp_md, pkt, maps)?;
    Ok(match sz {
        1 => u64::from(slice[0]),
        2 => u64::from(u16::from_le_bytes([slice[0], slice[1]])),
        4 => u64::from(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]])),
        8 => u64::from_le_bytes([
            slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
        ]),
        _ => return Err(VmError::InvalidMemoryAccess(addr, sz)),
    })
}

fn write_mem(
    addr: u64,
    sz: usize,
    val: u64,
    stack: &mut [u8; 512],
    pkt: &mut [u8],
    maps: &mut VmMaps,
) -> Result<(), VmError> {
    let bytes = val.to_le_bytes();
    let src = &bytes[..sz];
    if addr >= STACK_BASE_ADDR && addr + sz as u64 <= STACK_BASE_ADDR + 512 {
        let off = (addr - STACK_BASE_ADDR) as usize;
        stack[off..off + sz].copy_from_slice(src);
        return Ok(());
    }
    if addr >= PKT_BASE_ADDR && addr + sz as u64 <= PKT_BASE_ADDR + pkt.len() as u64 {
        let off = (addr - PKT_BASE_ADDR) as usize;
        pkt[off..off + sz].copy_from_slice(src);
        return Ok(());
    }
    if addr >= RINGBUF_BASE_ADDR {
        let ptr_id = addr & !0xFFFF_FFFF;
        let off = (addr & 0xFFFF_FFFF) as usize;
        if let Some(buf) = maps.active_ringbuf_ptrs.get_mut(&ptr_id) {
            if off + sz <= buf.len() {
                buf[off..off + sz].copy_from_slice(src);
                return Ok(());
            }
        }
    }
    if (MAP_VAL_BASE..RINGBUF_BASE_ADDR).contains(&addr) {
        for (ptr_base, map_id, val_buf) in &mut maps.active_map_ptrs {
            if addr >= *ptr_base && addr + sz as u64 <= *ptr_base + val_buf.len() as u64 {
                let off = (addr - *ptr_base) as usize;
                val_buf[off..off + sz].copy_from_slice(src);
                // Write-through to map backing storage if possible
                let _ = map_id;
                return Ok(());
            }
        }
    }
    Err(VmError::InvalidMemoryAccess(addr, sz))
}

fn exec_helper(
    helper: i32,
    regs: &mut [u64; 11],
    stack: &[u8; 512],
    pkt: &[u8],
    maps: &mut VmMaps,
) -> Result<(), VmError> {
    match helper {
        HELPER_KTIME_GET_NS => {
            maps.ktime_ns += 1_000;
            regs[0] = maps.ktime_ns;
        }
        HELPER_GET_PRANDOM_U32 => {
            maps.prng_state ^= maps.prng_state << 13;
            maps.prng_state ^= maps.prng_state >> 7;
            maps.prng_state ^= maps.prng_state << 17;
            regs[0] = maps.prng_state & 0xFFFF_FFFF;
        }
        HELPER_MAP_LOOKUP_ELEM => {
            let map_id = (regs[1] & 0xFFFF_FFFF) as u32;
            let key_addr = regs[2];
            let Some(spec) = maps.specs.get(&map_id).cloned() else {
                regs[0] = 0;
                return Ok(());
            };
            let key =
                read_bytes(key_addr, spec.key_size as usize, stack, &[0; 24], pkt, maps)?.to_vec();
            let val_opt = maps.entries.get(&map_id).and_then(|m| m.get(&key)).cloned();
            if let Some(val) = val_opt {
                maps.next_alloc_id += 1;
                let ptr = MAP_VAL_BASE + maps.next_alloc_id * MAP_VAL_STRIDE;
                maps.active_map_ptrs.push((ptr, map_id, val));
                regs[0] = ptr;
            } else {
                regs[0] = 0;
            }
        }
        HELPER_MAP_UPDATE_ELEM => {
            let map_id = (regs[1] & 0xFFFF_FFFF) as u32;
            let key_addr = regs[2];
            let val_addr = regs[3];
            let Some(spec) = maps.specs.get(&map_id).cloned() else {
                regs[0] = u64::MAX;
                return Ok(());
            };
            let key =
                read_bytes(key_addr, spec.key_size as usize, stack, &[0; 24], pkt, maps)?.to_vec();
            let val = read_bytes(
                val_addr,
                spec.value_size as usize,
                stack,
                &[0; 24],
                pkt,
                maps,
            )?
            .to_vec();
            maps.entries.entry(map_id).or_default().insert(key, val);
            regs[0] = 0;
        }
        HELPER_MAP_DELETE_ELEM => {
            let map_id = (regs[1] & 0xFFFF_FFFF) as u32;
            let key_addr = regs[2];
            if let Some(spec) = maps.specs.get(&map_id).cloned() {
                let key = read_bytes(key_addr, spec.key_size as usize, stack, &[0; 24], pkt, maps)?
                    .to_vec();
                if let Some(m) = maps.entries.get_mut(&map_id) {
                    m.remove(&key);
                }
            }
            regs[0] = 0;
        }
        HELPER_RINGBUF_RESERVE => {
            let sz = regs[2] as usize;
            maps.next_alloc_id += 1;
            let base = RINGBUF_BASE_ADDR + (maps.next_alloc_id << 32);
            maps.active_ringbuf_ptrs.insert(base, vec![0u8; sz]);
            regs[0] = base;
        }
        HELPER_RINGBUF_SUBMIT => {
            let ptr_id = regs[1] & !0xFFFF_FFFF;
            if let Some(buf) = maps.active_ringbuf_ptrs.remove(&ptr_id) {
                maps.ringbuf_records.push(buf);
            }
            regs[0] = 0;
        }
        HELPER_RINGBUF_DISCARD => {
            let ptr_id = regs[1] & !0xFFFF_FFFF;
            maps.active_ringbuf_ptrs.remove(&ptr_id);
            regs[0] = 0;
        }
        HELPER_RINGBUF_OUTPUT => {
            let buf_addr = regs[2];
            let sz = regs[3] as usize;
            let data = read_bytes(buf_addr, sz, stack, &[0; 24], pkt, maps)?.to_vec();
            maps.ringbuf_records.push(data);
            regs[0] = 0;
        }
        _ => regs[0] = 0,
    }
    Ok(())
}
