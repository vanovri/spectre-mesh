#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetArch {
    X86_64,
    Aarch64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodedInsn {
    pub offset: usize,
    pub len: usize,
    pub is_ret: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ImmKind {
    None,
    Imm8,
    Imm16,
    ImmZ,   // 16-bit if 0x66 (without REX.W), else 32-bit
    ImmV,   // 16-bit if 0x66 (without REX.W), 64-bit if REX.W, else 32-bit (B8..BF)
    Moffs,  // 32-bit if 0x67, else 64-bit (A0..A3)
    Enter,  // 3 bytes (imm16 + imm8)
    Group3, // F6 (/0,/1 -> Imm8), F7 (/0,/1 -> ImmZ)
}

#[inline]
const fn is_legacy_prefix(b: u8) -> bool {
    matches!(
        b,
        0xF0 | 0xF2 | 0xF3 | 0x26 | 0x2E | 0x36 | 0x3E | 0x64 | 0x65 | 0x66 | 0x67
    )
}

#[inline]
const fn x86_imm_size(kind: ImmKind, has_66: bool, has_67: bool, rex_w: bool, _modrm: u8) -> usize {
    match kind {
        ImmKind::None => 0,
        ImmKind::Imm8 => 1,
        ImmKind::Imm16 => 2,
        ImmKind::ImmZ => {
            if has_66 && !rex_w {
                2
            } else {
                4
            }
        }
        ImmKind::ImmV => {
            if rex_w {
                8
            } else if has_66 {
                2
            } else {
                4
            }
        }
        ImmKind::Moffs => {
            if has_67 {
                4
            } else {
                8
            }
        }
        ImmKind::Enter => 3,
        ImmKind::Group3 => 0, // Handled dynamically per opcode (F6 vs F7) and modrm.reg
    }
}

/// Compute ModR/M + optional SIB + displacement byte length (including the ModR/M byte itself).
fn modrm_len(bytes: &[u8], idx: usize, has_67: bool) -> Option<(usize, u8)> {
    let modrm = *bytes.get(idx)?;
    let mod_bits = (modrm >> 6) & 0x03;
    let rm = modrm & 0x07;
    if mod_bits == 3 {
        return Some((1, modrm));
    }

    let mut extra = 0usize;
    if has_67 {
        // 32-bit addressing mode in 64-bit mode
        if rm == 4 {
            // SIB
            let sib = *bytes.get(idx + 1)?;
            extra += 1;
            if mod_bits == 0 && (sib & 0x07) == 5 {
                extra += 4;
            }
        } else if mod_bits == 0 && rm == 5 {
            extra += 4;
        }
        match mod_bits {
            1 => extra += 1,
            2 => extra += 4,
            _ => {}
        }
    } else {
        if rm == 4 {
            let sib = *bytes.get(idx + 1)?;
            extra += 1;
            if mod_bits == 0 && (sib & 0x07) == 5 {
                extra += 4;
            }
        } else if mod_bits == 0 && rm == 5 {
            // [RIP + disp32]
            extra += 4;
        }
        match mod_bits {
            1 => extra += 1,
            2 => extra += 4,
            _ => {}
        }
    }
    Some((1 + extra, modrm))
}

fn one_byte_table(op: u8) -> (bool, ImmKind) {
    match op {
        // ALU/logic r/m & reg (00..3F, skipping DAA/DAS/AAA/AAS 27,2F,37,3F invalid in 64-bit)
        0x00..=0x03
        | 0x08..=0x0B
        | 0x10..=0x13
        | 0x18..=0x1B
        | 0x20..=0x23
        | 0x28..=0x2B
        | 0x30..=0x33
        | 0x38..=0x3B => (true, ImmKind::None),
        0x04 | 0x0C | 0x14 | 0x1C | 0x24 | 0x2C | 0x34 | 0x3C => (false, ImmKind::Imm8),
        0x05 | 0x0D | 0x15 | 0x1D | 0x25 | 0x2D | 0x35 | 0x3D => (false, ImmKind::ImmZ),
        // 50..5F PUSH/POP reg; 63 MOVSXD r, r/m32; 68 PUSH immZ; 69 IMUL r, r/m, immZ; 6A PUSH imm8; 6B IMUL r, r/m, imm8
        0x50..=0x5F => (false, ImmKind::None),
        0x63 | 0x6D | 0x6F => (true, ImmKind::None), // 6D/6F are INS/OUTS (no modrm actually!) - handle below
        0x68 => (false, ImmKind::ImmZ),
        0x69 => (true, ImmKind::ImmZ),
        0x6A => (false, ImmKind::Imm8),
        0x6B => (true, ImmKind::Imm8),
        // Jcc rel8 (70..7F)
        0x70..=0x7F => (false, ImmKind::Imm8),
        // 80..83 Immediate Group 1
        0x80 | 0x82 => (true, ImmKind::Imm8),
        0x81 => (true, ImmKind::ImmZ),
        0x83 => (true, ImmKind::Imm8),
        // 84..8F TEST, XCHG, MOV, LEA, POP r/m
        0x84..=0x8D | 0x8F => (true, ImmKind::None),
        // 90..9F NOP, XCHG rAX, CBW/CDQ, WAIT, PUSHF/POPF, SAHF/LAHF
        0x90..=0x99 | 0x9B..=0x9F => (false, ImmKind::None),
        // A0..A3 MOV AL/RAX <-> moffs
        0xA0..=0xA3 => (false, ImmKind::Moffs),
        // A4..AF MOVS/CMPS/TEST imm/STOS/LODS/SCAS
        0xA4..=0xA7 | 0xAA..=0xAF => (false, ImmKind::None),
        0xA8 => (false, ImmKind::Imm8),
        0xA9 => (false, ImmKind::ImmZ),
        // B0..B7 MOV r8, imm8
        0xB0..=0xB7 => (false, ImmKind::Imm8),
        // B8..BF MOV r, immV (64-bit with REX.W!)
        0xB8..=0xBF => (false, ImmKind::ImmV),
        // C0..C1 Shift Group 2 (imm8)
        0xC0 | 0xC1 => (true, ImmKind::Imm8),
        // C2 RET imm16; C3 RET
        0xC2 => (false, ImmKind::Imm16),
        0xC3 => (false, ImmKind::None),
        // C6/C7 MOV r/m, imm
        0xC6 => (true, ImmKind::Imm8),
        0xC7 => (true, ImmKind::ImmZ),
        // C8 ENTER, C9 LEAVE, CA RETF imm16, CB RETF, CC INT3, CD INT imm8, CF IRETD/Q
        0xC8 => (false, ImmKind::Enter),
        0xC9 | 0xCB | 0xCC | 0xCF => (false, ImmKind::None),
        0xCA => (false, ImmKind::Imm16),
        0xCD => (false, ImmKind::Imm8),
        // D0..D3 Shifts without imm; D8..DF x87 FPU (all ModR/M)
        0xD0..=0xD3 | 0xD8..=0xDF => (true, ImmKind::None),
        // D7 XLAT
        0xD7 => (false, ImmKind::None),
        // E0..E7 LOOP/JCXZ/IN/OUT imm8
        0xE0..=0xE7 => (false, ImmKind::Imm8),
        // E8 CALL rel32, E9 JMP rel32, EB JMP rel8
        0xE8 | 0xE9 => (false, ImmKind::ImmZ),
        0xEB => (false, ImmKind::Imm8),
        // EC..EE IN/OUT DX; F1 INT1; F4..F5 HLT/CMC; F8..FD flags
        0xEC..=0xEF | 0xF1 | 0xF4 | 0xF5 | 0xF8..=0xFD => (false, ImmKind::None),
        // F6/F7 Unary Group 3
        0xF6 | 0xF7 => (true, ImmKind::Group3),
        // FE/FF INC/DEC/CALL/JMP/PUSH
        0xFE | 0xFF => (true, ImmKind::None),
        _ => (false, ImmKind::None),
    }
}

fn two_byte_0f_table(op2: u8) -> (bool, ImmKind) {
    match op2 {
        // 0F 00..03 sys/lar/lsl; 0F 05 SYSCALL; 0F 06 CLTS; 0F 07 SYSRET; 0F 08..09 INVD/WBINVD; 0F 0B UD2; 0F 0D PREFETCHW; 0F 0E FEMMS
        0x00..=0x03 | 0x0D => (true, ImmKind::None),
        0x05..=0x09 | 0x0B | 0x0E => (false, ImmKind::None),
        // 0F 10..1F SSE MOV/NOP/PREFETCH
        0x10..=0x1F => (true, ImmKind::None),
        // 0F 20..2F Control reg moves & SSE
        0x20..=0x2F => (true, ImmKind::None),
        // 0F 30..37 WRMSR/RDTSC/RDMSR/SYSENTER/SYSEXIT/GETSEC
        0x30..=0x37 => (false, ImmKind::None),
        // 0F 40..6F CMOVcc + MMX/SSE
        0x40..=0x6F => (true, ImmKind::None),
        // 0F 70 PSHUFW/PSHUF*, 0F 71..73 SSE shift imm8
        0x70..=0x73 => (true, ImmKind::Imm8),
        // 0F 74..7F PCMPEQ/EMMS(77 no modrm)/VMREAD/MOVD/MOVQ
        0x77 => (false, ImmKind::None),
        0x74..=0x76 | 0x78..=0x7F => (true, ImmKind::None),
        // 0F 80..8F Jcc rel32
        0x80..=0x8F => (false, ImmKind::ImmZ),
        // 0F 90..9F SETcc
        0x90..=0x9F => (true, ImmKind::None),
        // 0F A0..AF: A0,A1,A8,A9 PUSH/POP FS/GS; A2 CPUID; A4,AC SHLD/SHRD imm8; AA RSM; A3,A5,AB,AD,AE,AF ModR/M
        0xA0 | 0xA1 | 0xA2 | 0xA8 | 0xA9 | 0xAA => (false, ImmKind::None),
        0xA4 | 0xAC => (true, ImmKind::Imm8),
        0xA3 | 0xA5 | 0xAB | 0xAD..=0xAF => (true, ImmKind::None),
        // 0F B0..BF CMPXCHG/LSS/BTR/BT/MOVZX/POPCNT/GRP10/BTS/BSF/BSR
        0xBA => (true, ImmKind::Imm8),
        0xB0..=0xB9 | 0xBB..=0xBF => (true, ImmKind::None),
        // 0F C0..C7: C0/C1 XADD; C2 CMPPS imm8; C3 MOVNTI; C4 PINSRW imm8; C5 PEXTRW imm8; C6 SHUFPS imm8; C7 CMPXCHG8B/16B
        0xC0 | 0xC1 | 0xC3 | 0xC7 => (true, ImmKind::None),
        0xC2 | 0xC4 | 0xC5 | 0xC6 => (true, ImmKind::Imm8),
        // 0F C8..CF BSWAP r32/r64 (1 byte, no ModR/M!)
        0xC8..=0xCF => (false, ImmKind::None),
        // 0F D0..FF MMX/SSE/SSE2/3
        0xD0..=0xFF => (true, ImmKind::None),
        _ => (false, ImmKind::None),
    }
}

/// Decode one x86_64 instruction starting at `offset` inside `code`.
pub fn decode_x86_64_insn(code: &[u8], offset: usize) -> Option<DecodedInsn> {
    let mut cur = offset;
    let mut has_66 = false;
    let mut has_67 = false;

    while let Some(&b) = code.get(cur) {
        if !is_legacy_prefix(b) {
            break;
        }
        if b == 0x66 {
            has_66 = true;
        } else if b == 0x67 {
            has_67 = true;
        }
        cur += 1;
        if cur - offset > 14 {
            return None;
        }
    }

    let first = *code.get(cur)?;

    // VEX3 (C4), VEX2 (C5), EVEX (62) in 64-bit mode
    if first == 0xC5 {
        let _vex2 = *code.get(cur + 1)?;
        let op = *code.get(cur + 2)?;
        cur += 3;
        let (ml, _) = modrm_len(code, cur, has_67)?;
        cur += ml;
        let (_, ik) = two_byte_0f_table(op);
        cur += x86_imm_size(ik, has_66, has_67, false, 0);
        return (cur <= code.len()).then_some(DecodedInsn {
            offset,
            len: cur - offset,
            is_ret: false,
        });
    }
    if first == 0xC4 {
        let b1 = *code.get(cur + 1)?;
        let b2 = *code.get(cur + 2)?;
        let op = *code.get(cur + 3)?;
        cur += 4;
        let map = b1 & 0x1F;
        let rex_w = (b2 & 0x80) != 0;
        let (ml, _) = modrm_len(code, cur, has_67)?;
        cur += ml;
        let ik = match map {
            1 => two_byte_0f_table(op).1,
            3 => ImmKind::Imm8,
            _ => ImmKind::None,
        };
        cur += x86_imm_size(ik, has_66, has_67, rex_w, 0);
        return (cur <= code.len()).then_some(DecodedInsn {
            offset,
            len: cur - offset,
            is_ret: false,
        });
    }
    if first == 0x62 {
        let b1 = *code.get(cur + 1)?;
        let _b2 = *code.get(cur + 2)?;
        let _b3 = *code.get(cur + 3)?;
        let op = *code.get(cur + 4)?;
        cur += 5;
        let map = b1 & 0x07;
        let (ml, _) = modrm_len(code, cur, has_67)?;
        cur += ml;
        let ik = match map {
            1 => two_byte_0f_table(op).1,
            3 => ImmKind::Imm8,
            _ => ImmKind::None,
        };
        cur += x86_imm_size(ik, has_66, has_67, false, 0);
        return (cur <= code.len()).then_some(DecodedInsn {
            offset,
            len: cur - offset,
            is_ret: false,
        });
    }

    let mut rex_w = false;
    let opcode = if (0x40..=0x4F).contains(&first) {
        rex_w = (first & 0x08) != 0;
        cur += 1;
        *code.get(cur)?
    } else {
        first
    };
    cur += 1;

    if opcode == 0x0F {
        let op2 = *code.get(cur)?;
        cur += 1;
        match op2 {
            0x38 => {
                let _op3 = *code.get(cur)?;
                cur += 1;
                let (ml, _) = modrm_len(code, cur, has_67)?;
                cur += ml;
            }
            0x3A => {
                let _op3 = *code.get(cur)?;
                cur += 1;
                let (ml, _) = modrm_len(code, cur, has_67)?;
                cur += ml + 1; // 0F 3A opcodes always take imm8
            }
            _ => {
                let (has_modrm, ik) = two_byte_0f_table(op2);
                let mut modrm_byte = 0u8;
                if has_modrm {
                    let (ml, m) = modrm_len(code, cur, has_67)?;
                    modrm_byte = m;
                    cur += ml;
                }
                cur += x86_imm_size(ik, has_66, has_67, rex_w, modrm_byte);
            }
        }
        return (cur <= code.len()).then_some(DecodedInsn {
            offset,
            len: cur - offset,
            is_ret: false,
        });
    }

    // Handle 6C..6F string I/O without ModR/M (distinct from 63 MOVSXD!)
    if matches!(opcode, 0x6C..=0x6F) {
        return (cur <= code.len()).then_some(DecodedInsn {
            offset,
            len: cur - offset,
            is_ret: false,
        });
    }

    let is_ret = opcode == 0xC3 || opcode == 0xC2;
    let (has_modrm, ik) = one_byte_table(opcode);
    let mut modrm_byte = 0u8;
    if has_modrm {
        let (ml, m) = modrm_len(code, cur, has_67)?;
        modrm_byte = m;
        cur += ml;
    }

    let imm = if ik == ImmKind::Group3 {
        let reg = (modrm_byte >> 3) & 0x07;
        if reg <= 1 {
            if opcode == 0xF6 {
                1
            } else {
                x86_imm_size(ImmKind::ImmZ, has_66, has_67, rex_w, modrm_byte)
            }
        } else {
            0
        }
    } else {
        x86_imm_size(ik, has_66, has_67, rex_w, modrm_byte)
    };
    cur += imm;

    (cur <= code.len()).then_some(DecodedInsn {
        offset,
        len: cur - offset,
        is_ret,
    })
}

/// Scan an `x86_64` function body `[0..code.len()]` at true instruction boundaries
/// and return relative offsets of every `RET` (`0xC3` / `0xC2` / `rep ret`) instruction.
pub fn scan_x86_64_ret_offsets(code: &[u8]) -> Vec<usize> {
    let mut rets = Vec::new();
    let mut pc = 0usize;
    while pc < code.len() {
        let Some(insn) = decode_x86_64_insn(code, pc) else {
            break;
        };
        if insn.len == 0 {
            break;
        }
        if insn.is_ret {
            rets.push(insn.offset);
        }
        pc += insn.len;
    }
    rets
}

/// Scan an `aarch64` function body on 4-byte instruction boundaries for `RET` (`0xD65F03C0`).
pub fn scan_aarch64_ret_offsets(code: &[u8]) -> Vec<usize> {
    let mut rets = Vec::new();
    let mut pc = 0usize;
    while pc + 4 <= code.len() {
        let w = u32::from_le_bytes([code[pc], code[pc + 1], code[pc + 2], code[pc + 3]]);
        if w == 0xD65F_03C0 {
            rets.push(pc);
        }
        pc += 4;
    }
    rets
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skips_embedded_0xc3_inside_immediates_and_displacements() {
        // 0:  48 b8 c3 c3 c3 c3 c3 c3 c3 c3  movabs rax, 0xc3c3c3c3c3c3c3c3
        // 10: 81 c3 c3 00 00 00              add ebx, 0xc3
        // 16: 48 8d 84 24 c3 00 00 00        lea rax, [rsp + 0xc3]
        // 24: e8 c3 00 00 00                 call +0xc3
        // 29: f3 c3                          rep ret
        // 31: c3                             ret
        let code: Vec<u8> = vec![
            0x48, 0xB8, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, //
            0x81, 0xC3, 0xC3, 0x00, 0x00, 0x00, //
            0x48, 0x8D, 0x84, 0x24, 0xC3, 0x00, 0x00, 0x00, //
            0xE8, 0xC3, 0x00, 0x00, 0x00, //
            0xF3, 0xC3, //
            0xC3,
        ];
        assert_eq!(scan_x86_64_ret_offsets(&code), vec![29, 31]);
    }

    #[test]
    fn handles_rex_66_vex_and_aarch64_ret() {
        // 0: 66 b8 34 c3        mov ax, 0xc334
        // 4: 48 f7 c1 c3 00 00 00 test rcx, 0xc3
        // 11: c5 f8 77          vzeroupper (no modrm? actually VEX2 + 77 has 0 bytes modrm in 2-byte map!)
        let code: Vec<u8> = vec![
            0x66, 0xB8, 0x34, 0xC3, //
            0x48, 0xF7, 0xC1, 0xC3, 0x00, 0x00, 0x00, //
            0x0F, 0x1F, 0x44, 0x00, 0xC3, // nop dword ptr [rax+rax*1+0xc3]
            0xC3,
        ];
        assert_eq!(scan_x86_64_ret_offsets(&code), vec![16]);

        let arm: Vec<u8> = [
            0xFD, 0x7B, 0xBF, 0xA9, // stp
            0xC3, 0x03, 0x5F, 0xD6, // ret x3 (not RET=D65F03C0)
            0xC0, 0x03, 0x5F, 0xD6, // ret
        ]
        .to_vec();
        assert_eq!(scan_aarch64_ret_offsets(&arm), vec![8]);
    }
}
