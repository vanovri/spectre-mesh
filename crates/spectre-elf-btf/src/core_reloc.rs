use std::collections::HashMap;

use crate::btf::{
    strip_core_flavor, Btf, BtfMember, BtfTypeKind, BTF_MAGIC, BTF_VERSION, MAX_BTF_DEPTH,
};
use crate::elf64::{checked_slice, read_u16_le, read_u32_le};
use crate::error::ElfBtfError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum CoreReloKind {
    FieldByteOffset = 0,
    FieldByteSize = 1,
    FieldExists = 2,
    FieldSigned = 3,
    FieldLshiftU64 = 4,
    FieldRshiftU64 = 5,
    TypeIdLocal = 6,
    TypeIdTarget = 7,
    TypeExists = 8,
    TypeSize = 9,
    EnumvalExists = 10,
    EnumvalValue = 11,
    TypeMatches = 12,
}

impl CoreReloKind {
    pub fn from_u32(v: u32) -> Result<Self, ElfBtfError> {
        match v {
            0 => Ok(Self::FieldByteOffset),
            1 => Ok(Self::FieldByteSize),
            2 => Ok(Self::FieldExists),
            3 => Ok(Self::FieldSigned),
            4 => Ok(Self::FieldLshiftU64),
            5 => Ok(Self::FieldRshiftU64),
            6 => Ok(Self::TypeIdLocal),
            7 => Ok(Self::TypeIdTarget),
            8 => Ok(Self::TypeExists),
            9 => Ok(Self::TypeSize),
            10 => Ok(Self::EnumvalExists),
            11 => Ok(Self::EnumvalValue),
            12 => Ok(Self::TypeMatches),
            _ => Err(ElfBtfError::InvalidBtfExt("unknown bpf_core_relo_kind")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BtfFuncInfoRec {
    pub insn_off: u32,
    pub type_id: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BtfLineInfoRec {
    pub insn_off: u32,
    pub file_name_off: u32,
    pub line_off: u32,
    pub line_col: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreReloRec {
    pub insn_off: u32,
    pub type_id: u32,
    pub access_str_off: u32,
    pub kind: CoreReloKind,
}

#[derive(Debug, Clone, Default)]
pub struct BtfExt {
    pub func_info: HashMap<String, Vec<BtfFuncInfoRec>>,
    pub line_info: HashMap<String, Vec<BtfLineInfoRec>>,
    pub core_relos: HashMap<String, Vec<CoreReloRec>>,
    pub func_info_rec_size: u32,
    pub line_info_rec_size: u32,
}

impl BtfExt {
    /// Parse `.BTF.ext` using string entries from the accompanying `.BTF` section.
    pub fn parse(data: &[u8], btf: &Btf) -> Result<Self, ElfBtfError> {
        if data.len() < 24 {
            return Err(ElfBtfError::InvalidBtfExt("shorter than 24 bytes"));
        }
        let magic = read_u16_le(data, 0)?;
        if magic != BTF_MAGIC {
            return Err(ElfBtfError::InvalidBtfExt("bad BTF.ext magic"));
        }
        let version = data[2];
        if version != BTF_VERSION {
            return Err(ElfBtfError::InvalidBtfExt("bad BTF.ext version"));
        }
        let hdr_len = usize::try_from(read_u32_le(data, 4)?)
            .map_err(|_| ElfBtfError::ArithmeticOverflow("btf.ext hdr_len"))?;
        if hdr_len < 24 || hdr_len > data.len() {
            return Err(ElfBtfError::InvalidBtfExt("invalid hdr_len"));
        }

        let func_off = usize::try_from(read_u32_le(data, 8)?)
            .map_err(|_| ElfBtfError::ArithmeticOverflow("func_off"))?;
        let func_len = usize::try_from(read_u32_le(data, 12)?)
            .map_err(|_| ElfBtfError::ArithmeticOverflow("func_len"))?;
        let line_off = usize::try_from(read_u32_le(data, 16)?)
            .map_err(|_| ElfBtfError::ArithmeticOverflow("line_off"))?;
        let line_len = usize::try_from(read_u32_le(data, 20)?)
            .map_err(|_| ElfBtfError::ArithmeticOverflow("line_len"))?;

        let (core_off, core_len) = if hdr_len >= 32 {
            (
                usize::try_from(read_u32_le(data, 24)?)
                    .map_err(|_| ElfBtfError::ArithmeticOverflow("core_off"))?,
                usize::try_from(read_u32_le(data, 28)?)
                    .map_err(|_| ElfBtfError::ArithmeticOverflow("core_len"))?,
            )
        } else {
            (0, 0)
        };

        let mut ext = Self::default();

        if func_len > 0 {
            let start = hdr_len
                .checked_add(func_off)
                .ok_or(ElfBtfError::ArithmeticOverflow("func_start"))?;
            let sub = checked_slice(data, start, func_len, "func_info")?;
            ext.func_info_rec_size = Self::parse_sec_records(
                sub,
                btf,
                8,
                |rec, out: &mut Vec<BtfFuncInfoRec>| {
                    out.push(BtfFuncInfoRec {
                        insn_off: read_u32_le(rec, 0)?,
                        type_id: read_u32_le(rec, 4)?,
                    });
                    Ok(())
                },
                &mut ext.func_info,
            )?;
        }

        if line_len > 0 {
            let start = hdr_len
                .checked_add(line_off)
                .ok_or(ElfBtfError::ArithmeticOverflow("line_start"))?;
            let sub = checked_slice(data, start, line_len, "line_info")?;
            ext.line_info_rec_size = Self::parse_sec_records(
                sub,
                btf,
                16,
                |rec, out: &mut Vec<BtfLineInfoRec>| {
                    out.push(BtfLineInfoRec {
                        insn_off: read_u32_le(rec, 0)?,
                        file_name_off: read_u32_le(rec, 4)?,
                        line_off: read_u32_le(rec, 8)?,
                        line_col: read_u32_le(rec, 12)?,
                    });
                    Ok(())
                },
                &mut ext.line_info,
            )?;
        }

        if core_len > 0 {
            let start = hdr_len
                .checked_add(core_off)
                .ok_or(ElfBtfError::ArithmeticOverflow("core_start"))?;
            let sub = checked_slice(data, start, core_len, "core_relo")?;
            Self::parse_sec_records(
                sub,
                btf,
                16,
                |rec, out: &mut Vec<CoreReloRec>| {
                    out.push(CoreReloRec {
                        insn_off: read_u32_le(rec, 0)?,
                        type_id: read_u32_le(rec, 4)?,
                        access_str_off: read_u32_le(rec, 8)?,
                        kind: CoreReloKind::from_u32(read_u32_le(rec, 12)?)?,
                    });
                    Ok(())
                },
                &mut ext.core_relos,
            )?;
        }

        Ok(ext)
    }

    fn parse_sec_records<T, F>(
        sub: &[u8],
        btf: &Btf,
        min_rec_size: usize,
        mut decode_rec: F,
        map: &mut HashMap<String, Vec<T>>,
    ) -> Result<u32, ElfBtfError>
    where
        F: FnMut(&[u8], &mut Vec<T>) -> Result<(), ElfBtfError>,
    {
        if sub.len() < 4 {
            return Err(ElfBtfError::InvalidBtfExt(
                "sub-section shorter than 4 bytes",
            ));
        }
        let rec_size_u32 = read_u32_le(sub, 0)?;
        let rec_size = usize::try_from(rec_size_u32)
            .map_err(|_| ElfBtfError::ArithmeticOverflow("rec_size"))?;
        if rec_size < min_rec_size {
            return Err(ElfBtfError::InvalidBtfExt("rec_size smaller than minimum"));
        }

        let mut cur = 4usize;
        while cur < sub.len() {
            let _ = checked_slice(sub, cur, 8, "btf_ext_info_sec")?;
            let sec_name_off = read_u32_le(sub, cur)?;
            let num_info = usize::try_from(read_u32_le(sub, cur + 4)?)
                .map_err(|_| ElfBtfError::ArithmeticOverflow("num_info"))?;
            cur += 8;

            let sec_name = btf.string_at(sec_name_off)?;
            let needed = num_info
                .checked_mul(rec_size)
                .ok_or(ElfBtfError::ArithmeticOverflow("sec records"))?;
            let _ = checked_slice(sub, cur, needed, "btf_ext_info records")?;

            let vec = map.entry(sec_name).or_default();
            vec.reserve(num_info);
            for i in 0..num_info {
                let rec = &sub[cur + i * rec_size..cur + (i + 1) * rec_size];
                decode_rec(rec, vec)?;
            }
            cur += needed;
        }
        Ok(rec_size_u32)
    }
}

#[derive(Debug, Clone)]
enum AccessStep {
    ArrayIndex(u32),
    FieldName(String),
}

#[derive(Debug, Clone, Copy)]
struct FieldSpec {
    byte_offset: u32,
    bit_offset_in_byte: u32,
    byte_size: u32,
    bitfield_bits: u32,
    signed: bool,
}

/// Apply CO-RE relocations for one BPF program section (`insns` encoded as little-endian 64-bit words).
/// Returns the number of relocations applied.
pub fn apply_core_relocations(
    insns: &mut [u64],
    local_btf: &Btf,
    target_btf: &Btf,
    relos: &[CoreReloRec],
) -> Result<usize, ElfBtfError> {
    let mut applied = 0usize;
    for relo in relos {
        let access_str = local_btf.string_at(relo.access_str_off)?;
        let local_ty = local_btf.resolve_modifiers(relo.type_id)?;
        let insn_idx = (relo.insn_off / 8) as usize;
        if insn_idx >= insns.len() {
            return Err(ElfBtfError::InvalidRelocation(format!(
                "CO-RE insn_off {} out of range ({} insns)",
                relo.insn_off,
                insns.len()
            )));
        }

        let resolved_val =
            resolve_relo_value(relo, local_btf, target_btf, local_ty.id, &access_str)?;
        match resolved_val {
            Some(val) => patch_bpf_insn(insns, insn_idx, relo.kind, val)?,
            None => {
                // Missing field or type for non-existence relocation: poison instruction so verifier
                // rejects if reachable and prunes if guarded by bpf_core_field_exists.
                poison_bpf_insn(&mut insns[insn_idx]);
            }
        }
        applied += 1;
    }
    Ok(applied)
}

fn resolve_relo_value(
    relo: &CoreReloRec,
    local_btf: &Btf,
    target_btf: &Btf,
    local_type_id: u32,
    access_str: &str,
) -> Result<Option<u32>, ElfBtfError> {
    let local_root = local_btf.resolve_modifiers(local_type_id)?;

    match relo.kind {
        CoreReloKind::TypeIdLocal => Ok(Some(local_root.id)),
        CoreReloKind::TypeExists => Ok(Some(u32::from(
            !target_btf.find_types_by_name(&local_root.name).is_empty(),
        ))),
        CoreReloKind::TypeMatches => Ok(Some(u32::from(
            !target_btf.find_types_by_name(&local_root.name).is_empty(),
        ))),
        CoreReloKind::TypeIdTarget => {
            let candidates = target_btf.find_types_by_name(&local_root.name);
            Ok(candidates.first().map(|t| t.id))
        }
        CoreReloKind::TypeSize => {
            let candidates = target_btf.find_types_by_name(&local_root.name);
            match candidates.first() {
                Some(t) => Ok(Some(target_btf.type_size(t.id)?)),
                None => Ok(None),
            }
        }
        CoreReloKind::EnumvalExists | CoreReloKind::EnumvalValue => {
            let idx: usize = access_str.parse().unwrap_or(0);
            let target_name = strip_core_flavor(&local_root.name);
            let local_entry_name = match &local_root.kind {
                BtfTypeKind::Enum { entries, .. } => entries.get(idx).map(|e| e.name.as_str()),
                BtfTypeKind::Enum64 { entries, .. } => entries.get(idx).map(|e| e.name.as_str()),
                _ => None,
            };
            let Some(ev_name) = local_entry_name else {
                return Ok(if relo.kind == CoreReloKind::EnumvalExists {
                    Some(0)
                } else {
                    None
                });
            };
            for cand in target_btf.find_types_by_name(target_name) {
                match &cand.kind {
                    BtfTypeKind::Enum { entries, .. } => {
                        if let Some(found) = entries.iter().find(|e| e.name == ev_name) {
                            return Ok(Some(if relo.kind == CoreReloKind::EnumvalExists {
                                1
                            } else {
                                found.val as u32
                            }));
                        }
                    }
                    BtfTypeKind::Enum64 { entries, .. } => {
                        if let Some(found) = entries.iter().find(|e| e.name == ev_name) {
                            return Ok(Some(if relo.kind == CoreReloKind::EnumvalExists {
                                1
                            } else {
                                found.val as u32
                            }));
                        }
                    }
                    _ => {}
                }
            }
            Ok(if relo.kind == CoreReloKind::EnumvalExists {
                Some(0)
            } else {
                None
            })
        }
        CoreReloKind::FieldByteOffset
        | CoreReloKind::FieldByteSize
        | CoreReloKind::FieldExists
        | CoreReloKind::FieldSigned
        | CoreReloKind::FieldLshiftU64
        | CoreReloKind::FieldRshiftU64 => {
            let steps = extract_local_access_steps(local_btf, local_root.id, access_str)?;
            let candidates = target_btf.find_types_by_name(&local_root.name);
            for cand in candidates {
                if let Some(spec) = resolve_target_steps(target_btf, cand.id, &steps)? {
                    let val = match relo.kind {
                        CoreReloKind::FieldByteOffset => spec.byte_offset,
                        CoreReloKind::FieldByteSize => spec.byte_size,
                        CoreReloKind::FieldExists => 1,
                        CoreReloKind::FieldSigned => u32::from(spec.signed),
                        CoreReloKind::FieldLshiftU64 => {
                            if spec.bitfield_bits == 0 {
                                64 - spec.byte_size * 8
                            } else {
                                64 - (spec.bit_offset_in_byte + spec.bitfield_bits)
                            }
                        }
                        CoreReloKind::FieldRshiftU64 => {
                            if spec.bitfield_bits == 0 {
                                64 - spec.byte_size * 8
                            } else {
                                64 - spec.bitfield_bits
                            }
                        }
                        _ => 0,
                    };
                    return Ok(Some(val));
                }
            }
            if relo.kind == CoreReloKind::FieldExists {
                Ok(Some(0))
            } else {
                Ok(None)
            }
        }
    }
}

fn extract_local_access_steps(
    btf: &Btf,
    mut cur_type_id: u32,
    access_str: &str,
) -> Result<Vec<AccessStep>, ElfBtfError> {
    let indices: Vec<u32> = access_str
        .split(':')
        .filter(|s| !s.is_empty())
        .map(|s| s.parse::<u32>())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ElfBtfError::CoreRelocationFailed {
            type_name: String::new(),
            access: access_str.to_owned(),
            reason: "non-numeric access string".to_owned(),
        })?;

    if indices.is_empty() {
        return Ok(Vec::new());
    }

    let mut steps = Vec::new();
    // First index is root array/pointer element offset (usually 0)
    steps.push(AccessStep::ArrayIndex(indices[0]));

    for &idx in &indices[1..] {
        let ty = btf.resolve_modifiers(cur_type_id)?;
        match &ty.kind {
            BtfTypeKind::Struct { members, .. } | BtfTypeKind::Union { members, .. } => {
                let member =
                    members
                        .get(idx as usize)
                        .ok_or_else(|| ElfBtfError::CoreRelocationFailed {
                            type_name: ty.name.clone(),
                            access: access_str.to_owned(),
                            reason: format!("member index {idx} out of range"),
                        })?;
                if !member.name.is_empty() {
                    steps.push(AccessStep::FieldName(member.name.clone()));
                }
                cur_type_id = member.type_id;
            }
            BtfTypeKind::Array { elem_type, .. } => {
                steps.push(AccessStep::ArrayIndex(idx));
                cur_type_id = *elem_type;
            }
            _ => {
                return Err(ElfBtfError::CoreRelocationFailed {
                    type_name: ty.name.clone(),
                    access: access_str.to_owned(),
                    reason: "cannot traverse non-composite local BTF type".to_owned(),
                });
            }
        }
    }
    Ok(steps)
}

fn resolve_target_steps(
    btf: &Btf,
    root_id: u32,
    steps: &[AccessStep],
) -> Result<Option<FieldSpec>, ElfBtfError> {
    if steps.is_empty() {
        return Ok(None);
    }

    let mut total_bit_off: u32 = 0;
    let mut cur_id = root_id;
    let mut last_bitfield_bits: u32 = 0;

    if let AccessStep::ArrayIndex(idx) = steps[0] {
        if idx != 0 {
            let sz = btf.type_size(cur_id)?;
            total_bit_off = total_bit_off
                .checked_add(idx.saturating_mul(sz).saturating_mul(8))
                .ok_or(ElfBtfError::ArithmeticOverflow("core array bit offset"))?;
        }
    }

    for step in &steps[1..] {
        match step {
            AccessStep::ArrayIndex(idx) => {
                let ty = btf.resolve_modifiers(cur_id)?;
                if let BtfTypeKind::Array {
                    elem_type, nelems, ..
                } = ty.kind
                {
                    if *idx >= nelems && nelems != 0 {
                        return Ok(None);
                    }
                    let elem_sz = btf.type_size(elem_type)?;
                    total_bit_off = total_bit_off
                        .checked_add(idx.saturating_mul(elem_sz).saturating_mul(8))
                        .ok_or(ElfBtfError::ArithmeticOverflow("core nested array"))?;
                    cur_id = elem_type;
                    last_bitfield_bits = 0;
                } else {
                    return Ok(None);
                }
            }
            AccessStep::FieldName(name) => {
                let Some((m_type, m_bit_off, m_bf_bits)) =
                    find_field_in_composite(btf, cur_id, name, 0)?
                else {
                    return Ok(None);
                };
                total_bit_off = total_bit_off
                    .checked_add(m_bit_off)
                    .ok_or(ElfBtfError::ArithmeticOverflow("core member bit offset"))?;
                cur_id = m_type;
                last_bitfield_bits = m_bf_bits;
            }
        }
    }

    let leaf = btf.resolve_modifiers(cur_id)?;
    let byte_size = btf.type_size(leaf.id)?;
    let signed = match &leaf.kind {
        BtfTypeKind::Int { encoding, .. } => (encoding & 1) != 0,
        BtfTypeKind::Enum { signed, .. } | BtfTypeKind::Enum64 { signed, .. } => *signed,
        _ => false,
    };

    Ok(Some(FieldSpec {
        byte_offset: total_bit_off / 8,
        bit_offset_in_byte: total_bit_off % 8,
        byte_size,
        bitfield_bits: last_bitfield_bits,
        signed,
    }))
}

/// Recursively search a struct/union (including anonymous nested structs/unions) for `field_name`.
fn find_field_in_composite(
    btf: &Btf,
    type_id: u32,
    field_name: &str,
    depth: usize,
) -> Result<Option<(u32, u32, u32)>, ElfBtfError> {
    if depth >= MAX_BTF_DEPTH {
        return Err(ElfBtfError::CyclicBtfGraph(MAX_BTF_DEPTH));
    }
    let ty = btf.resolve_modifiers(type_id)?;
    let (kflag, members): (bool, &[BtfMember]) = match &ty.kind {
        BtfTypeKind::Struct { kflag, members, .. } | BtfTypeKind::Union { kflag, members, .. } => {
            (*kflag, members)
        }
        _ => return Ok(None),
    };

    for m in members {
        let bit_off = if kflag {
            m.raw_offset & 0x00FF_FFFF
        } else {
            m.raw_offset
        };
        let bf_bits = if kflag { m.raw_offset >> 24 } else { 0 };

        if m.name == field_name {
            return Ok(Some((m.type_id, bit_off, bf_bits)));
        }
        if m.name.is_empty() {
            if let Some((inner_type, inner_bit_off, inner_bf)) =
                find_field_in_composite(btf, m.type_id, field_name, depth + 1)?
            {
                return Ok(Some((inner_type, bit_off + inner_bit_off, inner_bf)));
            }
        }
    }
    Ok(None)
}

fn patch_bpf_insn(
    insns: &mut [u64],
    idx: usize,
    kind: CoreReloKind,
    val: u32,
) -> Result<(), ElfBtfError> {
    let raw = insns[idx];
    let code = (raw & 0xFF) as u8;
    let class = code & 0x07;

    let mut bytes = raw.to_le_bytes();
    // Struct bpf_insn: [code: u8, regs: u8, off: i16 (bytes 2..4), imm: i32 (bytes 4..8)]
    if kind == CoreReloKind::FieldByteOffset && (class == 0x01 || class == 0x02 || class == 0x03) {
        // LDX / ST / STX: patch `off` (i16)
        let off_i16 = i16::try_from(val as i32).map_err(|_| {
            ElfBtfError::InvalidRelocation(format!("CO-RE offset {val} overflows i16"))
        })?;
        bytes[2..4].copy_from_slice(&off_i16.to_le_bytes());
        insns[idx] = u64::from_le_bytes(bytes);
        return Ok(());
    }

    // LD_IMM64 (0x18) uses 2 instruction slots
    if code == 0x18 {
        if idx + 1 >= insns.len() {
            return Err(ElfBtfError::InvalidRelocation(
                "truncated ld_imm64 at CO-RE target".to_owned(),
            ));
        }
        bytes[4..8].copy_from_slice(&(val as i32).to_le_bytes());
        insns[idx] = u64::from_le_bytes(bytes);
        let mut hi_bytes = insns[idx + 1].to_le_bytes();
        hi_bytes[4..8].copy_from_slice(&0i32.to_le_bytes());
        insns[idx + 1] = u64::from_le_bytes(hi_bytes);
        return Ok(());
    }

    // ALU / ALU64 / JMP / JMP32 immediate
    bytes[4..8].copy_from_slice(&(val as i32).to_le_bytes());
    insns[idx] = u64::from_le_bytes(bytes);
    Ok(())
}

fn poison_bpf_insn(insn: &mut u64) {
    // Emit `call 0xdead` (invalid helper ID) — safe if pruned, rejected if reachable.
    let mut bytes = [0u8; 8];
    bytes[0] = 0x85; // BPF_JMP | BPF_CALL
    bytes[4..8].copy_from_slice(&0x0000_DEADu32.to_le_bytes());
    *insn = u64::from_le_bytes(bytes);
}
