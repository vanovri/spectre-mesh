use std::collections::HashSet;
use std::path::Path;

use crate::elf64::{checked_slice, read_cstr, read_i32_le, read_u16_le, read_u32_le};
use crate::error::ElfBtfError;

pub const BTF_MAGIC: u16 = 0xEB9F;
pub const BTF_VERSION: u8 = 1;
pub const MAX_BTF_DEPTH: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BtfKindId {
    Unkn = 0,
    Int = 1,
    Ptr = 2,
    Array = 3,
    Struct = 4,
    Union = 5,
    Enum = 6,
    Fwd = 7,
    Typedef = 8,
    Volatile = 9,
    Const = 10,
    Restrict = 11,
    Func = 12,
    FuncProto = 13,
    Var = 14,
    Datasec = 15,
    Float = 16,
    DeclTag = 17,
    TypeTag = 18,
    Enum64 = 19,
}

impl BtfKindId {
    pub fn from_u8(v: u8) -> Result<Self, ElfBtfError> {
        match v {
            0 => Ok(Self::Unkn),
            1 => Ok(Self::Int),
            2 => Ok(Self::Ptr),
            3 => Ok(Self::Array),
            4 => Ok(Self::Struct),
            5 => Ok(Self::Union),
            6 => Ok(Self::Enum),
            7 => Ok(Self::Fwd),
            8 => Ok(Self::Typedef),
            9 => Ok(Self::Volatile),
            10 => Ok(Self::Const),
            11 => Ok(Self::Restrict),
            12 => Ok(Self::Func),
            13 => Ok(Self::FuncProto),
            14 => Ok(Self::Var),
            15 => Ok(Self::Datasec),
            16 => Ok(Self::Float),
            17 => Ok(Self::DeclTag),
            18 => Ok(Self::TypeTag),
            19 => Ok(Self::Enum64),
            other => Err(ElfBtfError::UnsupportedBtfKind(other)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtfMember {
    pub name: String,
    pub type_id: u32,
    /// Raw `offset` word: if enclosing struct has `kflag == true`, lower 24 bits are bit_offset
    /// and upper 8 bits are bitfield_size. Otherwise full 32 bits are bit_offset.
    pub raw_offset: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtfEnumEntry {
    pub name: String,
    pub val: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtfEnum64Entry {
    pub name: String,
    pub val: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtfParam {
    pub name: String,
    pub type_id: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtfVarSecInfo {
    pub type_id: u32,
    pub offset: u32,
    pub size: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BtfTypeKind {
    Unkn,
    Int {
        size: u32,
        encoding: u8,
        bit_offset: u8,
        bits: u8,
    },
    Ptr {
        target_type: u32,
    },
    Array {
        elem_type: u32,
        index_type: u32,
        nelems: u32,
    },
    Struct {
        size: u32,
        kflag: bool,
        members: Vec<BtfMember>,
    },
    Union {
        size: u32,
        kflag: bool,
        members: Vec<BtfMember>,
    },
    Enum {
        size: u32,
        signed: bool,
        entries: Vec<BtfEnumEntry>,
    },
    Fwd {
        is_union: bool,
    },
    Typedef {
        target_type: u32,
    },
    Volatile {
        target_type: u32,
    },
    Const {
        target_type: u32,
    },
    Restrict {
        target_type: u32,
    },
    Func {
        proto_type: u32,
        linkage: u16,
    },
    FuncProto {
        ret_type: u32,
        params: Vec<BtfParam>,
    },
    Var {
        var_type: u32,
        linkage: u32,
    },
    Datasec {
        size: u32,
        vars: Vec<BtfVarSecInfo>,
    },
    Float {
        size: u32,
    },
    DeclTag {
        target_type: u32,
        component_idx: i32,
    },
    TypeTag {
        target_type: u32,
    },
    Enum64 {
        size: u32,
        signed: bool,
        entries: Vec<BtfEnum64Entry>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtfType {
    pub id: u32,
    pub name: String,
    pub kind: BtfTypeKind,
}

/// Decoded map specification from `.BTF` `.maps` `DATASEC`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtfMapSpec {
    pub name: String,
    pub map_type: u32,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub map_flags: u32,
    pub btf_key_type_id: u32,
    pub btf_value_type_id: u32,
}

#[derive(Debug, Clone)]
pub struct Btf {
    pub types: Vec<BtfType>, // index 0 is Void (ID 0), types start at ID 1
    strings: Vec<u8>,
}

impl Btf {
    /// Load kernel BTF from `/sys/kernel/btf/vmlinux` (Linux hosts).
    pub fn from_vmlinux() -> Result<Self, ElfBtfError> {
        let bytes = std::fs::read(Path::new("/sys/kernel/btf/vmlinux"))?;
        Self::parse(&bytes)
    }

    /// Parse binary `.BTF` data strictly bounds-checked.
    pub fn parse(data: &[u8]) -> Result<Self, ElfBtfError> {
        if data.len() < 24 {
            return Err(ElfBtfError::InvalidBtfHeader(0));
        }
        let magic = read_u16_le(data, 0)?;
        if magic != BTF_MAGIC {
            return Err(ElfBtfError::InvalidBtfHeader(magic));
        }
        let version = data[2];
        if version != BTF_VERSION {
            return Err(ElfBtfError::InvalidBtfHeader(magic));
        }
        let hdr_len = usize::try_from(read_u32_le(data, 4)?)
            .map_err(|_| ElfBtfError::ArithmeticOverflow("btf hdr_len"))?;
        if hdr_len < 24 || hdr_len > data.len() {
            return Err(ElfBtfError::InvalidBtfHeader(magic));
        }

        let type_off = usize::try_from(read_u32_le(data, 8)?)
            .map_err(|_| ElfBtfError::ArithmeticOverflow("btf type_off"))?;
        let type_len = usize::try_from(read_u32_le(data, 12)?)
            .map_err(|_| ElfBtfError::ArithmeticOverflow("btf type_len"))?;
        let str_off = usize::try_from(read_u32_le(data, 16)?)
            .map_err(|_| ElfBtfError::ArithmeticOverflow("btf str_off"))?;
        let str_len = usize::try_from(read_u32_le(data, 20)?)
            .map_err(|_| ElfBtfError::ArithmeticOverflow("btf str_len"))?;

        let type_start = hdr_len
            .checked_add(type_off)
            .ok_or(ElfBtfError::ArithmeticOverflow("type_start"))?;
        let type_bytes = checked_slice(data, type_start, type_len, "BTF types")?;

        let str_start = hdr_len
            .checked_add(str_off)
            .ok_or(ElfBtfError::ArithmeticOverflow("str_start"))?;
        let str_bytes = checked_slice(data, str_start, str_len, "BTF strings")?;

        let mut types = vec![BtfType {
            id: 0,
            name: "void".to_owned(),
            kind: BtfTypeKind::Unkn,
        }];

        let mut cur = 0usize;
        let mut next_id = 1u32;
        while cur < type_bytes.len() {
            let _ = checked_slice(type_bytes, cur, 12, "btf_type")?;
            let name_off = read_u32_le(type_bytes, cur)? as usize;
            let info = read_u32_le(type_bytes, cur + 4)?;
            let size_or_type = read_u32_le(type_bytes, cur + 8)?;
            cur += 12;

            let name = if name_off == 0 && !str_bytes.is_empty() && str_bytes[0] == 0 {
                String::new()
            } else {
                read_cstr(str_bytes, name_off)?
            };

            let vlen = (info & 0xFFFF) as usize;
            let kind_raw = ((info >> 24) & 0x1F) as u8;
            let kflag = (info >> 31) != 0;
            let kind_id = BtfKindId::from_u8(kind_raw)?;

            let kind = match kind_id {
                BtfKindId::Unkn => BtfTypeKind::Unkn,
                BtfKindId::Int => {
                    let word = read_u32_le(type_bytes, cur)?;
                    cur += 4;
                    BtfTypeKind::Int {
                        size: size_or_type,
                        encoding: ((word >> 24) & 0x0F) as u8,
                        bit_offset: ((word >> 16) & 0xFF) as u8,
                        bits: (word & 0xFF) as u8,
                    }
                }
                BtfKindId::Ptr => BtfTypeKind::Ptr {
                    target_type: size_or_type,
                },
                BtfKindId::Array => {
                    let _ = checked_slice(type_bytes, cur, 12, "btf_array")?;
                    let elem_type = read_u32_le(type_bytes, cur)?;
                    let index_type = read_u32_le(type_bytes, cur + 4)?;
                    let nelems = read_u32_le(type_bytes, cur + 8)?;
                    cur += 12;
                    BtfTypeKind::Array {
                        elem_type,
                        index_type,
                        nelems,
                    }
                }
                BtfKindId::Struct | BtfKindId::Union => {
                    let needed = vlen
                        .checked_mul(12)
                        .ok_or(ElfBtfError::ArithmeticOverflow("btf_members"))?;
                    let _ = checked_slice(type_bytes, cur, needed, "btf_members")?;
                    let mut members = Vec::with_capacity(vlen);
                    for i in 0..vlen {
                        let m_off = cur + i * 12;
                        let m_name_off = read_u32_le(type_bytes, m_off)? as usize;
                        let m_type = read_u32_le(type_bytes, m_off + 4)?;
                        let m_raw_offset = read_u32_le(type_bytes, m_off + 8)?;
                        let m_name = if m_name_off == 0 && !str_bytes.is_empty() {
                            read_cstr(str_bytes, 0)?
                        } else {
                            read_cstr(str_bytes, m_name_off)?
                        };
                        members.push(BtfMember {
                            name: m_name,
                            type_id: m_type,
                            raw_offset: m_raw_offset,
                        });
                    }
                    cur += needed;
                    if kind_id == BtfKindId::Struct {
                        BtfTypeKind::Struct {
                            size: size_or_type,
                            kflag,
                            members,
                        }
                    } else {
                        BtfTypeKind::Union {
                            size: size_or_type,
                            kflag,
                            members,
                        }
                    }
                }
                BtfKindId::Enum => {
                    let needed = vlen
                        .checked_mul(8)
                        .ok_or(ElfBtfError::ArithmeticOverflow("btf_enum"))?;
                    let _ = checked_slice(type_bytes, cur, needed, "btf_enum")?;
                    let mut entries = Vec::with_capacity(vlen);
                    for i in 0..vlen {
                        let e_off = cur + i * 8;
                        let e_name_off = read_u32_le(type_bytes, e_off)? as usize;
                        let val = read_i32_le(type_bytes, e_off + 4)?;
                        entries.push(BtfEnumEntry {
                            name: read_cstr(str_bytes, e_name_off)?,
                            val,
                        });
                    }
                    cur += needed;
                    BtfTypeKind::Enum {
                        size: size_or_type,
                        signed: kflag,
                        entries,
                    }
                }
                BtfKindId::Fwd => BtfTypeKind::Fwd { is_union: kflag },
                BtfKindId::Typedef => BtfTypeKind::Typedef {
                    target_type: size_or_type,
                },
                BtfKindId::Volatile => BtfTypeKind::Volatile {
                    target_type: size_or_type,
                },
                BtfKindId::Const => BtfTypeKind::Const {
                    target_type: size_or_type,
                },
                BtfKindId::Restrict => BtfTypeKind::Restrict {
                    target_type: size_or_type,
                },
                BtfKindId::Func => BtfTypeKind::Func {
                    proto_type: size_or_type,
                    linkage: vlen as u16,
                },
                BtfKindId::FuncProto => {
                    let needed = vlen
                        .checked_mul(8)
                        .ok_or(ElfBtfError::ArithmeticOverflow("btf_func_proto"))?;
                    let _ = checked_slice(type_bytes, cur, needed, "btf_func_proto")?;
                    let mut params = Vec::with_capacity(vlen);
                    for i in 0..vlen {
                        let p_off = cur + i * 8;
                        let p_name_off = read_u32_le(type_bytes, p_off)? as usize;
                        let p_type = read_u32_le(type_bytes, p_off + 4)?;
                        let p_name = if p_name_off == 0 && !str_bytes.is_empty() {
                            read_cstr(str_bytes, 0)?
                        } else {
                            read_cstr(str_bytes, p_name_off)?
                        };
                        params.push(BtfParam {
                            name: p_name,
                            type_id: p_type,
                        });
                    }
                    cur += needed;
                    BtfTypeKind::FuncProto {
                        ret_type: size_or_type,
                        params,
                    }
                }
                BtfKindId::Var => {
                    let linkage = read_u32_le(type_bytes, cur)?;
                    cur += 4;
                    BtfTypeKind::Var {
                        var_type: size_or_type,
                        linkage,
                    }
                }
                BtfKindId::Datasec => {
                    let needed = vlen
                        .checked_mul(12)
                        .ok_or(ElfBtfError::ArithmeticOverflow("btf_datasec"))?;
                    let _ = checked_slice(type_bytes, cur, needed, "btf_datasec")?;
                    let mut vars = Vec::with_capacity(vlen);
                    for i in 0..vlen {
                        let v_off = cur + i * 12;
                        vars.push(BtfVarSecInfo {
                            type_id: read_u32_le(type_bytes, v_off)?,
                            offset: read_u32_le(type_bytes, v_off + 4)?,
                            size: read_u32_le(type_bytes, v_off + 8)?,
                        });
                    }
                    cur += needed;
                    BtfTypeKind::Datasec {
                        size: size_or_type,
                        vars,
                    }
                }
                BtfKindId::Float => BtfTypeKind::Float { size: size_or_type },
                BtfKindId::DeclTag => {
                    let component_idx = read_i32_le(type_bytes, cur)?;
                    cur += 4;
                    BtfTypeKind::DeclTag {
                        target_type: size_or_type,
                        component_idx,
                    }
                }
                BtfKindId::TypeTag => BtfTypeKind::TypeTag {
                    target_type: size_or_type,
                },
                BtfKindId::Enum64 => {
                    let needed = vlen
                        .checked_mul(12)
                        .ok_or(ElfBtfError::ArithmeticOverflow("btf_enum64"))?;
                    let _ = checked_slice(type_bytes, cur, needed, "btf_enum64")?;
                    let mut entries = Vec::with_capacity(vlen);
                    for i in 0..vlen {
                        let e_off = cur + i * 12;
                        let e_name_off = read_u32_le(type_bytes, e_off)? as usize;
                        let lo = u64::from(read_u32_le(type_bytes, e_off + 4)?);
                        let hi = u64::from(read_u32_le(type_bytes, e_off + 8)?);
                        entries.push(BtfEnum64Entry {
                            name: read_cstr(str_bytes, e_name_off)?,
                            val: (hi << 32) | lo,
                        });
                    }
                    cur += needed;
                    BtfTypeKind::Enum64 {
                        size: size_or_type,
                        signed: kflag,
                        entries,
                    }
                }
            };

            types.push(BtfType {
                id: next_id,
                name,
                kind,
            });
            next_id = next_id
                .checked_add(1)
                .ok_or(ElfBtfError::ArithmeticOverflow("btf type_id"))?;
        }

        Ok(Self {
            types,
            strings: str_bytes.to_vec(),
        })
    }

    pub fn string_at(&self, off: u32) -> Result<String, ElfBtfError> {
        read_cstr(&self.strings, off as usize)
    }

    pub fn get(&self, id: u32) -> Result<&BtfType, ElfBtfError> {
        let idx = id as usize;
        if idx >= self.types.len() {
            return Err(ElfBtfError::InvalidBtfTypeId(id, self.types.len()));
        }
        Ok(&self.types[idx])
    }

    /// Resolve through Typedef / Volatile / Const / Restrict / TypeTag modifiers with cycle protection.
    pub fn resolve_modifiers(&self, mut id: u32) -> Result<&BtfType, ElfBtfError> {
        let mut seen = HashSet::new();
        for _ in 0..MAX_BTF_DEPTH {
            if !seen.insert(id) {
                return Err(ElfBtfError::CyclicBtfGraph(MAX_BTF_DEPTH));
            }
            let ty = self.get(id)?;
            match ty.kind {
                BtfTypeKind::Typedef { target_type }
                | BtfTypeKind::Volatile { target_type }
                | BtfTypeKind::Const { target_type }
                | BtfTypeKind::Restrict { target_type }
                | BtfTypeKind::TypeTag { target_type } => {
                    id = target_type;
                }
                _ => return Ok(ty),
            }
        }
        Err(ElfBtfError::CyclicBtfGraph(MAX_BTF_DEPTH))
    }

    /// Compute the byte size of any BTF type with cycle and depth protection.
    pub fn type_size(&self, id: u32) -> Result<u32, ElfBtfError> {
        self.type_size_inner(id, 0)
    }

    fn type_size_inner(&self, id: u32, depth: usize) -> Result<u32, ElfBtfError> {
        if depth >= MAX_BTF_DEPTH {
            return Err(ElfBtfError::CyclicBtfGraph(MAX_BTF_DEPTH));
        }
        if id == 0 {
            return Ok(0);
        }
        let ty = self.get(id)?;
        match &ty.kind {
            BtfTypeKind::Int { size, .. }
            | BtfTypeKind::Struct { size, .. }
            | BtfTypeKind::Union { size, .. }
            | BtfTypeKind::Enum { size, .. }
            | BtfTypeKind::Enum64 { size, .. }
            | BtfTypeKind::Float { size }
            | BtfTypeKind::Datasec { size, .. } => Ok(*size),
            BtfTypeKind::Ptr { .. } => Ok(8),
            BtfTypeKind::Array {
                elem_type, nelems, ..
            } => {
                let elem_sz = self.type_size_inner(*elem_type, depth + 1)?;
                elem_sz
                    .checked_mul(*nelems)
                    .ok_or(ElfBtfError::ArithmeticOverflow("btf array size"))
            }
            BtfTypeKind::Typedef { target_type }
            | BtfTypeKind::Volatile { target_type }
            | BtfTypeKind::Const { target_type }
            | BtfTypeKind::Restrict { target_type }
            | BtfTypeKind::TypeTag { target_type }
            | BtfTypeKind::Var {
                var_type: target_type,
                ..
            } => self.type_size_inner(*target_type, depth + 1),
            _ => Ok(0),
        }
    }

    /// Find all non-anonymous types matching `base_name` (stripping `___*` flavor suffixes).
    pub fn find_types_by_name(&self, raw_name: &str) -> Vec<&BtfType> {
        let base = strip_core_flavor(raw_name);
        self.types
            .iter()
            .filter(|t| !t.name.is_empty() && t.name == base)
            .collect()
    }

    /// Decode BTF-defined `.maps` definitions from the `.maps` `DATASEC`.
    pub fn extract_btf_maps(&self) -> Result<Vec<BtfMapSpec>, ElfBtfError> {
        let mut specs = Vec::new();
        let Some(maps_sec) = self
            .types
            .iter()
            .find(|t| matches!(t.kind, BtfTypeKind::Datasec { .. }) && t.name == ".maps")
        else {
            return Ok(specs);
        };

        let BtfTypeKind::Datasec { vars, .. } = &maps_sec.kind else {
            return Ok(specs);
        };

        for vinfo in vars {
            let var_ty = self.get(vinfo.type_id)?;
            let BtfTypeKind::Var { var_type, .. } = var_ty.kind else {
                continue;
            };
            let resolved = self.resolve_modifiers(var_type)?;
            let BtfTypeKind::Struct { members, .. } = &resolved.kind else {
                continue;
            };

            let mut map_type: Option<u32> = None;
            let mut key_size: Option<u32> = None;
            let mut value_size: Option<u32> = None;
            let mut max_entries: u32 = 0;
            let mut map_flags: u32 = 0;
            let mut btf_key_type_id: u32 = 0;
            let mut btf_value_type_id: u32 = 0;

            for m in members {
                match m.name.as_str() {
                    "type" => {
                        map_type = Some(self.decode_btf_uint_member(m.type_id)?);
                    }
                    "max_entries" => {
                        max_entries = self.decode_btf_uint_member(m.type_id)?;
                    }
                    "map_flags" => {
                        map_flags = self.decode_btf_uint_member(m.type_id)?;
                    }
                    "key_size" => {
                        key_size = Some(self.decode_btf_uint_member(m.type_id)?);
                    }
                    "value_size" => {
                        value_size = Some(self.decode_btf_uint_member(m.type_id)?);
                    }
                    "key" => {
                        let target = self.unwrap_ptr_target(m.type_id)?;
                        btf_key_type_id = target;
                        key_size = Some(self.type_size(target)?);
                    }
                    "value" => {
                        let target = self.unwrap_ptr_target(m.type_id)?;
                        btf_value_type_id = target;
                        value_size = Some(self.type_size(target)?);
                    }
                    _ => {}
                }
            }

            let map_type = map_type.ok_or_else(|| ElfBtfError::InvalidBtfMapSpec {
                name: var_ty.name.clone(),
                attr: "type",
            })?;

            // RingBuf maps have key_size=0, value_size=0 in Linux.
            let is_ringbuf = map_type == 27 || map_type == 31; // RINGBUF=27, USER_RINGBUF=31
            let resolved_key = key_size.unwrap_or(if is_ringbuf { 0 } else { 4 });
            let resolved_val = value_size.unwrap_or(0);

            specs.push(BtfMapSpec {
                name: var_ty.name.clone(),
                map_type,
                key_size: resolved_key,
                value_size: resolved_val,
                max_entries,
                map_flags,
                btf_key_type_id,
                btf_value_type_id,
            });
        }

        Ok(specs)
    }

    fn unwrap_ptr_target(&self, type_id: u32) -> Result<u32, ElfBtfError> {
        let ty = self.resolve_modifiers(type_id)?;
        match ty.kind {
            BtfTypeKind::Ptr { target_type } => Ok(target_type),
            _ => Err(ElfBtfError::InvalidBtfTypeId(type_id, self.types.len())),
        }
    }

    fn decode_btf_uint_member(&self, type_id: u32) -> Result<u32, ElfBtfError> {
        let target = self.unwrap_ptr_target(type_id)?;
        let arr = self.resolve_modifiers(target)?;
        match arr.kind {
            BtfTypeKind::Array { nelems, .. } => Ok(nelems),
            _ => Err(ElfBtfError::InvalidBtfTypeId(target, self.types.len())),
        }
    }
}

/// Strip CO-RE flavor suffix `___*` (e.g. `task_struct___old` -> `task_struct`).
#[must_use]
pub fn strip_core_flavor(name: &str) -> &str {
    name.split("___").next().unwrap_or(name)
}
