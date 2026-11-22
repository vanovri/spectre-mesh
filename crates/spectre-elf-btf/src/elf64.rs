use crate::error::ElfBtfError;

const ELF_MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;

pub const ET_REL: u16 = 1;
pub const ET_EXEC: u16 = 2;
pub const ET_DYN: u16 = 3;

pub const EM_X86_64: u16 = 62;
pub const EM_AARCH64: u16 = 183;
pub const EM_BPF: u16 = 247;

pub const PT_LOAD: u32 = 1;

pub const SHT_PROGBITS: u32 = 1;
pub const SHT_SYMTAB: u32 = 2;
pub const SHT_STRTAB: u32 = 3;
pub const SHT_RELA: u32 = 4;
pub const SHT_NOBITS: u32 = 8;
pub const SHT_REL: u32 = 9;
pub const SHT_DYNSYM: u32 = 11;

pub const SHF_EXECINSTR: u64 = 0x4;

pub const R_BPF_64_64: u32 = 1;
pub const R_BPF_64_ABS64: u32 = 2;
pub const R_BPF_64_ABS32: u32 = 3;
pub const R_BPF_64_NODYLD32: u32 = 4;
pub const R_BPF_64_32: u32 = 10;

pub const STT_NOTYPE: u8 = 0;
pub const STT_OBJECT: u8 = 1;
pub const STT_FUNC: u8 = 2;
pub const STT_SECTION: u8 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Elf64Header {
    pub elf_type: u16,
    pub machine: u16,
    pub version: u32,
    pub entry: u64,
    pub phoff: u64,
    pub shoff: u64,
    pub flags: u32,
    pub ehsize: u16,
    pub phentsize: u16,
    pub phnum: u16,
    pub shentsize: u16,
    pub shnum: u16,
    pub shstrndx: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Elf64ProgramHeader {
    pub p_type: u32,
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_paddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
    pub p_align: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Elf64Section {
    pub index: usize,
    pub name: String,
    pub sh_type: u32,
    pub sh_flags: u64,
    pub sh_addr: u64,
    pub sh_offset: u64,
    pub sh_size: u64,
    pub sh_link: u32,
    pub sh_info: u32,
    pub sh_addralign: u64,
    pub sh_entsize: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Elf64Symbol {
    pub index: usize,
    pub name: String,
    pub st_info: u8,
    pub st_other: u8,
    pub st_shndx: u16,
    pub st_value: u64,
    pub st_size: u64,
}

impl Elf64Symbol {
    #[must_use]
    pub const fn sym_type(&self) -> u8 {
        self.st_info & 0x0f
    }

    #[must_use]
    pub const fn sym_bind(&self) -> u8 {
        self.st_info >> 4
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Elf64Relocation {
    pub target_section_idx: usize,
    pub offset: u64,
    pub sym_idx: u32,
    pub r_type: u32,
    pub addend: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoFuncSymbol {
    pub name: String,
    pub entry_vaddr: u64,
    pub end_vaddr: u64,
    pub file_offset: Option<u64>,
}

/// Zero-copy-validated, bounds-checked ELF64 parser for both `.bpf.o` objects
/// and Linux userspace executables/shared libraries (`libssl.so`, Go binaries).
#[derive(Debug, Clone)]
pub struct Elf64Object<'a> {
    data: &'a [u8],
    pub header: Elf64Header,
    pub program_headers: Vec<Elf64ProgramHeader>,
    pub sections: Vec<Elf64Section>,
    pub symbols: Vec<Elf64Symbol>,
    pub dyn_symbols: Vec<Elf64Symbol>,
}

#[inline]
pub(crate) fn checked_slice<'a>(
    data: &'a [u8],
    offset: usize,
    len: usize,
    context: &'static str,
) -> Result<&'a [u8], ElfBtfError> {
    let end = offset
        .checked_add(len)
        .ok_or(ElfBtfError::ArithmeticOverflow(context))?;
    if end > data.len() {
        return Err(ElfBtfError::OutOfBounds {
            context,
            offset,
            len,
            total: data.len(),
        });
    }
    Ok(&data[offset..end])
}

#[inline]
pub(crate) fn read_u16_le(data: &[u8], off: usize) -> Result<u16, ElfBtfError> {
    let b = checked_slice(data, off, 2, "u16")?;
    Ok(u16::from_le_bytes([b[0], b[1]]))
}

#[inline]
pub(crate) fn read_u32_le(data: &[u8], off: usize) -> Result<u32, ElfBtfError> {
    let b = checked_slice(data, off, 4, "u32")?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

#[inline]
pub(crate) fn read_i32_le(data: &[u8], off: usize) -> Result<i32, ElfBtfError> {
    let b = checked_slice(data, off, 4, "i32")?;
    Ok(i32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

#[inline]
pub(crate) fn read_u64_le(data: &[u8], off: usize) -> Result<u64, ElfBtfError> {
    let b = checked_slice(data, off, 8, "u64")?;
    Ok(u64::from_le_bytes([
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
    ]))
}

#[inline]
pub(crate) fn read_i64_le(data: &[u8], off: usize) -> Result<i64, ElfBtfError> {
    let b = checked_slice(data, off, 8, "i64")?;
    Ok(i64::from_le_bytes([
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
    ]))
}

pub(crate) fn read_cstr(table: &[u8], offset: usize) -> Result<String, ElfBtfError> {
    if offset >= table.len() {
        return Err(ElfBtfError::InvalidStringOffset {
            offset,
            table_len: table.len(),
        });
    }
    let rest = &table[offset..];
    let nul = rest
        .iter()
        .position(|&b| b == 0)
        .ok_or(ElfBtfError::InvalidStringOffset {
            offset,
            table_len: table.len(),
        })?;
    let s = std::str::from_utf8(&rest[..nul]).map_err(|_| ElfBtfError::InvalidUtf8)?;
    Ok(s.to_owned())
}

impl<'a> Elf64Object<'a> {
    /// Parse an ELF64 file from raw bytes without any unaligned casts or panics.
    pub fn parse(data: &'a [u8]) -> Result<Self, ElfBtfError> {
        if data.len() < 64 || data[0..4] != ELF_MAGIC {
            return Err(ElfBtfError::InvalidElfHeader);
        }
        if data[4] != ELFCLASS64 {
            return Err(ElfBtfError::UnsupportedElfFormat("only ELF64 supported"));
        }
        if data[5] != ELFDATA2LSB {
            return Err(ElfBtfError::UnsupportedElfFormat(
                "only little-endian ELF supported",
            ));
        }

        let header = Elf64Header {
            elf_type: read_u16_le(data, 16)?,
            machine: read_u16_le(data, 18)?,
            version: read_u32_le(data, 20)?,
            entry: read_u64_le(data, 24)?,
            phoff: read_u64_le(data, 32)?,
            shoff: read_u64_le(data, 40)?,
            flags: read_u32_le(data, 48)?,
            ehsize: read_u16_le(data, 52)?,
            phentsize: read_u16_le(data, 54)?,
            phnum: read_u16_le(data, 56)?,
            shentsize: read_u16_le(data, 58)?,
            shnum: read_u16_le(data, 60)?,
            shstrndx: read_u16_le(data, 62)?,
        };

        if header.ehsize < 64 {
            return Err(ElfBtfError::InvalidElfHeader);
        }

        let mut program_headers = Vec::new();
        if header.phnum > 0 {
            if header.phentsize < 56 {
                return Err(ElfBtfError::InvalidElfHeader);
            }
            let ph_off = usize::try_from(header.phoff)
                .map_err(|_| ElfBtfError::ArithmeticOverflow("phoff"))?;
            let ph_entsz = usize::from(header.phentsize);
            let ph_cnt = usize::from(header.phnum);
            let total_ph = ph_entsz
                .checked_mul(ph_cnt)
                .ok_or(ElfBtfError::ArithmeticOverflow("ph_table"))?;
            let _ = checked_slice(data, ph_off, total_ph, "program headers")?;
            program_headers.reserve(ph_cnt);
            for i in 0..ph_cnt {
                let off = ph_off + i * ph_entsz;
                program_headers.push(Elf64ProgramHeader {
                    p_type: read_u32_le(data, off)?,
                    p_flags: read_u32_le(data, off + 4)?,
                    p_offset: read_u64_le(data, off + 8)?,
                    p_vaddr: read_u64_le(data, off + 16)?,
                    p_paddr: read_u64_le(data, off + 24)?,
                    p_filesz: read_u64_le(data, off + 32)?,
                    p_memsz: read_u64_le(data, off + 40)?,
                    p_align: read_u64_le(data, off + 48)?,
                });
            }
        }

        let mut raw_sections = Vec::new();
        if header.shnum > 0 {
            if header.shentsize < 64 {
                return Err(ElfBtfError::InvalidElfHeader);
            }
            let sh_off = usize::try_from(header.shoff)
                .map_err(|_| ElfBtfError::ArithmeticOverflow("shoff"))?;
            let sh_entsz = usize::from(header.shentsize);
            let sh_cnt = usize::from(header.shnum);
            let total_sh = sh_entsz
                .checked_mul(sh_cnt)
                .ok_or(ElfBtfError::ArithmeticOverflow("sh_table"))?;
            let _ = checked_slice(data, sh_off, total_sh, "section headers")?;
            raw_sections.reserve(sh_cnt);
            for i in 0..sh_cnt {
                let off = sh_off + i * sh_entsz;
                let sh_name_off = read_u32_le(data, off)?;
                let sh_type = read_u32_le(data, off + 4)?;
                let sh_flags = read_u64_le(data, off + 8)?;
                let sh_addr = read_u64_le(data, off + 16)?;
                let sh_offset = read_u64_le(data, off + 24)?;
                let sh_size = read_u64_le(data, off + 32)?;
                let sh_link = read_u32_le(data, off + 40)?;
                let sh_info = read_u32_le(data, off + 44)?;
                let sh_addralign = read_u64_le(data, off + 48)?;
                let sh_entsize = read_u64_le(data, off + 56)?;

                if sh_type != SHT_NOBITS && sh_size > 0 {
                    let sec_off = usize::try_from(sh_offset)
                        .map_err(|_| ElfBtfError::ArithmeticOverflow("sh_offset"))?;
                    let sec_len = usize::try_from(sh_size)
                        .map_err(|_| ElfBtfError::ArithmeticOverflow("sh_size"))?;
                    let _ = checked_slice(data, sec_off, sec_len, "section data")?;
                }

                raw_sections.push((
                    sh_name_off,
                    sh_type,
                    sh_flags,
                    sh_addr,
                    sh_offset,
                    sh_size,
                    sh_link,
                    sh_info,
                    sh_addralign,
                    sh_entsize,
                ));
            }
        }

        let shstr_bytes: &[u8] = if !raw_sections.is_empty() {
            let idx = usize::from(header.shstrndx);
            if idx >= raw_sections.len() {
                return Err(ElfBtfError::InvalidElfHeader);
            }
            let (_, sh_type, _, _, sh_offset, sh_size, _, _, _, _) = raw_sections[idx];
            if sh_type != SHT_STRTAB {
                return Err(ElfBtfError::InvalidElfHeader);
            }
            let off = usize::try_from(sh_offset)
                .map_err(|_| ElfBtfError::ArithmeticOverflow("shstrtab offset"))?;
            let len = usize::try_from(sh_size)
                .map_err(|_| ElfBtfError::ArithmeticOverflow("shstrtab size"))?;
            checked_slice(data, off, len, ".shstrtab")?
        } else {
            &[]
        };

        let mut sections = Vec::with_capacity(raw_sections.len());
        for (
            idx,
            (
                sh_name_off,
                sh_type,
                sh_flags,
                sh_addr,
                sh_offset,
                sh_size,
                sh_link,
                sh_info,
                sh_addralign,
                sh_entsize,
            ),
        ) in raw_sections.into_iter().enumerate()
        {
            let name = if shstr_bytes.is_empty() {
                String::new()
            } else {
                read_cstr(shstr_bytes, sh_name_off as usize)?
            };
            sections.push(Elf64Section {
                index: idx,
                name,
                sh_type,
                sh_flags,
                sh_addr,
                sh_offset,
                sh_size,
                sh_link,
                sh_info,
                sh_addralign,
                sh_entsize,
            });
        }

        let symbols = Self::parse_symbol_table(data, &sections, SHT_SYMTAB)?;
        let dyn_symbols = Self::parse_symbol_table(data, &sections, SHT_DYNSYM)?;

        Ok(Self {
            data,
            header,
            program_headers,
            sections,
            symbols,
            dyn_symbols,
        })
    }

    fn parse_symbol_table(
        data: &'a [u8],
        sections: &[Elf64Section],
        target_type: u32,
    ) -> Result<Vec<Elf64Symbol>, ElfBtfError> {
        let Some(sym_sec) = sections.iter().find(|s| s.sh_type == target_type) else {
            return Ok(Vec::new());
        };
        let str_idx = sym_sec.sh_link as usize;
        if str_idx >= sections.len() {
            return Err(ElfBtfError::InvalidElfHeader);
        }
        let str_sec = &sections[str_idx];
        if str_sec.sh_type != SHT_STRTAB {
            return Err(ElfBtfError::InvalidElfHeader);
        }

        let str_off = usize::try_from(str_sec.sh_offset)
            .map_err(|_| ElfBtfError::ArithmeticOverflow("strtab off"))?;
        let str_len = usize::try_from(str_sec.sh_size)
            .map_err(|_| ElfBtfError::ArithmeticOverflow("strtab len"))?;
        let strtab = checked_slice(data, str_off, str_len, "strtab")?;

        let entsz = if sym_sec.sh_entsize == 0 {
            24
        } else {
            usize::try_from(sym_sec.sh_entsize)
                .map_err(|_| ElfBtfError::ArithmeticOverflow("sym entsize"))?
        };
        if entsz < 24 {
            return Err(ElfBtfError::InvalidElfHeader);
        }
        let sym_off = usize::try_from(sym_sec.sh_offset)
            .map_err(|_| ElfBtfError::ArithmeticOverflow("symtab off"))?;
        let sym_len = usize::try_from(sym_sec.sh_size)
            .map_err(|_| ElfBtfError::ArithmeticOverflow("symtab len"))?;
        let _ = checked_slice(data, sym_off, sym_len, "symtab")?;

        let count = sym_len / entsz;
        let mut syms = Vec::with_capacity(count);
        for i in 0..count {
            let off = sym_off + i * entsz;
            let st_name = read_u32_le(data, off)?;
            let st_info = *checked_slice(data, off + 4, 1, "st_info")?.first().unwrap();
            let st_other = *checked_slice(data, off + 5, 1, "st_other")?
                .first()
                .unwrap();
            let st_shndx = read_u16_le(data, off + 6)?;
            let st_value = read_u64_le(data, off + 8)?;
            let st_size = read_u64_le(data, off + 16)?;
            let name = if st_name == 0 && strtab.is_empty() {
                String::new()
            } else {
                read_cstr(strtab, st_name as usize)?
            };
            syms.push(Elf64Symbol {
                index: i,
                name,
                st_info,
                st_other,
                st_shndx,
                st_value,
                st_size,
            });
        }
        Ok(syms)
    }

    #[must_use]
    pub fn section_by_name(&self, name: &str) -> Option<&Elf64Section> {
        self.sections.iter().find(|s| s.name == name)
    }

    pub fn section_data(&self, sec: &Elf64Section) -> Result<&'a [u8], ElfBtfError> {
        if sec.sh_type == SHT_NOBITS {
            return Ok(&[]);
        }
        let off = usize::try_from(sec.sh_offset)
            .map_err(|_| ElfBtfError::ArithmeticOverflow("section off"))?;
        let len = usize::try_from(sec.sh_size)
            .map_err(|_| ElfBtfError::ArithmeticOverflow("section len"))?;
        checked_slice(self.data, off, len, "section data")
    }

    pub fn section_data_by_name(&self, name: &str) -> Result<Option<&'a [u8]>, ElfBtfError> {
        match self.section_by_name(name) {
            Some(sec) => Ok(Some(self.section_data(sec)?)),
            None => Ok(None),
        }
    }

    /// Return all `SHT_REL` / `SHT_RELA` entries targeting `target_sec_idx`.
    pub fn relocations_for_section(
        &self,
        target_sec_idx: usize,
    ) -> Result<Vec<Elf64Relocation>, ElfBtfError> {
        let mut rels = Vec::new();
        for sec in &self.sections {
            if (sec.sh_type != SHT_REL && sec.sh_type != SHT_RELA)
                || sec.sh_info as usize != target_sec_idx
            {
                continue;
            }
            let is_rela = sec.sh_type == SHT_RELA;
            let default_entsz = if is_rela { 24 } else { 16 };
            let entsz = if sec.sh_entsize == 0 {
                default_entsz
            } else {
                usize::try_from(sec.sh_entsize)
                    .map_err(|_| ElfBtfError::ArithmeticOverflow("rel entsz"))?
            };
            if entsz < default_entsz {
                return Err(ElfBtfError::InvalidElfHeader);
            }
            let sec_off = usize::try_from(sec.sh_offset)
                .map_err(|_| ElfBtfError::ArithmeticOverflow("rel off"))?;
            let sec_len = usize::try_from(sec.sh_size)
                .map_err(|_| ElfBtfError::ArithmeticOverflow("rel len"))?;
            let _ = checked_slice(self.data, sec_off, sec_len, "relocation table")?;
            let count = sec_len / entsz;
            for i in 0..count {
                let off = sec_off + i * entsz;
                let r_offset = read_u64_le(self.data, off)?;
                let r_info = read_u64_le(self.data, off + 8)?;
                let sym_idx = (r_info >> 32) as u32;
                let r_type = (r_info & 0xFFFF_FFFF) as u32;
                let addend = if is_rela {
                    Some(read_i64_le(self.data, off + 16)?)
                } else {
                    None
                };
                rels.push(Elf64Relocation {
                    target_section_idx: target_sec_idx,
                    offset: r_offset,
                    sym_idx,
                    r_type,
                    addend,
                });
            }
        }
        Ok(rels)
    }

    /// Convert a virtual address inside an executable/shared object to its file offset
    /// using `PT_LOAD` segments.
    #[must_use]
    pub fn vaddr_to_file_offset(&self, vaddr: u64) -> Option<u64> {
        for ph in &self.program_headers {
            if ph.p_type != PT_LOAD {
                continue;
            }
            if let Some(end) = ph.p_vaddr.checked_add(ph.p_filesz) {
                if vaddr >= ph.p_vaddr && vaddr < end {
                    return ph.p_offset.checked_add(vaddr - ph.p_vaddr);
                }
            }
        }
        // Fallback for relocatable ET_REL objects or section-mapped offsets
        for sec in &self.sections {
            if sec.sh_type == SHT_NOBITS || sec.sh_addr == 0 {
                continue;
            }
            if let Some(end) = sec.sh_addr.checked_add(sec.sh_size) {
                if vaddr >= sec.sh_addr && vaddr < end {
                    return sec.sh_offset.checked_add(vaddr - sec.sh_addr);
                }
            }
        }
        None
    }

    /// Resolve an exported symbol (`dynsym` or `symtab`) to its file offset (for `uprobe` attach).
    #[must_use]
    pub fn resolve_symbol_file_offset(&self, symbol_name: &str) -> Option<(u64, u64)> {
        let find_in = |table: &[Elf64Symbol]| -> Option<(u64, u64)> {
            let sym = table
                .iter()
                .find(|s| s.name == symbol_name && s.st_value != 0)?;
            let file_off = self.vaddr_to_file_offset(sym.st_value)?;
            Some((file_off, sym.st_size))
        };
        find_in(&self.dyn_symbols).or_else(|| find_in(&self.symbols))
    }

    /// Parse Go `.gopclntab` (v1.18 `0xFFFFFFF0` and v1.20+ `0xFFFFFFF1`) function tables.
    pub fn parse_gopclntab(&self) -> Result<Vec<GoFuncSymbol>, ElfBtfError> {
        let Some(sec) = self.section_by_name(".gopclntab") else {
            return Ok(Vec::new());
        };
        let gp = self.section_data(sec)?;
        if gp.len() < 72 {
            return Err(ElfBtfError::InvalidGoPclntab(
                "section shorter than 72B pcHeader",
            ));
        }

        let magic = read_u32_le(gp, 0)?;
        if magic != 0xFFFF_FFF0 && magic != 0xFFFF_FFF1 {
            return Err(ElfBtfError::InvalidGoPclntab(
                "unsupported .gopclntab magic (expect 0xFFFFFFF0 or 0xFFFFFFF1)",
            ));
        }
        let ptr_size = gp[7];
        if ptr_size != 8 {
            return Err(ElfBtfError::InvalidGoPclntab(
                "only 64-bit Go ptrSize=8 supported",
            ));
        }

        let nfunc = usize::try_from(read_u64_le(gp, 8)?)
            .map_err(|_| ElfBtfError::ArithmeticOverflow("gopclntab nfunc"))?;
        let text_start_hdr = read_u64_le(gp, 24)?;
        let funcname_off = usize::try_from(read_u64_le(gp, 32)?)
            .map_err(|_| ElfBtfError::ArithmeticOverflow("funcname_off"))?;
        let pcln_off = usize::try_from(read_u64_le(gp, 64)?)
            .map_err(|_| ElfBtfError::ArithmeticOverflow("pcln_off"))?;

        // Go 1.20+ often stores textStart=0 in ELF disk .gopclntab when runtime.text == .text sh_addr.
        let effective_text_start = if text_start_hdr != 0 {
            text_start_hdr
        } else if let Some(sym) = self.symbols.iter().find(|s| s.name == "runtime.text") {
            sym.st_value
        } else if let Some(text_sec) = self.section_by_name(".text") {
            text_sec.sh_addr
        } else {
            0
        };

        if funcname_off > gp.len() || pcln_off > gp.len() {
            return Err(ElfBtfError::InvalidGoPclntab(
                "header offsets out of bounds",
            ));
        }

        // Go functab has (nfunc + 1) entryoff sentinels, or at least nfunc * 8 bytes.
        let functab_bytes = nfunc
            .checked_add(1)
            .and_then(|n| n.checked_mul(8))
            .ok_or(ElfBtfError::ArithmeticOverflow("functab"))?;
        let _ = checked_slice(gp, pcln_off, functab_bytes, "gopclntab functab")?;

        let funcnames = &gp[funcname_off..];
        let pclntab = &gp[pcln_off..];
        let mut funcs = Vec::with_capacity(nfunc);

        for i in 0..nfunc {
            let entry_off = u64::from(read_u32_le(pclntab, i * 8)?);
            let func_meta_off = usize::try_from(read_u32_le(pclntab, i * 8 + 4)?)
                .map_err(|_| ElfBtfError::ArithmeticOverflow("func_meta_off"))?;
            let next_entry_off = u64::from(read_u32_le(pclntab, (i + 1) * 8)?);

            let _ = checked_slice(pclntab, func_meta_off, 8, "go _func record")?;
            let name_off_raw = read_i32_le(pclntab, func_meta_off + 4)?;
            let name = if name_off_raw >= 0 {
                read_cstr(funcnames, name_off_raw as usize)?
            } else {
                String::new()
            };

            let entry_vaddr = effective_text_start.saturating_add(entry_off);
            let end_vaddr = effective_text_start.saturating_add(next_entry_off.max(entry_off));
            let file_offset = self.vaddr_to_file_offset(entry_vaddr);
            funcs.push(GoFuncSymbol {
                name,
                entry_vaddr,
                end_vaddr,
                file_offset,
            });
        }

        Ok(funcs)
    }

    /// Detect the Go toolchain version string (e.g. `"go1.26.8"`) embedded inside `.go.buildinfo` or `.rodata`.
    #[must_use]
    pub fn detect_go_build_version(&self) -> Option<String> {
        for sec_name in [".go.buildinfo", ".rodata"] {
            if let Ok(Some(bytes)) = self.section_data_by_name(sec_name) {
                if let Some(pos) = bytes.windows(16).position(|w| {
                    w.starts_with(b"\xff Go buildinf:")
                        || (w.starts_with(b"go1.") && w[4].is_ascii_digit())
                }) {
                    let sub = &bytes[pos..];
                    if sub.starts_with(b"\xff Go buildinf:") && sub.len() >= 34 {
                        // Go 1.18+ buildinfo inline string or varint length at offset 32..
                        // Fallback scan for "go1." inside .go.buildinfo
                        if let Some(go_pos) = sub
                            .windows(5)
                            .position(|w| w.starts_with(b"go1.") && w[4].is_ascii_digit())
                        {
                            let ver_slice = &sub[go_pos..];
                            let end = ver_slice
                                .iter()
                                .take(32)
                                .position(|&b| !b.is_ascii_alphanumeric() && b != b'.' && b != b'-')
                                .unwrap_or(ver_slice.len().min(32));
                            if let Ok(s) = std::str::from_utf8(&ver_slice[..end]) {
                                return Some(s.to_owned());
                            }
                        }
                    } else {
                        let end = sub
                            .iter()
                            .take(24)
                            .position(|&b| !b.is_ascii_alphanumeric() && b != b'.' && b != b'-')
                            .unwrap_or(sub.len().min(24));
                        if let Ok(s) = std::str::from_utf8(&sub[..end]) {
                            return Some(s.to_owned());
                        }
                    }
                }
            }
        }
        None
    }
}
