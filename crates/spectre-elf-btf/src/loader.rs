use crate::btf::{Btf, BtfMapSpec};
use crate::core_reloc::BtfExt;
use crate::elf64::{Elf64Object, SHF_EXECINSTR};
use crate::error::ElfBtfError;
use crate::syscall;

/// Portable parsed representation of a compiled `.bpf.o` object (works on all OSes).
#[derive(Debug, Clone)]
pub struct ParsedBpfProgram {
    pub section_name: String,
    pub func_names: Vec<String>,
    pub insns: Vec<u64>,
}

#[derive(Debug, Clone)]
pub struct ParsedBpfObject {
    pub license: String,
    pub maps: Vec<BtfMapSpec>,
    pub btf: Option<Btf>,
    pub btf_ext: Option<BtfExt>,
    pub programs: Vec<ParsedBpfProgram>,
}

impl ParsedBpfObject {
    /// Parse a `.bpf.o` file without making any kernel syscalls (portable across all OSes).
    pub fn parse(bytes: &[u8]) -> Result<Self, ElfBtfError> {
        let elf = Elf64Object::parse(bytes)?;
        let license = match elf.section_data_by_name("license")? {
            Some(raw) => {
                let nul = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
                String::from_utf8_lossy(&raw[..nul]).into_owned()
            }
            None => "GPL".to_owned(),
        };

        let btf = match elf.section_data_by_name(".BTF")? {
            Some(raw) => Some(Btf::parse(raw)?),
            None => None,
        };
        let btf_ext = match (&btf, elf.section_data_by_name(".BTF.ext")?) {
            (Some(b), Some(raw)) => Some(BtfExt::parse(raw, b)?),
            _ => None,
        };

        let maps = match &btf {
            Some(b) => b.extract_btf_maps()?,
            None => Vec::new(),
        };

        let mut programs = Vec::new();
        for sec in &elf.sections {
            if (sec.sh_flags & SHF_EXECINSTR) == 0 || sec.sh_size == 0 {
                continue;
            }
            let raw = elf.section_data(sec)?;
            if raw.len() % 8 != 0 {
                return Err(ElfBtfError::InvalidRelocation(format!(
                    "section '{}' size {} is not 8-byte instruction aligned",
                    sec.name,
                    raw.len()
                )));
            }
            let mut insns = Vec::with_capacity(raw.len() / 8);
            for chunk in raw.as_chunks::<8>().0 {
                insns.push(u64::from_le_bytes(*chunk));
            }
            let func_names = elf
                .symbols
                .iter()
                .filter(|s| s.st_shndx as usize == sec.index && s.sym_type() == 2)
                .map(|s| s.name.clone())
                .collect();
            programs.push(ParsedBpfProgram {
                section_name: sec.name.clone(),
                func_names,
                insns,
            });
        }

        Ok(Self {
            license,
            maps,
            btf,
            btf_ext,
            programs,
        })
    }
}

/// Classify Linux `BPF_PROG_TYPE_*` from an ELF section name (`xdp`, `kprobe/...`, `uprobe/...`, `tp/...`, `perf_event`).
#[must_use]
pub fn classify_section_prog_type(section_name: &str) -> (u32, u32) {
    if section_name == "xdp" || section_name.starts_with("xdp/") || section_name.starts_with("xdp.")
    {
        (syscall::BPF_PROG_TYPE_XDP, syscall::BPF_XDP)
    } else if section_name.starts_with("kprobe/")
        || section_name.starts_with("kretprobe/")
        || section_name.starts_with("uprobe/")
        || section_name.starts_with("uretprobe/")
    {
        (syscall::BPF_PROG_TYPE_KPROBE, 0)
    } else if section_name.starts_with("tp/") || section_name.starts_with("tracepoint/") {
        (syscall::BPF_PROG_TYPE_TRACEPOINT, 0)
    } else if section_name.starts_with("raw_tp/") || section_name.starts_with("raw_tracepoint/") {
        (syscall::BPF_PROG_TYPE_RAW_TRACEPOINT, 0)
    } else if section_name == "perf_event" || section_name.starts_with("perf_event/") {
        (syscall::BPF_PROG_TYPE_PERF_EVENT, 0)
    } else {
        (syscall::BPF_PROG_TYPE_KPROBE, 0)
    }
}

#[cfg(target_os = "linux")]
mod linux_loader {
    use super::*;
    use crate::core_reloc::apply_core_relocations;
    use crate::elf64::{R_BPF_64_32, R_BPF_64_64, SHT_NOBITS};
    use std::collections::HashMap;
    use std::os::fd::RawFd;
    use syscall::OwnedBpfFd;

    /// A loaded eBPF object owning all kernel map, BTF, and program FDs via RAII.
    #[derive(Debug)]
    pub struct LoadedBpfObject {
        pub maps: HashMap<String, OwnedBpfFd>,
        pub map_specs: HashMap<String, BtfMapSpec>,
        pub internal_data_maps: HashMap<String, OwnedBpfFd>,
        pub programs: HashMap<String, OwnedBpfFd>,
        pub prog_sections: HashMap<String, String>,
        pub btf_fd: Option<OwnedBpfFd>,
    }

    impl LoadedBpfObject {
        #[must_use]
        pub fn map_fd(&self, name: &str) -> Option<RawFd> {
            self.maps.get(name).map(OwnedBpfFd::as_raw_fd)
        }

        #[must_use]
        pub fn prog_fd(&self, name: &str) -> Option<RawFd> {
            self.programs.get(name).map(OwnedBpfFd::as_raw_fd)
        }

        #[must_use]
        pub fn map_spec(&self, name: &str) -> Option<&BtfMapSpec> {
            self.map_specs.get(name)
        }
    }

    pub struct BpfObjectLoader;

    impl BpfObjectLoader {
        /// Parse `.bpf.o`, apply BTF CO-RE relocations against `/sys/kernel/btf/vmlinux`
        /// (or an explicit target BTF), create all maps, relocate map FDs, and load all programs via `SYS_bpf`.
        pub fn load_bytes(bytes: &[u8]) -> Result<LoadedBpfObject, ElfBtfError> {
            let vmlinux = if std::path::Path::new("/sys/kernel/btf/vmlinux").exists() {
                Some(Btf::from_vmlinux()?)
            } else {
                None
            };
            Self::load_bytes_with_btf(bytes, vmlinux.as_ref())
        }

        pub fn load_bytes_with_btf(
            bytes: &[u8],
            target_btf: Option<&Btf>,
        ) -> Result<LoadedBpfObject, ElfBtfError> {
            let elf = Elf64Object::parse(bytes)?;
            let parsed = ParsedBpfObject::parse(bytes)?;

            let mut maps = HashMap::new();
            let mut map_specs = HashMap::new();
            for spec in parsed.maps {
                let fd = syscall::bpf_map_create(
                    spec.map_type,
                    spec.key_size,
                    spec.value_size,
                    spec.max_entries,
                    spec.map_flags,
                    &spec.name,
                )?;
                if spec.name == "pidns_cfg" && spec.value_size == 24 {
                    syscall::configure_pidns_map(fd.as_raw_fd())?;
                }
                maps.insert(spec.name.clone(), fd);
                map_specs.insert(spec.name.clone(), spec);
            }

            // Create internal 1-element array maps for .rodata*, .data*, and .bss* sections
            let mut internal_data_maps = HashMap::new();
            let mut sec_idx_to_data_map: HashMap<usize, RawFd> = HashMap::new();
            for sec in &elf.sections {
                let is_data = sec.name == ".rodata"
                    || sec.name.starts_with(".rodata.")
                    || sec.name == ".data"
                    || sec.name.starts_with(".data.")
                    || sec.name == ".bss"
                    || sec.name.starts_with(".bss.");
                if !is_data || sec.sh_size == 0 {
                    continue;
                }
                let val_size = u32::try_from(sec.sh_size)
                    .map_err(|_| ElfBtfError::ArithmeticOverflow("internal map value size"))?;
                let flags = if sec.name.starts_with(".rodata") {
                    syscall::BPF_F_RDONLY_PROG
                } else {
                    0
                };
                let short_name: String = sec
                    .name
                    .chars()
                    .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
                    .collect();
                let map_fd = syscall::bpf_map_create(
                    syscall::BPF_MAP_TYPE_ARRAY,
                    4,
                    val_size,
                    1,
                    flags,
                    &short_name,
                )?;
                if sec.sh_type != SHT_NOBITS {
                    let data = elf.section_data(sec)?;
                    if !data.is_empty() {
                        let key = 0u32.to_le_bytes();
                        syscall::bpf_map_update_elem(
                            map_fd.as_raw_fd(),
                            &key,
                            data,
                            syscall::BPF_ANY,
                        )?;
                    }
                }
                if sec.name.starts_with(".rodata") {
                    let _ = syscall::bpf_map_freeze(map_fd.as_raw_fd());
                }
                sec_idx_to_data_map.insert(sec.index, map_fd.as_raw_fd());
                internal_data_maps.insert(sec.name.clone(), map_fd);
            }

            // Upload local .BTF if present (helps kernel verifier diagnostics; ignore harmless upload errors)
            let btf_fd = if let Some(btf_raw) = elf.section_data_by_name(".BTF")? {
                syscall::bpf_btf_load(btf_raw).ok()
            } else {
                None
            };

            let mut programs = HashMap::new();
            let mut prog_sections = HashMap::new();

            for sec in &elf.sections {
                if (sec.sh_flags & SHF_EXECINSTR) == 0 || sec.sh_size == 0 {
                    continue;
                }
                let raw = elf.section_data(sec)?;
                if raw.len() % 8 != 0 {
                    return Err(ElfBtfError::InvalidRelocation(format!(
                        "section '{}' size {} not aligned to 8",
                        sec.name,
                        raw.len()
                    )));
                }

                let mut insns = Vec::with_capacity(raw.len() / 8);
                for chunk in raw.as_chunks::<8>().0 {
                    insns.push(u64::from_le_bytes(*chunk));
                }

                // 1. Apply ELF relocations (maps, .rodata/.data/.bss, intra-section subprogs)
                let rels = elf.relocations_for_section(sec.index)?;
                for rel in rels {
                    if rel.offset % 8 != 0 {
                        return Err(ElfBtfError::InvalidRelocation(format!(
                            "unaligned relocation offset {} in {}",
                            rel.offset, sec.name
                        )));
                    }
                    let idx = (rel.offset / 8) as usize;
                    if idx >= insns.len() {
                        return Err(ElfBtfError::InvalidRelocation(format!(
                            "relocation index {idx} out of range in {}",
                            sec.name
                        )));
                    }
                    let sym = elf.symbols.get(rel.sym_idx as usize).ok_or_else(|| {
                        ElfBtfError::InvalidRelocation(format!(
                            "symbol index {} out of range",
                            rel.sym_idx
                        ))
                    })?;

                    match rel.r_type {
                        R_BPF_64_64 => {
                            if idx + 1 >= insns.len() {
                                return Err(ElfBtfError::InvalidRelocation(
                                    "R_BPF_64_64 at end of insn buffer".to_owned(),
                                ));
                            }
                            if let Some(mfd) = maps.get(&sym.name).map(OwnedBpfFd::as_raw_fd) {
                                patch_ld_imm64(&mut insns, idx, 1, mfd, 0);
                            } else if let Some(&data_mfd) =
                                sec_idx_to_data_map.get(&(sym.st_shndx as usize))
                            {
                                // BPF_PSEUDO_MAP_VALUE = 2
                                let mut lo_bytes = insns[idx].to_le_bytes();
                                let existing_imm = i32::from_le_bytes([
                                    lo_bytes[4],
                                    lo_bytes[5],
                                    lo_bytes[6],
                                    lo_bytes[7],
                                ]);
                                let addend = rel.addend.unwrap_or(i64::from(existing_imm));
                                let off_in_map = (sym.st_value as i64 + addend) as i32;
                                lo_bytes[1] = (lo_bytes[1] & 0x0F) | (2 << 4);
                                lo_bytes[4..8].copy_from_slice(&data_mfd.to_le_bytes());
                                insns[idx] = u64::from_le_bytes(lo_bytes);
                                let mut hi_bytes = insns[idx + 1].to_le_bytes();
                                hi_bytes[4..8].copy_from_slice(&off_in_map.to_le_bytes());
                                insns[idx + 1] = u64::from_le_bytes(hi_bytes);
                            } else {
                                return Err(ElfBtfError::InvalidRelocation(format!(
                                    "unresolved R_BPF_64_64 symbol '{}' (shndx {}) in '{}'",
                                    sym.name, sym.st_shndx, sec.name
                                )));
                            }
                        }
                        R_BPF_64_32 if sym.st_shndx as usize == sec.index => {
                            let target_idx = (sym.st_value / 8) as i64;
                            let rel_off = (target_idx - (idx as i64 + 1)) as i32;
                            let mut bytes = insns[idx].to_le_bytes();
                            bytes[1] = (bytes[1] & 0x0F) | (1 << 4); // src_reg = BPF_PSEUDO_CALL (1)
                            bytes[4..8].copy_from_slice(&rel_off.to_le_bytes());
                            insns[idx] = u64::from_le_bytes(bytes);
                        }
                        _ => {}
                    }
                }

                // 2. Apply BTF CO-RE relocations if present for this section
                if let (Some(local_btf), Some(ext), Some(tgt_btf)) =
                    (&parsed.btf, &parsed.btf_ext, target_btf)
                {
                    if let Some(core_relos) = ext.core_relos.get(&sec.name) {
                        apply_core_relocations(&mut insns, local_btf, tgt_btf, core_relos)?;
                    }
                }

                // 3. Determine primary ELF function symbol name in this section
                let prog_name = elf
                    .symbols
                    .iter()
                    .find(|s| {
                        s.st_shndx as usize == sec.index && s.sym_type() == 2 && s.st_value == 0
                    })
                    .or_else(|| {
                        elf.symbols
                            .iter()
                            .find(|s| s.st_shndx as usize == sec.index && s.sym_type() == 2)
                    })
                    .map_or_else(|| sec.name.replace(['/', '.'], "_"), |s| s.name.clone());

                let (prog_type, expected_attach_type) = classify_section_prog_type(&sec.name);
                let fd = syscall::bpf_prog_load(
                    prog_type,
                    expected_attach_type,
                    &prog_name,
                    &insns,
                    &parsed.license,
                    btf_fd.as_ref().map(OwnedBpfFd::as_raw_fd),
                    &[],
                    0,
                    &[],
                    0,
                )?;
                prog_sections.insert(prog_name.clone(), sec.name.clone());
                programs.insert(prog_name, fd);
            }

            Ok(LoadedBpfObject {
                maps,
                map_specs,
                internal_data_maps,
                programs,
                prog_sections,
                btf_fd,
            })
        }
    }

    fn patch_ld_imm64(insns: &mut [u64], idx: usize, src_reg: u8, lo_imm: i32, hi_imm: i32) {
        let mut lo_bytes = insns[idx].to_le_bytes();
        lo_bytes[1] = (lo_bytes[1] & 0x0F) | ((src_reg & 0x0F) << 4);
        lo_bytes[4..8].copy_from_slice(&lo_imm.to_le_bytes());
        insns[idx] = u64::from_le_bytes(lo_bytes);

        let mut hi_bytes = insns[idx + 1].to_le_bytes();
        hi_bytes[4..8].copy_from_slice(&hi_imm.to_le_bytes());
        insns[idx + 1] = u64::from_le_bytes(hi_bytes);
    }
}

#[cfg(target_os = "linux")]
pub use linux_loader::*;
