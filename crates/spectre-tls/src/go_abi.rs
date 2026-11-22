use serde::{Deserialize, Serialize};
use spectre_elf_btf::elf64::{EM_AARCH64, EM_X86_64};
use spectre_elf_btf::Elf64Object;

use crate::ret_scanner::{scan_aarch64_ret_offsets, scan_x86_64_ret_offsets, TargetArch};
use crate::TlsError;

pub const GO_TLS_READ_SYMBOL: &str = "crypto/tls.(*Conn).Read";
pub const GO_TLS_WRITE_SYMBOL: &str = "crypto/tls.(*Conn).Write";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoTlsTargetOffsets {
    pub symbol: String,
    pub entry_file_offset: u64,
    pub size_bytes: usize,
    pub ret_file_offsets: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoTlsProbePlan {
    pub binary_path: String,
    pub go_version: Option<String>,
    pub arch: String,
    pub write: GoTlsTargetOffsets,
    pub read: GoTlsTargetOffsets,
}

fn parse_go_minor(ver: &str) -> Option<u32> {
    let after = ver.strip_prefix("go1.")?;
    let digits: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse::<u32>().ok()
}

fn resolve_single_go_func(
    elf: &Elf64Object<'_>,
    raw_elf: &[u8],
    arch: TargetArch,
    symbol: &'static str,
) -> Result<GoTlsTargetOffsets, TlsError> {
    let funcs = elf.parse_gopclntab().unwrap_or_default();
    let (file_off, size_usize) = if let Some(gf) = funcs.iter().find(|f| f.name == symbol) {
        let start = gf
            .file_offset
            .ok_or_else(|| TlsError::MissingSymbol(symbol, "vaddr_to_file_offset".to_owned()))?;
        let sz = usize::try_from(gf.end_vaddr.saturating_sub(gf.entry_vaddr)).unwrap_or(0);
        (start, sz)
    } else if let Some((off, sym_sz)) = elf.resolve_symbol_file_offset(symbol) {
        let sz = usize::try_from(sym_sz).unwrap_or(0);
        (off, sz)
    } else {
        return Err(TlsError::MissingSymbol(symbol, "Go ELF".to_owned()));
    };

    let start_idx = usize::try_from(file_off).map_err(|_| TlsError::InvalidFuncRange {
        symbol: symbol.to_owned(),
        start: file_off,
        end: file_off,
    })?;
    let end_idx = start_idx
        .checked_add(size_usize)
        .filter(|&e| e > start_idx && e <= raw_elf.len())
        .ok_or_else(|| TlsError::InvalidFuncRange {
            symbol: symbol.to_owned(),
            start: file_off,
            end: file_off.saturating_add(size_usize as u64),
        })?;

    let fn_bytes = &raw_elf[start_idx..end_idx];
    let rel_rets = match arch {
        TargetArch::X86_64 => scan_x86_64_ret_offsets(fn_bytes),
        TargetArch::Aarch64 => scan_aarch64_ret_offsets(fn_bytes),
    };
    let ret_file_offsets: Vec<u64> = rel_rets.into_iter().map(|r| file_off + r as u64).collect();

    Ok(GoTlsTargetOffsets {
        symbol: symbol.to_owned(),
        entry_file_offset: file_off,
        size_bytes: size_usize,
        ret_file_offsets,
    })
}

/// Inspect a Go ELF binary and compute safe entry + `RET`-offset uprobe addresses
/// for `crypto/tls.(*Conn).Write` and `crypto/tls.(*Conn).Read`.
pub fn resolve_go_tls_probes(
    binary_path: &str,
    raw_elf: &[u8],
) -> Result<GoTlsProbePlan, TlsError> {
    let elf = Elf64Object::parse(raw_elf)?;
    let arch = match elf.header.machine {
        EM_X86_64 => TargetArch::X86_64,
        EM_AARCH64 => TargetArch::Aarch64,
        other => return Err(TlsError::UnsupportedArch(other)),
    };

    let go_version = elf.detect_go_build_version();
    if let Some(ref ver) = go_version {
        if let Some(minor) = parse_go_minor(ver) {
            if minor < 17 {
                return Err(TlsError::UnsupportedGoAbi(ver.clone()));
            }
        }
    }

    let write = resolve_single_go_func(&elf, raw_elf, arch, GO_TLS_WRITE_SYMBOL)?;
    let read = resolve_single_go_func(&elf, raw_elf, arch, GO_TLS_READ_SYMBOL)?;

    Ok(GoTlsProbePlan {
        binary_path: binary_path.to_owned(),
        go_version,
        arch: match arch {
            TargetArch::X86_64 => "x86_64".to_owned(),
            TargetArch::Aarch64 => "aarch64".to_owned(),
        },
        write,
        read,
    })
}
