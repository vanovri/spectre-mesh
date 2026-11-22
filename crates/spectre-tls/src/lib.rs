#![deny(unsafe_code)]

pub mod discover;
pub mod go_abi;
pub mod ret_scanner;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use discover::{discover_pid_tls_targets, DiscoveredTlsTargets};
#[cfg(target_os = "linux")]
pub use discover::{AttachedTlsSummary, TlsInterceptor};
pub use go_abi::{resolve_go_tls_probes, GoTlsProbePlan, GoTlsTargetOffsets};
pub use ret_scanner::{scan_aarch64_ret_offsets, scan_x86_64_ret_offsets, TargetArch};

#[derive(Debug, Error)]
pub enum TlsError {
    #[error("ELF/BTF error: {0}")]
    ElfBtf(#[from] spectre_elf_btf::ElfBtfError),
    #[error("XDP/probe attach error: {0}")]
    Xdp(#[from] spectre_xdp::XdpError),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("missing TLS symbol `{0}` in `{1}`")]
    MissingSymbol(&'static str, String),
    #[error("unsupported Go ABI or version `{0}` (requires Go >= 1.17 register ABI)")]
    UnsupportedGoAbi(String),
    #[error("unsupported target ELF machine architecture {0}")]
    UnsupportedArch(u16),
    #[error("invalid function range [{start:#x}..{end:#x}) for `{symbol}`")]
    InvalidFuncRange {
        symbol: String,
        start: u64,
        end: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UprobeAttachPoint {
    pub binary_path: String,
    pub offset: u64,
    pub is_retprobe: bool,
    pub label: String,
}
