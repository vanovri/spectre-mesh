#![deny(unsafe_code)]

pub mod flamegraph;
#[cfg(target_os = "linux")]
pub mod profiler;
pub mod symbolizer;

use thiserror::Error;

pub use flamegraph::{
    build_flamegraph, compute_differential_flamegraph, parse_folded, render_svg, to_folded,
    FlameGraph, FlameNode, FoldedStack,
};
#[cfg(target_os = "linux")]
pub use profiler::{ContinuousProfiler, ProfileSnapshot};
pub use symbolizer::{
    demangle_symbol, parse_kallsyms, parse_proc_maps_regions, KernelSym, ProcMapRegion,
    SymbolResolver,
};

#[derive(Debug, Error)]
pub enum ProfileError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[cfg(not(target_arch = "wasm32"))]
    #[error("ELF/BTF error: {0}")]
    ElfBtf(#[from] spectre_elf_btf::ElfBtfError),
    #[error("invalid profiler configuration or map `{0}`")]
    InvalidConfig(&'static str),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}
