pub mod btf;
pub mod core_reloc;
pub mod elf64;
pub mod error;
pub mod loader;
pub mod ringbuf;
pub mod syscall;

pub use btf::{Btf, BtfKindId, BtfMapSpec, BtfType, BtfTypeKind};
pub use core_reloc::{apply_core_relocations, BtfExt, CoreReloKind, CoreReloRec};
pub use elf64::{Elf64Object, Elf64Relocation, Elf64Section, Elf64Symbol, GoFuncSymbol};
pub use error::ElfBtfError;
pub use loader::{classify_section_prog_type, ParsedBpfObject, ParsedBpfProgram};
pub use ringbuf::{RingBufLayout, SimulatedRingBuf};

#[cfg(target_os = "linux")]
pub use loader::{BpfObjectLoader, LoadedBpfObject};
#[cfg(target_os = "linux")]
pub use ringbuf::RingBufConsumer;
