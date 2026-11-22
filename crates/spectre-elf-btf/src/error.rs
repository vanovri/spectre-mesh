use thiserror::Error;

/// Unified error type for ELF64 parsing, BTF decoding, CO-RE relocation,
/// raw `SYS_bpf` syscalls, and `BPF_MAP_TYPE_RINGBUF` consumption.
#[derive(Debug, Error)]
pub enum ElfBtfError {
    #[error("invalid ELF64 header or magic bytes")]
    InvalidElfHeader,

    #[error("unsupported ELF architecture or class: {0}")]
    UnsupportedElfFormat(&'static str),

    #[error("out-of-bounds offset/size in {context}: offset={offset}, len={len}, total={total}")]
    OutOfBounds {
        context: &'static str,
        offset: usize,
        len: usize,
        total: usize,
    },

    #[error("integer overflow while computing {0}")]
    ArithmeticOverflow(&'static str),

    #[error("invalid string table offset {offset} (table len {table_len})")]
    InvalidStringOffset { offset: usize, table_len: usize },

    #[error("invalid UTF-8 string in ELF/BTF metadata")]
    InvalidUtf8,

    #[error("missing required section: {0}")]
    MissingSection(&'static str),

    #[error("invalid BTF header or magic (expected 0xEB9F, got {0:#06x})")]
    InvalidBtfHeader(u16),

    #[error("unsupported BTF kind {0}")]
    UnsupportedBtfKind(u8),

    #[error("BTF type ID {0} out of range (max {1})")]
    InvalidBtfTypeId(u32, usize),

    #[error("cyclic or excessively deep BTF type graph (> {0} hops)")]
    CyclicBtfGraph(usize),

    #[error("invalid BTF.ext header or record layout: {0}")]
    InvalidBtfExt(&'static str),

    #[error("CO-RE relocation failed for type '{type_name}' access '{access}': {reason}")]
    CoreRelocationFailed {
        type_name: String,
        access: String,
        reason: String,
    },

    #[error("invalid BPF instruction stream or relocation target: {0}")]
    InvalidRelocation(String),

    #[error("invalid Go .gopclntab header or symbol table: {0}")]
    InvalidGoPclntab(&'static str),

    #[error("BPF map '{name}' missing required BTF attribute '{attr}'")]
    InvalidBtfMapSpec { name: String, attr: &'static str },

    #[error("Linux syscall '{op}' failed with errno {errno}: {message}")]
    Syscall {
        op: &'static str,
        errno: i32,
        message: String,
    },

    #[error("BPF_PROG_LOAD rejected '{prog_name}' (errno {errno}):\n{verifier_log}")]
    VerifierRejected {
        prog_name: String,
        errno: i32,
        verifier_log: String,
    },

    #[error("invalid RingBuf configuration: {0}")]
    InvalidRingBuf(&'static str),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
