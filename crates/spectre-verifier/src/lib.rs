#![deny(unsafe_code)]

pub mod disasm;
pub mod isa;
pub mod tnum;
pub mod verifier;
pub mod vm;

pub use disasm::{disassemble_insn, disassemble_program, DisasmLine};
pub use isa::{decode_bytes, decode_raw_insns, encode_raw, BpfInsn, BpfMapSpec, BpfProgType};
pub use tnum::Tnum;
pub use verifier::{
    verify_program, RegState, ScalarBounds, TraceStep, Verdict, VerificationReport, VerifierConfig,
    VerifierError,
};
pub use vm::{BpfVm, VmError, VmExecResult, VmMaps};
