#![deny(unsafe_code)]

#[cfg(target_os = "linux")]
pub mod mesh_harness;
pub mod oracle;

use thiserror::Error;

#[cfg(target_os = "linux")]
pub use mesh_harness::{run_live_mesh_oracle, MeshOracleConfig};
pub use oracle::{
    compute_percentiles_ms, evaluate_leg_parity, GroundTruthRecord, OracleReport,
    ProtocolOracleSummary,
};

#[derive(Debug, Error)]
pub enum OracleError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("XDP/TCP monitor error: {0}")]
    Xdp(#[from] spectre_xdp::XdpError),
    #[error("TLS interceptor error: {0}")]
    Tls(#[from] spectre_tls::TlsError),
    #[error("external workload build failed: {0}")]
    BuildFailed(String),
    #[error("oracle verification failed: {0}")]
    VerificationFailed(String),
    #[error("JSON serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}
