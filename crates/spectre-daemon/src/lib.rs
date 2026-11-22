#![deny(unsafe_code)]

pub mod server;
pub mod topology;

use thiserror::Error;

pub use server::{build_router, DaemonState};
pub use topology::{
    FlameGraphBundle, ServiceEdgeSummary, ServiceNodeSummary, TopologySnapshot, TopologyStore,
};

#[derive(Debug, Error)]
pub enum DaemonError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("XDP error: {0}")]
    Xdp(#[from] spectre_xdp::XdpError),
    #[error("TLS error: {0}")]
    Tls(#[from] spectre_tls::TlsError),
    #[error("Profile error: {0}")]
    Profile(#[from] spectre_profile::ProfileError),
    #[error("Benchmark failure: {0}")]
    BenchmarkFailed(String),
    #[error("JSON serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}
