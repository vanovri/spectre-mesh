#![deny(unsafe_code)]

pub mod classifier;
pub mod conn_state;
pub mod protocols;
pub mod span;

use thiserror::Error;

pub use classifier::{classify_protocol, HTTP2_PREFACE};
pub use conn_state::{dissect_stream, ConnConfig, ConnKey, L7Reassembler};
pub use protocols::hpack::{huffman_decode, huffman_encode, HpackDecoder};
pub use protocols::postgres::sanitize_sql;
pub use span::{
    ConnMeta, Direction, DissectionReport, GrpcInspectInfo, L7Chunk, L7Protocol, L7Span,
    ProtobufFieldSummary,
};

#[derive(Debug, Error)]
pub enum L7Error {
    #[error("unsupported or invalid L7 input: {0}")]
    InvalidInput(String),
}
