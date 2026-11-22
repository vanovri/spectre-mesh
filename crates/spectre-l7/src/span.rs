use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum L7Protocol {
    Unknown,
    Http1,
    Http2,
    Grpc,
    Postgres,
    Redis,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Direction {
    Egress = 0,
    Ingress = 1,
}

impl Direction {
    #[must_use]
    pub const fn from_u8(v: u8) -> Self {
        if v == 0 {
            Self::Egress
        } else {
            Self::Ingress
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ConnMeta {
    pub conn_id: u64,
    pub pid: u32,
    pub fd: i32,
    pub tls_source: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct L7Chunk<'a> {
    pub conn_id: u64,
    pub pid: u32,
    pub fd: i32,
    pub ts_ns: u64,
    pub direction: Direction,
    pub tls_source: u8,
    pub payload: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtobufFieldSummary {
    pub field_number: u64,
    pub wire_type: u8,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrpcInspectInfo {
    pub service: String,
    pub method: String,
    pub compressed: bool,
    pub message_len: u32,
    pub grpc_status: Option<i32>,
    pub proto_tags: Vec<ProtobufFieldSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct L7Span {
    pub span_id: u64,
    pub conn_id: u64,
    pub pid: u32,
    pub fd: i32,
    pub protocol: L7Protocol,
    pub method: String,
    pub path_or_query: String,
    pub host: Option<String>,
    pub user_agent: Option<String>,
    pub status_code: u16,
    pub request_bytes: usize,
    pub response_bytes: usize,
    pub start_ns: u64,
    pub first_byte_ns: u64,
    pub end_ns: u64,
    pub latency_ns: u64,
    pub traceparent: Option<String>,
    pub grpc: Option<GrpcInspectInfo>,
    pub sql_fingerprint: Option<String>,
    pub redis_key_prefix: Option<String>,
    pub error: bool,
    pub error_detail: Option<String>,
    pub tls_source: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DissectionReport {
    pub protocol: L7Protocol,
    pub spans: Vec<L7Span>,
    pub hpack_dynamic_table: Vec<(String, String)>,
    pub warnings: Vec<String>,
}
