use std::collections::HashMap;

use crate::classifier::classify_protocol;
use crate::protocols::http1::Http1Decoder;
use crate::protocols::http2::Http2Decoder;
use crate::protocols::postgres::PostgresDecoder;
use crate::protocols::redis::RedisDecoder;
use crate::protocols::TimestampStream;
use crate::span::{ConnMeta, Direction, DissectionReport, L7Chunk, L7Protocol, L7Span};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnKey {
    pub pid: u32,
    pub fd: i32,
    pub conn_id: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct ConnConfig {
    pub max_dir_buffer_bytes: usize,
    pub idle_ttl_ns: u64,
    pub max_active_conns: usize,
}

impl Default for ConnConfig {
    fn default() -> Self {
        Self {
            max_dir_buffer_bytes: 1_048_576,
            idle_ttl_ns: 60_000_000_000,
            max_active_conns: 16_384,
        }
    }
}

#[derive(Debug)]
enum ProtocolState {
    Unclassified,
    Http1(Http1Decoder),
    Http2(Http2Decoder),
    Postgres(PostgresDecoder),
    Redis(RedisDecoder),
}

impl ProtocolState {
    fn protocol(&self) -> L7Protocol {
        match self {
            Self::Unclassified => L7Protocol::Unknown,
            Self::Http1(_) => L7Protocol::Http1,
            Self::Http2(_) => L7Protocol::Http2,
            Self::Postgres(_) => L7Protocol::Postgres,
            Self::Redis(_) => L7Protocol::Redis,
        }
    }

    fn from_protocol(proto: L7Protocol) -> Self {
        match proto {
            L7Protocol::Http1 => Self::Http1(Http1Decoder::new()),
            L7Protocol::Http2 | L7Protocol::Grpc => Self::Http2(Http2Decoder::new()),
            L7Protocol::Postgres => Self::Postgres(PostgresDecoder::new()),
            L7Protocol::Redis => Self::Redis(RedisDecoder::new()),
            L7Protocol::Unknown => Self::Unclassified,
        }
    }
}

#[derive(Debug)]
struct ConnectionEntry {
    key: ConnKey,
    tls_source: u8,
    last_seen_ns: u64,
    egress: TimestampStream,
    ingress: TimestampStream,
    decoder: ProtocolState,
}

impl ConnectionEntry {
    fn new(key: ConnKey, hint: L7Protocol, ts_ns: u64, tls_source: u8) -> Self {
        Self {
            key,
            tls_source,
            last_seen_ns: ts_ns,
            egress: TimestampStream::default(),
            ingress: TimestampStream::default(),
            decoder: ProtocolState::from_protocol(hint),
        }
    }

    fn push_and_process(
        &mut self,
        chunk: &L7Chunk<'_>,
        max_buf: usize,
        out_spans: &mut Vec<L7Span>,
    ) {
        self.last_seen_ns = self.last_seen_ns.max(chunk.ts_ns);
        match chunk.direction {
            Direction::Egress => self.egress.push(chunk.payload, chunk.ts_ns, max_buf),
            Direction::Ingress => self.ingress.push(chunk.payload, chunk.ts_ns, max_buf),
        }

        if matches!(self.decoder, ProtocolState::Unclassified) {
            let detected = classify_protocol(self.egress.as_slice(), self.ingress.as_slice());
            if detected != L7Protocol::Unknown {
                self.decoder = ProtocolState::from_protocol(detected);
            } else {
                // Prevent unbounded unclassified buffer growth on garbage binary traffic
                if self.egress.len() > 4096 {
                    let drop_n = self.egress.len() - 4096;
                    self.egress.consume(drop_n);
                }
                if self.ingress.len() > 4096 {
                    let drop_n = self.ingress.len() - 4096;
                    self.ingress.consume(drop_n);
                }
                return;
            }
        }

        let meta = ConnMeta {
            conn_id: self.key.conn_id,
            pid: self.key.pid,
            fd: self.key.fd,
            tls_source: self.tls_source,
        };
        match &mut self.decoder {
            ProtocolState::Unclassified => {}
            ProtocolState::Http1(dec) => {
                dec.process(meta, &mut self.egress, &mut self.ingress, out_spans)
            }
            ProtocolState::Http2(dec) => {
                dec.process(meta, &mut self.egress, &mut self.ingress, out_spans)
            }
            ProtocolState::Postgres(dec) => {
                dec.process(meta, &mut self.egress, &mut self.ingress, out_spans)
            }
            ProtocolState::Redis(dec) => {
                dec.process(meta, &mut self.egress, &mut self.ingress, out_spans)
            }
        }
    }

    fn hpack_dynamic_table(&self) -> Vec<(String, String)> {
        if let ProtocolState::Http2(ref h2) = self.decoder {
            let mut tbl = h2.egress_dynamic_table();
            tbl.extend(h2.ingress_dynamic_table());
            tbl
        } else {
            Vec::new()
        }
    }

    fn warnings(&self) -> Vec<String> {
        if let ProtocolState::Http2(ref h2) = self.decoder {
            h2.warnings.clone()
        } else {
            Vec::new()
        }
    }
}

/// Multi-connection streaming L7 reassembler with bounded slowloris/TTL protection.
#[derive(Debug)]
pub struct L7Reassembler {
    cfg: ConnConfig,
    conns: HashMap<ConnKey, ConnectionEntry>,
    completed: Vec<L7Span>,
}

impl Default for L7Reassembler {
    fn default() -> Self {
        Self::new(ConnConfig::default())
    }
}

impl L7Reassembler {
    #[must_use]
    pub fn new(cfg: ConnConfig) -> Self {
        Self {
            cfg,
            conns: HashMap::new(),
            completed: Vec::new(),
        }
    }

    #[must_use]
    pub fn active_connection_count(&self) -> usize {
        self.conns.len()
    }

    pub fn ingest(&mut self, chunk: &L7Chunk<'_>) {
        self.ingest_with_hint(chunk, L7Protocol::Unknown);
    }

    pub fn ingest_with_hint(&mut self, chunk: &L7Chunk<'_>, hint: L7Protocol) {
        let key = ConnKey {
            pid: chunk.pid,
            fd: chunk.fd,
            conn_id: chunk.conn_id,
        };

        if !self.conns.contains_key(&key) && self.conns.len() >= self.cfg.max_active_conns {
            self.evict_oldest_one();
        }

        let entry = self
            .conns
            .entry(key)
            .or_insert_with(|| ConnectionEntry::new(key, hint, chunk.ts_ns, chunk.tls_source));

        entry.push_and_process(chunk, self.cfg.max_dir_buffer_bytes, &mut self.completed);
    }

    pub fn evict_idle(&mut self, now_ns: u64) -> usize {
        let ttl = self.cfg.idle_ttl_ns;
        let before = self.conns.len();
        self.conns
            .retain(|_, c| now_ns.saturating_sub(c.last_seen_ns) <= ttl);
        before - self.conns.len()
    }

    fn evict_oldest_one(&mut self) {
        if let Some(oldest_key) = self
            .conns
            .iter()
            .min_by_key(|(_, c)| c.last_seen_ns)
            .map(|(k, _)| *k)
        {
            self.conns.remove(&oldest_key);
        }
    }

    pub fn drain_spans(&mut self) -> Vec<L7Span> {
        std::mem::take(&mut self.completed)
    }

    #[must_use]
    pub fn connection_buffered_bytes(&self, key: ConnKey) -> usize {
        self.conns
            .get(&key)
            .map_or(0, |c| c.egress.len() + c.ingress.len())
    }
}

/// Statically dissect a single stream (arbitrary chunks, optional protocol hint)
/// returning decoded spans, detected protocol, HPACK dynamic table state, and warnings.
#[must_use]
pub fn dissect_stream(hint: L7Protocol, chunks: &[L7Chunk<'_>]) -> DissectionReport {
    let key = chunks.first().map_or(
        ConnKey {
            pid: 0,
            fd: -1,
            conn_id: 1,
        },
        |c| ConnKey {
            pid: c.pid,
            fd: c.fd,
            conn_id: c.conn_id,
        },
    );
    let mut entry = ConnectionEntry::new(
        key,
        hint,
        chunks.first().map_or(0, |c| c.ts_ns),
        chunks.first().map_or(0, |c| c.tls_source),
    );
    let mut spans = Vec::new();
    for ch in chunks {
        entry.push_and_process(ch, 1_048_576, &mut spans);
    }
    let protocol = if spans.iter().any(|s| s.protocol == L7Protocol::Grpc) {
        L7Protocol::Grpc
    } else {
        entry.decoder.protocol()
    };
    DissectionReport {
        protocol,
        spans,
        hpack_dynamic_table: entry.hpack_dynamic_table(),
        warnings: entry.warnings(),
    }
}
