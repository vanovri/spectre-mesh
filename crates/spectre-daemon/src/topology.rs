use std::collections::{BTreeMap, VecDeque};
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use spectre_l7::{L7Protocol, L7Span};
use spectre_profile::{build_flamegraph, parse_folded, render_svg, FlameGraph};
use spectre_xdp::{TcpEventKind, TcpTelemetryEvent, XdpStatsSnapshot};

const MAX_STORED_SPANS: usize = 512;
const MAX_STORED_TCP_EVENTS: usize = 512;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServiceNodeSummary {
    pub service: String,
    pub protocol_primary: L7Protocol,
    pub requests: u64,
    pub errors: u64,
    pub error_rate_pct: f64,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub tls_mode: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServiceEdgeSummary {
    pub source: String,
    pub target: String,
    pub protocol: L7Protocol,
    pub requests: u64,
    pub errors: u64,
    pub p99_ms: f64,
    pub avg_srtt_us: f64,
    pub retransmits: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TopologySnapshot {
    pub total_requests: u64,
    pub total_errors: u64,
    pub ringbuf_drops: u64,
    pub xdp_stats: XdpStatsSnapshot,
    pub tcp_retransmits: u64,
    pub avg_srtt_us: f64,
    pub nodes: Vec<ServiceNodeSummary>,
    pub edges: Vec<ServiceEdgeSummary>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FlameGraphBundle {
    pub mode: String,
    pub folded: String,
    pub flamegraph: FlameGraph,
    pub svg: String,
}

#[derive(Debug, Default)]
struct BucketStats {
    proto: Option<L7Protocol>,
    latencies_ns: Vec<u64>,
    errors: u64,
    bytes_in: u64,
    bytes_out: u64,
    tls_sources: u8,
}

impl BucketStats {
    fn record(&mut self, span: &L7Span) {
        if self.proto.is_none() {
            self.proto = Some(span.protocol);
        }
        if self.latencies_ns.len() < 4096 {
            self.latencies_ns.push(span.latency_ns);
        }
        if span.error {
            self.errors += 1;
        }
        self.bytes_out = self.bytes_out.saturating_add(span.request_bytes as u64);
        self.bytes_in = self.bytes_in.saturating_add(span.response_bytes as u64);
        self.tls_sources |= 1u8 << (span.tls_source.min(7));
    }

    fn percentiles_ms(&self) -> (f64, f64, f64) {
        if self.latencies_ns.is_empty() {
            return (0.0, 0.0, 0.0);
        }
        let mut s = self.latencies_ns.clone();
        s.sort_unstable();
        let pick = |p: usize| -> f64 {
            let idx = (s.len().saturating_sub(1) * p) / 100;
            (s[idx] as f64) / 1_000_000.0
        };
        (pick(50), pick(95), pick(99))
    }

    fn tls_label(&self) -> String {
        let has_oss = (self.tls_sources & (1 << 1)) != 0;
        let has_go = (self.tls_sources & (1 << 2)) != 0;
        let has_clear = (self.tls_sources & (1 << 0)) != 0;
        match (has_oss, has_go, has_clear) {
            (true, false, false) => "OpenSSL TLS 1.3".to_owned(),
            (false, true, false) => "Go crypto/tls 1.3".to_owned(),
            (false, false, true) => "Cleartext Socket".to_owned(),
            _ => "Hybrid Mesh".to_owned(),
        }
    }
}

#[derive(Debug)]
pub struct TopologyStore {
    total_requests: u64,
    total_errors: u64,
    ringbuf_drops: u64,
    xdp_stats: XdpStatsSnapshot,
    tcp_retransmits: u64,
    srtt_samples_us: VecDeque<u32>,
    node_stats: BTreeMap<String, BucketStats>,
    edge_stats: BTreeMap<(String, String, &'static str), BucketStats>,
    spans: VecDeque<L7Span>,
    tcp_events: VecDeque<TcpTelemetryEvent>,
    oncpu_folded: String,
    offcpu_folded: String,
}

impl Default for TopologyStore {
    fn default() -> Self {
        Self::new()
    }
}

impl TopologyStore {
    #[must_use]
    pub fn new() -> Self {
        Self {
            total_requests: 0,
            total_errors: 0,
            ringbuf_drops: 0,
            xdp_stats: XdpStatsSnapshot::default(),
            tcp_retransmits: 0,
            srtt_samples_us: VecDeque::with_capacity(256),
            node_stats: BTreeMap::new(),
            edge_stats: BTreeMap::new(),
            spans: VecDeque::with_capacity(MAX_STORED_SPANS),
            tcp_events: VecDeque::with_capacity(MAX_STORED_TCP_EVENTS),
            oncpu_folded: String::new(),
            offcpu_folded: String::new(),
        }
    }

    pub fn ingest_span(&mut self, src_service: &str, dst_service: &str, span: L7Span) {
        self.total_requests += 1;
        if span.error {
            self.total_errors += 1;
        }
        self.node_stats
            .entry(dst_service.to_owned())
            .or_default()
            .record(&span);
        self.edge_stats
            .entry((
                src_service.to_owned(),
                dst_service.to_owned(),
                proto_tag(span.protocol),
            ))
            .or_default()
            .record(&span);

        if self.spans.len() == MAX_STORED_SPANS {
            self.spans.pop_front();
        }
        self.spans.push_back(span);
    }

    pub fn ingest_tcp_event(&mut self, ev: TcpTelemetryEvent) {
        match ev.kind {
            TcpEventKind::Retransmit => self.tcp_retransmits += 1,
            TcpEventKind::RttSample if ev.srtt_us > 0 => {
                if self.srtt_samples_us.len() == 256 {
                    self.srtt_samples_us.pop_front();
                }
                self.srtt_samples_us.push_back(ev.srtt_us);
            }
            _ => {}
        }
        if self.tcp_events.len() == MAX_STORED_TCP_EVENTS {
            self.tcp_events.pop_front();
        }
        self.tcp_events.push_back(ev);
    }

    pub fn set_xdp_stats(&mut self, stats: XdpStatsSnapshot) {
        self.xdp_stats = stats;
    }

    pub fn set_ringbuf_drops(&mut self, drops: u64) {
        self.ringbuf_drops = drops;
    }

    pub fn set_flamegraphs(&mut self, oncpu_folded: String, offcpu_folded: String) {
        self.oncpu_folded = oncpu_folded;
        self.offcpu_folded = offcpu_folded;
    }

    #[must_use]
    pub fn recent_spans(&self, limit: usize) -> Vec<L7Span> {
        self.spans.iter().rev().take(limit).cloned().collect()
    }

    #[must_use]
    pub fn avg_srtt_us(&self) -> f64 {
        if self.srtt_samples_us.is_empty() {
            return 0.0;
        }
        let sum: u64 = self.srtt_samples_us.iter().map(|&v| u64::from(v)).sum();
        (sum as f64) / (self.srtt_samples_us.len() as f64)
    }

    #[must_use]
    pub fn snapshot(&self) -> TopologySnapshot {
        let avg_srtt_us = self.avg_srtt_us();
        let nodes = self
            .node_stats
            .iter()
            .map(|(service, b)| {
                let reqs = b.latencies_ns.len() as u64;
                let (p50, p95, p99) = b.percentiles_ms();
                ServiceNodeSummary {
                    service: service.clone(),
                    protocol_primary: b.proto.unwrap_or(L7Protocol::Unknown),
                    requests: reqs,
                    errors: b.errors,
                    error_rate_pct: if reqs > 0 {
                        (b.errors as f64) * 100.0 / (reqs as f64)
                    } else {
                        0.0
                    },
                    p50_ms: p50,
                    p95_ms: p95,
                    p99_ms: p99,
                    bytes_in: b.bytes_in,
                    bytes_out: b.bytes_out,
                    tls_mode: b.tls_label(),
                }
            })
            .collect();

        let edges = self
            .edge_stats
            .iter()
            .map(|((src, dst, _), b)| {
                let (_p50, _p95, p99) = b.percentiles_ms();
                ServiceEdgeSummary {
                    source: src.clone(),
                    target: dst.clone(),
                    protocol: b.proto.unwrap_or(L7Protocol::Unknown),
                    requests: b.latencies_ns.len() as u64,
                    errors: b.errors,
                    p99_ms: p99,
                    avg_srtt_us,
                    retransmits: self.tcp_retransmits,
                }
            })
            .collect();

        TopologySnapshot {
            total_requests: self.total_requests,
            total_errors: self.total_errors,
            ringbuf_drops: self.ringbuf_drops,
            xdp_stats: self.xdp_stats,
            tcp_retransmits: self.tcp_retransmits,
            avg_srtt_us,
            nodes,
            edges,
        }
    }

    #[must_use]
    pub fn flamegraph(&self, mode: &str) -> FlameGraphBundle {
        let (norm_mode, title, unit, raw) = if mode.eq_ignore_ascii_case("offcpu") {
            (
                "offcpu".to_owned(),
                "SpectreMesh Off-CPU Wait Profile",
                "ns",
                self.offcpu_folded.clone(),
            )
        } else {
            (
                "oncpu".to_owned(),
                "SpectreMesh On-CPU 99Hz Profile",
                "samples",
                self.oncpu_folded.clone(),
            )
        };
        let stacks = parse_folded(&raw);
        let flamegraph = build_flamegraph(title, unit, &stacks);
        let svg = render_svg(&flamegraph);
        FlameGraphBundle {
            mode: norm_mode,
            folded: raw,
            flamegraph,
            svg,
        }
    }

    #[must_use]
    pub fn render_prometheus_metrics(&self) -> String {
        let snap = self.snapshot();
        let mut out = String::with_capacity(1024);
        out.push_str(
            "# HELP spectre_l7_requests_total Total L7 requests captured by SpectreMesh.\n",
        );
        out.push_str("# TYPE spectre_l7_requests_total counter\n");
        for node in &snap.nodes {
            let _ = writeln!(
                out,
                "spectre_l7_requests_total{{service=\"{}\",protocol=\"{}\"}} {}",
                node.service,
                proto_tag(node.protocol_primary),
                node.requests
            );
        }
        out.push_str("# HELP spectre_l7_latency_p99_ms Observed L7 p99 latency in milliseconds.\n");
        out.push_str("# TYPE spectre_l7_latency_p99_ms gauge\n");
        for node in &snap.nodes {
            let _ = writeln!(
                out,
                "spectre_l7_latency_p99_ms{{service=\"{}\"}} {:.4}",
                node.service, node.p99_ms
            );
        }
        out.push_str("# HELP spectre_xdp_packets_total Total packets inspected at XDP hook.\n");
        out.push_str("# TYPE spectre_xdp_packets_total counter\n");
        let _ = writeln!(
            out,
            "spectre_xdp_packets_total {}",
            snap.xdp_stats.rx_packets
        );
        let _ = writeln!(
            out,
            "spectre_xdp_ratelimit_drops_total {}",
            snap.xdp_stats.drop_ratelimit
        );
        let _ = writeln!(out, "spectre_ringbuf_drops_total {}", snap.ringbuf_drops);
        let _ = writeln!(out, "spectre_tcp_srtt_microseconds {:.2}", snap.avg_srtt_us);
        out
    }

    /// Populate representative verified telemetry streams for `--demo` / unit testing.
    pub fn populate_demo_telemetry(&mut self) {
        let mut id = 1u64;
        for i in 0..24u64 {
            let is_err = i == 17;
            self.ingest_span(
                "ingress-gw",
                "checkout-api",
                L7Span {
                    span_id: id,
                    conn_id: 1001,
                    pid: 4120,
                    fd: 7,
                    protocol: L7Protocol::Http1,
                    method: if i % 3 == 0 { "POST" } else { "GET" }.to_owned(),
                    path_or_query: if i % 3 == 0 {
                        "/api/v1/orders"
                    } else {
                        "/api/v1/items"
                    }
                    .to_owned(),
                    host: Some("checkout.mesh.local".to_owned()),
                    user_agent: Some("envoy-edge/1.30".to_owned()),
                    status_code: if is_err { 503 } else { 200 },
                    request_bytes: 184,
                    response_bytes: 512,
                    start_ns: 1_000_000 + i * 2_000_000,
                    first_byte_ns: 1_240_000 + i * 2_000_000,
                    end_ns: 1_480_000 + i * 2_000_000 + (i % 5) * 120_000,
                    latency_ns: 480_000 + (i % 5) * 120_000,
                    traceparent: Some(format!("00-4bf92f3577b34da6a3ce929d0e0e4736-{id:016x}-01")),
                    grpc: None,
                    sql_fingerprint: None,
                    redis_key_prefix: None,
                    error: is_err,
                    error_detail: is_err.then(|| "HTTP 503".to_owned()),
                    tls_source: 1,
                },
            );
            id += 1;
        }

        for i in 0..24u64 {
            self.ingest_span(
                "checkout-api",
                "ml-scorer-go",
                L7Span {
                    span_id: id,
                    conn_id: 2002,
                    pid: 4310,
                    fd: 9,
                    protocol: L7Protocol::Grpc,
                    method: "POST".to_owned(),
                    path_or_query: "/spectre.MeshService/Infer".to_owned(),
                    host: Some("scorer.mesh.local".to_owned()),
                    user_agent: Some("grpc-go/1.66".to_owned()),
                    status_code: 200,
                    request_bytes: 96,
                    response_bytes: 84,
                    start_ns: 2_000_000 + i * 1_500_000,
                    first_byte_ns: 2_800_000 + i * 1_500_000,
                    end_ns: 2_900_000 + i * 1_500_000 + (i % 7) * 350_000,
                    latency_ns: 900_000 + (i % 7) * 350_000,
                    traceparent: Some(format!("00-4bf92f3577b34da6a3ce929d0e0e4736-{id:016x}-01")),
                    grpc: None,
                    sql_fingerprint: None,
                    redis_key_prefix: None,
                    error: false,
                    error_detail: None,
                    tls_source: 2,
                },
            );
            id += 1;
        }

        for i in 0..16u64 {
            let slow = i == 15;
            self.ingest_span(
                "checkout-api",
                "orders-postgres",
                L7Span {
                    span_id: id,
                    conn_id: 3003,
                    pid: 4120,
                    fd: 11,
                    protocol: L7Protocol::Postgres,
                    method: "SELECT".to_owned(),
                    path_or_query: "SELECT id, total FROM orders WHERE customer_id = $1".to_owned(),
                    host: None,
                    user_agent: None,
                    status_code: 200,
                    request_bytes: 72,
                    response_bytes: 128,
                    start_ns: 3_000_000 + i * 1_000_000,
                    first_byte_ns: 3_150_000 + i * 1_000_000,
                    end_ns: 3_250_000 + i * 1_000_000 + if slow { 4_100_000 } else { 180_000 },
                    latency_ns: 250_000 + if slow { 4_100_000 } else { 180_000 },
                    traceparent: None,
                    grpc: None,
                    sql_fingerprint: Some(
                        "SELECT id, total FROM orders WHERE customer_id = $1".to_owned(),
                    ),
                    redis_key_prefix: None,
                    error: false,
                    error_detail: None,
                    tls_source: 0,
                },
            );
            id += 1;
        }

        for i in 0..16u64 {
            self.ingest_span(
                "ml-scorer-go",
                "feature-redis",
                L7Span {
                    span_id: id,
                    conn_id: 4004,
                    pid: 4310,
                    fd: 14,
                    protocol: L7Protocol::Redis,
                    method: if i % 2 == 0 { "GET" } else { "SET" }.to_owned(),
                    path_or_query: if i % 2 == 0 {
                        "GET session:*"
                    } else {
                        "SET user:*"
                    }
                    .to_owned(),
                    host: None,
                    user_agent: None,
                    status_code: 200,
                    request_bytes: 44,
                    response_bytes: 32,
                    start_ns: 4_000_000 + i * 500_000,
                    first_byte_ns: 4_050_000 + i * 500_000,
                    end_ns: 4_120_000 + i * 500_000,
                    latency_ns: 120_000 + (i % 4) * 20_000,
                    traceparent: None,
                    grpc: None,
                    sql_fingerprint: None,
                    redis_key_prefix: Some(
                        if i % 2 == 0 { "session:" } else { "user:" }.to_owned(),
                    ),
                    error: false,
                    error_detail: None,
                    tls_source: 0,
                },
            );
            id += 1;
        }

        self.set_xdp_stats(XdpStatsSnapshot {
            rx_packets: 128_400,
            rx_bytes: 18_489_600,
            pass: 126_150,
            drop_ratelimit: 2_140,
            drop_blocklist: 95,
            drop_malformed: 15,
        });
        self.set_ringbuf_drops(0);
        for srtt in [180, 210, 195, 225, 240] {
            self.ingest_tcp_event(TcpTelemetryEvent {
                ts_ns: 1_000_000,
                skaddr: 0xffff_8881_0010,
                pid: 4120,
                srtt_us: srtt,
                saddr: 0x0a00_0001,
                daddr: 0x0a00_0002,
                sport: 44312,
                dport: 8443,
                kind: TcpEventKind::RttSample,
                old_state: 1,
                new_state: 1,
            });
        }
        self.set_flamegraphs(
            "checkout-api;openssl_evp;aes_gcm_encrypt 42\n\
             checkout-api;hot_sha256_spin 318\n\
             ml-scorer-go;crypto/tls.(*Conn).Write;net.(*conn).Write 94\n\
             ml-scorer-go;grpc.(*Server).ServeHTTP;protobuf_encode 140\n"
                .to_owned(),
            "checkout-api;contended_mutex_wait;[k] __x64_sys_futex;[k] futex_wait;[k] __schedule 11535256250\n\
             checkout-api;pg_query_wait;[k] ep_poll;[k] __schedule 3157018688\n"
                .to_owned(),
        );
    }
}

fn proto_tag(p: L7Protocol) -> &'static str {
    match p {
        L7Protocol::Http1 => "http1",
        L7Protocol::Http2 => "http2",
        L7Protocol::Grpc => "grpc",
        L7Protocol::Postgres => "postgres",
        L7Protocol::Redis => "redis",
        L7Protocol::Unknown => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demo_topology_aggregates_nodes_edges_and_prometheus() {
        let mut store = TopologyStore::new();
        store.populate_demo_telemetry();
        let snap = store.snapshot();
        assert_eq!(snap.total_requests, 80);
        assert_eq!(snap.ringbuf_drops, 0);
        assert_eq!(snap.nodes.len(), 4);
        assert_eq!(snap.edges.len(), 4);

        let prom = store.render_prometheus_metrics();
        assert!(prom.contains("spectre_l7_requests_total"));
        assert!(prom.contains("spectre_xdp_ratelimit_drops_total 2140"));
        assert!(prom.contains("spectre_ringbuf_drops_total 0"));

        let fg = store.flamegraph("offcpu");
        assert!(fg.svg.starts_with("<svg "));
        assert!(fg.folded.contains("contended_mutex_wait"));
    }
}
