# M08 Design — Mesh Telemetry Daemon (`spectre-daemon`), Benchmark Harness (`spectre-bench`), & Terminal UI (`spectre-tui`)

## 1. Overview
Module M08 surfaces SpectreMesh kernel telemetry (L7/TLS spans, XDP firewall drops, kernel RingBuf stats, TCP SRTT/retransmits, On-CPU/Off-CPU flamegraphs) through three `#![deny(unsafe_code)]` interfaces:
1. **`spectred` (`crates/spectre-daemon`):** `axum` HTTP/SSE/Prometheus telemetry daemon backed by `parking_lot::RwLock<TopologyStore>`.
2. **`spectre-bench` (`crates/spectre-daemon/src/bin/spectre-bench.rs`):** Automated benchmark runner executing live `BPF_PROG_TEST_RUN` XDP benchmarks, `BPF_MAP_TYPE_RINGBUF` throughput tests, live OpenSSL 3.5.5 TLS 1.3 baseline-vs-uprobe overhead measurements, `spectre-l7` decoding speed benchmarks, and `spectre-verifier` static verification latency benchmarks. Emits `docs/benchmarks/ebpf_perf.{md,json}` and `studio/public/telemetry/summary.json`.
3. **`spectre-top` (`crates/spectre-tui`):** Live 4-panel `ratatui` cockpit displaying Service Mesh Topology, Live Plaintext L7/TLS Streams, XDP Firewall/RingBuf Health, and On-CPU/Off-CPU Flamegraph Hotspots, verified headlessly via `ratatui::backend::TestBackend::new(120, 40)`.

## 2. Topology & Telemetry Contracts
- **Service Aggregation (`TopologyStore`):** Groups captured `L7Span` entries into `(source_comm -> target_service:protocol)` edges computing request count, error rate %, p50/p95/p99 latency in ms, byte throughput, and TLS interception source (`CLEARTEXT`, `OpenSSL 3.x`, `Go crypto/tls`).
- **Prometheus Metrics (`GET /metrics`):** Exports `spectre_l7_requests_total`, `spectre_l7_latency_p99_ms`, `spectre_xdp_packets_total`, `spectre_ringbuf_drops_total`, and `spectre_tcp_srtt_microseconds`.
- **REST & SSE Endpoints:**
  - `GET /v1/topology` -> `TopologySnapshot` JSON (nodes, edges, ringbuf drops, XDP counters, TCP SRTT).
  - `GET /v1/spans` -> Bounded ring buffer of recent decoded `L7Span` items (sanitized SQL `$1/$2`, redacted Redis prefixes).
  - `GET /v1/flamegraph?mode=oncpu|offcpu` -> JSON bundle containing `FlameGraph`, `.folded` stacks, and standalone `<svg>`.
  - `GET /v1/events/stream` -> Server-Sent Events (`text/event-stream`, `event: telemetry`, `retry: 1500`).
- **Portfolio Summary Contract (`studio/public/telemetry/summary.json`):** Strictly conforms to `LabTelemetrySummary` (`schemaVersion: 1`, `slug: "spectre"`, `status: "VERIFIED_LIVE"`, `commitSha`, `generatedAtIso`, `wasmSizeKb`, `wasmAssetPath`, `verificationGate`, `headlineMetric`, `secondaryMetrics[3]`).
