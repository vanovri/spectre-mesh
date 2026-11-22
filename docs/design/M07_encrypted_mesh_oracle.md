# M07 Design — Encrypted Multi-Service Mesh Oracle (`crates/spectre-oracle`)

## 1. Purpose
Module M07 proves end-to-end **Zero-Instrumentation L7 + Plaintext TLS + XDP Kernel Observability** against `N = 50,000` live network requests (12,500 per protocol leg by default) with strict ground-truth parity, zero RingBuf drops, zero Go goroutine stack crashes, `< 2.0 ms` p99 latency error, and zero kernel FD or child process leaks.

## 2. Architecture & Process Topology
Because `spectre-l7`'s `L7Reassembler` assigns `Direction::Egress (0)` to outgoing requests and `Direction::Ingress (1)` to incoming responses, sensors attach to the **client** processes of each protocol leg:

| Leg | Transport / Cipher | Zero-Instr Hook | Wire Protocol | Truth Assertions |
| --- | --- | --- | --- | --- |
| **1. OpenSSL 3.5.5** | TLS 1.3 (`SSL_write` / `SSL_read` uprobes) | `probes/tls_openssl.bpf.o` | HTTP/1.1 (keep-alive, GET/POST, `traceparent`, 200/201/503) | Exact count, method, path, status, `< 2ms` p99 delta |
| **2. Go 1.26 `crypto/tls`** | TLS 1.3 ALPN `"h2"` (`RET`-offset entry uprobes ONLY) | `probes/tls_go.bpf.o` | HTTP/2 + HPACK + gRPC (`application/grpc`, protobuf tags, `grpc-status: 0` trailer) + `recurseStack` stack growth | Exact count, `0` Go stack crashes, exact `:method`/`:path`/gRPC fields, `< 2ms` p99 delta |
| **3. PostgreSQL v3** | Loopback TCP (`TCP_NODELAY`) | `probes/tcp_trace.bpf.o` (`sys_enter`/`sys_exit`) | Startup + SimpleQuery `'Q'` (`SELECT ... WHERE id = 42` -> sanitized `?`, plus `INSERT`) | Exact count, sanitized SQL fingerprint, fast vs 4ms slow query attribution |
| **4. Redis RESP2/3** | Loopback TCP (`TCP_NODELAY`) | `probes/tcp_trace.bpf.o` (`sys_enter`/`sys_exit`) | `SET user:<id> ...` / `GET order:<id>` / `PING` | Exact count, redacted `redis_key_prefix`, exact command & latency |
| **5. XDP SYN Flood** | Isolated `netns` `veth` pair | `probes/xdp_net.bpf.o` | Token-bucket rate limiter over raw L2/IPv4/TCP SYN burst | `drop_ratelimit > 0` and clean `XdpAttachment` detach |

## 3. Non-Blocking RingBuf Drain & Zero-Leak Guarantees
- A dedicated drain worker polls `TlsInterceptor::drain_tls_events()` and `TcpMonitor::drain_l7_events()` every `500 us`, sorting per-batch events deterministically by `(ts_ns, chunk_seq)` and feeding `L7Reassembler` continuously so kernel 16 MB `BPF_MAP_TYPE_RINGBUF` buffers stay empty (`ringbuf_drops == 0`).
- Every child process uses an RAII `ChildGuard` (`kill()` + `wait()` on `Drop`) and every eBPF map/program/uprobe/netlink link relies on RAII FDs verified via `/proc/self/fd` count equality (`fds_before == fds_after`).

## 4. Oracle Verification Gates
1. `recovered_requests == requested_requests` across every protocol leg (`50,000 / 50,000`).
2. `ringbuf_drops == 0` across OpenSSL, Go TLS, and TCP probes.
3. `go_stack_crashes == 0` under concurrent recursive stack relocation.
4. `|p99_observed_ms - p99_ground_truth_ms| < 2.0 ms` per protocol leg.
5. `mismatch_count == 0` for method, normalized path / SQL fingerprint / Redis command, and status/error flags.
