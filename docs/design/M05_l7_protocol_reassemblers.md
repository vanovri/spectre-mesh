# M05 Design Spec — `crates/spectre-l7` Streaming L7 Protocol Reassemblers

## 1. Objective & Constitutional Constraints
Build a zero-`unsafe` (`#![deny(unsafe_code)]`), panic-free, OOM-bounded streaming L7 reassembly engine portable across Linux, Windows, and `wasm32-unknown-unknown`. Reconstructs arbitrary TCP/TLS byte fragments emitted via `RingBuf` (`M03`/`M04`) into normalized `L7Span` records with request/TTFB/response nanosecond timestamps.

## 2. Architecture
1. **Per-Connection Ordered Buffering (`conn_state.rs`):**
   - Connections keyed by `(pid, fd, conn_ptr)` maintain bounded directional byte queues (`Egress` / `Ingress`, capped at 1 MiB per direction) and idle TTL eviction (`60 s`) against slowloris exhaustion.
2. **Protocol Auto-Classification (`classifier.rs`):**
   - Inspects initial bytes for HTTP/2 preface (`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`), HTTP/1.1 verbs/status lines, Redis RESP2/3 prefixes (`*`, `+`, `-`, `:`, `$`, `%`, `~`), and PostgreSQL v3 Startup / FE / BE framing.
3. **Zero-Panic Streaming Decoders (`protocols/`):**
   - **HTTP/1.1 (`http1.rs`):** Supports pipelining, `Content-Length`, `Transfer-Encoding: chunked`, header normalization (`Host`, `User-Agent`, W3C `traceparent`), and exact start -> first-response-byte -> response-complete timing.
   - **HTTP/2 + HPACK + gRPC (`http2.rs`, `hpack.rs`, `grpc.rs`):** 9-byte binary frame parser with concurrent multiplexed `stream_id` lifecycles, full RFC 7541 HPACK (61-entry static table, FIFO dynamic table with size updates, N-bit integers, canonical Appendix B Huffman trie decoder), 5-byte gRPC envelopes (`compressed + msg_len`), `grpc-status` trailers, and non-recursive Protobuf wire tag inspector.
   - **PostgreSQL v3 (`postgres.rs`):** Tracks Simple Query (`'Q'`) and Extended Query (`'P'`/`'B'`/`'E'`/`'S'`) paired with `'T'`, `'D'`, `'C'`, `'E'` (SQLSTATE), `'Z'`, sanitizing string and numeric literals to `$N` fingerprints.
   - **Redis RESP2/3 (`redis.rs`):** Iterative explicit-stack streaming decoder (`+`, `-`, `:`, `$`, `*`, `_`, `#`, `,`, `!`, `=`, `%`, `~`, `|`, `>`) capped at depth 64, FIFO command matching, key prefix extraction.
