use spectre_l7::protocols::hpack::huffman_encode;
use spectre_l7::protocols::postgres::sanitize_sql;
use spectre_l7::{
    classify_protocol, dissect_stream, huffman_decode, ConnConfig, ConnKey, Direction,
    HpackDecoder, L7Chunk, L7Protocol, L7Reassembler, L7Span, HTTP2_PREFACE,
};

struct XorShift64(u64);

impl XorShift64 {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn fill_bytes(&mut self, len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            out.extend_from_slice(&self.next_u64().to_le_bytes());
        }
        out.truncate(len);
        out
    }
}

fn h2_frame(ftype: u8, flags: u8, sid: u32, payload: &[u8]) -> Vec<u8> {
    let len = payload.len();
    let mut out = Vec::with_capacity(9 + len);
    out.push(((len >> 16) & 0xFF) as u8);
    out.push(((len >> 8) & 0xFF) as u8);
    out.push((len & 0xFF) as u8);
    out.push(ftype);
    out.push(flags);
    out.extend_from_slice(&(sid & 0x7FFF_FFFF).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn pg_msg(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + body.len());
    out.push(tag);
    out.extend_from_slice(&((4 + body.len()) as u32).to_be_bytes());
    out.extend_from_slice(body);
    out
}

fn pg_startup() -> Vec<u8> {
    let body = b"\x00\x03\x00\x00user\0postgres\0\0";
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&((4 + body.len()) as u32).to_be_bytes());
    out.extend_from_slice(body);
    out
}

fn run_fragmented(
    egress: &[u8],
    ingress: &[u8],
    step_mode: usize, // 0=whole, 1=1B, 3=3B, >3=random
) -> Vec<L7Span> {
    let mut reasm = L7Reassembler::default();
    let mut rng = XorShift64(0x9E37_79B9_7F4A_7C15);

    let feed_stream =
        |dir: Direction, data: &[u8], reasm: &mut L7Reassembler, rng: &mut XorShift64| {
            if step_mode == 0 {
                reasm.ingest(&L7Chunk {
                    conn_id: 77,
                    pid: 1001,
                    fd: 9,
                    ts_ns: if dir == Direction::Egress {
                        1_000
                    } else {
                        5_000
                    },
                    direction: dir,
                    tls_source: 1,
                    payload: data,
                });
                return;
            }
            let mut off = 0usize;
            let base_ts = if dir == Direction::Egress {
                1_000
            } else {
                5_000
            };
            while off < data.len() {
                let chunk_sz = if step_mode == 1 || step_mode == 3 {
                    step_mode
                } else {
                    ((rng.next_u64() % 11) + 1) as usize
                };
                let end = (off + chunk_sz).min(data.len());
                reasm.ingest(&L7Chunk {
                    conn_id: 77,
                    pid: 1001,
                    fd: 9,
                    ts_ns: base_ts + off as u64,
                    direction: dir,
                    tls_source: 1,
                    payload: &data[off..end],
                });
                off = end;
            }
        };

    feed_stream(Direction::Egress, egress, &mut reasm, &mut rng);
    feed_stream(Direction::Ingress, ingress, &mut reasm, &mut rng);
    reasm.drain_spans()
}

fn assert_span_semantics_eq(a: &[L7Span], b: &[L7Span]) {
    assert_eq!(
        a.len(),
        b.len(),
        "span count mismatch: {} vs {}",
        a.len(),
        b.len()
    );
    for (x, y) in a.iter().zip(b.iter()) {
        assert_eq!(x.protocol, y.protocol);
        assert_eq!(x.method, y.method);
        assert_eq!(x.path_or_query, y.path_or_query);
        assert_eq!(x.host, y.host);
        assert_eq!(x.status_code, y.status_code);
        assert_eq!(x.request_bytes, y.request_bytes);
        assert_eq!(x.response_bytes, y.response_bytes);
        assert_eq!(x.traceparent, y.traceparent);
        assert_eq!(x.grpc, y.grpc);
        assert_eq!(x.sql_fingerprint, y.sql_fingerprint);
        assert_eq!(x.redis_key_prefix, y.redis_key_prefix);
        assert_eq!(x.error, y.error);
        assert_eq!(x.error_detail, y.error_detail);
    }
}

fn hpack_lit_huff_inc_name(name_idx: u8, val: &[u8]) -> Vec<u8> {
    let mut out = vec![0x40 | (name_idx & 0x3F)];
    let enc = huffman_encode(val);
    assert!(enc.len() < 127);
    out.push(0x80 | (enc.len() as u8));
    out.extend_from_slice(&enc);
    out
}

fn hpack_lit_huff_inc_custom(name: &[u8], val: &[u8]) -> Vec<u8> {
    let mut out = vec![0x40];
    let nenc = huffman_encode(name);
    let venc = huffman_encode(val);
    assert!(nenc.len() < 127 && venc.len() < 127);
    out.push(0x80 | (nenc.len() as u8));
    out.extend_from_slice(&nenc);
    out.push(0x80 | (venc.len() as u8));
    out.extend_from_slice(&venc);
    out
}

#[test]
fn fragmentation_1b_3b_random_parity_across_all_4_protocols() {
    // 1. HTTP/1.1 pipelined + chunked + traceparent
    let http1_egress = b"\
GET /api/v1/orders?id=7 HTTP/1.1\r\n\
Host: api.spectre.local\r\n\
User-Agent: spectre-cli/1.0\r\n\
traceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01\r\n\
\r\n\
POST /submit HTTP/1.1\r\n\
Host: api.spectre.local\r\n\
Transfer-Encoding: chunked\r\n\
\r\n\
5\r\nhello\r\n0\r\n\r\n";

    let http1_ingress = b"\
HTTP/1.1 200 OK\r\n\
Content-Length: 4\r\n\
\r\n\
pong\
HTTP/1.1 201 Created\r\n\
Transfer-Encoding: chunked\r\n\
\r\n\
2\r\nok\r\n0\r\n\r\n";

    let h1_base = run_fragmented(http1_egress, http1_ingress, 0);
    assert_eq!(h1_base.len(), 2);
    assert_eq!(h1_base[0].method, "GET");
    assert_eq!(h1_base[0].path_or_query, "/api/v1/orders?id=7");
    assert_eq!(h1_base[0].host.as_deref(), Some("api.spectre.local"));
    assert_eq!(
        h1_base[0].traceparent.as_deref(),
        Some("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
    );
    assert_eq!(h1_base[0].status_code, 200);
    assert_eq!(h1_base[1].method, "POST");
    assert_eq!(h1_base[1].status_code, 201);
    for mode in [1, 3, 7] {
        assert_span_semantics_eq(&h1_base, &run_fragmented(http1_egress, http1_ingress, mode));
    }

    // 2. HTTP/2 + HPACK (Huffman + dynamic indexing + eviction) + gRPC Protobuf
    let mut h2_egress = HTTP2_PREFACE.to_vec();
    h2_egress.extend_from_slice(&h2_frame(4, 0, 0, &[0, 1, 0, 0, 1, 0])); // SETTINGS_HEADER_TABLE_SIZE=256

    // Stream 1 HPACK block: :method POST (0x83), :scheme https (0x87), :path /orders.Book/Place, :authority orders.mesh, content-type application/grpc
    let mut req1_hdr = vec![0x83, 0x87];
    req1_hdr.extend_from_slice(&hpack_lit_huff_inc_name(4, b"/orders.Book/Place"));
    req1_hdr.extend_from_slice(&hpack_lit_huff_inc_name(1, b"orders.mesh"));
    req1_hdr.extend_from_slice(&hpack_lit_huff_inc_name(31, b"application/grpc"));
    let split = req1_hdr.len() / 2;
    h2_egress.extend_from_slice(&h2_frame(1, 0x00, 1, &req1_hdr[..split])); // HEADERS without END_HEADERS
    h2_egress.extend_from_slice(&h2_frame(9, 0x04, 1, &req1_hdr[split..])); // CONTINUATION + END_HEADERS

    // Protobuf payload: field 1 varint 42 (08 2A), field 2 string "BTC" (12 03 42 54 43)
    let proto_msg = [0x08, 0x2A, 0x12, 0x03, b'B', b'T', b'C'];
    let mut grpc_env = vec![0u8];
    grpc_env.extend_from_slice(&(proto_msg.len() as u32).to_be_bytes());
    grpc_env.extend_from_slice(&proto_msg);
    h2_egress.extend_from_slice(&h2_frame(0, 0x01, 1, &grpc_env)); // DATA + END_STREAM

    // Stream 3 reuses dynamic table entries 62 (/orders.Book/Place) & 64 (application/grpc)!
    let req3_hdr = vec![0x83, 0x87, 0x80 | 64, 0x80 | 63, 0x80 | 62];
    h2_egress.extend_from_slice(&h2_frame(1, 0x05, 3, &req3_hdr));

    let mut h2_ingress = h2_frame(4, 0, 0, &[]); // Server SETTINGS
    let mut resp_hdr = vec![0x88]; // :status 200
    resp_hdr.extend_from_slice(&hpack_lit_huff_inc_name(31, b"application/grpc"));
    h2_ingress.extend_from_slice(&h2_frame(1, 0x04, 1, &resp_hdr));
    h2_ingress.extend_from_slice(&h2_frame(0, 0x00, 1, &grpc_env));
    let mut tr1 = Vec::new();
    tr1.extend_from_slice(&hpack_lit_huff_inc_custom(b"grpc-status", b"0"));
    h2_ingress.extend_from_slice(&h2_frame(1, 0x05, 1, &tr1)); // Trailers END_STREAM|END_HEADERS

    let mut tr3 = vec![0x88]; // :status 200 trailers-only with grpc-status 7
    tr3.extend_from_slice(&hpack_lit_huff_inc_custom(b"grpc-status", b"7"));
    h2_ingress.extend_from_slice(&h2_frame(1, 0x05, 3, &tr3));

    let mut h2_base = run_fragmented(&h2_egress, &h2_ingress, 0);
    h2_base.sort_by_key(|s| s.span_id);
    assert_eq!(h2_base.len(), 2);
    assert_eq!(h2_base[0].protocol, L7Protocol::Grpc);
    assert_eq!(h2_base[0].path_or_query, "/orders.Book/Place");
    assert_eq!(h2_base[0].status_code, 200);
    let g0 = h2_base[0].grpc.as_ref().unwrap();
    assert_eq!(g0.service, "orders.Book");
    assert_eq!(g0.method, "Place");
    assert_eq!(g0.grpc_status, Some(0));
    assert_eq!(g0.proto_tags.len(), 2);
    assert_eq!(g0.proto_tags[0].summary, "varint(42)");
    assert_eq!(g0.proto_tags[1].summary, "str(\"BTC\")");
    assert!(h2_base[1].error); // grpc-status=7
    for mode in [1, 3, 7] {
        let mut r = run_fragmented(&h2_egress, &h2_ingress, mode);
        r.sort_by_key(|s| s.span_id);
        assert_span_semantics_eq(&h2_base, &r);
    }

    // Also inspect live HPACK dynamic table via dissect_stream
    let report = dissect_stream(
        L7Protocol::Unknown,
        &[
            L7Chunk {
                conn_id: 1,
                pid: 1,
                fd: 5,
                ts_ns: 10,
                direction: Direction::Egress,
                tls_source: 2,
                payload: &h2_egress,
            },
            L7Chunk {
                conn_id: 1,
                pid: 1,
                fd: 5,
                ts_ns: 20,
                direction: Direction::Ingress,
                tls_source: 2,
                payload: &h2_ingress,
            },
        ],
    );
    assert!(!report.hpack_dynamic_table.is_empty());

    // 3. PostgreSQL v3 Simple + Extended Query & SQL Sanitizer
    let mut pg_egress = pg_startup();
    pg_egress.extend_from_slice(&pg_msg(
        b'Q',
        b"SELECT * FROM orders WHERE user_id = 42 AND tier = 'gold';\0",
    ));
    let mut parse_body =
        Vec::from(&b"s1\0INSERT INTO audit(uid, msg) VALUES (99, 'hello''world');\0"[..]);
    parse_body.extend_from_slice(&0u16.to_be_bytes());
    pg_egress.extend_from_slice(&pg_msg(b'P', &parse_body));
    pg_egress.extend_from_slice(&pg_msg(b'B', b"p1\0s1\0\0\0\0\0\0\0\0\0"));
    pg_egress.extend_from_slice(&pg_msg(b'E', b"p1\0\0\0\0\0"));
    pg_egress.extend_from_slice(&pg_msg(b'S', &[]));

    let mut pg_ingress = pg_msg(b'R', &0u32.to_be_bytes());
    pg_ingress.extend_from_slice(&pg_msg(b'Z', b"I"));
    pg_ingress.extend_from_slice(&pg_msg(
        b'T',
        b"\0\x01col\0\0\0\0\0\0\0\0\0\x00\x17\0\x04\xff\xff\xff\xff\0\0",
    ));
    pg_ingress.extend_from_slice(&pg_msg(b'D', b"\0\x01\0\0\0\x011"));
    pg_ingress.extend_from_slice(&pg_msg(b'C', b"SELECT 1\0"));
    pg_ingress.extend_from_slice(&pg_msg(b'Z', b"I"));
    pg_ingress.extend_from_slice(&pg_msg(b'1', &[]));
    pg_ingress.extend_from_slice(&pg_msg(b'2', &[]));
    pg_ingress.extend_from_slice(&pg_msg(b'E', b"SERROR\0C23505\0Mduplicate key\0\0"));
    pg_ingress.extend_from_slice(&pg_msg(b'Z', b"I"));

    let pg_base = run_fragmented(&pg_egress, &pg_ingress, 0);
    assert_eq!(pg_base.len(), 2);
    assert_eq!(pg_base[0].protocol, L7Protocol::Postgres);
    assert_eq!(
        pg_base[0].sql_fingerprint.as_deref(),
        Some("SELECT * FROM orders WHERE user_id = $1 AND tier = $2")
    );
    assert!(!pg_base[0].error);
    assert_eq!(
        pg_base[1].sql_fingerprint.as_deref(),
        Some("INSERT INTO audit(uid, msg) VALUES ($1, $2)")
    );
    assert!(pg_base[1].error);
    assert!(pg_base[1]
        .error_detail
        .as_deref()
        .unwrap()
        .contains("23505"));
    for mode in [1, 3, 7] {
        assert_span_semantics_eq(&pg_base, &run_fragmented(&pg_egress, &pg_ingress, mode));
    }

    // 4. Redis RESP2/RESP3 pipelined
    let redis_egress = b"\
*3\r\n$3\r\nSET\r\n$7\r\nuser:42\r\n$6\r\nactive\r\n\
*2\r\n$7\r\nHGETALL\r\n$7\r\ncart:77\r\n\
*2\r\n$3\r\nGET\r\n$9\r\nmissing:1\r\n";
    let redis_ingress = b"\
+OK\r\n\
%2\r\n$1\r\na\r\n:5\r\n$1\r\nb\r\n#t\r\n\
-ERR key missing\r\n";

    let rd_base = run_fragmented(redis_egress, redis_ingress, 0);
    assert_eq!(rd_base.len(), 3);
    assert_eq!(rd_base[0].protocol, L7Protocol::Redis);
    assert_eq!(rd_base[0].method, "SET");
    assert_eq!(rd_base[0].redis_key_prefix.as_deref(), Some("user:"));
    assert_eq!(rd_base[1].method, "HGETALL");
    assert_eq!(rd_base[1].redis_key_prefix.as_deref(), Some("cart:"));
    assert_eq!(rd_base[2].status_code, 500);
    assert!(rd_base[2].error);
    for mode in [1, 3, 7] {
        assert_span_semantics_eq(&rd_base, &run_fragmented(redis_egress, redis_ingress, mode));
    }
}

#[test]
fn slowloris_buffer_caps_and_idle_ttl_eviction() {
    let mut reasm = L7Reassembler::new(ConnConfig {
        max_dir_buffer_bytes: 8192,
        idle_ttl_ns: 1_000,
        max_active_conns: 4,
    });

    let huge = vec![b'X'; 64 * 1024];
    for c in 0..10u64 {
        reasm.ingest(&L7Chunk {
            conn_id: c,
            pid: 1,
            fd: c as i32 + 3,
            ts_ns: c * 500,
            direction: Direction::Egress,
            tls_source: 0,
            payload: &huge,
        });
    }
    assert!(reasm.active_connection_count() <= 4);
    for c in 0..10u64 {
        assert!(
            reasm.connection_buffered_bytes(ConnKey {
                pid: 1,
                fd: c as i32 + 3,
                conn_id: c
            }) <= 8192
        );
    }
    let evicted = reasm.evict_idle(100_000);
    assert!(evicted > 0);
    assert_eq!(reasm.active_connection_count(), 0);
}

#[test]
fn fuzz_100000_malformed_truncated_huffman_and_l7_inputs_zero_panics() {
    let mut rng = XorShift64(0xD1B5_4A32_D192_ED03);
    let hints = [
        L7Protocol::Unknown,
        L7Protocol::Http1,
        L7Protocol::Http2,
        L7Protocol::Postgres,
        L7Protocol::Redis,
    ];

    // Crafted pathological edge inputs
    let pathological: Vec<&[u8]> = vec![
        b"POST / HTTP/1.1\r\nContent-Length: 99999999999999999\r\n\r\n",
        b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nFFFFFFFFFFFFFFFF\r\n",
        b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\xff\xff\xff\x01\xff\x7f\xff\xff\xff",
        b"*999999999\r\n*999999999\r\n$999999999\r\n",
        b"*******************************************************************\r\n",
        b"Q\xff\xff\xff\xffSELECT ''''''''''''''''''''' 999999999999999999999",
        b"E\x00\x00\x00\x02bogus",
        b"\xff\xff\xff\xff\xff\x00",
        b"\r\n\r\n*2\r\n\r\n",
    ];
    for &p in &pathological {
        let _ = huffman_decode(p);
        let _ = HpackDecoder::new(256).decode_block(p);
        let _ = sanitize_sql(&String::from_utf8_lossy(p));
        let _ = classify_protocol(p, p);
        for &h in &hints {
            let _ = dissect_stream(
                h,
                &[
                    L7Chunk {
                        conn_id: 1,
                        pid: 1,
                        fd: 3,
                        ts_ns: 1,
                        direction: Direction::Egress,
                        tls_source: 0,
                        payload: p,
                    },
                    L7Chunk {
                        conn_id: 1,
                        pid: 1,
                        fd: 3,
                        ts_ns: 2,
                        direction: Direction::Ingress,
                        tls_source: 0,
                        payload: p,
                    },
                ],
            );
        }
    }

    for i in 0..100_000usize {
        let len = (rng.next_u64() % 192) as usize;
        let mut buf = rng.fill_bytes(len);
        // Inject protocol trigger prefixes periodically to exercise deep state machines
        if !buf.is_empty() && i % 5 == 0 {
            let pfx: &[u8] = match (i / 5) % 4 {
                0 => b"GET /",
                1 => b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
                2 => b"Q\x00\x00\x00\x10",
                _ => b"*3\r\n$",
            };
            let take = pfx.len().min(buf.len());
            buf[..take].copy_from_slice(&pfx[..take]);
        }

        let _ = huffman_decode(&buf);
        let mut hpack = HpackDecoder::new(128);
        let _ = hpack.decode_block(&buf);
        let _ = classify_protocol(&buf, &buf);

        let mid = buf.len() / 2;
        let hint = hints[i % hints.len()];
        let _ = dissect_stream(
            hint,
            &[
                L7Chunk {
                    conn_id: i as u64,
                    pid: 1,
                    fd: 4,
                    ts_ns: i as u64,
                    direction: Direction::Egress,
                    tls_source: 0,
                    payload: &buf[..mid],
                },
                L7Chunk {
                    conn_id: i as u64,
                    pid: 1,
                    fd: 4,
                    ts_ns: i as u64 + 1,
                    direction: Direction::Ingress,
                    tls_source: 0,
                    payload: &buf[mid..],
                },
            ],
        );
    }
}
