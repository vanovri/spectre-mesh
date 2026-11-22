use serde::Serialize;
use spectre_verifier::isa::*;
use spectre_verifier::{encode_raw, BpfInsn};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EbpfPreset {
    pub id: &'static str,
    pub label: &'static str,
    pub expected_verdict: &'static str,
    pub bytecode_hex: String,
    pub sample_packet_hex: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct L7Preset {
    pub id: &'static str,
    pub label: &'static str,
    pub protocol_hint: &'static str,
    pub egress_hex: String,
    pub ingress_hex: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FlamePreset {
    pub id: &'static str,
    pub label: &'static str,
    pub title: &'static str,
    pub unit: &'static str,
    pub folded: &'static str,
    pub baseline_folded: Option<&'static str>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PresetCatalog {
    pub ebpf: Vec<EbpfPreset>,
    pub l7: Vec<L7Preset>,
    pub flamegraphs: Vec<FlamePreset>,
}

fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn insns_to_hex(insns: &[BpfInsn]) -> String {
    let raw = encode_raw(insns);
    let mut bytes = Vec::with_capacity(raw.len() * 8);
    for w in raw {
        bytes.extend_from_slice(&w.to_le_bytes());
    }
    to_hex(&bytes)
}

fn sample_tcp_syn_hex() -> String {
    let mut pkt = vec![0u8; 54];
    pkt[0..6].copy_from_slice(&[0x02, 0, 0, 0, 0, 2]);
    pkt[6..12].copy_from_slice(&[0x02, 0, 0, 0, 0, 1]);
    pkt[12..14].copy_from_slice(&[0x08, 0x00]); // IPv4
    pkt[14] = 0x45; // v4, ihl=5
    pkt[16..18].copy_from_slice(&40u16.to_be_bytes());
    pkt[23] = 6; // TCP
    pkt[26..30].copy_from_slice(&[10, 0, 0, 1]);
    pkt[30..34].copy_from_slice(&[10, 0, 0, 2]);
    pkt[46] = 0x50;
    pkt[47] = 0x02;
    to_hex(&pkt)
}

#[must_use]
pub fn valid_ipv4_xdp_insns() -> Vec<BpfInsn> {
    vec![
        BpfInsn::ldx_mem(BPF_W, 2, 1, 0),
        BpfInsn::ldx_mem(BPF_W, 3, 1, 4),
        BpfInsn::mov64_reg(4, 2),
        BpfInsn::alu64_imm(BPF_ADD, 4, 34),
        BpfInsn::jmp_reg(BPF_JGT, 4, 3, 7),
        BpfInsn::ldx_mem(BPF_H, 5, 2, 12),
        BpfInsn::jmp_imm(BPF_JNE, 5, 0x0008, 3),
        BpfInsn::ldx_mem(BPF_B, 6, 2, 14),
        BpfInsn::alu64_imm(BPF_AND, 6, 0x0F),
        BpfInsn::jmp_imm(BPF_JLT, 6, 5, 2),
        BpfInsn::mov64_imm(0, XDP_PASS as i32),
        BpfInsn::exit(),
        BpfInsn::mov64_imm(0, XDP_DROP as i32),
        BpfInsn::exit(),
    ]
}

#[must_use]
pub fn hostile_oob_pkt_insns() -> Vec<BpfInsn> {
    vec![
        BpfInsn::ldx_mem(BPF_W, 2, 1, 0),
        // Missing bounds check vs data_end before reading Eth+IP byte!
        BpfInsn::ldx_mem(BPF_B, 0, 2, 14),
        BpfInsn::exit(),
    ]
}

#[must_use]
pub fn hostile_back_edge_insns() -> Vec<BpfInsn> {
    vec![
        BpfInsn::mov64_imm(0, 0),
        BpfInsn::alu64_imm(BPF_ADD, 0, 1),
        BpfInsn::jmp_imm(BPF_JA, 0, 0, -2),
        BpfInsn::exit(),
    ]
}

#[must_use]
pub fn hostile_uninit_reg_insns() -> Vec<BpfInsn> {
    vec![BpfInsn::mov64_reg(0, 7), BpfInsn::exit()]
}

#[must_use]
pub fn build_preset_catalog() -> PresetCatalog {
    let pkt_hex = sample_tcp_syn_hex();
    let mut short_pkt = vec![0u8; 10];
    short_pkt[0..6].copy_from_slice(&[0x02, 0, 0, 0, 0, 2]);
    let _short_hex = to_hex(&short_pkt);

    // Pre-encoded HTTP/2 gRPC trace (preface + HEADERS + DATA(5B len + protobuf) + trailing grpc-status:0)
    let mut h2_egress = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    // Static HPACK: :method POST (0x83), :scheme https (0x87), literal :path /spectre.MeshService/Infer (0x44), literal content-type application/grpc
    let h2_req_hdrs: Vec<u8> = vec![
        0x83, 0x87, 0x44, 26, b'/', b's', b'p', b'e', b'c', b't', b'r', b'e', b'.', b'M', b'e',
        b's', b'h', b'S', b'e', b'r', b'v', b'i', b'c', b'e', b'/', b'I', b'n', b'f', b'e', b'r',
        0x00, 12, b'c', b'o', b'n', b't', b'e', b'n', b't', b'-', b't', b'y', b'p', b'e', 16, b'a',
        b'p', b'p', b'l', b'i', b'c', b'a', b't', b'i', b'o', b'n', b'/', b'g', b'r', b'p', b'c',
    ];
    let l = h2_req_hdrs.len();
    h2_egress.extend_from_slice(&[
        (l >> 16) as u8,
        (l >> 8) as u8,
        l as u8,
        0x01,
        0x04,
        0,
        0,
        0,
        1,
    ]);
    h2_egress.extend_from_slice(&h2_req_hdrs);
    // DATA frame stream 1, END_STREAM (0x01), 11 bytes = 5B gRPC prefix (len=6) + protobuf tag1 "go" + tag2=1
    let grpc_data = [0x00, 0, 0, 0, 6, 0x0a, 2, b'g', b'o', 0x10, 1];
    h2_egress.extend_from_slice(&[0, 0, grpc_data.len() as u8, 0x00, 0x01, 0, 0, 0, 1]);
    h2_egress.extend_from_slice(&grpc_data);

    let mut h2_ingress = Vec::new();
    // Response HEADERS :status 200 (0x88), END_HEADERS
    h2_ingress.extend_from_slice(&[0, 0, 1, 0x01, 0x04, 0, 0, 0, 1, 0x88]);
    // Response DATA + END_STREAM + grpc payload
    let grpc_rsp = [0x00, 0, 0, 0, 6, 0x0a, 2, b'o', b'k', 0x10, 7];
    h2_ingress.extend_from_slice(&[0, 0, grpc_rsp.len() as u8, 0x00, 0x01, 0, 0, 0, 1]);
    h2_ingress.extend_from_slice(&grpc_rsp);

    let pg_egress = b"\x00\x00\x00\x17\x00\x03\x00\x00user\0postgres\0\0Q\x00\x00\x00\x3bSELECT id, total FROM orders WHERE customer_id = 94218\0";
    let pg_ingress = b"R\x00\x00\x00\x08\x00\x00\x00\x00Z\x00\x00\x00\x05ID\x00\x00\x00\x0c\x00\x01\x00\x00\x00\x02okC\x00\x00\x00\x0dSELECT 1\0Z\x00\x00\x00\x05I";

    PresetCatalog {
        ebpf: vec![
            EbpfPreset {
                id: "xdp_valid_ipv4_tcp",
                label: "Valid XDP IPv4/TCP Bounds Checker",
                expected_verdict: "Accept",
                bytecode_hex: insns_to_hex(&valid_ipv4_xdp_insns()),
                sample_packet_hex: pkt_hex.clone(),
            },
            EbpfPreset {
                id: "hostile_pkt_oob_no_bounds",
                label: "Hostile: Unchecked Packet Read (OOB)",
                expected_verdict: "Reject",
                bytecode_hex: insns_to_hex(&hostile_oob_pkt_insns()),
                sample_packet_hex: pkt_hex.clone(),
            },
            EbpfPreset {
                id: "hostile_back_edge_loop",
                label: "Hostile: Non-DAG Infinite Loop",
                expected_verdict: "Reject",
                bytecode_hex: insns_to_hex(&hostile_back_edge_insns()),
                sample_packet_hex: pkt_hex.clone(),
            },
            EbpfPreset {
                id: "hostile_uninit_r7_read",
                label: "Hostile: Uninitialized Register R7",
                expected_verdict: "Reject",
                bytecode_hex: insns_to_hex(&hostile_uninit_reg_insns()),
                sample_packet_hex: pkt_hex,
            },
        ],
        l7: vec![
            L7Preset {
                id: "http2_grpc",
                label: "HTTP/2 + HPACK + gRPC Protobuf",
                protocol_hint: "http2",
                egress_hex: to_hex(&h2_egress),
                ingress_hex: to_hex(&h2_ingress),
            },
            L7Preset {
                id: "postgres_v3",
                label: "PostgreSQL v3 Wire Protocol + SQL Sanitizer",
                protocol_hint: "postgres",
                egress_hex: to_hex(pg_egress),
                ingress_hex: to_hex(pg_ingress),
            },
            L7Preset {
                id: "http1_tls",
                label: "HTTP/1.1 Keep-Alive (Captured via OpenSSL Uprobe)",
                protocol_hint: "http1",
                egress_hex: to_hex(
                    b"POST /api/v1/orders HTTP/1.1\r\nHost: checkout.mesh\r\ntraceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01\r\nContent-Length: 15\r\n\r\n{\"item\":\"mesh\"}",
                ),
                ingress_hex: to_hex(b"HTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\nok"),
            },
            L7Preset {
                id: "redis_resp3",
                label: "Redis RESP2/3 + Key Prefix Redaction",
                protocol_hint: "redis",
                egress_hex: to_hex(b"*3\r\n$3\r\nSET\r\n$11\r\nuser:981234\r\n$6\r\ntok123\r\n"),
                ingress_hex: to_hex(b"+OK\r\n"),
            },
        ],
        flamegraphs: vec![
            FlamePreset {
                id: "differential_cpu_mutex",
                label: "Differential On-CPU vs Off-CPU Mutex Regression",
                title: "SpectreMesh Differential Stall Profile (Red = Regression)",
                unit: "ns",
                folded: "checkout-api;handle_order;hot_sha256_spin 318000\n\
                         checkout-api;handle_order;contended_mutex_wait;syscall;[k] __x64_sys_futex;[k] futex_wait;[k] __schedule 1153500\n\
                         ml-scorer-go;crypto/tls.(*Conn).Write;net.(*conn).Write 210000\n",
                baseline_folded: Some(
                    "checkout-api;handle_order;hot_sha256_spin 305000\n\
                     checkout-api;handle_order;contended_mutex_wait;syscall;[k] __x64_sys_futex;[k] futex_wait;[k] __schedule 195000\n\
                     ml-scorer-go;crypto/tls.(*Conn).Write;net.(*conn).Write 208000\n",
                ),
            },
            FlamePreset {
                id: "oncpu_99hz_mesh",
                label: "On-CPU 99 Hz TLS + Protobuf Hotspot Profile",
                title: "On-CPU 99 Hz Profile",
                unit: "samples",
                folded: "checkout-api;hot_sha256_spin 315\n\
                         checkout-api;openssl_evp;aes_gcm_encrypt 48\n\
                         ml-scorer-go;crypto/tls.(*Conn).Write;aes_ctr_xor 26\n\
                         ml-scorer-go;grpc.Infer;protobuf_marshal 10\n",
                baseline_folded: None,
            },
        ],
    }
}
