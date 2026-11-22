#![deny(unsafe_code)]

pub mod presets;

use std::collections::HashMap;

use serde::Serialize;
use spectre_l7::{dissect_stream, Direction, DissectionReport, L7Chunk, L7Protocol};
use spectre_profile::{
    build_flamegraph, compute_differential_flamegraph, parse_folded, render_svg, FlameGraph,
};
use spectre_verifier::{
    decode_bytes, disassemble_program, verify_program, BpfMapSpec, BpfProgType, BpfVm, DisasmLine,
    VerificationReport, VerifierConfig, VmExecResult, VmMaps,
};
use wasm_bindgen::prelude::*;

use presets::{build_preset_catalog, PresetCatalog};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WasmVerifyResponse {
    pub accepted: bool,
    pub report: VerificationReport,
    pub disassembly: Vec<DisasmLine>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WasmXdpSimResponse {
    pub action_label: String,
    pub result: VmExecResult,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WasmFlameGraphResponse {
    pub flamegraph: FlameGraph,
    pub svg: String,
}

pub fn decode_hex_bytes(input: &str) -> Result<Vec<u8>, String> {
    let clean: String = input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ':' && *c != '_')
        .collect();
    let stripped = clean
        .strip_prefix("0x")
        .or_else(|| clean.strip_prefix("0X"))
        .unwrap_or(&clean);
    if !stripped.len().is_multiple_of(2) {
        return Err("hex string must have even number of nibbles".to_owned());
    }
    let mut out = Vec::with_capacity(stripped.len() / 2);
    for pair in stripped.as_bytes().as_chunks::<2>().0 {
        let s = std::str::from_utf8(pair).map_err(|e| e.to_string())?;
        let byte = u8::from_str_radix(s, 16).map_err(|e| format!("invalid hex byte `{s}`: {e}"))?;
        out.push(byte);
    }
    Ok(out)
}

fn resolve_program_bytes(hex_or_preset: &str) -> Result<Vec<u8>, String> {
    let trimmed = hex_or_preset.trim();
    if let Some(p) = build_preset_catalog()
        .ebpf
        .into_iter()
        .find(|p| p.id == trimmed)
    {
        return decode_hex_bytes(&p.bytecode_hex);
    }
    decode_hex_bytes(trimmed)
}

pub fn verify_ebpf_program_core(hex_or_preset: &str) -> Result<WasmVerifyResponse, String> {
    let bytes = resolve_program_bytes(hex_or_preset)?;
    let insns = decode_bytes(&bytes).map_err(|e| e.to_string())?;
    let cfg = VerifierConfig {
        prog_type: BpfProgType::Xdp,
        maps: HashMap::<u32, BpfMapSpec>::new(),
        max_trace_steps: 2048,
        ..VerifierConfig::default()
    };
    let report = verify_program(&insns, &cfg);
    let accepted = matches!(report.verdict, spectre_verifier::Verdict::Accept);
    let disassembly = disassemble_program(&insns);
    Ok(WasmVerifyResponse {
        accepted,
        report,
        disassembly,
    })
}

pub fn run_xdp_simulation_core(
    hex_or_preset: &str,
    packet_hex: &str,
) -> Result<WasmXdpSimResponse, String> {
    let bytes = resolve_program_bytes(hex_or_preset)?;
    let insns = decode_bytes(&bytes).map_err(|e| e.to_string())?;
    let mut packet = decode_hex_bytes(packet_hex)?;
    if packet.is_empty() {
        packet.resize(14, 0);
    }
    let mut maps = VmMaps::new();
    let result =
        BpfVm::run_xdp(&insns, &mut packet, &mut maps, 10_000).map_err(|e| e.to_string())?;
    let action_label = match result.return_code {
        0 => "XDP_ABORTED",
        1 => "XDP_DROP",
        2 => "XDP_PASS",
        3 => "XDP_TX",
        4 => "XDP_REDIRECT",
        other => {
            return Ok(WasmXdpSimResponse {
                action_label: format!("XDP_CODE({other})"),
                result,
            });
        }
    }
    .to_owned();
    Ok(WasmXdpSimResponse {
        action_label,
        result,
    })
}

fn parse_protocol_hint(s: &str) -> L7Protocol {
    match s.trim().to_ascii_lowercase().as_str() {
        "http1" | "http/1.1" => L7Protocol::Http1,
        "http2" | "http/2" | "h2" => L7Protocol::Http2,
        "grpc" => L7Protocol::Grpc,
        "postgres" | "pg" => L7Protocol::Postgres,
        "redis" | "resp" | "resp3" => L7Protocol::Redis,
        _ => L7Protocol::Unknown,
    }
}

pub fn dissect_l7_payload_core(
    protocol_hint: &str,
    egress_hex: &str,
    ingress_hex: &str,
) -> Result<DissectionReport, String> {
    let egress = decode_hex_bytes(egress_hex)?;
    let ingress = decode_hex_bytes(ingress_hex)?;
    let hint = parse_protocol_hint(protocol_hint);

    let mut chunks = Vec::new();
    if !egress.is_empty() {
        chunks.push(L7Chunk {
            conn_id: 1,
            pid: 100,
            fd: 4,
            ts_ns: 1_000_000,
            direction: Direction::Egress,
            tls_source: 1,
            payload: &egress,
        });
    }
    if !ingress.is_empty() {
        chunks.push(L7Chunk {
            conn_id: 1,
            pid: 100,
            fd: 4,
            ts_ns: 1_450_000,
            direction: Direction::Ingress,
            tls_source: 1,
            payload: &ingress,
        });
    }
    Ok(dissect_stream(hint, &chunks))
}

pub fn build_flamegraph_core(
    title: &str,
    unit: &str,
    folded: &str,
    baseline_folded: Option<&str>,
) -> WasmFlameGraphResponse {
    let flamegraph = match baseline_folded.filter(|b| !b.trim().is_empty()) {
        Some(base) => compute_differential_flamegraph(title, unit, base, folded),
        None => {
            let parsed = parse_folded(folded);
            build_flamegraph(title, unit, &parsed)
        }
    };
    let svg = render_svg(&flamegraph);
    WasmFlameGraphResponse { flamegraph, svg }
}

#[must_use]
pub fn preset_catalog_core() -> PresetCatalog {
    build_preset_catalog()
}

fn to_js<T: Serialize>(v: &T) -> Result<JsValue, JsValue> {
    let serializer = serde_wasm_bindgen::Serializer::json_compatible();
    v.serialize(&serializer)
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn verify_ebpf_program(hex_or_preset: &str) -> Result<JsValue, JsValue> {
    let res = verify_ebpf_program_core(hex_or_preset).map_err(|e| JsValue::from_str(&e))?;
    to_js(&res)
}

#[wasm_bindgen]
pub fn run_xdp_simulation(hex_or_preset: &str, packet_hex: &str) -> Result<JsValue, JsValue> {
    let res =
        run_xdp_simulation_core(hex_or_preset, packet_hex).map_err(|e| JsValue::from_str(&e))?;
    to_js(&res)
}

#[wasm_bindgen]
pub fn dissect_l7_payload(
    protocol_hint: &str,
    egress_hex: &str,
    ingress_hex: &str,
) -> Result<JsValue, JsValue> {
    let res = dissect_l7_payload_core(protocol_hint, egress_hex, ingress_hex)
        .map_err(|e| JsValue::from_str(&e))?;
    to_js(&res)
}

#[wasm_bindgen]
pub fn build_flamegraph_from_folded(
    title: &str,
    unit: &str,
    folded: &str,
    baseline_folded: Option<String>,
) -> Result<JsValue, JsValue> {
    let res = build_flamegraph_core(title, unit, folded, baseline_folded.as_deref());
    to_js(&res)
}

#[wasm_bindgen]
pub fn preset_catalog() -> Result<JsValue, JsValue> {
    to_js(&preset_catalog_core())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wasm_core_verifier_vm_l7_and_flamegraph_presets_all_pass() {
        let cat = preset_catalog_core();
        assert_eq!(cat.ebpf.len(), 4);
        assert_eq!(cat.l7.len(), 4);
        assert_eq!(cat.flamegraphs.len(), 2);

        for p in &cat.ebpf {
            let rep = verify_ebpf_program_core(&p.bytecode_hex).unwrap();
            assert_eq!(
                rep.accepted,
                p.expected_verdict == "Accept",
                "preset {} mismatch",
                p.id
            );
            if rep.accepted {
                let sim = run_xdp_simulation_core(&p.bytecode_hex, &p.sample_packet_hex).unwrap();
                assert_eq!(sim.action_label, "XDP_PASS");
                // Truncated 10B packet triggers XDP_DROP cleanly
                let sim_short = run_xdp_simulation_core(p.id, "00112233445566778899").unwrap();
                assert_eq!(sim_short.action_label, "XDP_DROP");
            }
        }

        for l7 in &cat.l7 {
            let d =
                dissect_l7_payload_core(l7.protocol_hint, &l7.egress_hex, &l7.ingress_hex).unwrap();
            assert_eq!(
                d.spans.len(),
                1,
                "preset {} expected 1 decoded span, warnings={:?}",
                l7.id,
                d.warnings
            );
        }

        let fg_diff = &cat.flamegraphs[0];
        let fg_res = build_flamegraph_core(
            fg_diff.title,
            fg_diff.unit,
            fg_diff.folded,
            fg_diff.baseline_folded,
        );
        assert!(fg_res.flamegraph.differential);
        assert!(fg_res.svg.starts_with("<svg ") && fg_res.svg.contains("contended_mutex_wait"));
    }
}
