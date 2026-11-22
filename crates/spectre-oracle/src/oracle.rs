use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use spectre_l7::{L7Protocol, L7Span};

use crate::OracleError;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroundTruthRecord {
    pub protocol: L7Protocol,
    pub method: String,
    pub expected_target: String,
    pub status_code: u16,
    pub latency_ns: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProtocolOracleSummary {
    pub protocol: L7Protocol,
    pub requested: usize,
    pub recovered: usize,
    pub matched: usize,
    pub mismatches: usize,
    pub truth_p50_ms: f64,
    pub truth_p95_ms: f64,
    pub truth_p99_ms: f64,
    pub obs_p50_ms: f64,
    pub obs_p95_ms: f64,
    pub obs_p99_ms: f64,
    pub p99_delta_ms: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OracleReport {
    pub total_requested: usize,
    pub total_recovered: usize,
    pub total_mismatches: usize,
    pub ringbuf_drops: u64,
    pub go_stack_crashes: u64,
    pub xdp_drops: u64,
    pub elapsed_secs: f64,
    pub fds_before: usize,
    pub fds_after: usize,
    pub legs: Vec<ProtocolOracleSummary>,
}

/// Compute `(p50, p95, p99)` percentiles in milliseconds from nanosecond latencies.
#[must_use]
pub fn compute_percentiles_ms(latencies_ns: &[u64]) -> (f64, f64, f64) {
    if latencies_ns.is_empty() {
        return (0.0, 0.0, 0.0);
    }
    let mut sorted = latencies_ns.to_vec();
    sorted.sort_unstable();
    let pick = |pct: usize| -> f64 {
        let idx = (sorted.len().saturating_sub(1) * pct) / 100;
        (sorted[idx] as f64) / 1_000_000.0
    };
    (pick(50), pick(95), pick(99))
}

fn span_normalized_target(proto: L7Protocol, span: &L7Span) -> String {
    match proto {
        L7Protocol::Postgres => span
            .sql_fingerprint
            .as_deref()
            .unwrap_or(span.path_or_query.as_str())
            .to_owned(),
        L7Protocol::Redis => span
            .redis_key_prefix
            .as_deref()
            .unwrap_or(span.path_or_query.as_str())
            .to_owned(),
        _ => span.path_or_query.clone(),
    }
}

/// Verify ground-truth records vs decoded `L7Span` outputs for one protocol leg.
pub fn evaluate_leg_parity(
    proto: L7Protocol,
    truth: &[GroundTruthRecord],
    spans: &[&L7Span],
    max_p99_delta_ms: f64,
) -> Result<ProtocolOracleSummary, OracleError> {
    let mut truth_multiset: HashMap<(String, String, u16), usize> = HashMap::new();
    let mut truth_lats = Vec::with_capacity(truth.len());
    for rec in truth {
        *truth_multiset
            .entry((
                rec.method.clone(),
                rec.expected_target.clone(),
                rec.status_code,
            ))
            .or_insert(0) += 1;
        truth_lats.push(rec.latency_ns);
    }

    let mut obs_lats = Vec::with_capacity(spans.len());
    let mut matched = 0usize;
    let mut mismatches = 0usize;

    for sp in spans {
        obs_lats.push(sp.latency_ns);
        let key = (
            sp.method.clone(),
            span_normalized_target(proto, sp),
            sp.status_code,
        );
        if let Some(rem) = truth_multiset.get_mut(&key) {
            if *rem > 0 {
                *rem -= 1;
                matched += 1;
                continue;
            }
        }
        mismatches += 1;
    }
    let leftover: usize = truth_multiset.values().sum();
    mismatches += leftover;

    let (truth_p50_ms, truth_p95_ms, truth_p99_ms) = compute_percentiles_ms(&truth_lats);
    let (obs_p50_ms, obs_p95_ms, obs_p99_ms) = compute_percentiles_ms(&obs_lats);
    let p99_delta_ms = (obs_p99_ms - truth_p99_ms).abs();

    let summary = ProtocolOracleSummary {
        protocol: proto,
        requested: truth.len(),
        recovered: spans.len(),
        matched,
        mismatches,
        truth_p50_ms,
        truth_p95_ms,
        truth_p99_ms,
        obs_p50_ms,
        obs_p95_ms,
        obs_p99_ms,
        p99_delta_ms,
    };

    if summary.recovered != summary.requested {
        return Err(OracleError::VerificationFailed(format!(
            "{proto:?}: recovered {} != requested {} (mismatches={mismatches})",
            summary.recovered, summary.requested
        )));
    }
    if summary.mismatches > 0 {
        return Err(OracleError::VerificationFailed(format!(
            "{proto:?}: {mismatches} field/status mismatches against ground truth"
        )));
    }
    if summary.p99_delta_ms >= max_p99_delta_ms {
        return Err(OracleError::VerificationFailed(format!(
            "{proto:?}: p99 latency delta {:.3} ms >= {:.3} ms (truth={truth_p99_ms:.3} ms, obs={obs_p99_ms:.3} ms)",
            summary.p99_delta_ms, max_p99_delta_ms
        )));
    }
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evaluate_leg_parity_verifies_multiset_and_percentiles() {
        let mut truth = Vec::new();
        let mut spans = Vec::new();
        for i in 0..200u64 {
            let lat = 150_000 + (i % 10) * 20_000;
            let status = if i.is_multiple_of(50) { 503 } else { 200 };
            truth.push(GroundTruthRecord {
                protocol: L7Protocol::Http1,
                method: "GET".to_owned(),
                expected_target: "/api/v1/items".to_owned(),
                status_code: status,
                latency_ns: lat,
            });
            spans.push(L7Span {
                span_id: i,
                conn_id: 1,
                pid: 100,
                fd: 4,
                protocol: L7Protocol::Http1,
                method: "GET".to_owned(),
                path_or_query: "/api/v1/items".to_owned(),
                host: None,
                user_agent: None,
                status_code: status,
                request_bytes: 64,
                response_bytes: 128,
                start_ns: 1_000_000,
                first_byte_ns: 1_000_000 + lat,
                end_ns: 1_000_000 + lat + 5_000,
                latency_ns: lat + 5_000,
                traceparent: None,
                grpc: None,
                sql_fingerprint: None,
                redis_key_prefix: None,
                error: status >= 500,
                error_detail: None,
                tls_source: 1,
            });
        }
        let refs: Vec<&L7Span> = spans.iter().collect();
        let summary = evaluate_leg_parity(L7Protocol::Http1, &truth, &refs, 2.0).unwrap();
        assert_eq!(summary.requested, 200);
        assert_eq!(summary.recovered, 200);
        assert_eq!(summary.mismatches, 0);
        assert!(summary.p99_delta_ms < 0.05);
    }
}
