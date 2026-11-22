#![deny(unsafe_code)]

use std::path::PathBuf;

fn main() {
    let mut requests = 50_000usize;
    let mut json_out: Option<PathBuf> = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--requests" => {
                let val = args.next().expect("--requests requires numeric value");
                requests = val.parse().expect("invalid --requests number");
            }
            "--json-out" => {
                let val = args.next().expect("--json-out requires path");
                json_out = Some(PathBuf::from(val));
            }
            other => {
                eprintln!("Unknown flag: {other}");
                std::process::exit(2);
            }
        }
    }

    run_entry(requests, json_out);
}

#[cfg(target_os = "linux")]
fn run_entry(requests: usize, json_out: Option<PathBuf>) {
    use spectre_oracle::{run_live_mesh_oracle, MeshOracleConfig};

    let cfg = MeshOracleConfig {
        total_requests: requests,
        ..MeshOracleConfig::default()
    };
    match run_live_mesh_oracle(&cfg) {
        Ok(report) => {
            println!("=== SpectreMesh Live Encrypted Mesh Oracle ===");
            println!(
                "Requests: {}/{} recovered | Mismatches: {} | RingBuf Drops: {} | Go Crashes: {} | XDP SYN Drops: {} | FDs: {}->{} | Elapsed: {:.2}s",
                report.total_recovered,
                report.total_requested,
                report.total_mismatches,
                report.ringbuf_drops,
                report.go_stack_crashes,
                report.xdp_drops,
                report.fds_before,
                report.fds_after,
                report.elapsed_secs
            );
            for leg in &report.legs {
                println!(
                    "  [{:?}] {}/{} matched | truth p50={:.3}ms p95={:.3}ms p99={:.3}ms | obs p50={:.3}ms p95={:.3}ms p99={:.3}ms | delta_p99={:.3}ms",
                    leg.protocol,
                    leg.matched,
                    leg.requested,
                    leg.truth_p50_ms,
                    leg.truth_p95_ms,
                    leg.truth_p99_ms,
                    leg.obs_p50_ms,
                    leg.obs_p95_ms,
                    leg.obs_p99_ms,
                    leg.p99_delta_ms
                );
            }
            if let Some(path) = json_out {
                let raw = serde_json::to_string_pretty(&report).unwrap();
                std::fs::write(path, raw).unwrap();
            }
        }
        Err(e) => {
            eprintln!("ORACLE FAILED: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn run_entry(_requests: usize, _json_out: Option<PathBuf>) {
    eprintln!("spectre-oracle live kernel harness requires Linux eBPF (use Docker / WSL2)");
}
