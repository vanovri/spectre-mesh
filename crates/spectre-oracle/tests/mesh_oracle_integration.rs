#![cfg(target_os = "linux")]

use spectre_oracle::{run_live_mesh_oracle, MeshOracleConfig};

#[test]
fn live_mesh_oracle_smoke_800_requests_zero_loss() {
    let cfg = MeshOracleConfig {
        total_requests: 800,
        ..MeshOracleConfig::default()
    };
    let report = run_live_mesh_oracle(&cfg).expect("800-req live mesh oracle must pass");
    assert_eq!(report.total_requested, 800);
    assert_eq!(report.total_recovered, 800);
    assert_eq!(report.total_mismatches, 0);
    assert_eq!(report.ringbuf_drops, 0);
    assert_eq!(report.go_stack_crashes, 0);
    assert!(report.xdp_drops > 0);
    assert_eq!(report.fds_before, report.fds_after);
}
