#![deny(unsafe_code)]

use std::net::SocketAddr;
use std::sync::Arc;

use clap::Parser;
use spectre_daemon::{build_router, DaemonState, TopologyStore};

#[derive(Debug, Parser)]
#[command(
    name = "spectred",
    about = "SpectreMesh eBPF Observability & Topology Daemon"
)]
struct Cli {
    /// Listen address (`host:port`)
    #[arg(long, default_value = "127.0.0.1:9095")]
    listen: SocketAddr,

    /// Populate representative demo service-mesh telemetry
    #[arg(long, default_value_t = false)]
    demo: bool,

    /// Optional PID to attach live eBPF TLS + continuous profiler telemetry (Linux only)
    #[arg(long)]
    attach_pid: Option<u32>,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let mut store = TopologyStore::new();
    if cli.demo || cli.attach_pid.is_none() {
        store.populate_demo_telemetry();
    }
    let state = Arc::new(DaemonState::new(store));

    #[cfg(target_os = "linux")]
    if let Some(pid) = cli.attach_pid {
        let state_bg = Arc::clone(&state);
        tokio::task::spawn_blocking(move || {
            if let Err(err) = run_live_pid_loop(pid, &state_bg) {
                eprintln!("live PID observer error for pid={pid}: {err}");
            }
        });
    }

    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind(cli.listen)
        .await
        .expect("bind daemon listener");
    println!("spectred listening on http://{}", cli.listen);
    axum::serve(listener, app)
        .await
        .expect("axum serve terminated");
}

#[cfg(target_os = "linux")]
fn run_live_pid_loop(pid: u32, state: &DaemonState) -> Result<(), String> {
    use spectre_l7::{ConnConfig, Direction, L7Chunk, L7Reassembler};
    use spectre_profile::ContinuousProfiler;
    use spectre_tls::TlsInterceptor;
    use std::path::Path;
    use std::time::Duration;

    let probe_dir = Path::new("probes/build");
    let oss = std::fs::read(probe_dir.join("tls_openssl.bpf.o")).map_err(|e| e.to_string())?;
    let go = std::fs::read(probe_dir.join("tls_go.bpf.o")).map_err(|e| e.to_string())?;
    let prof_bytes = std::fs::read(probe_dir.join("profiler.bpf.o")).map_err(|e| e.to_string())?;

    let mut tls = TlsInterceptor::load(&oss, &go).map_err(|e| e.to_string())?;
    tls.attach_pid(pid).map_err(|e| e.to_string())?;

    let mut prof = ContinuousProfiler::load(&prof_bytes).map_err(|e| e.to_string())?;
    prof.set_pid_filter(Some(&[pid]))
        .map_err(|e| e.to_string())?;
    prof.refresh_pid_maps(pid);
    prof.start(99).map_err(|e| e.to_string())?;

    let mut reasm = L7Reassembler::new(ConnConfig::default());
    let mut tick = 0u64;
    loop {
        if !Path::new(&format!("/proc/{pid}")).exists() {
            break;
        }
        let events = tls.drain_tls_events();
        for ev in &events {
            reasm.ingest(&L7Chunk {
                conn_id: ev.conn_ptr,
                pid: ev.pid,
                fd: ev.fd,
                ts_ns: ev.ts_ns,
                direction: Direction::from_u8(ev.direction),
                tls_source: ev.tls_source,
                payload: &ev.payload,
            });
        }
        let spans = reasm.drain_spans();
        let drops = tls.read_ringbuf_drops().unwrap_or(0);
        {
            let mut store = state.store.write();
            store.set_ringbuf_drops(drops);
            for sp in spans {
                store.ingest_span("local-client", &format!("pid-{pid}"), sp);
            }
            if tick.is_multiple_of(50) {
                if let Ok(snap) = prof.snapshot() {
                    store.set_flamegraphs(snap.oncpu_folded, snap.offcpu_folded);
                }
            }
        }
        tick = tick.wrapping_add(1);
        std::thread::sleep(Duration::from_millis(20));
    }
    Ok(())
}
