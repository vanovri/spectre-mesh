#![cfg(target_os = "linux")]

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use spectre_profile::{
    compute_differential_flamegraph, parse_folded, render_svg, ContinuousProfiler,
};

static LIVE_PROF_LOCK: Mutex<()> = Mutex::new(());

fn count_open_fds() -> usize {
    std::fs::read_dir("/proc/self/fd")
        .map(|it| it.count())
        .unwrap_or(0)
}

fn build_target_binary(dir: &std::path::Path) -> PathBuf {
    let src_path = dir.join("m06_target.rs");
    let bin_path = dir.join("m06_target");

    let src = r#"
use std::hint::black_box;
use std::io::{BufRead, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[inline(never)]
#[no_mangle]
pub extern "C" fn hot_sha256_spin(stop: &AtomicBool) -> u64 {
    let mut state: [u64; 4] = [
        0x6a09_e667_f3bc_c908,
        0xbb67_ae85_84ca_a73b,
        0x3c6e_f372_fe94_f82b,
        0xa54f_f53a_5f1d_36f1,
    ];
    let mut rounds: u64 = 0;
    while !stop.load(Ordering::Relaxed) {
        for i in 0..4096u64 {
            let x = state[0].rotate_right(13) ^ state[1].rotate_right(27) ^ i;
            let y = state[2].wrapping_add(x).wrapping_mul(0x9e37_79b9_7f4a_7c15);
            state[0] = state[1] ^ y;
            state[1] = state[2].rotate_left(7);
            state[2] = state[3].wrapping_add(state[0]);
            state[3] = y ^ rounds;
        }
        rounds = rounds.wrapping_add(1);
    }
    black_box(state[0] ^ state[3] ^ rounds)
}

#[inline(never)]
#[no_mangle]
pub extern "C" fn contended_mutex_wait(mtx: &Mutex<u64>) -> u64 {
    let mut guard = mtx.lock().unwrap();
    *guard = guard.wrapping_add(1);
    let val = *guard;
    drop(guard);
    black_box(val)
}

#[inline(never)]
#[no_mangle]
pub extern "C" fn holder_sleep_loop(mtx: &Mutex<u64>, stop: &AtomicBool) {
    while !stop.load(Ordering::Relaxed) {
        {
            let mut guard = mtx.lock().unwrap();
            *guard = guard.wrapping_add(1);
            std::thread::sleep(Duration::from_millis(20));
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

fn main() {
    let started = Arc::new(AtomicBool::new(false));
    let stop = Arc::new(AtomicBool::new(false));
    let mtx = Arc::new(Mutex::new(0u64));

    println!("READY");
    let _ = std::io::stdout().flush();

    let mut line = String::new();
    let stdin = std::io::stdin();
    let _ = stdin.lock().read_line(&mut line);

    started.store(true, Ordering::SeqCst);

    let stop_cpu = stop.clone();
    let t_cpu = std::thread::spawn(move || hot_sha256_spin(&stop_cpu));

    let mtx_h = mtx.clone();
    let stop_h = stop.clone();
    let t_hold = std::thread::spawn(move || holder_sleep_loop(&mtx_h, &stop_h));

    let mut waiters = Vec::new();
    for _ in 0..4 {
        let mtx_w = mtx.clone();
        let stop_w = stop.clone();
        waiters.push(std::thread::spawn(move || {
            let mut acc = 0u64;
            while !stop_w.load(Ordering::Relaxed) {
                acc ^= contended_mutex_wait(&mtx_w);
            }
            black_box(acc)
        }));
    }

    // Wait for STOP command on stdin (bounded by 10s failsafe)
    let stop_stdin = stop.clone();
    std::thread::spawn(move || {
        let mut cmd = String::new();
        let _ = std::io::stdin().lock().read_line(&mut cmd);
        stop_stdin.store(true, Ordering::SeqCst);
    });

    let deadline = Instant::now() + Duration::from_secs(10);
    while !stop.load(Ordering::SeqCst) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(25));
    }
    stop.store(true, Ordering::SeqCst);

    let _ = t_cpu.join();
    let _ = t_hold.join();
    for w in waiters {
        let _ = w.join();
    }
}
"#;
    std::fs::write(&src_path, src).expect("write m06 target source");

    let status = Command::new("rustc")
        .args([
            "-O",
            "-C",
            "force-frame-pointers=yes",
            src_path.to_str().unwrap(),
            "-o",
            bin_path.to_str().unwrap(),
        ])
        .status()
        .expect("invoke rustc for m06 target binary");
    assert!(status.success(), "rustc failed compiling m06 target");
    bin_path
}

fn sum_matching_samples(folded: &str, needle: &str) -> (u64, u64) {
    let stacks = parse_folded(folded);
    let mut total = 0u64;
    let mut matched = 0u64;
    for s in stacks {
        total = total.saturating_add(s.value);
        if s.stack.iter().any(|frame| frame.contains(needle)) {
            matched = matched.saturating_add(s.value);
        }
    }
    (matched, total)
}

#[test]
fn bottleneck_attribution_cpu_vs_mutex_offcpu() {
    let _guard = LIVE_PROF_LOCK.lock().unwrap();
    let fds_before = count_open_fds();

    let tmp_dir = std::env::temp_dir().join(format!("spectre_m06_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp_dir);
    std::fs::create_dir_all(&tmp_dir).unwrap();
    let target_bin = build_target_binary(&tmp_dir);

    let probe_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../probes/build/profiler.bpf.o");
    let probe_bytes = std::fs::read(&probe_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", probe_path.display()));

    let mut profiler =
        ContinuousProfiler::load(&probe_bytes).expect("ContinuousProfiler::load failed");

    let mut child = Command::new(&target_bin)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn m06 target");

    let child_pid = child.id();
    let mut child_stdin = child.stdin.take().unwrap();
    let child_stdout = child.stdout.take().unwrap();
    let mut reader = BufReader::new(child_stdout);
    let mut ready_line = String::new();
    reader.read_line(&mut ready_line).unwrap();
    drop(reader);
    assert!(
        ready_line.trim() == "READY",
        "unexpected target handshake line: {ready_line:?}"
    );

    profiler
        .set_pid_filter(Some(&[child_pid]))
        .expect("set_pid_filter failed");
    profiler.refresh_pid_maps(child_pid);
    profiler.start(99).expect("profiler.start(99) failed");

    writeln!(child_stdin, "GO").unwrap();
    child_stdin.flush().unwrap();

    // Let CPU spinner + contended mutex waiters run for ~3.2s
    let run_start = Instant::now();
    std::thread::sleep(Duration::from_millis(1600));
    profiler.refresh_pid_maps(child_pid);
    std::thread::sleep(Duration::from_millis(1600));
    let elapsed = run_start.elapsed();

    // Snapshot while process & /proc/<pid>/maps are still live
    let snap = profiler.snapshot().expect("profiler.snapshot() failed");

    // Signal clean shutdown & wait for target
    let _ = writeln!(child_stdin, "STOP");
    let _ = child_stdin.flush();
    drop(child_stdin);
    let exit_status = child.wait().unwrap();
    assert!(exit_status.success(), "m06 target exited abnormally");

    drop(profiler);
    let _ = std::fs::remove_dir_all(&tmp_dir);

    println!("=== M06 Elapsed: {elapsed:?} ===");
    println!(
        "On-CPU samples: {}, Off-CPU total ns: {}",
        snap.oncpu_samples, snap.offcpu_total_ns
    );
    println!("--- On-CPU Folded Top Stacks ---");
    for line in snap.oncpu_folded.lines().take(20) {
        println!("  {line}");
    }
    println!("--- Off-CPU Folded Top Stacks ---");
    for line in snap.offcpu_folded.lines().take(20) {
        println!("  {line}");
    }

    assert!(
        snap.oncpu_samples > 20,
        "expected > 20 On-CPU samples at 99Hz over ~3.2s, got {}",
        snap.oncpu_samples
    );
    let (hot_samples, hot_total) = sum_matching_samples(&snap.oncpu_folded, "hot_sha256_spin");
    println!(
        "On-CPU hot_sha256_spin: {hot_samples}/{hot_total} ({:.1}%)",
        if hot_total > 0 {
            (hot_samples as f64) * 100.0 / (hot_total as f64)
        } else {
            0.0
        }
    );
    assert!(
        hot_samples * 2 > hot_total && hot_samples > 0,
        "expected hot_sha256_spin > 50% of On-CPU samples ({hot_samples}/{hot_total})"
    );

    assert!(
        snap.offcpu_total_ns > 500_000_000,
        "expected > 500ms Off-CPU wait ns, got {}",
        snap.offcpu_total_ns
    );
    let (mutex_ns, off_total) = sum_matching_samples(&snap.offcpu_folded, "contended_mutex_wait");
    println!(
        "Off-CPU contended_mutex_wait: {mutex_ns}/{off_total} ns ({:.1}%)",
        if off_total > 0 {
            (mutex_ns as f64) * 100.0 / (off_total as f64)
        } else {
            0.0
        }
    );
    assert!(
        mutex_ns * 2 > off_total && mutex_ns > 0,
        "expected contended_mutex_wait > 50% of Off-CPU ns ({mutex_ns}/{off_total})"
    );
    assert!(
        snap.offcpu_folded.contains("[k] "),
        "expected kernel futex/schedule frames (`[k] `) in Off-CPU stacks"
    );

    // Check .folded roundtrip, SVG rendering, and differential flamegraph
    let reparsed_on = parse_folded(&snap.oncpu_folded);
    assert!(!reparsed_on.is_empty());
    let svg_on = render_svg(&snap.oncpu_flamegraph);
    assert!(svg_on.starts_with("<svg ") && svg_on.trim_end().ends_with("</svg>"));
    let svg_off = render_svg(&snap.offcpu_flamegraph);
    assert!(svg_off.starts_with("<svg ") && svg_off.trim_end().ends_with("</svg>"));

    let diff = compute_differential_flamegraph(
        "Diff Test",
        "samples",
        &snap.oncpu_folded,
        "m06_target;hot_sha256_spin 500\n",
    );
    let diff_svg = render_svg(&diff);
    assert!(diff_svg.contains("<svg ") && diff_svg.contains("hot_sha256_spin"));

    let fds_after = count_open_fds();
    assert_eq!(
        fds_before, fds_after,
        "FD leak detected: before={fds_before}, after={fds_after}"
    );
}
