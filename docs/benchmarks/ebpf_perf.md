# SpectreMesh Real Kernel & Userspace Benchmarks

- **Host:** `linux` (`x86_64`)
- **Commit:** `5149d8960fdf`
- **Timestamp:** `2026-11-22T10:53:37Z`

| Subsystem | Workload | Primary Throughput | Latency / Overhead | Integrity |
| --- | --- | --- | --- | --- |
| **XDP Kernel (`xdp_net.bpf.o`)** | `BPF_PROG_TEST_RUN` (500000 pkts) | **17.24 Mpps** | `58.00 ns/pkt` | Exact L2/VLAN/IPv4/TCP parse |
| **Rust `BpfVm` XDP** | Pure-Rust ISA v3 VM (100000 pkts) | **4.55 Mpps** | `219.65 ns/pkt` | `#![deny(unsafe_code)]` parity |
| **Lock-Free `BPF_MAP_TYPE_RINGBUF`** | `m01_ringbuf_test.bpf.o` (100000 evts) | **24.2 k evt/s** (0.6 MB/s) | `4138.07 ms` total | **0 drops** |
| **OpenSSL 3.5.5 TLS 1.3 Uprobe** | 2000 persistent req/resp (`TCP_NODELAY`) | Baseline `249.67 us/req` -> Attached `328.07 us/req` | **+78.40 us/req** delta | **0 drops**, 0 MITM certs |
| **`spectre-l7` Streaming Dissector** | HTTP/1.1 + HTTP/2 + PG v3 + Redis (20000 reqs) | **454.9 k req/s** (29.0 MB/s) | `2198.1 ns/req` | `#![deny(unsafe_code)]` zero-panic |
| **`spectre-verifier` Static Analysis** | 2000 static verifications + 6 ELF probes | **1.0 k verifs/s** | `1017.82 us/prog` | 0 false accepts vs Linux 6.18 |
