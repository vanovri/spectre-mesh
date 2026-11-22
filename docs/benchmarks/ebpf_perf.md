# SpectreMesh Real Kernel & Userspace Benchmarks

- **Host:** `linux` (`x86_64`)
- **Commit:** `51370b42626d`
- **Timestamp:** `2026-11-22T11:14:15Z`

| Subsystem | Workload | Primary Throughput | Latency / Overhead | Integrity |
| --- | --- | --- | --- | --- |
| **XDP Kernel (`xdp_net.bpf.o`)** | `BPF_PROG_TEST_RUN` (500000 pkts) | **10.10 Mpps** | `99.00 ns/pkt` | Exact L2/VLAN/IPv4/TCP parse |
| **Rust `BpfVm` XDP** | Pure-Rust ISA v3 VM (100000 pkts) | **8.23 Mpps** | `121.57 ns/pkt` | `#![deny(unsafe_code)]` parity |
| **Lock-Free `BPF_MAP_TYPE_RINGBUF`** | `m01_ringbuf_test.bpf.o` (100000 evts) | **23.3 k evt/s** (0.5 MB/s) | `4296.05 ms` total | **0 drops** |
| **OpenSSL 3.5.5 TLS 1.3 Uprobe** | 2000 persistent req/resp (`TCP_NODELAY`) | Baseline `74.28 us/req` -> Attached `123.27 us/req` | **+48.99 us/req** delta | **0 drops**, 0 MITM certs |
| **`spectre-l7` Streaming Dissector** | HTTP/1.1 + HTTP/2 + PG v3 + Redis (20000 reqs) | **1094.9 k req/s** (69.7 MB/s) | `913.3 ns/req` | `#![deny(unsafe_code)]` zero-panic |
| **`spectre-verifier` Static Analysis** | 2000 static verifications + 6 ELF probes | **3.3 k verifs/s** | `302.48 us/prog` | 0 false accepts vs Linux 6.18 |
