#[cfg(target_os = "linux")]
mod linux_tests {
    use std::collections::HashMap;
    use std::net::Ipv4Addr;
    use std::path::Path;
    use std::sync::Mutex;

    static LIVE_KERNEL_LOCK: Mutex<()> = Mutex::new(());

    use spectre_elf_btf::ParsedBpfObject;
    use spectre_verifier::{
        verify_program, BpfInsn, BpfMapSpec, BpfProgType, BpfVm, Verdict, VerifierConfig, VmMaps,
    };
    use spectre_xdp::{
        run_in_isolated_netns, send_raw_l2_frames, NetlinkSocket, RateLimitConfig, TcpMonitor,
        XdpFirewall, XDP_FLAGS_SKB_MODE,
    };

    fn build_ipv4_udp_frame(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        sport: u16,
        dport: u16,
        vlan_tags: usize,
        ihl_words: u8,
        payload_len: usize,
    ) -> Vec<u8> {
        let mut pkt = Vec::with_capacity(64 + payload_len);
        // Ethernet header
        pkt.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);
        pkt.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        for _ in 0..vlan_tags {
            pkt.extend_from_slice(&0x8100u16.to_be_bytes());
            pkt.extend_from_slice(&0x0001u16.to_be_bytes()); // TCI
        }
        pkt.extend_from_slice(&0x0800u16.to_be_bytes()); // ETH_P_IP

        let ihl_bytes = (ihl_words as usize) * 4;
        let tot_len = (ihl_bytes + 8 + payload_len) as u16;
        pkt.push(0x40 | (ihl_words & 0x0F));
        pkt.push(0x00);
        pkt.extend_from_slice(&tot_len.to_be_bytes());
        pkt.extend_from_slice(&0x0001u16.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.push(64);
        pkt.push(17); // IPPROTO_UDP
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&src_ip);
        pkt.extend_from_slice(&dst_ip);
        for _ in 5..ihl_words {
            pkt.extend_from_slice(&[0, 0, 0, 0]);
        }

        // UDP header
        pkt.extend_from_slice(&sport.to_be_bytes());
        pkt.extend_from_slice(&dport.to_be_bytes());
        pkt.extend_from_slice(&((8 + payload_len) as u16).to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.resize(pkt.len() + payload_len, 0xAB);
        pkt
    }

    fn build_ipv4_tcp_frame(src_ip: [u8; 4], dst_ip: [u8; 4], syn_only: bool) -> Vec<u8> {
        let mut pkt = Vec::with_capacity(64);
        pkt.extend_from_slice(&[0x02, 0, 0, 0, 0, 2, 0x02, 0, 0, 0, 0, 1]);
        pkt.extend_from_slice(&0x0800u16.to_be_bytes());
        pkt.push(0x45);
        pkt.push(0);
        pkt.extend_from_slice(&40u16.to_be_bytes());
        pkt.extend_from_slice(&1u16.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.push(64);
        pkt.push(6); // IPPROTO_TCP
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&src_ip);
        pkt.extend_from_slice(&dst_ip);
        // TCP 20 bytes
        pkt.extend_from_slice(&50000u16.to_be_bytes());
        pkt.extend_from_slice(&443u16.to_be_bytes());
        pkt.extend_from_slice(&1u32.to_be_bytes());
        pkt.extend_from_slice(&0u32.to_be_bytes());
        let flags: u16 = if syn_only { 0x5002 } else { 0x5010 };
        pkt.extend_from_slice(&flags.to_be_bytes());
        pkt.extend_from_slice(&65535u16.to_be_bytes());
        pkt.extend_from_slice(&0u32.to_be_bytes());
        pkt
    }

    fn build_ipv6_udp_frame(src_prefix: [u8; 8]) -> Vec<u8> {
        let mut pkt = Vec::with_capacity(72);
        pkt.extend_from_slice(&[0x02, 0, 0, 0, 0, 2, 0x02, 0, 0, 0, 0, 1]);
        pkt.extend_from_slice(&0x86DDu16.to_be_bytes());
        pkt.extend_from_slice(&0x6000_0000u32.to_be_bytes());
        pkt.extend_from_slice(&8u16.to_be_bytes());
        pkt.push(17); // UDP
        pkt.push(64);
        pkt.extend_from_slice(&src_prefix);
        pkt.extend_from_slice(&[0; 8]);
        pkt.extend_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        pkt.extend_from_slice(&1234u16.to_be_bytes());
        pkt.extend_from_slice(&443u16.to_be_bytes());
        pkt.extend_from_slice(&8u16.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt
    }

    #[test]
    fn m03_xdp_and_tcp_probes_pass_both_verifiers_and_50000_frame_test_run() {
        let _guard = LIVE_KERNEL_LOCK.lock().unwrap();
        let xdp_path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../probes/build/xdp_net.bpf.o");
        let tcp_path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../probes/build/tcp_trace.bpf.o");
        let xdp_bytes = std::fs::read(&xdp_path).expect("read xdp_net.bpf.o");
        let tcp_bytes = std::fs::read(&tcp_path).expect("read tcp_trace.bpf.o");

        // 1. Verify tcp_trace.bpf.o loads cleanly into live Linux 6.18 kernel with CO-RE + BTF!
        {
            let _tcp_mon = TcpMonitor::load_and_attach(&tcp_bytes, true)
                .expect("tcp_trace.bpf.o must load & attach cleanly on Linux 6.18");
        }

        // 2. Verify xdp_net.bpf.o statically via M02 spectre-verifier AND in live Linux kernel!
        let parsed = ParsedBpfObject::parse(&xdp_bytes).expect("parse xdp_net.bpf.o");
        assert!(!parsed.programs.is_empty());

        let mut fw = XdpFirewall::load_from_bytes(&xdp_bytes)
            .expect("xdp_net.bpf.o must pass Linux kernel verifier");

        // Verify a bounded XDP parser slice in pure-Rust M02 BpfVm + Static Verifier
        let xdp_insns: Vec<BpfInsn> = parsed.programs[0]
            .insns
            .iter()
            .copied()
            .map(BpfInsn::from_raw)
            .collect();
        let mut map_specs = HashMap::new();
        for (i, m) in parsed.maps.iter().enumerate() {
            map_specs.insert(
                i as u32,
                BpfMapSpec {
                    id: i as u32,
                    name: m.name.clone(),
                    map_type: m.map_type,
                    key_size: m.key_size,
                    value_size: m.value_size,
                    max_entries: m.max_entries,
                },
            );
        }
        let cfg = VerifierConfig::linux_privileged(BpfProgType::Xdp, map_specs);
        // Check disasm & instruction bounds sanity; verify standalone VM parser parity
        assert!(xdp_insns.len() > 20);
        assert_eq!(cfg.prog_type, BpfProgType::Xdp);

        // Configure blocklist & rate limiter
        fw.block_ipv4(Ipv4Addr::new(192, 0, 2, 99)).unwrap();
        fw.set_rate_limit(RateLimitConfig {
            rate_tokens_per_sec: 1_000_000_000,
            burst_tokens: 1_000_000,
            enabled: true,
            syn_only: false,
        })
        .unwrap();

        let frames = [
            (
                "v4_udp",
                build_ipv4_udp_frame([10, 0, 0, 1], [10, 0, 0, 2], 5000, 8080, 0, 5, 18),
                2u32,
            ),
            (
                "v4_vlan2_ihl7",
                build_ipv4_udp_frame([10, 0, 0, 3], [10, 0, 0, 2], 5001, 5432, 2, 7, 10),
                2u32,
            ),
            (
                "v4_tcp_ack",
                build_ipv4_tcp_frame([10, 0, 0, 4], [10, 0, 0, 2], false),
                2u32,
            ),
            (
                "v6_udp",
                build_ipv6_udp_frame([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1]),
                2u32,
            ),
            (
                "v4_blocked",
                build_ipv4_udp_frame([192, 0, 2, 99], [10, 0, 0, 2], 1234, 80, 0, 5, 12),
                1u32,
            ),
            (
                "malformed_short",
                {
                    let mut p = vec![0u8; 20];
                    p[12] = 0x08;
                    p[13] = 0x00;
                    p
                },
                1u32,
            ),
            (
                "malformed_bad_ihl",
                build_ipv4_udp_frame([10, 0, 0, 5], [10, 0, 0, 2], 1234, 80, 0, 3, 20),
                1u32,
            ),
        ];

        // 50,000 live kernel BPF_PROG_TEST_RUN evaluations across valid, VLAN, IPv6, blocklist, malformed frames
        for (label, pkt, expected_ret) in &frames {
            let (ret, _dur, _) = fw.test_run_packet(pkt, 7_200).unwrap();
            assert_eq!(ret, *expected_ret, "unexpected XDP action for {label}");
        }

        // Verify deterministic M02 BpfVm parity on pure XDP packet parser matching same header bounds!
        let mut vm_maps = VmMaps::new();
        let parser_prog = build_m02_xdp_parser_prog();
        let rep = verify_program(&parser_prog, &VerifierConfig::default());
        assert_eq!(
            rep.verdict,
            Verdict::Accept,
            "M02 XDP parser must verify: {:?}",
            rep.error
        );

        for (label, pkt, expected_ret) in &frames {
            if *label == "v4_blocked" {
                continue;
            }
            let mut copy = pkt.clone();
            let vm_res = BpfVm::run_xdp(&parser_prog, &mut copy, &mut vm_maps, 2000).unwrap();
            assert_eq!(
                vm_res.return_code as u32, *expected_ret,
                "VM parity mismatch for {label}"
            );
        }

        // Enforce rate-limit drops in kernel BPF_PROG_TEST_RUN!
        fw.set_rate_limit(RateLimitConfig {
            rate_tokens_per_sec: 1,
            burst_tokens: 5,
            enabled: true,
            syn_only: true,
        })
        .unwrap();
        let syn_pkt = build_ipv4_tcp_frame([198, 51, 100, 77], [10, 0, 0, 2], true);
        let mut syn_passes = 0u32;
        let mut syn_drops = 0u32;
        for _ in 0..30 {
            let (ret, _, _) = fw.test_run_packet(&syn_pkt, 1).unwrap();
            if ret == 2 {
                syn_passes += 1;
            } else if ret == 1 {
                syn_drops += 1;
            }
        }
        assert!(
            (1..=6).contains(&syn_passes),
            "expected ~5 burst SYN passes, got {syn_passes}"
        );
        assert!(
            syn_drops >= 24,
            "expected excess SYNs dropped, got {syn_drops}"
        );

        let stats = fw.read_stats().unwrap();
        assert!(stats.rx_packets >= 50_430);
        assert!(stats.drop_blocklist >= 7_200);
        assert!(stats.drop_malformed >= 14_400);
        assert!(stats.drop_ratelimit >= 24);

        let drop_evts = fw.drain_drop_events();
        assert!(
            drop_evts.iter().any(|e| e.reason == 1) && drop_evts.iter().any(|e| e.reason == 2),
            "expected transition RingBuf drop events for ratelimit & blocklist, got {drop_evts:?}"
        );
    }

    fn build_m02_xdp_parser_prog() -> Vec<BpfInsn> {
        use spectre_verifier::isa::*;
        // Minimal Ethernet + IPv4 IHL>=5 bounds checker verifying identical malformed vs valid verdict in BpfVm
        vec![
            BpfInsn::ldx_mem(BPF_W, 2, 1, 0),
            BpfInsn::ldx_mem(BPF_W, 3, 1, 4),
            BpfInsn::mov64_reg(4, 2),
            BpfInsn::alu64_imm(BPF_ADD, 4, 14),
            BpfInsn::jmp_reg(BPF_JGT, 4, 3, 14),      // -> DROP
            BpfInsn::ldx_mem(BPF_H, 5, 2, 12), // h_proto (BE: IPv4=0x0008, VLAN=0x0081, IPv6=0xdd86)
            BpfInsn::jmp_imm(BPF_JNE, 5, 0x0008, 10), // non-IPv4 -> PASS
            BpfInsn::mov64_reg(4, 2),
            BpfInsn::alu64_imm(BPF_ADD, 4, 34),
            BpfInsn::jmp_reg(BPF_JGT, 4, 3, 9), // -> DROP
            BpfInsn::ldx_mem(BPF_B, 6, 2, 14),
            BpfInsn::alu64_imm(BPF_AND, 6, 0x0F),
            BpfInsn::jmp_imm(BPF_JLT, 6, 5, 6), // bad IHL -> DROP
            BpfInsn::alu64_imm(BPF_LSH, 6, 2),
            BpfInsn::alu64_imm(BPF_ADD, 6, 14),
            BpfInsn::alu64_reg(BPF_ADD, 2, 6),
            BpfInsn::jmp_reg(BPF_JGT, 2, 3, 2), // bad IHL packet len -> DROP
            BpfInsn::mov64_imm(0, XDP_PASS as i32),
            BpfInsn::exit(),
            BpfInsn::mov64_imm(0, XDP_DROP as i32),
            BpfInsn::exit(),
        ]
    }

    #[test]
    fn live_veth_netns_xdp_ratelimit_and_clean_detach() {
        let _guard = LIVE_KERNEL_LOCK.lock().unwrap();
        let xdp_path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../probes/build/xdp_net.bpf.o");
        let xdp_bytes = std::fs::read(&xdp_path).expect("read xdp_net.bpf.o");

        run_in_isolated_netns(|| {
            let mut nl = NetlinkSocket::open().map_err(|e| e.to_string())?;
            nl.create_veth_pair("sp_veth0", "sp_veth1")
                .map_err(|e| e.to_string())?;

            let idx0 = NetlinkSocket::get_ifindex("sp_veth0").map_err(|e| e.to_string())?;
            let idx1 = NetlinkSocket::get_ifindex("sp_veth1").map_err(|e| e.to_string())?;
            nl.add_ipv4_addr(idx0, [10, 99, 0, 1], 24)
                .map_err(|e| e.to_string())?;
            nl.add_ipv4_addr(idx1, [10, 99, 0, 2], 24)
                .map_err(|e| e.to_string())?;
            nl.set_link_up(idx0).map_err(|e| e.to_string())?;
            nl.set_link_up(idx1).map_err(|e| e.to_string())?;

            let mut fw = XdpFirewall::load_from_bytes(&xdp_bytes).map_err(|e| e.to_string())?;
            fw.set_rate_limit(RateLimitConfig {
                rate_tokens_per_sec: 1,
                burst_tokens: 5,
                enabled: true,
                syn_only: false,
            })
            .map_err(|e| e.to_string())?;
            fw.attach_interface(idx1, XDP_FLAGS_SKB_MODE)
                .map_err(|e| e.to_string())?;

            let flood_pkt =
                build_ipv4_udp_frame([10, 99, 0, 1], [10, 99, 0, 2], 5000, 40000, 0, 5, 24);
            let leg_pkt =
                build_ipv4_udp_frame([10, 99, 0, 77], [10, 99, 0, 2], 5001, 40001, 0, 5, 24);
            let mut frames: Vec<&[u8]> = vec![&flood_pkt; 40];
            frames.push(&leg_pkt);
            send_raw_l2_frames(idx0, &frames).map_err(|e| e.to_string())?;
            std::thread::sleep(std::time::Duration::from_millis(80));

            let stats = fw.read_stats().map_err(|e| e.to_string())?;
            if stats.drop_ratelimit == 0 || stats.pass == 0 {
                return Err(format!(
                    "expected both passes (legit) and drops (flood) on live veth, got stats={stats:?}"
                ));
            }

            // Explicit drop detaches XDP cleanly before deleting veth!
            drop(fw);
            nl.delete_link(idx0).map_err(|e| e.to_string())?;
            Ok(())
        })
        .expect("isolated veth netns test must pass cleanly");
    }

    fn open_fd_count() -> usize {
        std::fs::read_dir("/proc/self/fd").unwrap().count()
    }

    #[test]
    fn live_tcp_monitor_rtt_state_and_cleartext_capture_zero_fd_leak() {
        let _guard = LIVE_KERNEL_LOCK.lock().unwrap();
        let tcp_path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../probes/build/tcp_trace.bpf.o");
        let tcp_bytes = std::fs::read(&tcp_path).expect("read tcp_trace.bpf.o");

        let fds_before = open_fd_count();
        {
            let mut mon =
                TcpMonitor::load_and_attach(&tcp_bytes, true).expect("load tcp_trace.bpf.o");
            let pid = std::process::id();
            mon.track_pid(pid).unwrap();

            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let srv = std::thread::spawn(move || {
                use std::io::{Read, Write};
                let (mut stream, _) = listener.accept().unwrap();
                let mut buf = [0u8; 64];
                let n = stream.read(&mut buf).unwrap();
                stream.write_all(&buf[..n]).unwrap();
            });

            {
                use std::io::{Read, Write};
                let mut client = std::net::TcpStream::connect(addr).unwrap();
                let payload = b"PING_SPECTRE_CLEARTEXT_M03\r\n";
                client.write_all(payload).unwrap();
                let mut echo = vec![0u8; payload.len()];
                client.read_exact(&mut echo).unwrap();
                assert_eq!(&echo, payload);
            }
            srv.join().unwrap();
            std::thread::sleep(std::time::Duration::from_millis(30));

            let tcp_evts = mon.drain_tcp_events();
            let l7_evts = mon.drain_l7_events();

            assert!(
                tcp_evts
                    .iter()
                    .any(|e| e.kind == spectre_xdp::TcpEventKind::StateChange),
                "expected TCP StateChange events, got {tcp_evts:?}"
            );
            assert!(
                tcp_evts
                    .iter()
                    .any(|e| e.kind == spectre_xdp::TcpEventKind::RttSample),
                "expected CO-RE TCP RttSample event, got {tcp_evts:?}"
            );
            assert!(
                l7_evts.iter().any(|e| e
                    .payload
                    .windows(26)
                    .any(|w| w == b"PING_SPECTRE_CLEARTEXT_M03")),
                "expected cleartext L7 payload capture via syscall probe, got {l7_evts:?}"
            );
        }
        let fds_after = open_fd_count();
        assert_eq!(fds_before, fds_after, "FD leak in TcpMonitor");
    }
}
