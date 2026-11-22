#[cfg(target_os = "linux")]
mod linux_tests {
    use spectre_elf_btf::syscall::bpf_prog_test_run;
    use spectre_elf_btf::{BpfObjectLoader, Btf, RingBufConsumer};
    use std::path::Path;

    fn open_fd_count() -> usize {
        std::fs::read_dir("/proc/self/fd")
            .expect("/proc/self/fd readable")
            .count()
    }

    #[test]
    fn live_kernel_ringbuf_10000_records_zero_drop_zero_fd_leak() {
        let probe_path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../probes/build/m01_ringbuf_test.bpf.o");
        if !probe_path.exists() {
            panic!(
                "compiled probe missing at {}; run `make build-probes` first",
                probe_path.display()
            );
        }
        let bytes = std::fs::read(&probe_path).expect("read probe object");

        // Verify vmlinux BTF parses cleanly on this kernel!
        let vmlinux = Btf::from_vmlinux().expect("parse /sys/kernel/btf/vmlinux");
        assert!(vmlinux.types.len() > 1000, "expected rich kernel BTF types");
        assert!(
            !vmlinux.find_types_by_name("task_struct").is_empty(),
            "task_struct present in kernel BTF"
        );

        let fds_before = open_fd_count();

        {
            let loaded = BpfObjectLoader::load_bytes_with_btf(&bytes, Some(&vmlinux))
                .expect("load m01_ringbuf_test.bpf.o into live Linux kernel");
            let prog_fd = loaded.prog_fd("m01_emit_ringbuf").expect("prog fd");
            let rb_fd = loaded.map_fd("m01_events").expect("ringbuf fd");
            let rb_spec = loaded.map_spec("m01_events").expect("ringbuf spec");
            assert_eq!(rb_spec.max_entries, 524_288);

            let mut consumer = RingBufConsumer::new(rb_fd, rb_spec.max_entries as usize)
                .expect("double-mmap RingBufConsumer");

            // Minimal 64-byte synthetic Ethernet/IP packet buffer for BPF_PROG_TEST_RUN
            let mut pkt_in = vec![0u8; 64];
            pkt_in[12] = 0x08;
            pkt_in[13] = 0x00;
            let mut pkt_out = vec![0u8; 64];

            let mut received_seqs = Vec::with_capacity(10_000);
            // Execute 10,000 invocations in batches of 500 and drain RingBuf after each batch
            for _batch in 0..20 {
                let (retval, _dur, _out_sz) =
                    bpf_prog_test_run(prog_fd, &pkt_in, &mut pkt_out, 500)
                        .expect("BPF_PROG_TEST_RUN 500");
                assert_eq!(retval, 2, "expected XDP_PASS (2)");

                consumer.consume_available(|rec| {
                    assert_eq!(rec.len(), 24, "struct m01_seq_event must be 24 bytes");
                    let seq = u64::from_le_bytes(rec[0..8].try_into().unwrap());
                    let pkt_len = u32::from_le_bytes(rec[16..20].try_into().unwrap());
                    let magic = u32::from_le_bytes(rec[20..24].try_into().unwrap());
                    assert_eq!(pkt_len, 64);
                    assert_eq!(magic, 0x5350_4543);
                    received_seqs.push(seq);
                });
            }

            // Final non-blocking poll drain
            let _ = consumer.poll(10, |rec| {
                let seq = u64::from_le_bytes(rec[0..8].try_into().unwrap());
                received_seqs.push(seq);
            });

            assert_eq!(
                received_seqs.len(),
                10_000,
                "expected 10,000 zero-drop RingBuf events"
            );
            for (i, &seq) in received_seqs.iter().enumerate() {
                assert_eq!(seq, (i + 1) as u64, "out-of-order/missing seq at index {i}");
            }
        }

        let fds_after = open_fd_count();
        assert_eq!(
            fds_before, fds_after,
            "FD leak detected: before={fds_before}, after={fds_after}"
        );
    }
}
