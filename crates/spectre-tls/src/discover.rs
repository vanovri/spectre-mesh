use std::collections::BTreeSet;
use std::path::Path;

use serde::{Deserialize, Serialize};
use spectre_elf_btf::Elf64Object;

use crate::go_abi::resolve_go_tls_probes;
use crate::TlsError;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveredTlsTargets {
    pub pid: u32,
    pub exe_path: Option<String>,
    pub openssl_paths: Vec<String>,
    pub go_binary_paths: Vec<String>,
}

/// Pure helper extracting unique executable/shared-object paths from Linux `/proc/<pid>/maps` text.
#[must_use]
pub fn parse_proc_maps_paths(maps_text: &str) -> Vec<String> {
    let mut paths = BTreeSet::new();
    for line in maps_text.lines() {
        let mut cols = line.split_whitespace();
        let _addr = cols.next();
        let Some(perms) = cols.next() else {
            continue;
        };
        if !perms.contains('x') {
            continue;
        }
        let _off = cols.next();
        let _dev = cols.next();
        let _inode = cols.next();
        let Some(path_part) = cols.next() else {
            continue;
        };
        let rest: String = std::iter::once(path_part)
            .chain(cols)
            .collect::<Vec<_>>()
            .join(" ");
        if rest.starts_with('/') && !rest.ends_with("(deleted)") {
            paths.insert(rest);
        }
    }
    paths.into_iter().collect()
}

/// Inspect `/proc/<pid>/maps` and `/proc/<pid>/exe` to discover OpenSSL (`libssl.so*` or statically linked)
/// and Go `crypto/tls` targets loaded inside `pid`.
pub fn discover_pid_tls_targets(pid: u32) -> Result<DiscoveredTlsTargets, TlsError> {
    let maps_path = format!("/proc/{pid}/maps");
    let maps_text = std::fs::read_to_string(&maps_path)?;
    let exe_path = std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
        .map(|s| s.strip_suffix(" (deleted)").unwrap_or(&s).to_owned());

    let mut mapped_paths = parse_proc_maps_paths(&maps_text);
    if let Some(ref exe) = exe_path {
        if !mapped_paths.contains(exe) {
            mapped_paths.push(exe.clone());
        }
    }

    let mut openssl_paths = BTreeSet::new();
    let mut go_binary_paths = BTreeSet::new();

    for path_str in mapped_paths {
        let p = Path::new(&path_str);
        if !p.exists() {
            continue;
        }
        let file_name = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
        let is_libssl_name = file_name.starts_with("libssl.so");
        let is_exe = exe_path.as_deref() == Some(path_str.as_str());
        if !is_libssl_name && !is_exe {
            continue;
        }

        let Ok(bytes) = std::fs::read(p) else {
            continue;
        };
        let Ok(elf) = Elf64Object::parse(&bytes) else {
            continue;
        };

        if elf.resolve_symbol_file_offset("SSL_write").is_some()
            || elf.resolve_symbol_file_offset("SSL_write_ex").is_some()
        {
            openssl_paths.insert(path_str.clone());
        }

        if elf.section_by_name(".gopclntab").is_some()
            && resolve_go_tls_probes(&path_str, &bytes).is_ok()
        {
            go_binary_paths.insert(path_str);
        }
    }

    Ok(DiscoveredTlsTargets {
        pid,
        exe_path,
        openssl_paths: openssl_paths.into_iter().collect(),
        go_binary_paths: go_binary_paths.into_iter().collect(),
    })
}

#[cfg(target_os = "linux")]
mod linux_tls {
    use super::*;
    use serde::{Deserialize, Serialize};
    use spectre_elf_btf::syscall::{attach_uprobe_perf, bpf_map_update_elem, PerfEventFd, BPF_ANY};
    use spectre_elf_btf::{BpfObjectLoader, Elf64Object, LoadedBpfObject, RingBufConsumer};
    use spectre_xdp::L7RawChunkEvent;
    use std::collections::HashSet;

    #[derive(Debug, Clone, Default, Serialize, Deserialize)]
    pub struct AttachedTlsSummary {
        pub tracked_pid: u32,
        pub openssl_probes_attached: usize,
        pub go_ret_offsets_attached: usize,
        pub attached_paths: Vec<String>,
    }

    pub struct TlsInterceptor {
        openssl_obj: LoadedBpfObject,
        go_obj: LoadedBpfObject,
        openssl_rb: RingBufConsumer,
        go_rb: RingBufConsumer,
        probes: Vec<PerfEventFd>,
        attached_openssl: HashSet<String>,
        attached_go: HashSet<String>,
    }

    impl TlsInterceptor {
        pub fn load(openssl_bpf: &[u8], go_bpf: &[u8]) -> Result<Self, TlsError> {
            let openssl_obj = BpfObjectLoader::load_bytes(openssl_bpf)?;
            let go_obj = BpfObjectLoader::load_bytes(go_bpf)?;

            let oss_fd = openssl_obj.map_fd("tls_events").ok_or_else(|| {
                TlsError::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "missing openssl tls_events",
                ))
            })?;
            let oss_spec = openssl_obj.map_spec("tls_events").ok_or_else(|| {
                TlsError::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "missing openssl tls_events spec",
                ))
            })?;
            let openssl_rb = RingBufConsumer::new(oss_fd, oss_spec.max_entries as usize)?;

            let go_fd = go_obj.map_fd("tls_events").ok_or_else(|| {
                TlsError::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "missing go tls_events",
                ))
            })?;
            let go_spec = go_obj.map_spec("tls_events").ok_or_else(|| {
                TlsError::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "missing go tls_events spec",
                ))
            })?;
            let go_rb = RingBufConsumer::new(go_fd, go_spec.max_entries as usize)?;

            Ok(Self {
                openssl_obj,
                go_obj,
                openssl_rb,
                go_rb,
                probes: Vec::new(),
                attached_openssl: HashSet::new(),
                attached_go: HashSet::new(),
            })
        }

        pub fn track_pid(&self, pid: u32) -> Result<(), TlsError> {
            let key = pid.to_le_bytes();
            let val = 1u32.to_le_bytes();
            if let Some(mfd) = self.openssl_obj.map_fd("tracked_pids") {
                bpf_map_update_elem(mfd, &key, &val, BPF_ANY)?;
            }
            if let Some(mfd) = self.go_obj.map_fd("tracked_pids") {
                bpf_map_update_elem(mfd, &key, &val, BPF_ANY)?;
            }
            Ok(())
        }

        /// Attach OpenSSL entry+return uprobes to an ELF binary/shared library (`libssl.so*` or static binary).
        /// Uses `pid = -1` so multi-threaded processes are covered across all OS threads.
        pub fn attach_openssl_path(&mut self, path: &str) -> Result<usize, TlsError> {
            if self.attached_openssl.contains(path) {
                return Ok(0);
            }
            let raw = std::fs::read(path)?;
            let elf = Elf64Object::parse(&raw)?;
            let mut count = 0usize;

            let hook_specs = [
                ("SSL_set_fd", "uprobe_ssl_set_fd", false),
                ("SSL_set_rfd", "uprobe_ssl_set_rfd", false),
                ("SSL_set_wfd", "uprobe_ssl_set_wfd", false),
                ("SSL_write", "uprobe_ssl_write", false),
                ("SSL_write", "uretprobe_ssl_write", true),
                ("SSL_write_ex", "uprobe_ssl_write_ex", false),
                ("SSL_write_ex", "uretprobe_ssl_write_ex", true),
                ("SSL_read", "uprobe_ssl_read", false),
                ("SSL_read", "uretprobe_ssl_read", true),
                ("SSL_read_ex", "uprobe_ssl_read_ex", false),
                ("SSL_read_ex", "uretprobe_ssl_read_ex", true),
            ];

            for (sym, prog_name, is_ret) in hook_specs {
                if let (Some((file_off, _)), Some(pfd)) = (
                    elf.resolve_symbol_file_offset(sym),
                    self.openssl_obj.prog_fd(prog_name),
                ) {
                    let fd = attach_uprobe_perf(path, file_off, -1, is_ret, pfd)?;
                    self.probes.push(fd);
                    count += 1;
                }
            }
            if count == 0 {
                return Err(TlsError::MissingSymbol(
                    "SSL_write/SSL_read",
                    path.to_owned(),
                ));
            }
            self.attached_openssl.insert(path.to_owned());
            Ok(count)
        }

        /// Attach safe Go `crypto/tls.(*Conn).Write/Read` entry uprobes + instruction-boundary
        /// `RET`-offset **entry** uprobes (zero kernel `uretprobe`s on Go!).
        pub fn attach_go_path(&mut self, path: &str) -> Result<usize, TlsError> {
            if self.attached_go.contains(path) {
                return Ok(0);
            }
            let raw = std::fs::read(path)?;
            let plan = resolve_go_tls_probes(path, &raw)?;
            let mut rets_attached = 0usize;

            if let Some(pfd) = self.go_obj.prog_fd("uprobe_go_tls_write_enter") {
                self.probes.push(attach_uprobe_perf(
                    path,
                    plan.write.entry_file_offset,
                    -1,
                    false,
                    pfd,
                )?);
            }
            if let Some(pfd) = self.go_obj.prog_fd("uprobe_go_tls_write_ret") {
                for &ret_off in &plan.write.ret_file_offsets {
                    self.probes
                        .push(attach_uprobe_perf(path, ret_off, -1, false, pfd)?);
                    rets_attached += 1;
                }
            }

            if let Some(pfd) = self.go_obj.prog_fd("uprobe_go_tls_read_enter") {
                self.probes.push(attach_uprobe_perf(
                    path,
                    plan.read.entry_file_offset,
                    -1,
                    false,
                    pfd,
                )?);
            }
            if let Some(pfd) = self.go_obj.prog_fd("uprobe_go_tls_read_ret") {
                for &ret_off in &plan.read.ret_file_offsets {
                    self.probes
                        .push(attach_uprobe_perf(path, ret_off, -1, false, pfd)?);
                    rets_attached += 1;
                }
            }

            if rets_attached == 0 {
                return Err(TlsError::InvalidFuncRange {
                    symbol: "crypto/tls.(*Conn).Read/Write RET".to_owned(),
                    start: plan.read.entry_file_offset,
                    end: plan.read.entry_file_offset,
                });
            }
            self.attached_go.insert(path.to_owned());
            Ok(rets_attached)
        }

        pub fn attach_pid(&mut self, pid: u32) -> Result<AttachedTlsSummary, TlsError> {
            self.track_pid(pid)?;
            let disc = discover_pid_tls_targets(pid)?;
            let mut summary = AttachedTlsSummary {
                tracked_pid: pid,
                openssl_probes_attached: 0,
                go_ret_offsets_attached: 0,
                attached_paths: Vec::new(),
            };

            for p in disc.openssl_paths {
                let n = self.attach_openssl_path(&p)?;
                summary.openssl_probes_attached += n;
                summary.attached_paths.push(p);
            }
            for p in disc.go_binary_paths {
                let n = self.attach_go_path(&p)?;
                summary.go_ret_offsets_attached += n;
                summary.attached_paths.push(p);
            }
            Ok(summary)
        }

        pub fn drain_tls_events(&mut self) -> Vec<L7RawChunkEvent> {
            let mut out = Vec::new();
            self.openssl_rb.consume_available(|rec| {
                if let Some(ev) = L7RawChunkEvent::decode(rec) {
                    out.push(ev);
                }
            });
            self.go_rb.consume_available(|rec| {
                if let Some(ev) = L7RawChunkEvent::decode(rec) {
                    out.push(ev);
                }
            });
            out.sort_by_key(|e| (e.ts_ns, e.chunk_seq));
            out
        }

        pub fn read_ringbuf_drops(&self) -> Result<u64, TlsError> {
            let mut total = 0u64;
            if let Some(mfd) = self.openssl_obj.map_fd("ringbuf_drops") {
                total += spectre_elf_btf::syscall::sum_percpu_u64(mfd, 0)?;
            }
            if let Some(mfd) = self.go_obj.map_fd("ringbuf_drops") {
                total += spectre_elf_btf::syscall::sum_percpu_u64(mfd, 0)?;
            }
            Ok(total)
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux_tls::{AttachedTlsSummary, TlsInterceptor};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_proc_maps_unique_executable_paths() {
        let sample = "\
555555554000-555555556000 r--p 00000000 fd:01 1234 /usr/local/bin/go-tls-srv\n\
555555556000-555555700000 r-xp 00002000 fd:01 1234 /usr/local/bin/go-tls-srv\n\
7ffff7c00000-7ffff7c90000 r-xp 00020000 fd:01 5678 /usr/lib/x86_64-linux-gnu/libssl.so.3\n\
7ffff7ff9000-7ffff7ffd000 r-xp 00000000 00:00 0 [vdso]\n\
7ffff7e00000-7ffff7e10000 r-xp 00001000 fd:01 9999 /tmp/old.so (deleted)\n";
        let paths = parse_proc_maps_paths(sample);
        assert_eq!(
            paths,
            vec![
                "/usr/lib/x86_64-linux-gnu/libssl.so.3".to_owned(),
                "/usr/local/bin/go-tls-srv".to_owned(),
            ]
        );
    }
}
