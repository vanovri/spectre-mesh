use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use spectre_elf_btf::syscall::{
    attach_cpu_sampler_perf, attach_tracepoint_perf, bpf_map_get_next_key, bpf_map_lookup_elem,
    bpf_map_update_elem, online_cpu_ids, PerfEventFd, BPF_ANY,
};
use spectre_elf_btf::{BpfObjectLoader, LoadedBpfObject};

use crate::flamegraph::{build_flamegraph, to_folded, FlameGraph, FoldedStack};
use crate::symbolizer::SymbolResolver;
use crate::ProfileError;

const PERF_MAX_STACK_DEPTH: usize = 127;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileSnapshot {
    pub oncpu_samples: u64,
    pub offcpu_total_ns: u64,
    pub oncpu_folded: String,
    pub offcpu_folded: String,
    pub oncpu_flamegraph: FlameGraph,
    pub offcpu_flamegraph: FlameGraph,
}

#[derive(Debug, Clone)]
struct StackKeyRaw {
    pid: u32,
    kern_stack_id: i32,
    user_stack_id: i32,
    comm: String,
}

impl StackKeyRaw {
    fn from_bytes(bytes: &[u8; 32]) -> Self {
        let pid = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let kern_stack_id = i32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let user_stack_id = i32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let comm_slice = &bytes[16..32];
        let end = comm_slice
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(comm_slice.len());
        let comm = String::from_utf8_lossy(&comm_slice[..end]).into_owned();
        Self {
            pid,
            kern_stack_id,
            user_stack_id,
            comm,
        }
    }
}

pub struct ContinuousProfiler {
    obj: LoadedBpfObject,
    probes: Vec<PerfEventFd>,
    resolver: SymbolResolver,
}

impl ContinuousProfiler {
    pub fn load(probe_bytes: &[u8]) -> Result<Self, ProfileError> {
        let obj = BpfObjectLoader::load_bytes(probe_bytes)?;
        let mut resolver = SymbolResolver::new();
        resolver.load_host_kallsyms();
        Ok(Self {
            obj,
            probes: Vec::new(),
            resolver,
        })
    }

    /// Filter profiling to specific target PIDs (`Some(&[pid, ...])`), or profile system-wide (`None`).
    pub fn set_pid_filter(&self, pids: Option<&[u32]>) -> Result<(), ProfileError> {
        let cfg_fd = self
            .obj
            .map_fd("filter_cfg")
            .ok_or(ProfileError::InvalidConfig("filter_cfg"))?;
        let key0 = 0u32.to_le_bytes();
        match pids {
            None => {
                bpf_map_update_elem(cfg_fd, &key0, &0u32.to_le_bytes(), BPF_ANY)?;
            }
            Some(list) => {
                let tracked_fd = self
                    .obj
                    .map_fd("tracked_pids")
                    .ok_or(ProfileError::InvalidConfig("tracked_pids"))?;
                for &pid in list {
                    bpf_map_update_elem(
                        tracked_fd,
                        &pid.to_le_bytes(),
                        &1u32.to_le_bytes(),
                        BPF_ANY,
                    )?;
                    self.resolver_check(pid);
                }
                bpf_map_update_elem(cfg_fd, &key0, &1u32.to_le_bytes(), BPF_ANY)?;
            }
        }
        Ok(())
    }

    fn resolver_check(&self, _pid: u32) {
        // Maps refreshed on snapshot resolution once target has mapped all segments
    }

    pub fn refresh_pid_maps(&mut self, pid: u32) {
        self.resolver.refresh_pid_maps(pid);
    }

    /// Attach 99 Hz CPU software clock sampler on all online CPUs + `sched/sched_switch` tracepoint.
    pub fn start(&mut self, sample_freq_hz: u64) -> Result<(), ProfileError> {
        let perf_fd = self
            .obj
            .prog_fd("oncpu_sample")
            .ok_or(ProfileError::InvalidConfig("oncpu_sample"))?;
        for cpu in online_cpu_ids() {
            self.probes
                .push(attach_cpu_sampler_perf(sample_freq_hz, -1, cpu, perf_fd)?);
        }

        let tp_fd = self
            .obj
            .prog_fd("tp_sched_switch")
            .ok_or(ProfileError::InvalidConfig("tp_sched_switch"))?;
        self.probes
            .push(attach_tracepoint_perf("sched", "sched_switch", tp_fd)?);
        Ok(())
    }

    pub fn snapshot(&mut self) -> Result<ProfileSnapshot, ProfileError> {
        let stacks_fd = self
            .obj
            .map_fd("stack_traces")
            .ok_or(ProfileError::InvalidConfig("stack_traces"))?;
        let oncpu_fd = self
            .obj
            .map_fd("oncpu_counts")
            .ok_or(ProfileError::InvalidConfig("oncpu_counts"))?;
        let offcpu_fd = self
            .obj
            .map_fd("offcpu_ns")
            .ok_or(ProfileError::InvalidConfig("offcpu_ns"))?;

        let mut stack_id_cache: HashMap<(u32, i32, bool), Vec<String>> = HashMap::new();

        let (oncpu_stacks, oncpu_samples) =
            self.collect_map_stacks(oncpu_fd, stacks_fd, &mut stack_id_cache)?;
        let (offcpu_stacks, offcpu_total_ns) =
            self.collect_map_stacks(offcpu_fd, stacks_fd, &mut stack_id_cache)?;

        let oncpu_folded = to_folded(&oncpu_stacks);
        let offcpu_folded = to_folded(&offcpu_stacks);
        let oncpu_flamegraph = build_flamegraph("On-CPU 99Hz Profile", "samples", &oncpu_stacks);
        let offcpu_flamegraph = build_flamegraph("Off-CPU Stall Profile", "ns", &offcpu_stacks);

        Ok(ProfileSnapshot {
            oncpu_samples,
            offcpu_total_ns,
            oncpu_folded,
            offcpu_folded,
            oncpu_flamegraph,
            offcpu_flamegraph,
        })
    }

    fn collect_map_stacks(
        &mut self,
        counts_fd: std::os::fd::RawFd,
        stacks_fd: std::os::fd::RawFd,
        cache: &mut HashMap<(u32, i32, bool), Vec<String>>,
    ) -> Result<(Vec<FoldedStack>, u64), ProfileError> {
        let mut out = Vec::new();
        let mut total_val = 0u64;
        let mut cur_key: Option<[u8; 32]> = None;
        let mut next_key = [0u8; 32];
        let mut val_buf = [0u8; 8];

        while bpf_map_get_next_key(counts_fd, cur_key.as_ref().map(|k| &k[..]), &mut next_key)? {
            if bpf_map_lookup_elem(counts_fd, &next_key, &mut val_buf)? {
                let val = u64::from_le_bytes(val_buf);
                if val > 0 {
                    let parsed = StackKeyRaw::from_bytes(&next_key);
                    let mut frames = Vec::new();
                    frames.push(if parsed.comm.is_empty() {
                        format!("pid:{}", parsed.pid)
                    } else {
                        parsed.comm.clone()
                    });

                    if parsed.user_stack_id >= 0 {
                        let uframes = self.resolve_stack_id(
                            stacks_fd,
                            parsed.pid,
                            parsed.user_stack_id,
                            false,
                            cache,
                        )?;
                        frames.extend(uframes);
                    }
                    if parsed.kern_stack_id >= 0 {
                        let kframes = self.resolve_stack_id(
                            stacks_fd,
                            parsed.pid,
                            parsed.kern_stack_id,
                            true,
                            cache,
                        )?;
                        frames.extend(kframes);
                    }
                    total_val = total_val.saturating_add(val);
                    out.push(FoldedStack {
                        stack: frames,
                        value: val,
                    });
                }
            }
            cur_key = Some(next_key);
        }

        Ok((out, total_val))
    }

    fn resolve_stack_id(
        &mut self,
        stacks_fd: std::os::fd::RawFd,
        pid: u32,
        stack_id: i32,
        is_kernel: bool,
        cache: &mut HashMap<(u32, i32, bool), Vec<String>>,
    ) -> Result<Vec<String>, ProfileError> {
        let ckey = (if is_kernel { 0 } else { pid }, stack_id, is_kernel);
        if let Some(cached) = cache.get(&ckey) {
            return Ok(cached.clone());
        }

        let mut buf = vec![0u8; PERF_MAX_STACK_DEPTH * 8];
        let mut frames = Vec::new();
        if bpf_map_lookup_elem(stacks_fd, &stack_id.to_le_bytes(), &mut buf)? {
            let mut ips = Vec::new();
            for c in buf.as_chunks::<8>().0 {
                let ip = u64::from_le_bytes(*c);
                if ip == 0 {
                    break;
                }
                ips.push(ip);
            }
            // BPF stack traces record leaf -> root; reverse for flamegraph root -> leaf ordering
            ips.reverse();
            for ip in ips {
                let sym = if is_kernel {
                    self.resolver.resolve_kernel_ip(ip)
                } else {
                    self.resolver.resolve_user_ip(pid, ip)
                };
                frames.push(sym);
            }
        }
        cache.insert(ckey, frames.clone());
        Ok(frames)
    }
}
