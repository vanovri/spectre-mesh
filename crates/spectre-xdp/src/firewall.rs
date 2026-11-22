use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct XdpDropEvent {
    pub ts_ns: u64,
    pub src_ipv4: u32,
    pub dst_ipv4: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
    pub reason: u8,
    pub pkt_len: u16,
}

impl XdpDropEvent {
    pub const WIRE_SIZE: usize = 24;

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < Self::WIRE_SIZE {
            return None;
        }
        Some(Self {
            ts_ns: u64::from_le_bytes(bytes[0..8].try_into().ok()?),
            src_ipv4: u32::from_le_bytes(bytes[8..12].try_into().ok()?),
            dst_ipv4: u32::from_le_bytes(bytes[12..16].try_into().ok()?),
            src_port: u16::from_le_bytes(bytes[16..18].try_into().ok()?),
            dst_port: u16::from_le_bytes(bytes[18..20].try_into().ok()?),
            proto: bytes[20],
            reason: bytes[21],
            pkt_len: u16::from_le_bytes(bytes[22..24].try_into().ok()?),
        })
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct XdpStatsSnapshot {
    pub rx_packets: u64,
    pub rx_bytes: u64,
    pub pass: u64,
    pub drop_ratelimit: u64,
    pub drop_blocklist: u64,
    pub drop_malformed: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct RateLimitConfig {
    pub rate_tokens_per_sec: u64,
    pub burst_tokens: u64,
    pub enabled: bool,
    pub syn_only: bool,
}

impl RateLimitConfig {
    #[must_use]
    pub fn to_wire_bytes(self) -> [u8; 24] {
        let mut out = [0u8; 24];
        out[0..8].copy_from_slice(&self.rate_tokens_per_sec.to_le_bytes());
        out[8..16].copy_from_slice(&self.burst_tokens.to_le_bytes());
        out[16..20].copy_from_slice(&u32::from(self.enabled).to_le_bytes());
        out[20..24].copy_from_slice(&u32::from(self.syn_only).to_le_bytes());
        out
    }
}

#[cfg(target_os = "linux")]
mod linux_fw {
    use super::*;
    use crate::netlink::{num_online_cpus, XdpAttachment, XdpError};
    use spectre_elf_btf::syscall::{
        bpf_map_delete_elem, bpf_map_lookup_elem, bpf_map_update_elem, bpf_prog_test_run, BPF_ANY,
    };
    use spectre_elf_btf::{BpfObjectLoader, LoadedBpfObject, RingBufConsumer};
    use std::net::Ipv4Addr;

    pub struct XdpFirewall {
        obj: LoadedBpfObject,
        ringbuf: RingBufConsumer,
        _attachments: Vec<XdpAttachment>,
    }

    impl XdpFirewall {
        pub fn load_from_bytes(probe_bytes: &[u8]) -> Result<Self, XdpError> {
            let obj = BpfObjectLoader::load_bytes(probe_bytes)?;
            let rb_fd = obj
                .map_fd("xdp_events")
                .ok_or(XdpError::InvalidArg("missing xdp_events map"))?;
            let rb_spec = obj
                .map_spec("xdp_events")
                .ok_or(XdpError::InvalidArg("missing xdp_events spec"))?;
            let ringbuf = RingBufConsumer::new(rb_fd, rb_spec.max_entries as usize)?;
            Ok(Self {
                obj,
                ringbuf,
                _attachments: Vec::new(),
            })
        }

        pub fn attach_interface(&mut self, ifindex: u32, flags: u32) -> Result<(), XdpError> {
            let prog_fd = self
                .obj
                .prog_fd("xdp_spectre_fw")
                .ok_or(XdpError::InvalidArg("missing xdp_spectre_fw program"))?;
            let att = XdpAttachment::attach(ifindex, prog_fd, flags)?;
            self._attachments.push(att);
            Ok(())
        }

        pub fn set_rate_limit(&self, cfg: RateLimitConfig) -> Result<(), XdpError> {
            let map_fd = self
                .obj
                .map_fd("xdp_rl_config")
                .ok_or(XdpError::InvalidArg("missing xdp_rl_config"))?;
            let key = 0u32.to_le_bytes();
            let val = cfg.to_wire_bytes();
            bpf_map_update_elem(map_fd, &key, &val, BPF_ANY)?;
            Ok(())
        }

        pub fn block_ipv4(&self, ip: Ipv4Addr) -> Result<(), XdpError> {
            let map_fd = self
                .obj
                .map_fd("xdp_blocklist")
                .ok_or(XdpError::InvalidArg("missing xdp_blocklist"))?;
            let key = ip.octets();
            let val = 1u32.to_le_bytes();
            bpf_map_update_elem(map_fd, &key, &val, BPF_ANY)?;
            Ok(())
        }

        pub fn unblock_ipv4(&self, ip: Ipv4Addr) -> Result<(), XdpError> {
            let map_fd = self
                .obj
                .map_fd("xdp_blocklist")
                .ok_or(XdpError::InvalidArg("missing xdp_blocklist"))?;
            let key = ip.octets();
            let _ = bpf_map_delete_elem(map_fd, &key)?;
            Ok(())
        }

        pub fn test_run_packet(
            &self,
            pkt_in: &[u8],
            repeat: u32,
        ) -> Result<(u32, u32, Vec<u8>), XdpError> {
            let prog_fd = self
                .obj
                .prog_fd("xdp_spectre_fw")
                .ok_or(XdpError::InvalidArg("missing xdp_spectre_fw"))?;
            let mut pkt_out = vec![0u8; pkt_in.len().max(64)];
            let (ret, dur, out_sz) = bpf_prog_test_run(prog_fd, pkt_in, &mut pkt_out, repeat)?;
            pkt_out.truncate(out_sz);
            Ok((ret, dur, pkt_out))
        }

        pub fn read_stats(&self) -> Result<XdpStatsSnapshot, XdpError> {
            let map_fd = self
                .obj
                .map_fd("xdp_stats")
                .ok_or(XdpError::InvalidArg("missing xdp_stats"))?;
            let ncpus = num_online_cpus();
            // Per-CPU lookup buffer must be rounded up to 8-byte stride per CPU (`possible` CPUs).
            // Query `/sys/devices/system/cpu/possible` for exact slot count!
            let slots = possible_cpu_count().max(ncpus);
            let mut buf = vec![0u8; slots * 8];
            let mut snap = XdpStatsSnapshot::default();
            for idx in 0..6u32 {
                buf.fill(0);
                let key = idx.to_le_bytes();
                if bpf_map_lookup_elem(map_fd, &key, &mut buf)? {
                    let sum: u64 = buf
                        .as_chunks::<8>()
                        .0
                        .iter()
                        .map(|c| u64::from_le_bytes(*c))
                        .sum();
                    match idx {
                        0 => snap.rx_packets = sum,
                        1 => snap.rx_bytes = sum,
                        2 => snap.pass = sum,
                        3 => snap.drop_ratelimit = sum,
                        4 => snap.drop_blocklist = sum,
                        5 => snap.drop_malformed = sum,
                        _ => {}
                    }
                }
            }
            Ok(snap)
        }

        pub fn drain_drop_events(&mut self) -> Vec<XdpDropEvent> {
            let mut out = Vec::new();
            self.ringbuf.consume_available(|rec| {
                if let Some(ev) = XdpDropEvent::decode(rec) {
                    out.push(ev);
                }
            });
            out
        }
    }

    fn possible_cpu_count() -> usize {
        if let Ok(s) = std::fs::read_to_string("/sys/devices/system/cpu/possible") {
            if let Some((_, end)) = s.trim().split_once('-') {
                if let Ok(max_id) = end.parse::<usize>() {
                    return max_id + 1;
                }
            }
        }
        num_online_cpus()
    }
}

#[cfg(target_os = "linux")]
pub use linux_fw::XdpFirewall;
