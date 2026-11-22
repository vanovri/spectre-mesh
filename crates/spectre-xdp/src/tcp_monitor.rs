use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TcpEventKind {
    StateChange = 1,
    Retransmit = 2,
    RttSample = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcpTelemetryEvent {
    pub ts_ns: u64,
    pub skaddr: u64,
    pub pid: u32,
    pub srtt_us: u32,
    pub saddr: u32,
    pub daddr: u32,
    pub sport: u16,
    pub dport: u16,
    pub kind: TcpEventKind,
    pub old_state: u8,
    pub new_state: u8,
}

impl TcpTelemetryEvent {
    pub const WIRE_SIZE: usize = 40;

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < Self::WIRE_SIZE {
            return None;
        }
        let kind = match bytes[36] {
            1 => TcpEventKind::StateChange,
            2 => TcpEventKind::Retransmit,
            3 => TcpEventKind::RttSample,
            _ => return None,
        };
        Some(Self {
            ts_ns: u64::from_le_bytes(bytes[0..8].try_into().ok()?),
            skaddr: u64::from_le_bytes(bytes[8..16].try_into().ok()?),
            pid: u32::from_le_bytes(bytes[16..20].try_into().ok()?),
            srtt_us: u32::from_le_bytes(bytes[20..24].try_into().ok()?),
            saddr: u32::from_le_bytes(bytes[24..28].try_into().ok()?),
            daddr: u32::from_le_bytes(bytes[28..32].try_into().ok()?),
            sport: u16::from_le_bytes(bytes[32..34].try_into().ok()?),
            dport: u16::from_le_bytes(bytes[34..36].try_into().ok()?),
            kind,
            old_state: bytes[37],
            new_state: bytes[38],
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct L7RawChunkEvent {
    pub ts_ns: u64,
    pub conn_ptr: u64,
    pub pid: u32,
    pub tid: u32,
    pub fd: i32,
    pub direction: u8,
    pub tls_source: u8,
    pub chunk_seq: u16,
    pub comm: String,
    pub payload: Vec<u8>,
}

impl L7RawChunkEvent {
    pub const HEADER_SIZE: usize = 52;

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < Self::HEADER_SIZE {
            return None;
        }
        let payload_len = u32::from_le_bytes(bytes[28..32].try_into().ok()?) as usize;
        if bytes.len() < Self::HEADER_SIZE + payload_len {
            return None;
        }
        let comm_raw = &bytes[36..52];
        let comm_end = comm_raw
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(comm_raw.len());
        let comm = String::from_utf8_lossy(&comm_raw[..comm_end]).into_owned();
        Some(Self {
            ts_ns: u64::from_le_bytes(bytes[0..8].try_into().ok()?),
            conn_ptr: u64::from_le_bytes(bytes[8..16].try_into().ok()?),
            pid: u32::from_le_bytes(bytes[16..20].try_into().ok()?),
            tid: u32::from_le_bytes(bytes[20..24].try_into().ok()?),
            fd: i32::from_le_bytes(bytes[24..28].try_into().ok()?),
            direction: bytes[32],
            tls_source: bytes[33],
            chunk_seq: u16::from_le_bytes(bytes[34..36].try_into().ok()?),
            comm,
            payload: bytes[Self::HEADER_SIZE..Self::HEADER_SIZE + payload_len].to_vec(),
        })
    }
}

#[cfg(target_os = "linux")]
mod linux_tcp {
    use super::*;
    use crate::netlink::XdpError;
    use spectre_elf_btf::syscall::{
        attach_kprobe_perf, attach_tracepoint_perf, bpf_map_delete_elem, bpf_map_update_elem,
        bpf_raw_tracepoint_open, OwnedBpfFd, PerfEventFd, BPF_ANY,
    };
    use spectre_elf_btf::{BpfObjectLoader, LoadedBpfObject, RingBufConsumer};

    pub struct TcpMonitor {
        obj: LoadedBpfObject,
        tcp_ringbuf: RingBufConsumer,
        l7_ringbuf: RingBufConsumer,
        _probes: Vec<PerfEventFd>,
        _raw_tps: Vec<OwnedBpfFd>,
    }

    impl TcpMonitor {
        pub fn load_and_attach(
            probe_bytes: &[u8],
            enable_l7_syscalls: bool,
        ) -> Result<Self, XdpError> {
            let obj = BpfObjectLoader::load_bytes(probe_bytes)?;
            let mut probes = Vec::new();
            let mut raw_tps = Vec::new();

            if let Some(pfd) = obj.prog_fd("tp_inet_sock_set_state") {
                probes.push(attach_tracepoint_perf("sock", "inet_sock_set_state", pfd)?);
            }
            if let Some(pfd) = obj.prog_fd("tp_tcp_retransmit_skb") {
                probes.push(attach_tracepoint_perf("tcp", "tcp_retransmit_skb", pfd)?);
            }
            if let Some(pfd) = obj.prog_fd("kp_tcp_rcv_established") {
                probes.push(attach_kprobe_perf("tcp_rcv_established", 0, false, pfd)?);
            }
            if enable_l7_syscalls {
                if let Some(pfd) = obj.prog_fd("raw_tp_sys_enter") {
                    raw_tps.push(bpf_raw_tracepoint_open("sys_enter", pfd)?);
                }
                if let Some(pfd) = obj.prog_fd("raw_tp_sys_exit") {
                    raw_tps.push(bpf_raw_tracepoint_open("sys_exit", pfd)?);
                }
            }

            let tcp_fd = obj
                .map_fd("tcp_events")
                .ok_or(XdpError::InvalidArg("missing tcp_events"))?;
            let tcp_spec = obj
                .map_spec("tcp_events")
                .ok_or(XdpError::InvalidArg("missing tcp_events spec"))?;
            let tcp_ringbuf = RingBufConsumer::new(tcp_fd, tcp_spec.max_entries as usize)?;

            let l7_fd = obj
                .map_fd("l7_events")
                .ok_or(XdpError::InvalidArg("missing l7_events"))?;
            let l7_spec = obj
                .map_spec("l7_events")
                .ok_or(XdpError::InvalidArg("missing l7_events spec"))?;
            let l7_ringbuf = RingBufConsumer::new(l7_fd, l7_spec.max_entries as usize)?;

            Ok(Self {
                obj,
                tcp_ringbuf,
                l7_ringbuf,
                _probes: probes,
                _raw_tps: raw_tps,
            })
        }

        pub fn track_pid(&self, pid: u32) -> Result<(), XdpError> {
            let map_fd = self
                .obj
                .map_fd("tracked_pids")
                .ok_or(XdpError::InvalidArg("missing tracked_pids"))?;
            let key = pid.to_le_bytes();
            let val = 1u32.to_le_bytes();
            bpf_map_update_elem(map_fd, &key, &val, BPF_ANY)?;
            Ok(())
        }

        pub fn untrack_pid(&self, pid: u32) -> Result<(), XdpError> {
            let map_fd = self
                .obj
                .map_fd("tracked_pids")
                .ok_or(XdpError::InvalidArg("missing tracked_pids"))?;
            let key = pid.to_le_bytes();
            let _ = bpf_map_delete_elem(map_fd, &key)?;
            Ok(())
        }

        pub fn drain_tcp_events(&mut self) -> Vec<TcpTelemetryEvent> {
            let mut out = Vec::new();
            self.tcp_ringbuf.consume_available(|rec| {
                if let Some(ev) = TcpTelemetryEvent::decode(rec) {
                    out.push(ev);
                }
            });
            out
        }

        pub fn drain_l7_events(&mut self) -> Vec<L7RawChunkEvent> {
            let mut out = Vec::new();
            self.l7_ringbuf.consume_available(|rec| {
                if let Some(ev) = L7RawChunkEvent::decode(rec) {
                    out.push(ev);
                }
            });
            out
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux_tcp::TcpMonitor;
