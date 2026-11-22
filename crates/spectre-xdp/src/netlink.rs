//! Controlled `unsafe` quarantine for raw Linux `AF_NETLINK` (`NETLINK_ROUTE`)
//! XDP attachment and `veth` network namespace orchestration (zero shell-outs).

use thiserror::Error;

#[derive(Debug, Error)]
pub enum XdpError {
    #[error("BPF/ELF error: {0}")]
    ElfBtf(#[from] spectre_elf_btf::ElfBtfError),
    #[error("Netlink/syscall '{op}' failed (errno {errno}): {message}")]
    Netlink {
        op: &'static str,
        errno: i32,
        message: String,
    },
    #[error("interface '{0}' not found")]
    InterfaceNotFound(String),
    #[error("invalid argument: {0}")]
    InvalidArg(&'static str),
}

#[cfg(target_os = "linux")]
mod linux {
    use super::XdpError;
    use spectre_elf_btf::syscall::{bpf_link_create, BpfLinkGuard, BPF_XDP};
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

    pub const XDP_FLAGS_UPDATE_IF_NOEXIST: u32 = 1 << 0;
    pub const XDP_FLAGS_SKB_MODE: u32 = 1 << 1;
    pub const XDP_FLAGS_DRV_MODE: u32 = 1 << 2;

    const RTM_NEWLINK: u16 = 16;
    const RTM_DELLINK: u16 = 17;
    const RTM_SETLINK: u16 = 19;
    const RTM_NEWADDR: u16 = 20;

    const NLM_F_REQUEST: u16 = 1;
    const NLM_F_ACK: u16 = 4;
    const NLM_F_EXCL: u16 = 0x200;
    const NLM_F_CREATE: u16 = 0x400;

    const IFLA_IFNAME: u16 = 3;
    const IFLA_LINKINFO: u16 = 18;
    const IFLA_NET_NS_FD: u16 = 28;
    const IFLA_XDP: u16 = 43;

    const IFLA_INFO_KIND: u16 = 1;
    const IFLA_INFO_DATA: u16 = 2;
    const VETH_INFO_PEER: u16 = 1;

    const IFLA_XDP_FD: u16 = 1;
    const IFLA_XDP_FLAGS: u16 = 3;

    const IFA_ADDRESS: u16 = 1;
    const IFA_LOCAL: u16 = 2;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct NlMsgHdr {
        nlmsg_len: u32,
        nlmsg_type: u16,
        nlmsg_flags: u16,
        nlmsg_seq: u32,
        nlmsg_pid: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct IfInfoMsg {
        ifi_family: u8,
        __ifi_pad: u8,
        ifi_type: u16,
        ifi_index: i32,
        ifi_flags: u32,
        ifi_change: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct IfAddrMsg {
        ifa_family: u8,
        ifa_prefixlen: u8,
        ifa_flags: u8,
        ifa_scope: u8,
        ifa_index: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct NlAttr {
        nla_len: u16,
        nla_type: u16,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct NlMsgErr {
        error: i32,
        msg: NlMsgHdr,
    }

    #[inline]
    fn align4(n: usize) -> usize {
        (n + 3) & !3
    }

    struct NlBuilder {
        buf: Vec<u8>,
    }

    impl NlBuilder {
        fn new(msg_type: u16, flags: u16, seq: u32) -> Self {
            let hdr = NlMsgHdr {
                nlmsg_len: std::mem::size_of::<NlMsgHdr>() as u32,
                nlmsg_type: msg_type,
                nlmsg_flags: flags,
                nlmsg_seq: seq,
                nlmsg_pid: 0,
            };
            let mut buf = Vec::with_capacity(256);
            // SAFETY: `NlMsgHdr` is `#[repr(C)]` POD with no padding holes.
            let bytes = unsafe {
                std::slice::from_raw_parts(
                    &hdr as *const NlMsgHdr as *const u8,
                    std::mem::size_of::<NlMsgHdr>(),
                )
            };
            buf.extend_from_slice(bytes);
            Self { buf }
        }

        fn push_pod<T: Copy>(&mut self, val: &T) {
            // SAFETY: Caller passes plain-old-data `#[repr(C)]` kernel Netlink headers.
            let bytes = unsafe {
                std::slice::from_raw_parts(val as *const T as *const u8, std::mem::size_of::<T>())
            };
            self.buf.extend_from_slice(bytes);
            let padded = align4(self.buf.len());
            self.buf.resize(padded, 0);
        }

        fn put_attr(&mut self, attr_type: u16, payload: &[u8]) {
            let total_len = std::mem::size_of::<NlAttr>() + payload.len();
            let hdr = NlAttr {
                nla_len: total_len as u16,
                nla_type: attr_type,
            };
            // SAFETY: `NlAttr` is 4-byte POD.
            let hdr_bytes = unsafe {
                std::slice::from_raw_parts(
                    &hdr as *const NlAttr as *const u8,
                    std::mem::size_of::<NlAttr>(),
                )
            };
            self.buf.extend_from_slice(hdr_bytes);
            self.buf.extend_from_slice(payload);
            let padded = align4(self.buf.len());
            self.buf.resize(padded, 0);
        }

        fn begin_nested(&mut self, attr_type: u16) -> usize {
            let off = self.buf.len();
            let hdr = NlAttr {
                nla_len: std::mem::size_of::<NlAttr>() as u16,
                nla_type: attr_type | 0x8000, // NLA_F_NESTED
            };
            // SAFETY: `NlAttr` is 4-byte POD.
            let hdr_bytes = unsafe {
                std::slice::from_raw_parts(
                    &hdr as *const NlAttr as *const u8,
                    std::mem::size_of::<NlAttr>(),
                )
            };
            self.buf.extend_from_slice(hdr_bytes);
            off
        }

        fn end_nested(&mut self, off: usize) {
            let len = (self.buf.len() - off) as u16;
            self.buf[off..off + 2].copy_from_slice(&len.to_le_bytes());
        }

        fn finish(mut self) -> Vec<u8> {
            let len = self.buf.len() as u32;
            self.buf[0..4].copy_from_slice(&len.to_le_bytes());
            self.buf
        }
    }

    pub struct NetlinkSocket {
        fd: OwnedFd,
        seq: u32,
    }

    impl NetlinkSocket {
        pub fn open() -> Result<Self, XdpError> {
            // SAFETY: Creating a standard AF_NETLINK NETLINK_ROUTE raw socket.
            let raw = unsafe {
                libc::socket(
                    libc::AF_NETLINK,
                    libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                    libc::NETLINK_ROUTE,
                )
            };
            if raw < 0 {
                return Err(last_err("socket(AF_NETLINK)"));
            }
            // SAFETY: `raw` is a newly created valid netlink FD.
            let fd = unsafe { OwnedFd::from_raw_fd(raw) };

            // SAFETY: Zeroed `sockaddr_nl` with `nl_family = AF_NETLINK`.
            let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
            addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
            // SAFETY: Binding local netlink endpoint.
            let rc = unsafe {
                libc::bind(
                    fd.as_raw_fd(),
                    &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
                )
            };
            if rc < 0 {
                return Err(last_err("bind(AF_NETLINK)"));
            }
            Ok(Self { fd, seq: 1 })
        }

        fn next_seq(&mut self) -> u32 {
            let s = self.seq;
            self.seq = self.seq.wrapping_add(1);
            s
        }

        fn send_and_ack(&mut self, msg: &[u8], op: &'static str) -> Result<(), XdpError> {
            // SAFETY: Kernel netlink destination address (`nl_pid = 0`).
            let mut dst: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
            dst.nl_family = libc::AF_NETLINK as libc::sa_family_t;

            // SAFETY: `self.fd` is a bound netlink socket and `msg` is a valid buffer.
            let sent = unsafe {
                libc::sendto(
                    self.fd.as_raw_fd(),
                    msg.as_ptr() as *const libc::c_void,
                    msg.len(),
                    0,
                    &dst as *const libc::sockaddr_nl as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
                )
            };
            if sent < 0 {
                return Err(last_err(op));
            }

            let mut resp = [0u8; 4096];
            // SAFETY: Receive Netlink ACK response into stack buffer.
            let n = unsafe {
                libc::recv(
                    self.fd.as_raw_fd(),
                    resp.as_mut_ptr() as *mut libc::c_void,
                    resp.len(),
                    0,
                )
            };
            if n < 0 {
                return Err(last_err(op));
            }
            let n = n as usize;
            if n < std::mem::size_of::<NlMsgHdr>() + std::mem::size_of::<NlMsgErr>() {
                return Ok(());
            }
            let nlmsg_type = u16::from_le_bytes([resp[4], resp[5]]);
            if nlmsg_type == libc::NLMSG_ERROR as u16 {
                let err_code = i32::from_le_bytes([resp[16], resp[17], resp[18], resp[19]]);
                if err_code != 0 {
                    let errno = -err_code;
                    return Err(XdpError::Netlink {
                        op,
                        errno,
                        message: std::io::Error::from_raw_os_error(errno).to_string(),
                    });
                }
            }
            Ok(())
        }

        pub fn get_ifindex(ifname: &str) -> Result<u32, XdpError> {
            let c_name =
                CString::new(ifname).map_err(|_| XdpError::InvalidArg("NUL in interface name"))?;
            // SAFETY: `c_name` is a valid NUL-terminated C string.
            let idx = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
            if idx == 0 {
                return Err(XdpError::InterfaceNotFound(ifname.to_owned()));
            }
            Ok(idx)
        }

        pub fn set_xdp_fd(
            &mut self,
            ifindex: u32,
            prog_fd: RawFd,
            flags: u32,
        ) -> Result<(), XdpError> {
            let seq = self.next_seq();
            let mut b = NlBuilder::new(RTM_SETLINK, NLM_F_REQUEST | NLM_F_ACK, seq);
            b.push_pod(&IfInfoMsg {
                ifi_family: libc::AF_UNSPEC as u8,
                __ifi_pad: 0,
                ifi_type: 0,
                ifi_index: ifindex as i32,
                ifi_flags: 0,
                ifi_change: 0,
            });
            let xdp_nest = b.begin_nested(IFLA_XDP);
            b.put_attr(IFLA_XDP_FD, &prog_fd.to_le_bytes());
            if flags != 0 {
                b.put_attr(IFLA_XDP_FLAGS, &flags.to_le_bytes());
            }
            b.end_nested(xdp_nest);
            self.send_and_ack(&b.finish(), "RTM_SETLINK(IFLA_XDP)")
        }

        pub fn create_veth_pair(&mut self, name_a: &str, name_b: &str) -> Result<(), XdpError> {
            let mut a_bytes = name_a.as_bytes().to_vec();
            a_bytes.push(0);
            let mut b_bytes = name_b.as_bytes().to_vec();
            b_bytes.push(0);

            let seq = self.next_seq();
            let mut b = NlBuilder::new(
                RTM_NEWLINK,
                NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK,
                seq,
            );
            b.push_pod(&IfInfoMsg {
                ifi_family: libc::AF_UNSPEC as u8,
                __ifi_pad: 0,
                ifi_type: 0,
                ifi_index: 0,
                ifi_flags: 0,
                ifi_change: 0,
            });
            b.put_attr(IFLA_IFNAME, &a_bytes);
            let linkinfo = b.begin_nested(IFLA_LINKINFO);
            b.put_attr(IFLA_INFO_KIND, b"veth\0");
            let infodata = b.begin_nested(IFLA_INFO_DATA);
            let peer = b.begin_nested(VETH_INFO_PEER);
            b.push_pod(&IfInfoMsg {
                ifi_family: libc::AF_UNSPEC as u8,
                __ifi_pad: 0,
                ifi_type: 0,
                ifi_index: 0,
                ifi_flags: 0,
                ifi_change: 0,
            });
            b.put_attr(IFLA_IFNAME, &b_bytes);
            b.end_nested(peer);
            b.end_nested(infodata);
            b.end_nested(linkinfo);
            self.send_and_ack(&b.finish(), "RTM_NEWLINK(veth)")
        }

        pub fn set_link_up(&mut self, ifindex: u32) -> Result<(), XdpError> {
            let seq = self.next_seq();
            let mut b = NlBuilder::new(RTM_SETLINK, NLM_F_REQUEST | NLM_F_ACK, seq);
            b.push_pod(&IfInfoMsg {
                ifi_family: libc::AF_UNSPEC as u8,
                __ifi_pad: 0,
                ifi_type: 0,
                ifi_index: ifindex as i32,
                ifi_flags: libc::IFF_UP as u32,
                ifi_change: libc::IFF_UP as u32,
            });
            self.send_and_ack(&b.finish(), "RTM_SETLINK(IFF_UP)")
        }

        pub fn add_ipv4_addr(
            &mut self,
            ifindex: u32,
            addr: [u8; 4],
            prefix_len: u8,
        ) -> Result<(), XdpError> {
            let seq = self.next_seq();
            let mut b = NlBuilder::new(RTM_NEWADDR, NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK, seq);
            b.push_pod(&IfAddrMsg {
                ifa_family: libc::AF_INET as u8,
                ifa_prefixlen: prefix_len,
                ifa_flags: 0,
                ifa_scope: 0,
                ifa_index: ifindex,
            });
            b.put_attr(IFA_LOCAL, &addr);
            b.put_attr(IFA_ADDRESS, &addr);
            self.send_and_ack(&b.finish(), "RTM_NEWADDR")
        }

        pub fn delete_link(&mut self, ifindex: u32) -> Result<(), XdpError> {
            let seq = self.next_seq();
            let mut b = NlBuilder::new(RTM_DELLINK, NLM_F_REQUEST | NLM_F_ACK, seq);
            b.push_pod(&IfInfoMsg {
                ifi_family: libc::AF_UNSPEC as u8,
                __ifi_pad: 0,
                ifi_type: 0,
                ifi_index: ifindex as i32,
                ifi_flags: 0,
                ifi_change: 0,
            });
            self.send_and_ack(&b.finish(), "RTM_DELLINK")
        }

        pub fn set_link_netns_fd(&mut self, ifindex: u32, netns_fd: RawFd) -> Result<(), XdpError> {
            let seq = self.next_seq();
            let mut b = NlBuilder::new(RTM_SETLINK, NLM_F_REQUEST | NLM_F_ACK, seq);
            b.push_pod(&IfInfoMsg {
                ifi_family: libc::AF_UNSPEC as u8,
                __ifi_pad: 0,
                ifi_type: 0,
                ifi_index: ifindex as i32,
                ifi_flags: 0,
                ifi_change: 0,
            });
            b.put_attr(IFLA_NET_NS_FD, &netns_fd.to_le_bytes());
            self.send_and_ack(&b.finish(), "RTM_SETLINK(IFLA_NET_NS_FD)")
        }
    }

    /// Inject raw L2 Ethernet frames directly onto interface `ifindex` via `AF_PACKET`.
    pub fn send_raw_l2_frames(ifindex: u32, frames: &[&[u8]]) -> Result<usize, XdpError> {
        // SAFETY: Opening a standard AF_PACKET raw socket.
        let raw = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                (libc::ETH_P_ALL as u16).to_be() as libc::c_int,
            )
        };
        if raw < 0 {
            return Err(last_err("socket(AF_PACKET)"));
        }
        // SAFETY: `raw` is a newly opened valid socket FD.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };

        // SAFETY: Zeroed `sockaddr_ll` populated with target `sll_ifindex`.
        let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        sll.sll_family = libc::AF_PACKET as u16;
        sll.sll_ifindex = ifindex as libc::c_int;
        sll.sll_halen = 6;

        let mut sent = 0usize;
        for frame in frames {
            if frame.len() >= 6 {
                sll.sll_addr[..6].copy_from_slice(&frame[..6]);
            }
            // SAFETY: `fd` and `sll` are valid, `frame` slice is alive across `sendto`.
            let rc = unsafe {
                libc::sendto(
                    fd.as_raw_fd(),
                    frame.as_ptr() as *const libc::c_void,
                    frame.len(),
                    0,
                    &sll as *const libc::sockaddr_ll as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
                )
            };
            if rc < 0 {
                return Err(last_err("sendto(AF_PACKET)"));
            }
            sent += 1;
        }
        Ok(sent)
    }

    /// Run `f` inside a fresh isolated child `CLONE_NEWNET` network namespace so host
    /// interfaces are never modified and all virtual devices vanish automatically on exit.
    pub fn run_in_isolated_netns<F>(f: F) -> Result<(), XdpError>
    where
        F: FnOnce() -> Result<(), String>,
    {
        // SAFETY: `fork()` + `waitpid()` isolates child network namespace safely.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(last_err("fork"));
        }
        if pid == 0 {
            if let Err(err) = unshare_netns() {
                eprintln!("unshare(CLONE_NEWNET) failed: {err}");
                std::process::exit(2);
            }
            match f() {
                Ok(()) => std::process::exit(0),
                Err(msg) => {
                    eprintln!("isolated netns task failed: {msg}");
                    std::process::exit(1);
                }
            }
        }
        let mut status: libc::c_int = 0;
        // SAFETY: Waiting on valid child PID `pid`.
        let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
        if waited < 0 {
            return Err(last_err("waitpid"));
        }
        if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
            return Err(XdpError::Netlink {
                op: "isolated_netns_child",
                errno: libc::WEXITSTATUS(status),
                message: format!("child exited with status {status}"),
            });
        }
        Ok(())
    }

    /// RAII XDP attachment guard: prefers `BPF_LINK_CREATE(BPF_XDP)`, falls back to
    /// `NETLINK_ROUTE` `RTM_SETLINK(IFLA_XDP_FD)`. Automatically detaches on `Drop`.
    #[derive(Debug)]
    pub struct XdpAttachment {
        ifindex: u32,
        flags: u32,
        link: Option<BpfLinkGuard>,
    }

    impl XdpAttachment {
        pub fn attach(ifindex: u32, prog_fd: RawFd, flags: u32) -> Result<Self, XdpError> {
            if let Ok(link) = bpf_link_create(prog_fd, ifindex, BPF_XDP, flags) {
                return Ok(Self {
                    ifindex,
                    flags,
                    link: Some(link),
                });
            }
            let mut nl = NetlinkSocket::open()?;
            nl.set_xdp_fd(ifindex, prog_fd, flags)?;
            Ok(Self {
                ifindex,
                flags,
                link: None,
            })
        }

        #[must_use]
        pub const fn ifindex(&self) -> u32 {
            self.ifindex
        }
    }

    impl Drop for XdpAttachment {
        fn drop(&mut self) {
            if self.link.is_none() {
                if let Ok(mut nl) = NetlinkSocket::open() {
                    let _ = nl.set_xdp_fd(self.ifindex, -1, self.flags);
                }
            }
        }
    }

    pub fn unshare_netns() -> Result<(), XdpError> {
        // SAFETY: `unshare(CLONE_NEWNET)` isolates network namespace of the calling process.
        let rc = unsafe { libc::unshare(libc::CLONE_NEWNET) };
        if rc < 0 {
            return Err(last_err("unshare(CLONE_NEWNET)"));
        }
        Ok(())
    }

    pub fn num_online_cpus() -> usize {
        // SAFETY: `sysconf(_SC_NPROCESSORS_CONF)` returns configured CPU count.
        let n = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_CONF) };
        usize::try_from(n).unwrap_or(1).max(1)
    }

    fn last_err(op: &'static str) -> XdpError {
        let err = std::io::Error::last_os_error();
        let errno = err.raw_os_error().unwrap_or(-1);
        XdpError::Netlink {
            op,
            errno,
            message: err.to_string(),
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux::*;
