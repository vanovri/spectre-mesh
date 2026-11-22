//! Controlled `unsafe` quarantine for Linux kernel `SYS_bpf`, `SYS_perf_event_open`,
//! `ioctl`, and `epoll_*` system calls with strict RAII FD lifecycle management.

#[cfg(target_os = "linux")]
mod linux {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

    use crate::error::ElfBtfError;

    // BPF syscall commands (`enum bpf_cmd` from linux/bpf.h)
    pub const BPF_MAP_CREATE: libc::c_long = 0;
    pub const BPF_MAP_LOOKUP_ELEM: libc::c_long = 1;
    pub const BPF_MAP_UPDATE_ELEM: libc::c_long = 2;
    pub const BPF_MAP_DELETE_ELEM: libc::c_long = 3;
    pub const BPF_MAP_GET_NEXT_KEY: libc::c_long = 4;
    pub const BPF_PROG_LOAD: libc::c_long = 5;
    pub const BPF_OBJ_PIN: libc::c_long = 6;
    pub const BPF_OBJ_GET: libc::c_long = 7;
    pub const BPF_PROG_TEST_RUN: libc::c_long = 10;
    pub const BPF_RAW_TRACEPOINT_OPEN: libc::c_long = 17;
    pub const BPF_BTF_LOAD: libc::c_long = 18;
    pub const BPF_MAP_FREEZE: libc::c_long = 22;
    pub const BPF_LINK_CREATE: libc::c_long = 28;
    pub const BPF_LINK_DETACH: libc::c_long = 34;

    pub const BPF_OBJ_NAME_LEN: usize = 16;

    // BPF map types
    pub const BPF_MAP_TYPE_HASH: u32 = 1;
    pub const BPF_MAP_TYPE_ARRAY: u32 = 2;
    pub const BPF_MAP_TYPE_PERCPU_HASH: u32 = 5;
    pub const BPF_MAP_TYPE_PERCPU_ARRAY: u32 = 6;
    pub const BPF_MAP_TYPE_STACK_TRACE: u32 = 7;
    pub const BPF_MAP_TYPE_RINGBUF: u32 = 27;

    // BPF map flags
    pub const BPF_ANY: u64 = 0;
    pub const BPF_F_RDONLY_PROG: u32 = 1 << 7;

    // BPF program types
    pub const BPF_PROG_TYPE_KPROBE: u32 = 2;
    pub const BPF_PROG_TYPE_TRACEPOINT: u32 = 5;
    pub const BPF_PROG_TYPE_XDP: u32 = 6;
    pub const BPF_PROG_TYPE_PERF_EVENT: u32 = 7;
    pub const BPF_PROG_TYPE_RAW_TRACEPOINT: u32 = 17;

    // BPF attach types
    pub const BPF_PERF_EVENT: u32 = 41;
    pub const BPF_XDP: u32 = 37;

    // perf_event constants (`linux/perf_event.h`)
    pub const PERF_TYPE_SOFTWARE: u32 = 1;
    pub const PERF_COUNT_SW_CPU_CLOCK: u64 = 0;
    pub const PERF_FLAG_FD_CLOEXEC: libc::c_ulong = 8;

    // `_IO('$', 0)`, `_IO('$', 1)`, `_IOW('$', 8, __u32)` on x86_64/aarch64 Linux
    const PERF_EVENT_IOC_ENABLE: libc::c_ulong = 0x2400;
    const PERF_EVENT_IOC_DISABLE: libc::c_ulong = 0x2401;
    const PERF_EVENT_IOC_SET_BPF: libc::c_ulong = 0x4004_2408;

    /// RAII wrapper around a Linux BPF FD (`map`, `prog`, or `btf`), guaranteeing close on `Drop`.
    #[derive(Debug)]
    pub struct OwnedBpfFd {
        fd: OwnedFd,
    }

    impl OwnedBpfFd {
        /// # Safety
        /// `raw_fd` must be a valid open file descriptor owned exclusively by the caller.
        pub unsafe fn from_raw(raw_fd: RawFd) -> Self {
            Self {
                // SAFETY: Caller guarantees `raw_fd` is newly opened and exclusively owned.
                fd: unsafe { OwnedFd::from_raw_fd(raw_fd) },
            }
        }

        #[must_use]
        pub fn as_raw_fd(&self) -> RawFd {
            self.fd.as_raw_fd()
        }
    }

    /// RAII wrapper for a kernel `bpf_link` FD. Closing it auto-detaches the attached program.
    #[derive(Debug)]
    pub struct BpfLinkGuard {
        fd: OwnedBpfFd,
    }

    impl BpfLinkGuard {
        #[must_use]
        pub fn as_raw_fd(&self) -> RawFd {
            self.fd.as_raw_fd()
        }
    }

    impl Drop for BpfLinkGuard {
        fn drop(&mut self) {
            let mut attr = BpfAttr::zeroed();
            attr.link_detach.link_fd = self.fd.as_raw_fd() as u32;
            let _ = sys_bpf_raw(
                BPF_LINK_DETACH,
                &attr,
                std::mem::size_of::<BpfLinkDetachAttr>(),
            );
        }
    }

    /// RAII wrapper for a `perf_event_open` attachment (kprobe/uprobe/tracepoint/CPU sampler).
    #[derive(Debug)]
    pub struct PerfEventFd {
        fd: OwnedFd,
    }

    impl PerfEventFd {
        #[must_use]
        pub fn as_raw_fd(&self) -> RawFd {
            self.fd.as_raw_fd()
        }
    }

    impl Drop for PerfEventFd {
        fn drop(&mut self) {
            // SAFETY: `self.fd` is a valid open perf_event FD; disabling before OwnedFd closes it cleanly.
            unsafe {
                libc::ioctl(self.fd.as_raw_fd(), PERF_EVENT_IOC_DISABLE as _, 0);
            }
        }
    }

    #[repr(C, align(8))]
    #[derive(Clone, Copy)]
    pub struct BpfMapCreateAttr {
        pub map_type: u32,
        pub key_size: u32,
        pub value_size: u32,
        pub max_entries: u32,
        pub map_flags: u32,
        pub inner_map_fd: u32,
        pub numa_node: u32,
        pub map_name: [u8; BPF_OBJ_NAME_LEN],
        pub map_ifindex: u32,
        pub btf_fd: u32,
        pub btf_key_type_id: u32,
        pub btf_value_type_id: u32,
        pub btf_vmlinux_value_type_id: u32,
        pub map_extra: u64,
        pub value_type_btf_obj_fd: i32,
        pub map_token_fd: i32,
    }

    #[repr(C, align(8))]
    #[derive(Clone, Copy)]
    pub struct BpfMapElemAttr {
        pub map_fd: u32,
        pub _pad: u32,
        pub key: u64,
        pub value_or_next_key: u64,
        pub flags: u64,
    }

    #[repr(C, align(8))]
    #[derive(Clone, Copy)]
    pub struct BpfProgLoadAttr {
        pub prog_type: u32,
        pub insn_cnt: u32,
        pub insns: u64,
        pub license: u64,
        pub log_level: u32,
        pub log_size: u32,
        pub log_buf: u64,
        pub kern_version: u32,
        pub prog_flags: u32,
        pub prog_name: [u8; BPF_OBJ_NAME_LEN],
        pub prog_ifindex: u32,
        pub expected_attach_type: u32,
        pub prog_btf_fd: u32,
        pub func_info_rec_size: u32,
        pub func_info: u64,
        pub func_info_cnt: u32,
        pub line_info_rec_size: u32,
        pub line_info: u64,
        pub line_info_cnt: u32,
        pub attach_btf_id: u32,
        pub attach_prog_fd: u32,
        pub core_relo_cnt: u32,
        pub fd_array: u64,
        pub core_relos: u64,
        pub core_relo_rec_size: u32,
        pub log_true_size: u32,
        pub prog_token_fd: i32,
        pub fd_array_cnt: u32,
    }

    #[repr(C, align(8))]
    #[derive(Clone, Copy)]
    pub struct BpfObjAttr {
        pub pathname: u64,
        pub bpf_fd: u32,
        pub file_flags: u32,
        pub path_fd: i32,
    }

    #[repr(C, align(8))]
    #[derive(Clone, Copy)]
    pub struct BpfTestRunAttr {
        pub prog_fd: u32,
        pub retval: u32,
        pub data_size_in: u32,
        pub data_size_out: u32,
        pub data_in: u64,
        pub data_out: u64,
        pub repeat: u32,
        pub duration: u32,
        pub ctx_size_in: u32,
        pub ctx_size_out: u32,
        pub ctx_in: u64,
        pub ctx_out: u64,
        pub flags: u32,
        pub cpu: u32,
        pub batch_size: u32,
    }

    #[repr(C, align(8))]
    #[derive(Clone, Copy)]
    pub struct BpfRawTpAttr {
        pub name: u64,
        pub prog_fd: u32,
    }

    #[repr(C, align(8))]
    #[derive(Clone, Copy)]
    pub struct BpfBtfLoadAttr {
        pub btf: u64,
        pub btf_log_buf: u64,
        pub btf_size: u32,
        pub btf_log_size: u32,
        pub btf_log_level: u32,
        pub btf_log_true_size: u32,
        pub btf_flags: u32,
        pub btf_token_fd: i32,
    }

    #[repr(C, align(8))]
    #[derive(Clone, Copy)]
    pub struct BpfLinkCreateAttr {
        pub prog_fd: u32,
        pub target_fd_or_ifindex: u32,
        pub attach_type: u32,
        pub flags: u32,
        pub extra_u64: u64,
    }

    #[repr(C, align(8))]
    #[derive(Clone, Copy)]
    pub struct BpfLinkDetachAttr {
        pub link_fd: u32,
    }

    #[repr(C, align(8))]
    #[derive(Clone, Copy)]
    pub union BpfAttr {
        pub map_create: BpfMapCreateAttr,
        pub map_elem: BpfMapElemAttr,
        pub prog_load: BpfProgLoadAttr,
        pub obj: BpfObjAttr,
        pub test_run: BpfTestRunAttr,
        pub raw_tp: BpfRawTpAttr,
        pub btf_load: BpfBtfLoadAttr,
        pub link_create: BpfLinkCreateAttr,
        pub link_detach: BpfLinkDetachAttr,
        pub raw_bytes: [u8; 160],
    }

    impl BpfAttr {
        #[must_use]
        pub fn zeroed() -> Self {
            Self {
                raw_bytes: [0u8; 160],
            }
        }
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct PerfEventAttr {
        pub type_: u32,
        pub size: u32,
        pub config: u64,
        pub sample_period_or_freq: u64,
        pub sample_type: u64,
        pub read_format: u64,
        pub flags: u64,
        pub wakeup_events_or_watermark: u32,
        pub bp_type: u32,
        pub config1_or_path: u64,
        pub config2_or_offset: u64,
        pub branch_sample_type: u64,
        pub sample_regs_user: u64,
        pub sample_stack_user: u32,
        pub clockid: i32,
        pub sample_regs_intr: u64,
        pub aux_watermark: u32,
        pub sample_max_stack: u16,
        pub __reserved_2: u16,
        pub aux_sample_size: u32,
        pub aux_action: u32,
    }

    #[inline]
    fn sys_bpf_raw(cmd: libc::c_long, attr: &BpfAttr, size: usize) -> libc::c_long {
        // SAFETY: `attr` is valid, 8-byte aligned, and `size` matches the active union variant size.
        unsafe {
            libc::syscall(
                libc::SYS_bpf,
                cmd,
                attr as *const BpfAttr as *const libc::c_void,
                size,
            )
        }
    }

    fn last_errno(op: &'static str) -> ElfBtfError {
        let err = std::io::Error::last_os_error();
        let errno = err.raw_os_error().unwrap_or(-1);
        ElfBtfError::Syscall {
            op,
            errno,
            message: err.to_string(),
        }
    }

    fn copy_bpf_name(name: &str) -> [u8; BPF_OBJ_NAME_LEN] {
        let mut buf = [0u8; BPF_OBJ_NAME_LEN];
        let bytes = name.as_bytes();
        let copy_len = bytes.len().min(BPF_OBJ_NAME_LEN - 1);
        buf[..copy_len].copy_from_slice(&bytes[..copy_len]);
        buf
    }

    pub fn bpf_map_create(
        map_type: u32,
        key_size: u32,
        value_size: u32,
        max_entries: u32,
        map_flags: u32,
        name: &str,
    ) -> Result<OwnedBpfFd, ElfBtfError> {
        let mut attr = BpfAttr::zeroed();
        attr.map_create.map_type = map_type;
        attr.map_create.key_size = key_size;
        attr.map_create.value_size = value_size;
        attr.map_create.max_entries = max_entries;
        attr.map_create.map_flags = map_flags;
        attr.map_create.map_name = copy_bpf_name(name);

        let ret = sys_bpf_raw(
            BPF_MAP_CREATE,
            &attr,
            std::mem::size_of::<BpfMapCreateAttr>(),
        );
        if ret < 0 {
            return Err(last_errno("BPF_MAP_CREATE"));
        }
        // SAFETY: Kernel returned a valid newly created BPF map FD.
        Ok(unsafe { OwnedBpfFd::from_raw(ret as RawFd) })
    }

    pub fn bpf_map_freeze(map_fd: RawFd) -> Result<(), ElfBtfError> {
        let mut attr = BpfAttr::zeroed();
        attr.map_elem.map_fd = map_fd as u32;
        let ret = sys_bpf_raw(BPF_MAP_FREEZE, &attr, 8);
        if ret < 0 {
            return Err(last_errno("BPF_MAP_FREEZE"));
        }
        Ok(())
    }

    pub fn bpf_map_update_elem(
        map_fd: RawFd,
        key: &[u8],
        value: &[u8],
        flags: u64,
    ) -> Result<(), ElfBtfError> {
        let mut attr = BpfAttr::zeroed();
        attr.map_elem.map_fd = map_fd as u32;
        attr.map_elem.key = key.as_ptr() as u64;
        attr.map_elem.value_or_next_key = value.as_ptr() as u64;
        attr.map_elem.flags = flags;
        let ret = sys_bpf_raw(
            BPF_MAP_UPDATE_ELEM,
            &attr,
            std::mem::size_of::<BpfMapElemAttr>(),
        );
        if ret < 0 {
            return Err(last_errno("BPF_MAP_UPDATE_ELEM"));
        }
        Ok(())
    }

    pub fn bpf_map_lookup_elem(
        map_fd: RawFd,
        key: &[u8],
        value_out: &mut [u8],
    ) -> Result<bool, ElfBtfError> {
        let mut attr = BpfAttr::zeroed();
        attr.map_elem.map_fd = map_fd as u32;
        attr.map_elem.key = key.as_ptr() as u64;
        attr.map_elem.value_or_next_key = value_out.as_mut_ptr() as u64;
        let ret = sys_bpf_raw(
            BPF_MAP_LOOKUP_ELEM,
            &attr,
            std::mem::size_of::<BpfMapElemAttr>(),
        );
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ENOENT) {
                return Ok(false);
            }
            return Err(last_errno("BPF_MAP_LOOKUP_ELEM"));
        }
        Ok(true)
    }

    pub fn bpf_map_delete_elem(map_fd: RawFd, key: &[u8]) -> Result<bool, ElfBtfError> {
        let mut attr = BpfAttr::zeroed();
        attr.map_elem.map_fd = map_fd as u32;
        attr.map_elem.key = key.as_ptr() as u64;
        let ret = sys_bpf_raw(
            BPF_MAP_DELETE_ELEM,
            &attr,
            std::mem::size_of::<BpfMapElemAttr>(),
        );
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ENOENT) {
                return Ok(false);
            }
            return Err(last_errno("BPF_MAP_DELETE_ELEM"));
        }
        Ok(true)
    }

    pub fn bpf_map_get_next_key(
        map_fd: RawFd,
        cur_key: Option<&[u8]>,
        next_key_out: &mut [u8],
    ) -> Result<bool, ElfBtfError> {
        let mut attr = BpfAttr::zeroed();
        attr.map_elem.map_fd = map_fd as u32;
        attr.map_elem.key = cur_key.map_or(0, |k| k.as_ptr() as u64);
        attr.map_elem.value_or_next_key = next_key_out.as_mut_ptr() as u64;
        let ret = sys_bpf_raw(
            BPF_MAP_GET_NEXT_KEY,
            &attr,
            std::mem::size_of::<BpfMapElemAttr>(),
        );
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ENOENT) {
                return Ok(false);
            }
            return Err(last_errno("BPF_MAP_GET_NEXT_KEY"));
        }
        Ok(true)
    }

    pub fn bpf_btf_load(btf_bytes: &[u8]) -> Result<OwnedBpfFd, ElfBtfError> {
        let mut log_buf = vec![0u8; 64 * 1024];
        let mut attr = BpfAttr::zeroed();
        attr.btf_load.btf = btf_bytes.as_ptr() as u64;
        attr.btf_load.btf_size = u32::try_from(btf_bytes.len())
            .map_err(|_| ElfBtfError::ArithmeticOverflow("btf_size"))?;
        attr.btf_load.btf_log_buf = log_buf.as_mut_ptr() as u64;
        attr.btf_load.btf_log_size = log_buf.len() as u32;
        attr.btf_load.btf_log_level = 1;

        let ret = sys_bpf_raw(BPF_BTF_LOAD, &attr, std::mem::size_of::<BpfBtfLoadAttr>());
        if ret < 0 {
            return Err(last_errno("BPF_BTF_LOAD"));
        }
        // SAFETY: Kernel returned a valid BTF FD.
        Ok(unsafe { OwnedBpfFd::from_raw(ret as RawFd) })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn bpf_prog_load(
        prog_type: u32,
        expected_attach_type: u32,
        prog_name: &str,
        insns: &[u64],
        license: &str,
        prog_btf_fd: Option<RawFd>,
        func_info: &[u8],
        func_info_rec_size: u32,
        line_info: &[u8],
        line_info_rec_size: u32,
    ) -> Result<OwnedBpfFd, ElfBtfError> {
        let c_lic = CString::new(license).unwrap_or_else(|_| CString::new("GPL").unwrap());
        let mut log_buf = vec![0u8; 256 * 1024];
        let mut attr = BpfAttr::zeroed();
        attr.prog_load.prog_type = prog_type;
        attr.prog_load.expected_attach_type = expected_attach_type;
        attr.prog_load.insn_cnt =
            u32::try_from(insns.len()).map_err(|_| ElfBtfError::ArithmeticOverflow("insn_cnt"))?;
        attr.prog_load.insns = insns.as_ptr() as u64;
        attr.prog_load.license = c_lic.as_ptr() as u64;
        attr.prog_load.log_level = 1;
        attr.prog_load.log_size = log_buf.len() as u32;
        attr.prog_load.log_buf = log_buf.as_mut_ptr() as u64;
        attr.prog_load.prog_name = copy_bpf_name(prog_name);

        if let Some(btf_fd) = prog_btf_fd {
            attr.prog_load.prog_btf_fd = btf_fd as u32;
            if !func_info.is_empty() && func_info_rec_size > 0 {
                attr.prog_load.func_info = func_info.as_ptr() as u64;
                attr.prog_load.func_info_rec_size = func_info_rec_size;
                attr.prog_load.func_info_cnt =
                    (func_info.len() / func_info_rec_size as usize) as u32;
            }
            if !line_info.is_empty() && line_info_rec_size > 0 {
                attr.prog_load.line_info = line_info.as_ptr() as u64;
                attr.prog_load.line_info_rec_size = line_info_rec_size;
                attr.prog_load.line_info_cnt =
                    (line_info.len() / line_info_rec_size as usize) as u32;
            }
        }

        let ret = sys_bpf_raw(BPF_PROG_LOAD, &attr, std::mem::size_of::<BpfProgLoadAttr>());
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            let errno = err.raw_os_error().unwrap_or(-1);
            let nul = log_buf
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(log_buf.len());
            let verifier_log = String::from_utf8_lossy(&log_buf[..nul]).into_owned();
            if verifier_log.is_empty() {
                return Err(ElfBtfError::Syscall {
                    op: "BPF_PROG_LOAD",
                    errno,
                    message: err.to_string(),
                });
            }
            return Err(ElfBtfError::VerifierRejected {
                prog_name: prog_name.to_owned(),
                errno,
                verifier_log,
            });
        }
        // SAFETY: Kernel returned a valid loaded eBPF program FD.
        Ok(unsafe { OwnedBpfFd::from_raw(ret as RawFd) })
    }

    pub fn bpf_prog_test_run(
        prog_fd: RawFd,
        data_in: &[u8],
        data_out: &mut [u8],
        repeat: u32,
    ) -> Result<(u32, u32, usize), ElfBtfError> {
        let mut attr = BpfAttr::zeroed();
        attr.test_run.prog_fd = prog_fd as u32;
        attr.test_run.data_size_in = u32::try_from(data_in.len())
            .map_err(|_| ElfBtfError::ArithmeticOverflow("data_size_in"))?;
        attr.test_run.data_in = data_in.as_ptr() as u64;
        attr.test_run.data_size_out = u32::try_from(data_out.len())
            .map_err(|_| ElfBtfError::ArithmeticOverflow("data_size_out"))?;
        attr.test_run.data_out = data_out.as_mut_ptr() as u64;
        attr.test_run.repeat = repeat;

        let ret = sys_bpf_raw(
            BPF_PROG_TEST_RUN,
            &attr,
            std::mem::size_of::<BpfTestRunAttr>(),
        );
        if ret < 0 {
            return Err(last_errno("BPF_PROG_TEST_RUN"));
        }
        // SAFETY: Kernel populated `retval`, `duration`, and `data_size_out` inside `attr.test_run`.
        let tr = unsafe { attr.test_run };
        Ok((tr.retval, tr.duration, tr.data_size_out as usize))
    }

    pub fn bpf_link_create(
        prog_fd: RawFd,
        target_fd_or_ifindex: u32,
        attach_type: u32,
        flags: u32,
    ) -> Result<BpfLinkGuard, ElfBtfError> {
        let mut attr = BpfAttr::zeroed();
        attr.link_create.prog_fd = prog_fd as u32;
        attr.link_create.target_fd_or_ifindex = target_fd_or_ifindex;
        attr.link_create.attach_type = attach_type;
        attr.link_create.flags = flags;
        let ret = sys_bpf_raw(
            BPF_LINK_CREATE,
            &attr,
            std::mem::size_of::<BpfLinkCreateAttr>(),
        );
        if ret < 0 {
            return Err(last_errno("BPF_LINK_CREATE"));
        }
        // SAFETY: Kernel returned a valid BPF link FD.
        Ok(BpfLinkGuard {
            fd: unsafe { OwnedBpfFd::from_raw(ret as RawFd) },
        })
    }

    pub fn bpf_raw_tracepoint_open(
        tp_name: &str,
        prog_fd: RawFd,
    ) -> Result<OwnedBpfFd, ElfBtfError> {
        let c_name = CString::new(tp_name).map_err(|_| {
            ElfBtfError::InvalidRelocation("tracepoint name contains NUL byte".to_owned())
        })?;
        let mut attr = BpfAttr::zeroed();
        attr.raw_tp.name = c_name.as_ptr() as u64;
        attr.raw_tp.prog_fd = prog_fd as u32;
        let ret = sys_bpf_raw(
            BPF_RAW_TRACEPOINT_OPEN,
            &attr,
            std::mem::size_of::<BpfRawTpAttr>(),
        );
        if ret < 0 {
            return Err(last_errno("BPF_RAW_TRACEPOINT_OPEN"));
        }
        // SAFETY: Kernel returned a valid raw tracepoint FD.
        Ok(unsafe { OwnedBpfFd::from_raw(ret as RawFd) })
    }

    pub fn bpf_obj_pin(path: &str, fd: RawFd) -> Result<(), ElfBtfError> {
        let c_path = CString::new(path)
            .map_err(|_| ElfBtfError::InvalidRelocation("pin path contains NUL byte".to_owned()))?;
        let mut attr = BpfAttr::zeroed();
        attr.obj.pathname = c_path.as_ptr() as u64;
        attr.obj.bpf_fd = fd as u32;
        let ret = sys_bpf_raw(BPF_OBJ_PIN, &attr, std::mem::size_of::<BpfObjAttr>());
        if ret < 0 {
            return Err(last_errno("BPF_OBJ_PIN"));
        }
        Ok(())
    }

    pub fn bpf_obj_get(path: &str) -> Result<OwnedBpfFd, ElfBtfError> {
        let c_path = CString::new(path)
            .map_err(|_| ElfBtfError::InvalidRelocation("obj path contains NUL byte".to_owned()))?;
        let mut attr = BpfAttr::zeroed();
        attr.obj.pathname = c_path.as_ptr() as u64;
        let ret = sys_bpf_raw(BPF_OBJ_GET, &attr, std::mem::size_of::<BpfObjAttr>());
        if ret < 0 {
            return Err(last_errno("BPF_OBJ_GET"));
        }
        // SAFETY: Kernel returned a valid pinned BPF FD.
        Ok(unsafe { OwnedBpfFd::from_raw(ret as RawFd) })
    }

    fn read_pmu_type(sysfs_path: &str) -> Result<u32, ElfBtfError> {
        let s = std::fs::read_to_string(sysfs_path)?;
        s.trim()
            .parse::<u32>()
            .map_err(|_| ElfBtfError::InvalidRelocation(format!("bad PMU type in {sysfs_path}")))
    }

    fn open_perf_event(
        attr: &PerfEventAttr,
        pid: i32,
        cpu: i32,
        prog_fd: RawFd,
    ) -> Result<PerfEventFd, ElfBtfError> {
        // SAFETY: `attr` is initialized with exact size and zeroed reserved bits.
        let raw = unsafe {
            libc::syscall(
                libc::SYS_perf_event_open,
                attr as *const PerfEventAttr as *const libc::c_void,
                pid as libc::pid_t,
                cpu as libc::c_int,
                -1 as libc::c_int,
                PERF_FLAG_FD_CLOEXEC,
            )
        };
        if raw < 0 {
            return Err(last_errno("SYS_perf_event_open"));
        }
        // SAFETY: `raw` is a valid perf_event FD just created above.
        let perf = PerfEventFd {
            fd: unsafe { OwnedFd::from_raw_fd(raw as RawFd) },
        };
        // SAFETY: `perf.fd` is a valid perf_event FD and `prog_fd` is a loaded eBPF program FD.
        let rc = unsafe { libc::ioctl(perf.as_raw_fd(), PERF_EVENT_IOC_SET_BPF as _, prog_fd) };
        if rc < 0 {
            return Err(last_errno("PERF_EVENT_IOC_SET_BPF"));
        }
        // SAFETY: Enable the configured perf_event probe atomically after BPF binding.
        let rc = unsafe { libc::ioctl(perf.as_raw_fd(), PERF_EVENT_IOC_ENABLE as _, 0) };
        if rc < 0 {
            return Err(last_errno("PERF_EVENT_IOC_ENABLE"));
        }
        Ok(perf)
    }

    /// Attach an eBPF `uprobe` or `uretprobe` at `binary_path` + `offset` via `perf_event_open`.
    pub fn attach_uprobe_perf(
        binary_path: &str,
        offset: u64,
        pid: i32,
        is_retprobe: bool,
        prog_fd: RawFd,
    ) -> Result<PerfEventFd, ElfBtfError> {
        let pmu_type = read_pmu_type("/sys/bus/event_source/devices/uprobe/type")?;
        let ret_bit = if is_retprobe { 1u64 } else { 0u64 };
        let c_path = CString::new(binary_path).map_err(|_| {
            ElfBtfError::InvalidRelocation("binary path contains NUL byte".to_owned())
        })?;
        // SAFETY: Zeroed PerfEventAttr with valid size and C string pointer alive across syscall.
        let mut attr: PerfEventAttr = unsafe { std::mem::zeroed() };
        attr.type_ = pmu_type;
        attr.size = std::mem::size_of::<PerfEventAttr>() as u32;
        attr.config = ret_bit;
        attr.config1_or_path = c_path.as_ptr() as u64;
        attr.config2_or_offset = offset;

        let cpu = if pid >= 0 { -1 } else { 0 };
        open_perf_event(&attr, pid, cpu, prog_fd)
    }

    /// Attach an eBPF `kprobe` or `kretprobe` on `func_name` via `perf_event_open`.
    pub fn attach_kprobe_perf(
        func_name: &str,
        offset: u64,
        is_retprobe: bool,
        prog_fd: RawFd,
    ) -> Result<PerfEventFd, ElfBtfError> {
        let pmu_type = read_pmu_type("/sys/bus/event_source/devices/kprobe/type")?;
        let ret_bit = if is_retprobe { 1u64 } else { 0u64 };
        let c_func = CString::new(func_name).map_err(|_| {
            ElfBtfError::InvalidRelocation("kprobe symbol contains NUL byte".to_owned())
        })?;
        // SAFETY: Zeroed PerfEventAttr with valid size and symbol pointer alive across syscall.
        let mut attr: PerfEventAttr = unsafe { std::mem::zeroed() };
        attr.type_ = pmu_type;
        attr.size = std::mem::size_of::<PerfEventAttr>() as u32;
        attr.config = ret_bit;
        attr.config1_or_path = c_func.as_ptr() as u64;
        attr.config2_or_offset = offset;
        open_perf_event(&attr, -1, 0, prog_fd)
    }

    /// Attach an eBPF tracepoint (`category/name`, e.g. `sched/sched_switch`) via tracefs ID + `perf_event_open`.
    pub fn attach_tracepoint_perf(
        category: &str,
        name: &str,
        prog_fd: RawFd,
    ) -> Result<PerfEventFd, ElfBtfError> {
        let tracefs_id_path = format!("/sys/kernel/tracing/events/{category}/{name}/id");
        let alt_path = format!("/sys/kernel/debug/tracing/events/{category}/{name}/id");
        let id_str = std::fs::read_to_string(&tracefs_id_path)
            .or_else(|_| std::fs::read_to_string(&alt_path))?;
        let tp_id = id_str.trim().parse::<u64>().map_err(|_| {
            ElfBtfError::InvalidRelocation(format!("invalid tracepoint id {category}/{name}"))
        })?;

        // SAFETY: Zeroed PerfEventAttr for PERF_TYPE_TRACEPOINT (2).
        let mut attr: PerfEventAttr = unsafe { std::mem::zeroed() };
        attr.type_ = 2; // PERF_TYPE_TRACEPOINT
        attr.size = std::mem::size_of::<PerfEventAttr>() as u32;
        attr.config = tp_id;
        attr.sample_period_or_freq = 1;
        attr.wakeup_events_or_watermark = 1;
        open_perf_event(&attr, -1, 0, prog_fd)
    }

    /// Attach a software CPU clock sampler (e.g. 99 Hz) on a specific CPU (`cpu >= 0`).
    pub fn attach_cpu_sampler_perf(
        sample_freq_hz: u64,
        pid: i32,
        cpu: i32,
        prog_fd: RawFd,
    ) -> Result<PerfEventFd, ElfBtfError> {
        // SAFETY: Zeroed PerfEventAttr for PERF_TYPE_SOFTWARE / PERF_COUNT_SW_CPU_CLOCK.
        let mut attr: PerfEventAttr = unsafe { std::mem::zeroed() };
        attr.type_ = PERF_TYPE_SOFTWARE;
        attr.size = std::mem::size_of::<PerfEventAttr>() as u32;
        attr.config = PERF_COUNT_SW_CPU_CLOCK;
        attr.sample_period_or_freq = sample_freq_hz;
        // bit 10 = `freq` (use sample_freq rather than period)
        attr.flags = 1 << 10;
        open_perf_event(&attr, pid, cpu, prog_fd)
    }

    /// RAII epoll FD waiting efficiently for RingBuf EPOLLIN notifications.
    #[derive(Debug)]
    pub struct EpollGuard {
        epfd: OwnedFd,
    }

    impl EpollGuard {
        pub fn new_for_fd(target_fd: RawFd) -> Result<Self, ElfBtfError> {
            // SAFETY: epoll_create1(EPOLL_CLOEXEC) takes only flags.
            let raw = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
            if raw < 0 {
                return Err(last_errno("epoll_create1"));
            }
            // SAFETY: `raw` is a newly created epoll FD.
            let epfd = unsafe { OwnedFd::from_raw_fd(raw) };
            let mut ev = libc::epoll_event {
                events: libc::EPOLLIN as u32,
                u64: target_fd as u64,
            };
            // SAFETY: `epfd` and `target_fd` are valid open FDs and `ev` is properly initialized.
            let rc = unsafe {
                libc::epoll_ctl(epfd.as_raw_fd(), libc::EPOLL_CTL_ADD, target_fd, &mut ev)
            };
            if rc < 0 {
                return Err(last_errno("epoll_ctl"));
            }
            Ok(Self { epfd })
        }

        pub fn wait(&self, timeout_ms: i32) -> Result<bool, ElfBtfError> {
            let mut ev = libc::epoll_event { events: 0, u64: 0 };
            // SAFETY: `self.epfd` is valid and `&mut ev` provides space for 1 event.
            let n = unsafe { libc::epoll_wait(self.epfd.as_raw_fd(), &mut ev, 1, timeout_ms) };
            if n < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    return Ok(false);
                }
                return Err(last_errno("epoll_wait"));
            }
            Ok(n > 0)
        }
    }

    #[cfg(test)]
    mod abi_tests {
        use super::*;

        #[test]
        fn bpf_prog_load_attr_offsets_match_linux_uapi() {
            assert_eq!(std::mem::offset_of!(BpfProgLoadAttr, core_relo_cnt), 116);
            assert_eq!(std::mem::offset_of!(BpfProgLoadAttr, fd_array), 120);
            assert_eq!(std::mem::offset_of!(BpfProgLoadAttr, core_relos), 128);
            assert_eq!(
                std::mem::offset_of!(BpfProgLoadAttr, core_relo_rec_size),
                136
            );
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(not(target_os = "linux"))]
mod non_linux {
    use crate::error::ElfBtfError;

    pub const BPF_MAP_TYPE_HASH: u32 = 1;
    pub const BPF_MAP_TYPE_ARRAY: u32 = 2;
    pub const BPF_MAP_TYPE_PERCPU_HASH: u32 = 5;
    pub const BPF_MAP_TYPE_PERCPU_ARRAY: u32 = 6;
    pub const BPF_MAP_TYPE_STACK_TRACE: u32 = 7;
    pub const BPF_MAP_TYPE_RINGBUF: u32 = 27;

    pub const BPF_PROG_TYPE_KPROBE: u32 = 2;
    pub const BPF_PROG_TYPE_TRACEPOINT: u32 = 5;
    pub const BPF_PROG_TYPE_XDP: u32 = 6;
    pub const BPF_PROG_TYPE_PERF_EVENT: u32 = 7;
    pub const BPF_PROG_TYPE_RAW_TRACEPOINT: u32 = 17;

    pub const BPF_ANY: u64 = 0;
    pub const BPF_XDP: u32 = 37;

    #[derive(Debug)]
    pub struct OwnedBpfFd;

    #[derive(Debug)]
    pub struct BpfLinkGuard;

    #[derive(Debug)]
    pub struct PerfEventFd;

    pub fn unsupported<T>(op: &'static str) -> Result<T, ElfBtfError> {
        Err(ElfBtfError::Syscall {
            op,
            errno: -1,
            message: "live kernel eBPF syscalls require Linux".to_owned(),
        })
    }
}

#[cfg(not(target_os = "linux"))]
pub use non_linux::*;
