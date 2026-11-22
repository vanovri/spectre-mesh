//! Lock-free zero-copy `BPF_MAP_TYPE_RINGBUF` consumer & portable Miri-verifiable double-mapped simulator.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::error::ElfBtfError;

pub const BPF_RINGBUF_BUSY_BIT: u32 = 1 << 31;
pub const BPF_RINGBUF_DISCARD_BIT: u32 = 1 << 30;
pub const BPF_RINGBUF_HDR_SZ: usize = 8;
const RINGBUF_LEN_MASK: u32 = 0x3FFF_FFFF;

#[inline]
#[must_use]
pub const fn round_up_8(n: usize) -> usize {
    (n + 7) & !7
}

/// Validates and computes Linux `BPF_MAP_TYPE_RINGBUF` power-of-two ring layout parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RingBufLayout {
    pub page_size: usize,
    pub ring_size: usize,
    pub mask: u64,
}

impl RingBufLayout {
    pub fn new(page_size: usize, ring_size: usize) -> Result<Self, ElfBtfError> {
        if page_size == 0 || !page_size.is_power_of_two() {
            return Err(ElfBtfError::InvalidRingBuf(
                "page_size must be a power of 2",
            ));
        }
        if ring_size < page_size || !ring_size.is_power_of_two() {
            return Err(ElfBtfError::InvalidRingBuf(
                "ring_size must be >= page_size and a power of 2",
            ));
        }
        Ok(Self {
            page_size,
            ring_size,
            mask: (ring_size - 1) as u64,
        })
    }
}

/// Portable in-memory simulation of the Linux kernel double-`mmap`ed RingBuf region.
/// Allows testing exact wrap-around contiguous slice extraction, `BPF_RINGBUF_BUSY_BIT`,
/// `BPF_RINGBUF_DISCARD_BIT`, and `Acquire`/`Release` barriers under `cargo +nightly miri test`.
pub struct SimulatedRingBuf {
    layout: RingBufLayout,
    consumer_pos: Box<AtomicU64>,
    producer_pos: Box<AtomicU64>,
    /// Twice `ring_size`, keeping `[0..ring_size]` and `[ring_size..2*ring_size]` mirrored.
    doubled_data: Vec<u8>,
}

impl SimulatedRingBuf {
    pub fn new(ring_size: usize) -> Result<Self, ElfBtfError> {
        let layout = RingBufLayout::new(4096, ring_size)?;
        Ok(Self {
            layout,
            consumer_pos: Box::new(AtomicU64::new(0)),
            producer_pos: Box::new(AtomicU64::new(0)),
            doubled_data: vec![0u8; ring_size * 2],
        })
    }

    /// Reserve and commit (or leave busy / discard) a record like kernel `bpf_ringbuf_reserve`.
    pub fn produce(
        &mut self,
        payload: &[u8],
        busy: bool,
        discard: bool,
    ) -> Result<u64, ElfBtfError> {
        let total = BPF_RINGBUF_HDR_SZ + round_up_8(payload.len());
        if total > self.layout.ring_size {
            return Err(ElfBtfError::InvalidRingBuf("record larger than ring"));
        }
        let cons = self.consumer_pos.load(Ordering::Acquire);
        let prod = self.producer_pos.load(Ordering::Relaxed);
        if (prod - cons) as usize + total > self.layout.ring_size {
            return Err(ElfBtfError::InvalidRingBuf("ring buffer full"));
        }

        let off = (prod & self.layout.mask) as usize;
        let len_u32 = u32::try_from(payload.len())
            .map_err(|_| ElfBtfError::InvalidRingBuf("payload too large"))?;
        let mut hdr = len_u32 & RINGBUF_LEN_MASK;
        if busy {
            hdr |= BPF_RINGBUF_BUSY_BIT;
        }
        if discard {
            hdr |= BPF_RINGBUF_DISCARD_BIT;
        }
        let pg_off = off / 4096;
        let hdr_bytes = hdr.to_le_bytes();
        let pg_bytes = (pg_off as u32).to_le_bytes();
        self.write_mirrored(off, &hdr_bytes);
        self.write_mirrored(off + 4, &pg_bytes);
        self.write_mirrored(off + BPF_RINGBUF_HDR_SZ, payload);

        self.producer_pos
            .store(prod + total as u64, Ordering::Release);
        Ok(prod)
    }

    /// Commit a previously `busy=true` record at `prod_offset`.
    pub fn commit_busy(&mut self, prod_offset: u64, payload_len: usize, discard: bool) {
        let off = (prod_offset & self.layout.mask) as usize;
        let mut hdr = (payload_len as u32) & RINGBUF_LEN_MASK;
        if discard {
            hdr |= BPF_RINGBUF_DISCARD_BIT;
        }
        self.write_mirrored(off, &hdr.to_le_bytes());
        std::sync::atomic::fence(Ordering::Release);
    }

    fn write_mirrored(&mut self, offset: usize, bytes: &[u8]) {
        let rs = self.layout.ring_size;
        for (i, &b) in bytes.iter().enumerate() {
            let pos1 = (offset + i) % rs;
            let pos2 = pos1 + rs;
            self.doubled_data[pos1] = b;
            self.doubled_data[pos2] = b;
        }
    }

    /// Consume all non-busy records zero-copy via contiguous slices across the doubled mapping.
    pub fn consume<F>(&self, mut on_record: F) -> usize
    where
        F: FnMut(&[u8]),
    {
        let mut cons_pos = self.consumer_pos.load(Ordering::Relaxed);
        let prod_pos = self.producer_pos.load(Ordering::Acquire);
        let mut processed = 0usize;

        while cons_pos < prod_pos {
            let off = (cons_pos & self.layout.mask) as usize;
            let hdr_slice = &self.doubled_data[off..off + 4];
            let hdr_word =
                u32::from_le_bytes([hdr_slice[0], hdr_slice[1], hdr_slice[2], hdr_slice[3]]);
            std::sync::atomic::fence(Ordering::Acquire);

            if (hdr_word & BPF_RINGBUF_BUSY_BIT) != 0 {
                break;
            }
            let len = (hdr_word & RINGBUF_LEN_MASK) as usize;
            let step = (BPF_RINGBUF_HDR_SZ + round_up_8(len)) as u64;
            if (hdr_word & BPF_RINGBUF_DISCARD_BIT) == 0 {
                let data_start = off + BPF_RINGBUF_HDR_SZ;
                on_record(&self.doubled_data[data_start..data_start + len]);
                processed += 1;
            }
            cons_pos += step;
            self.consumer_pos.store(cons_pos, Ordering::Release);
        }
        processed
    }

    #[must_use]
    pub fn consumer_pos(&self) -> u64 {
        self.consumer_pos.load(Ordering::Acquire)
    }

    #[must_use]
    pub fn producer_pos(&self) -> u64 {
        self.producer_pos.load(Ordering::Acquire)
    }
}

/// Atomic header read helper used by Linux `RingBufConsumer`.
#[inline]
#[allow(dead_code)]
fn atomic_load_u32_acquire(ptr: *const u8) -> u32 {
    // SAFETY: Caller guarantees `ptr` is 8-byte aligned within the valid producer/data mmap region.
    let atom = unsafe { &*(ptr as *const AtomicU32) };
    atom.load(Ordering::Acquire)
}

#[cfg(target_os = "linux")]
mod linux_ringbuf {
    use super::*;
    use crate::syscall::EpollGuard;
    use std::os::fd::RawFd;
    use std::ptr::NonNull;

    /// Lock-free zero-copy double-`mmap`ed `BPF_MAP_TYPE_RINGBUF` consumer.
    pub struct RingBufConsumer {
        layout: RingBufLayout,
        consumer_ptr: NonNull<u8>,
        producer_ptr: NonNull<u8>,
        data_ptr: *const u8,
        epoll: EpollGuard,
    }

    // SAFETY: Consumer owns exclusive access to `consumer_ptr` mmap page; `producer_ptr` & `data_ptr`
    // are read-only shared kernel mappings accessed exclusively via atomic Acquire barriers.
    unsafe impl Send for RingBufConsumer {}

    impl RingBufConsumer {
        /// Map an existing `BPF_MAP_TYPE_RINGBUF` FD with `ring_size` (must match `max_entries`).
        pub fn new(map_fd: RawFd, ring_size: usize) -> Result<Self, ElfBtfError> {
            // SAFETY: `sysconf(_SC_PAGESIZE)` returns the kernel page size (> 0).
            let pg = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
            let page_size =
                usize::try_from(pg).map_err(|_| ElfBtfError::InvalidRingBuf("bad page_size"))?;
            let layout = RingBufLayout::new(page_size, ring_size)?;

            // SAFETY: Map page 0 (RW) for `consumer_pos` at offset 0.
            let cons_raw = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    page_size,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED,
                    map_fd,
                    0,
                )
            };
            if cons_raw == libc::MAP_FAILED {
                return Err(ElfBtfError::Io(std::io::Error::last_os_error()));
            }
            let consumer_ptr = NonNull::new(cons_raw as *mut u8)
                .ok_or(ElfBtfError::InvalidRingBuf("null mmap consumer_ptr"))?;

            // SAFETY: Map page 1 (`producer_pos`) + 2 * `ring_size` (double-mapped ring data) at offset `page_size`.
            let prod_map_len = page_size + 2 * ring_size;
            let prod_raw = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    prod_map_len,
                    libc::PROT_READ,
                    libc::MAP_SHARED,
                    map_fd,
                    page_size as libc::off_t,
                )
            };
            if prod_raw == libc::MAP_FAILED {
                let err = std::io::Error::last_os_error();
                // SAFETY: Clean up `consumer_ptr` before returning error.
                unsafe {
                    libc::munmap(consumer_ptr.as_ptr() as *mut libc::c_void, page_size);
                }
                return Err(ElfBtfError::Io(err));
            }
            let producer_ptr = NonNull::new(prod_raw as *mut u8)
                .ok_or(ElfBtfError::InvalidRingBuf("null mmap producer_ptr"))?;

            // SAFETY: `producer_ptr + page_size` points directly to the start of the doubly-mapped data ring.
            let data_ptr = unsafe { producer_ptr.as_ptr().add(page_size) as *const u8 };

            let epoll = match EpollGuard::new_for_fd(map_fd) {
                Ok(e) => e,
                Err(err) => {
                    // SAFETY: Clean up both mappings on error.
                    unsafe {
                        libc::munmap(consumer_ptr.as_ptr() as *mut libc::c_void, page_size);
                        libc::munmap(producer_ptr.as_ptr() as *mut libc::c_void, prod_map_len);
                    }
                    return Err(err);
                }
            };

            Ok(Self {
                layout,
                consumer_ptr,
                producer_ptr,
                data_ptr,
                epoll,
            })
        }

        #[inline]
        fn consumer_atomic(&self) -> &AtomicU64 {
            // SAFETY: `consumer_ptr` is page-aligned (`>= 8B`) and mapped RW for `page_size` bytes.
            unsafe { &*(self.consumer_ptr.as_ptr() as *const AtomicU64) }
        }

        #[inline]
        fn producer_atomic(&self) -> &AtomicU64 {
            // SAFETY: `producer_ptr` is page-aligned (`>= 8B`) and mapped RO for `page_size + 2*ring_size` bytes.
            unsafe { &*(self.producer_ptr.as_ptr() as *const AtomicU64) }
        }

        /// Drain all currently committed RingBuf records without copying across wrap boundaries.
        pub fn consume_available<F>(&mut self, mut on_record: F) -> usize
        where
            F: FnMut(&[u8]),
        {
            let mut cons_pos = self.consumer_atomic().load(Ordering::Relaxed);
            let prod_pos = self.producer_atomic().load(Ordering::Acquire);
            let mut count = 0usize;

            while cons_pos < prod_pos {
                let off = (cons_pos & self.layout.mask) as usize;
                // SAFETY: `off < ring_size`, and kernel guarantees headers are 8-byte aligned inside doubled mapping.
                let hdr_ptr = unsafe { self.data_ptr.add(off) };
                let hdr = atomic_load_u32_acquire(hdr_ptr);
                if (hdr & BPF_RINGBUF_BUSY_BIT) != 0 {
                    break;
                }
                let len = (hdr & RINGBUF_LEN_MASK) as usize;
                let step = (BPF_RINGBUF_HDR_SZ + round_up_8(len)) as u64;
                if (hdr & BPF_RINGBUF_DISCARD_BIT) == 0 && len <= self.layout.ring_size {
                    // SAFETY: Because data is doubly mapped (`2 * ring_size`), `off + 8 + len <= 2 * ring_size`
                    // forms a single contiguous slice even when wrapping past `ring_size`.
                    let payload = unsafe {
                        std::slice::from_raw_parts(self.data_ptr.add(off + BPF_RINGBUF_HDR_SZ), len)
                    };
                    on_record(payload);
                    count += 1;
                }
                cons_pos += step;
                self.consumer_atomic().store(cons_pos, Ordering::Release);
            }
            count
        }

        /// Poll via `epoll_wait` up to `timeout_ms` and consume any available records.
        pub fn poll<F>(&mut self, timeout_ms: i32, mut on_record: F) -> Result<usize, ElfBtfError>
        where
            F: FnMut(&[u8]),
        {
            let drained = self.consume_available(&mut on_record);
            if drained > 0 {
                return Ok(drained);
            }
            if self.epoll.wait(timeout_ms)? {
                return Ok(self.consume_available(on_record));
            }
            Ok(0)
        }
    }

    impl Drop for RingBufConsumer {
        fn drop(&mut self) {
            let prod_map_len = self.layout.page_size + 2 * self.layout.ring_size;
            // SAFETY: Both pointers were mapped in `new` with these exact lengths.
            unsafe {
                libc::munmap(
                    self.consumer_ptr.as_ptr() as *mut libc::c_void,
                    self.layout.page_size,
                );
                libc::munmap(
                    self.producer_ptr.as_ptr() as *mut libc::c_void,
                    prod_map_len,
                );
            }
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux_ringbuf::RingBufConsumer;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn miri_ringbuf_wrap_busy_discard_zero_copy() {
        let mut rb = SimulatedRingBuf::new(4096).expect("4096 ring");
        // Fill near the end of 4096-byte ring so the next record straddles the wrap boundary!
        let big = vec![0xAAu8; 3992]; // 8 + 3992 = 4000 bytes
        let p0 = rb.produce(&big, false, false).unwrap();
        assert_eq!(p0, 0);

        let mut seen = Vec::new();
        assert_eq!(rb.consume(|s| seen.push(s.to_vec())), 1);
        assert_eq!(seen[0].len(), 3992);

        // Now cons_pos == prod_pos == 4000. Produce a 128-byte record wrapping across 4096!
        let wrap_payload: Vec<u8> = (0u8..128).collect();
        let p1 = rb.produce(&wrap_payload, true, false).unwrap();
        assert_eq!(p1, 4000);
        // Busy bit prevents premature read
        assert_eq!(rb.consume(|_| panic!("must not read busy record")), 0);

        // Commit busy record -> now readable as a single contiguous slice across 4096 boundary!
        rb.commit_busy(p1, wrap_payload.len(), false);
        let mut wrapped_out = None;
        assert_eq!(
            rb.consume(|s| {
                wrapped_out = Some(s.to_vec());
            }),
            1
        );
        assert_eq!(wrapped_out.as_deref(), Some(wrap_payload.as_slice()));

        // Discarded record must advance consumer_pos without invoking callback
        let _ = rb.produce(b"discard-me", false, true).unwrap();
        let mut called = false;
        assert_eq!(rb.consume(|_| called = true), 0);
        assert!(!called);
        assert_eq!(rb.consumer_pos(), rb.producer_pos());
    }
}
