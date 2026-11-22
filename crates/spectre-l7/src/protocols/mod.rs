pub mod grpc;
pub mod hpack;
pub mod http1;
pub mod http2;
pub mod postgres;
pub mod redis;

use std::collections::VecDeque;

/// Tracks byte offsets -> arrival timestamps so fragmented L7 spans report
/// exact `start_ns` (first request byte), `first_byte_ns` (first response byte),
/// and `end_ns` (last response byte).
#[derive(Debug, Default, Clone)]
pub struct TimestampStream {
    data: Vec<u8>,
    marks: VecDeque<(usize, u64)>,
    abs_head: usize,
    abs_tail: usize,
}

impl TimestampStream {
    pub fn push(&mut self, bytes: &[u8], ts_ns: u64, max_bytes: usize) {
        if bytes.is_empty() {
            return;
        }
        // Guard against slowloris / malicious unbounded connections
        if self.data.len() + bytes.len() > max_bytes {
            let overflow = (self.data.len() + bytes.len()) - max_bytes;
            let drop_n = overflow.min(self.data.len());
            if drop_n > 0 {
                self.consume(drop_n);
            }
            if bytes.len() > max_bytes {
                let tail = &bytes[bytes.len() - max_bytes..];
                self.data.extend_from_slice(tail);
                self.abs_tail += tail.len();
                self.marks.push_back((self.abs_tail, ts_ns));
                return;
            }
        }
        self.data.extend_from_slice(bytes);
        self.abs_tail += bytes.len();
        self.marks.push_back((self.abs_tail, ts_ns));
    }

    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    #[must_use]
    pub fn abs_head(&self) -> usize {
        self.abs_head
    }

    /// Timestamp associated with byte at `abs_offset`.
    #[must_use]
    pub fn ts_at(&self, abs_offset: usize) -> u64 {
        for &(end_off, ts) in &self.marks {
            if abs_offset < end_off {
                return ts;
            }
        }
        self.marks.back().map_or(0, |&(_, ts)| ts)
    }

    /// Return `(start_ts, end_ts)` covering consumed range `[abs_head .. abs_head + n)`.
    #[must_use]
    pub fn range_ts(&self, len: usize) -> (u64, u64) {
        if len == 0 {
            let t = self.ts_at(self.abs_head);
            return (t, t);
        }
        let start = self.ts_at(self.abs_head);
        let end = self.ts_at(self.abs_head + len - 1);
        (start, end)
    }

    pub fn consume(&mut self, n: usize) {
        let take = n.min(self.data.len());
        if take == 0 {
            return;
        }
        self.data.drain(..take);
        self.abs_head += take;
        while let Some(&(end_off, _)) = self.marks.front() {
            if end_off <= self.abs_head {
                self.marks.pop_front();
            } else {
                break;
            }
        }
    }
}
