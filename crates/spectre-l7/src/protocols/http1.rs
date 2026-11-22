use std::collections::VecDeque;

use memchr::memmem;

use crate::protocols::TimestampStream;
use crate::span::{ConnMeta, L7Protocol, L7Span};

const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_CONTENT_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone)]
struct PendingHttp1Req {
    method: String,
    path: String,
    host: Option<String>,
    user_agent: Option<String>,
    traceparent: Option<String>,
    request_bytes: usize,
    start_ns: u64,
}

#[derive(Debug, Default)]
pub struct Http1Decoder {
    pending: VecDeque<PendingHttp1Req>,
    next_span_id: u64,
}

enum BodyKind {
    None,
    ContentLength(usize),
    Chunked,
}

impl Http1Decoder {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn process(
        &mut self,
        meta: ConnMeta,
        egress: &mut TimestampStream,
        ingress: &mut TimestampStream,
        out_spans: &mut Vec<L7Span>,
    ) {
        self.parse_requests(egress);
        self.parse_responses(meta, ingress, out_spans);
    }

    fn parse_requests(&mut self, egress: &mut TimestampStream) {
        loop {
            let buf = egress.as_slice();
            if buf.is_empty() {
                break;
            }
            let Some(hdr_end) = memmem::find(buf, b"\r\n\r\n") else {
                if buf.len() > MAX_HEADER_BYTES {
                    // Drop malformed oversized header gracefully without panicking or OOM
                    egress.consume(buf.len() - 4);
                }
                break;
            };
            let hdr_block_len = hdr_end + 4;
            let hdr_bytes = &buf[..hdr_end];

            let mut lines = hdr_bytes.split(|&b| b == b'\n');
            let first_line = lines.next().unwrap_or(&[]);
            let first_trim = strip_cr(first_line);
            let mut parts = first_trim.split(|&b| b == b' ').filter(|s| !s.is_empty());
            let method_b = parts.next().unwrap_or(b"");
            let path_b = parts.next().unwrap_or(b"/");
            let method = String::from_utf8_lossy(method_b).into_owned();
            let path = String::from_utf8_lossy(path_b).into_owned();
            let is_http_req = is_valid_method(&method);

            let mut host = None;
            let mut user_agent = None;
            let mut traceparent = None;
            let mut content_len: Option<usize> = None;
            let mut is_chunked = false;

            for line in lines {
                let line = strip_cr(line);
                if let Some(colon) = line.iter().position(|&b| b == b':') {
                    let k = &line[..colon];
                    let v = trim_ascii(&line[colon + 1..]);
                    if k.eq_ignore_ascii_case(b"host") {
                        host = Some(String::from_utf8_lossy(v).into_owned());
                    } else if k.eq_ignore_ascii_case(b"user-agent") {
                        user_agent = Some(String::from_utf8_lossy(v).into_owned());
                    } else if k.eq_ignore_ascii_case(b"traceparent") {
                        traceparent = Some(String::from_utf8_lossy(v).into_owned());
                    } else if k.eq_ignore_ascii_case(b"content-length") {
                        if let Ok(s) = std::str::from_utf8(v) {
                            if let Ok(n) = s.trim().parse::<usize>() {
                                content_len = Some(n.min(MAX_CONTENT_BYTES));
                            }
                        }
                    } else if k.eq_ignore_ascii_case(b"transfer-encoding")
                        && contains_ignore_ascii_case(v, b"chunked")
                    {
                        is_chunked = true;
                    }
                }
            }

            let body_kind = if is_chunked {
                BodyKind::Chunked
            } else if let Some(cl) = content_len {
                BodyKind::ContentLength(cl)
            } else {
                BodyKind::None
            };

            let Some(body_consumed) = check_body_complete(&buf[hdr_block_len..], body_kind) else {
                break;
            };
            let total_req = hdr_block_len + body_consumed;
            let (start_ns, _) = egress.range_ts(total_req);
            egress.consume(total_req);

            if is_http_req {
                self.pending.push_back(PendingHttp1Req {
                    method,
                    path,
                    host,
                    user_agent,
                    traceparent,
                    request_bytes: total_req,
                    start_ns,
                });
            }
        }
    }

    fn parse_responses(
        &mut self,
        meta: ConnMeta,
        ingress: &mut TimestampStream,
        out_spans: &mut Vec<L7Span>,
    ) {
        let ConnMeta {
            conn_id,
            pid,
            fd,
            tls_source,
        } = meta;
        loop {
            let buf = ingress.as_slice();
            if buf.is_empty() {
                break;
            }
            let Some(hdr_end) = memmem::find(buf, b"\r\n\r\n") else {
                if buf.len() > MAX_HEADER_BYTES {
                    ingress.consume(buf.len() - 4);
                }
                break;
            };
            let hdr_block_len = hdr_end + 4;
            let hdr_bytes = &buf[..hdr_end];

            let mut lines = hdr_bytes.split(|&b| b == b'\n');
            let first_line = strip_cr(lines.next().unwrap_or(&[]));
            let mut status_code: u16 = 0;
            let mut parts = first_line.split(|&b| b == b' ').filter(|s| !s.is_empty());
            let _proto = parts.next();
            if let Some(code_b) = parts.next() {
                if let Ok(s) = std::str::from_utf8(code_b) {
                    status_code = s.parse::<u16>().unwrap_or(0);
                }
            }

            let mut content_len: Option<usize> = None;
            let mut is_chunked = false;
            for line in lines {
                let line = strip_cr(line);
                if let Some(colon) = line.iter().position(|&b| b == b':') {
                    let k = &line[..colon];
                    let v = trim_ascii(&line[colon + 1..]);
                    if k.eq_ignore_ascii_case(b"content-length") {
                        if let Ok(s) = std::str::from_utf8(v) {
                            if let Ok(n) = s.trim().parse::<usize>() {
                                content_len = Some(n.min(MAX_CONTENT_BYTES));
                            }
                        }
                    } else if k.eq_ignore_ascii_case(b"transfer-encoding")
                        && contains_ignore_ascii_case(v, b"chunked")
                    {
                        is_chunked = true;
                    }
                }
            }

            let is_head_req = self
                .pending
                .front()
                .is_some_and(|r| r.method.eq_ignore_ascii_case("HEAD"));
            let no_body_status = (100..200).contains(&status_code)
                || status_code == 204
                || status_code == 304
                || is_head_req;

            let body_kind = if no_body_status {
                BodyKind::None
            } else if is_chunked {
                BodyKind::Chunked
            } else if let Some(cl) = content_len {
                BodyKind::ContentLength(cl)
            } else {
                BodyKind::None
            };

            let Some(body_consumed) = check_body_complete(&buf[hdr_block_len..], body_kind) else {
                break;
            };
            let total_resp = hdr_block_len + body_consumed;
            let (first_byte_ns, end_ns) = ingress.range_ts(total_resp);
            ingress.consume(total_resp);

            // Skip intermediate 1xx responses while preserving queued request
            if (100..200).contains(&status_code) && status_code != 101 {
                continue;
            }

            self.next_span_id += 1;
            let req = self.pending.pop_front().unwrap_or(PendingHttp1Req {
                method: "UNKNOWN".to_owned(),
                path: "/".to_owned(),
                host: None,
                user_agent: None,
                traceparent: None,
                request_bytes: 0,
                start_ns: first_byte_ns,
            });

            let start_ns = if req.start_ns == 0 {
                first_byte_ns
            } else {
                req.start_ns
            };
            let latency_ns = end_ns.saturating_sub(start_ns);
            let is_err = status_code >= 500 || status_code == 0;

            out_spans.push(L7Span {
                span_id: self.next_span_id,
                conn_id,
                pid,
                fd,
                protocol: L7Protocol::Http1,
                method: req.method,
                path_or_query: req.path,
                host: req.host,
                user_agent: req.user_agent,
                status_code,
                request_bytes: req.request_bytes,
                response_bytes: total_resp,
                start_ns,
                first_byte_ns,
                end_ns,
                latency_ns,
                traceparent: req.traceparent,
                grpc: None,
                sql_fingerprint: None,
                redis_key_prefix: None,
                error: is_err,
                error_detail: is_err.then(|| format!("HTTP {status_code}")),
                tls_source,
            });
        }
    }
}

fn check_body_complete(body: &[u8], kind: BodyKind) -> Option<usize> {
    match kind {
        BodyKind::None => Some(0),
        BodyKind::ContentLength(cl) => (body.len() >= cl).then_some(cl),
        BodyKind::Chunked => parse_chunked_total_len(body),
    }
}

fn parse_chunked_total_len(buf: &[u8]) -> Option<usize> {
    let mut cur = 0usize;
    for _ in 0..16_384 {
        let rem = &buf[cur..];
        let line_end = memmem::find(rem, b"\r\n")?;
        let line = &rem[..line_end];
        let size_part = match line.iter().position(|&b| b == b';') {
            Some(semi) => &line[..semi],
            None => line,
        };
        let size_str = std::str::from_utf8(trim_ascii(size_part)).ok()?;
        let chunk_sz = usize::from_str_radix(size_str, 16)
            .ok()?
            .min(MAX_CONTENT_BYTES);
        cur += line_end + 2;

        if chunk_sz == 0 {
            // Optional trailer headers terminated by CRLF; empty trailers start immediately with "\r\n".
            let after_zero = &buf[cur..];
            if after_zero.starts_with(b"\r\n") {
                return Some(cur + 2);
            }
            let trailer_end = memmem::find(after_zero, b"\r\n\r\n")?;
            return Some(cur + trailer_end + 4);
        }

        let need = chunk_sz.checked_add(2)?;
        if buf.len().saturating_sub(cur) < need {
            return None;
        }
        if &buf[cur + chunk_sz..cur + need] != b"\r\n" {
            // Malformed CRLF boundary; consume through here safely to avoid deadlock
            return Some(cur + chunk_sz);
        }
        cur += need;
    }
    Some(cur)
}

#[inline]
fn strip_cr(s: &[u8]) -> &[u8] {
    s.strip_suffix(b"\r").unwrap_or(s)
}

#[inline]
fn trim_ascii(mut s: &[u8]) -> &[u8] {
    while let Some((&first, rest)) = s.split_first() {
        if first.is_ascii_whitespace() {
            s = rest;
        } else {
            break;
        }
    }
    while let Some((&last, rest)) = s.split_last() {
        if last.is_ascii_whitespace() {
            s = rest;
        } else {
            break;
        }
    }
    s
}

#[inline]
fn contains_ignore_ascii_case(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || hay.len() < needle.len() {
        return false;
    }
    hay.windows(needle.len())
        .any(|w| w.eq_ignore_ascii_case(needle))
}

#[inline]
fn is_valid_method(m: &str) -> bool {
    matches!(
        m,
        "GET" | "POST" | "PUT" | "DELETE" | "HEAD" | "OPTIONS" | "PATCH" | "CONNECT" | "TRACE"
    )
}
