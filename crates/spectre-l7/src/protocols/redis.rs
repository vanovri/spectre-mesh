use std::collections::VecDeque;

use memchr::memmem;

use crate::protocols::TimestampStream;
use crate::span::{ConnMeta, L7Protocol, L7Span};

const MAX_RESP_DEPTH: usize = 64;
const MAX_RESP_ELEMS: usize = 4096;
const MAX_BULK_BYTES: usize = 1_048_576;

#[derive(Debug, Clone)]
enum RespValue {
    Simple(String),
    Error(String),
    Integer,
    Bulk(Option<Vec<u8>>),
    Array(Vec<RespValue>),
    Null,
}

#[derive(Debug)]
enum FrameBuilder {
    Aggregate {
        target: usize,
        items: Vec<RespValue>,
    },
}

#[derive(Debug, Clone)]
struct PendingRedisCmd {
    cmd: String,
    key_prefix: Option<String>,
    full_cmd: String,
    req_bytes: usize,
    start_ns: u64,
}

#[derive(Debug, Default)]
pub struct RedisDecoder {
    pending: VecDeque<PendingRedisCmd>,
    next_span_id: u64,
}

impl RedisDecoder {
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
            match parse_one_resp(buf) {
                ParseOutcome::Incomplete => break,
                ParseOutcome::Invalid => {
                    egress.consume(1);
                }
                ParseOutcome::Complete(val, consumed) => {
                    let (start_ns, _) = egress.range_ts(consumed);
                    egress.consume(consumed);
                    let (cmd, key_prefix, full_cmd) = extract_redis_command(&val);
                    self.pending.push_back(PendingRedisCmd {
                        cmd,
                        key_prefix,
                        full_cmd,
                        req_bytes: consumed,
                        start_ns,
                    });
                }
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
            match parse_one_resp(buf) {
                ParseOutcome::Incomplete => break,
                ParseOutcome::Invalid => {
                    ingress.consume(1);
                }
                ParseOutcome::Complete(val, consumed) => {
                    let (first_byte_ns, end_ns) = ingress.range_ts(consumed);
                    ingress.consume(consumed);

                    let (is_err, err_msg) = match val {
                        RespValue::Error(e) => (true, Some(e)),
                        _ => (false, None),
                    };

                    let req = self.pending.pop_front().unwrap_or(PendingRedisCmd {
                        cmd: "REDIS".to_owned(),
                        key_prefix: None,
                        full_cmd: "REDIS".to_owned(),
                        req_bytes: 0,
                        start_ns: first_byte_ns,
                    });

                    self.next_span_id += 1;
                    let start_ns = if req.start_ns == 0 {
                        first_byte_ns
                    } else {
                        req.start_ns
                    };

                    out_spans.push(L7Span {
                        span_id: self.next_span_id,
                        conn_id,
                        pid,
                        fd,
                        protocol: L7Protocol::Redis,
                        method: req.cmd,
                        path_or_query: req.full_cmd,
                        host: None,
                        user_agent: None,
                        status_code: if is_err { 500 } else { 200 },
                        request_bytes: req.req_bytes,
                        response_bytes: consumed,
                        start_ns,
                        first_byte_ns,
                        end_ns,
                        latency_ns: end_ns.saturating_sub(start_ns),
                        traceparent: None,
                        grpc: None,
                        sql_fingerprint: None,
                        redis_key_prefix: req.key_prefix,
                        error: is_err,
                        error_detail: err_msg,
                        tls_source,
                    });
                }
            }
        }
    }
}

enum ParseOutcome {
    Incomplete,
    Invalid,
    Complete(RespValue, usize),
}

fn parse_one_resp(buf: &[u8]) -> ParseOutcome {
    let mut stack: Vec<FrameBuilder> = Vec::new();
    let mut cur = 0usize;

    for _ in 0..32_768 {
        if cur >= buf.len() {
            return ParseOutcome::Incomplete;
        }
        let prefix = buf[cur];
        let rem = &buf[cur..];
        let Some(crlf) = memmem::find(rem, b"\r\n") else {
            return ParseOutcome::Incomplete;
        };
        if crlf == 0 {
            return ParseOutcome::Invalid;
        }
        let line = &rem[1..crlf];
        let after_line = cur + crlf + 2;

        enum Step {
            Leaf(RespValue),
            PushAgg(usize),
        }

        let step = match prefix {
            b'+' | b'(' | b'_' | b'#' | b',' => {
                cur = after_line;
                if prefix == b'_' {
                    Step::Leaf(RespValue::Null)
                } else {
                    Step::Leaf(RespValue::Simple(
                        String::from_utf8_lossy(line).into_owned(),
                    ))
                }
            }
            b'-' => {
                cur = after_line;
                Step::Leaf(RespValue::Error(String::from_utf8_lossy(line).into_owned()))
            }
            b':' => {
                cur = after_line;
                Step::Leaf(RespValue::Integer)
            }
            b'$' | b'!' | b'=' => {
                let Ok(len_s) = std::str::from_utf8(line) else {
                    return ParseOutcome::Invalid;
                };
                let Ok(n) = len_s.parse::<isize>() else {
                    return ParseOutcome::Invalid;
                };
                if n < 0 {
                    cur = after_line;
                    Step::Leaf(RespValue::Bulk(None))
                } else {
                    let ulen = (n as usize).min(MAX_BULK_BYTES);
                    let Some(end) = after_line.checked_add(ulen).and_then(|v| v.checked_add(2))
                    else {
                        return ParseOutcome::Invalid;
                    };
                    if end > buf.len() {
                        return ParseOutcome::Incomplete;
                    }
                    let slice = &buf[after_line..after_line + ulen];
                    cur = end;
                    if prefix == b'!' {
                        Step::Leaf(RespValue::Error(
                            String::from_utf8_lossy(slice).into_owned(),
                        ))
                    } else {
                        Step::Leaf(RespValue::Bulk(Some(slice.to_vec())))
                    }
                }
            }
            b'*' | b'~' | b'>' | b'%' | b'|' => {
                let Ok(len_s) = std::str::from_utf8(line) else {
                    return ParseOutcome::Invalid;
                };
                let Ok(n) = len_s.parse::<isize>() else {
                    return ParseOutcome::Invalid;
                };
                cur = after_line;
                if n <= 0 {
                    Step::Leaf(RespValue::Array(Vec::new()))
                } else {
                    let count = (n as usize).min(MAX_RESP_ELEMS);
                    let elem_target = if prefix == b'%' || prefix == b'|' {
                        count.saturating_mul(2).min(MAX_RESP_ELEMS * 2)
                    } else {
                        count
                    };
                    Step::PushAgg(elem_target)
                }
            }
            _ => {
                // Inline Redis command terminated by CRLF
                if !rem[..crlf].is_empty() && rem[..crlf].iter().all(|&b| b.is_ascii()) {
                    let inline = String::from_utf8_lossy(&rem[..crlf]).into_owned();
                    let items: Vec<RespValue> = inline
                        .split_whitespace()
                        .map(|w| RespValue::Bulk(Some(w.as_bytes().to_vec())))
                        .collect();
                    cur = after_line;
                    Step::Leaf(RespValue::Array(items))
                } else {
                    return ParseOutcome::Invalid;
                }
            }
        };

        match step {
            Step::PushAgg(target) => {
                if stack.len() >= MAX_RESP_DEPTH {
                    return ParseOutcome::Invalid;
                }
                stack.push(FrameBuilder::Aggregate {
                    target,
                    items: Vec::with_capacity(target.min(16)),
                });
            }
            Step::Leaf(mut finished) => loop {
                let Some(mut top) = stack.pop() else {
                    return ParseOutcome::Complete(finished, cur);
                };
                let FrameBuilder::Aggregate {
                    target,
                    ref mut items,
                } = top;
                items.push(finished);
                if items.len() < target {
                    stack.push(top);
                    break;
                }
                finished = RespValue::Array(match top {
                    FrameBuilder::Aggregate { items, .. } => items,
                });
            },
        }
    }
    ParseOutcome::Invalid
}

fn extract_redis_command(val: &RespValue) -> (String, Option<String>, String) {
    let items: &[RespValue] = match val {
        RespValue::Array(v) => v.as_slice(),
        _ => return ("PING".to_owned(), None, "PING".to_owned()),
    };
    let get_str = |idx: usize| -> Option<String> {
        match items.get(idx)? {
            RespValue::Bulk(Some(b)) => Some(String::from_utf8_lossy(b).into_owned()),
            RespValue::Simple(s) => Some(s.clone()),
            _ => None,
        }
    };
    let cmd = get_str(0)
        .unwrap_or_else(|| "UNKNOWN".to_owned())
        .to_ascii_uppercase();
    let key = get_str(1);
    let key_prefix = key.as_ref().map(|k| {
        if let Some(colon) = k.find(':') {
            k[..=colon].to_owned()
        } else {
            k.clone()
        }
    });
    let full = if let Some(ref k) = key {
        format!("{cmd} {k}")
    } else {
        cmd.clone()
    };
    (cmd, key_prefix, full)
}
