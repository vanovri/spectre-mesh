use std::collections::{HashMap, VecDeque};

use crate::protocols::TimestampStream;
use crate::span::{ConnMeta, L7Protocol, L7Span};

const MAX_PG_FRAME_LEN: usize = 1_048_576;

#[derive(Debug, Clone)]
struct PendingPgQuery {
    verb: String,
    fingerprint: String,
    req_bytes: usize,
    start_ns: u64,
}

#[derive(Debug, Default)]
pub struct PostgresDecoder {
    statements: HashMap<String, String>,
    portals: HashMap<String, String>,
    pending: VecDeque<PendingPgQuery>,
    cur_resp_bytes: usize,
    cur_first_byte_ns: Option<u64>,
    cur_rows: u64,
    cur_error: Option<(String, String)>,
    next_span_id: u64,
}

impl PostgresDecoder {
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
        self.parse_frontend(egress);
        self.parse_backend(meta, ingress, out_spans);
    }

    fn parse_frontend(&mut self, egress: &mut TimestampStream) {
        loop {
            let buf = egress.as_slice();
            if buf.is_empty() {
                break;
            }
            // Untagged Startup / SSLRequest / CancelRequest packet
            if buf[0] == 0 {
                if buf.len() < 8 {
                    break;
                }
                let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
                if !(8..=16_384).contains(&len) {
                    egress.consume(1);
                    continue;
                }
                if buf.len() < len {
                    break;
                }
                egress.consume(len);
                continue;
            }

            if buf.len() < 5 {
                break;
            }
            let tag = buf[0];
            let body_plus_4 = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
            if !(4..=MAX_PG_FRAME_LEN).contains(&body_plus_4) {
                egress.consume(1);
                continue;
            }
            let total_len = 1 + body_plus_4;
            if buf.len() < total_len {
                break;
            }

            let payload = &buf[5..total_len];
            let (start_ns, _) = egress.range_ts(total_len);

            match tag {
                b'Q' => {
                    let sql = read_cstr_lossy(payload);
                    let fp = sanitize_sql(&sql);
                    let verb = extract_sql_verb(&fp);
                    self.pending.push_back(PendingPgQuery {
                        verb,
                        fingerprint: fp,
                        req_bytes: total_len,
                        start_ns,
                    });
                }
                b'P' => {
                    if let Some(nul1) = payload.iter().position(|&b| b == 0) {
                        let stmt = String::from_utf8_lossy(&payload[..nul1]).into_owned();
                        let query = read_cstr_lossy(&payload[nul1 + 1..]);
                        self.statements.insert(stmt, sanitize_sql(&query));
                    }
                }
                b'B' => {
                    if let Some(nul1) = payload.iter().position(|&b| b == 0) {
                        let portal = String::from_utf8_lossy(&payload[..nul1]).into_owned();
                        let stmt = read_cstr_lossy(&payload[nul1 + 1..]);
                        self.portals.insert(portal, stmt);
                    }
                }
                b'E' => {
                    let portal = read_cstr_lossy(payload);
                    let stmt_name = self.portals.get(&portal).cloned().unwrap_or(portal);
                    let fp = self
                        .statements
                        .get(&stmt_name)
                        .cloned()
                        .unwrap_or_else(|| format!("EXECUTE {stmt_name}"));
                    let verb = extract_sql_verb(&fp);
                    self.pending.push_back(PendingPgQuery {
                        verb,
                        fingerprint: fp,
                        req_bytes: total_len,
                        start_ns,
                    });
                }
                _ => {}
            }
            egress.consume(total_len);
        }
    }

    fn parse_backend(
        &mut self,
        meta: ConnMeta,
        ingress: &mut TimestampStream,
        out_spans: &mut Vec<L7Span>,
    ) {
        loop {
            let buf = ingress.as_slice();
            if buf.is_empty() {
                break;
            }
            // Single-byte SSL response 'N' or 'S' (NoticeResponse is 'N' followed by 0x00 BE length)
            if (buf[0] == b'N' || buf[0] == b'S') && (buf.len() == 1 || buf[1] != 0) {
                ingress.consume(1);
                continue;
            }
            if buf.len() < 5 {
                break;
            }
            let tag = buf[0];
            let body_plus_4 = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
            if !(4..=MAX_PG_FRAME_LEN).contains(&body_plus_4) {
                ingress.consume(1);
                continue;
            }
            let total_len = 1 + body_plus_4;
            if buf.len() < total_len {
                break;
            }

            let payload = &buf[5..total_len];
            let (ts_first, ts_end) = ingress.range_ts(total_len);

            if self.cur_first_byte_ns.is_none()
                && !matches!(tag, b'R' | b'K' | b'S' | b'1' | b'2' | b'3' | b'N')
            {
                self.cur_first_byte_ns = Some(ts_first);
            }
            if !matches!(tag, b'R' | b'K' | b'S' | b'N') {
                self.cur_resp_bytes += total_len;
            }

            match tag {
                b'D' => {
                    self.cur_rows += 1;
                }
                b'E' => {
                    self.cur_error = Some(parse_pg_error(payload));
                }
                b'C' => {
                    // Emit span cleanly at CommandComplete if a query is pending
                    self.emit_pending_span(meta, ts_end, out_spans);
                }
                b'Z' => {
                    // Flush any error or empty query that ended directly with ReadyForQuery
                    if self.cur_error.is_some()
                        || (!self.pending.is_empty() && self.cur_resp_bytes > 6)
                    {
                        self.emit_pending_span(meta, ts_end, out_spans);
                    }
                    self.cur_resp_bytes = 0;
                    self.cur_first_byte_ns = None;
                    self.cur_rows = 0;
                    self.cur_error = None;
                }
                _ => {}
            }
            ingress.consume(total_len);
        }
    }

    fn emit_pending_span(&mut self, meta: ConnMeta, end_ns: u64, out_spans: &mut Vec<L7Span>) {
        let ConnMeta {
            conn_id,
            pid,
            fd,
            tls_source,
        } = meta;
        let Some(req) = self.pending.pop_front() else {
            self.cur_resp_bytes = 0;
            self.cur_first_byte_ns = None;
            self.cur_rows = 0;
            self.cur_error = None;
            return;
        };

        self.next_span_id += 1;
        let first_byte_ns = self.cur_first_byte_ns.unwrap_or(end_ns);
        let start_ns = if req.start_ns == 0 {
            first_byte_ns
        } else {
            req.start_ns
        };
        let latency_ns = end_ns.saturating_sub(start_ns);
        let (is_err, status_code, detail) = match self.cur_error.take() {
            Some((state, msg)) => (true, 500, Some(format!("SQLSTATE {state}: {msg}"))),
            None => (false, 200, None),
        };

        out_spans.push(L7Span {
            span_id: self.next_span_id,
            conn_id,
            pid,
            fd,
            protocol: L7Protocol::Postgres,
            method: req.verb,
            path_or_query: req.fingerprint.clone(),
            host: None,
            user_agent: None,
            status_code,
            request_bytes: req.req_bytes,
            response_bytes: self.cur_resp_bytes,
            start_ns,
            first_byte_ns,
            end_ns,
            latency_ns,
            traceparent: None,
            grpc: None,
            sql_fingerprint: Some(req.fingerprint),
            redis_key_prefix: None,
            error: is_err,
            error_detail: detail,
            tls_source,
        });

        self.cur_resp_bytes = 0;
        self.cur_first_byte_ns = None;
        self.cur_rows = 0;
    }
}

fn read_cstr_lossy(bytes: &[u8]) -> String {
    let nul = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..nul]).into_owned()
}

fn parse_pg_error(payload: &[u8]) -> (String, String) {
    let mut code = String::from("XX000");
    let mut msg = String::new();
    let mut cur = 0usize;
    while cur < payload.len() {
        let ftype = payload[cur];
        cur += 1;
        if ftype == 0 {
            break;
        }
        let val = read_cstr_lossy(&payload[cur..]);
        let adv = payload[cur..]
            .iter()
            .position(|&b| b == 0)
            .map_or(payload.len() - cur, |p| p + 1);
        cur += adv;
        if ftype == b'C' {
            code = val;
        } else if ftype == b'M' {
            msg = val;
        }
    }
    (code, msg)
}

/// Replace SQL string literals (`'...'`) and numeric literals (`42`, `3.14`) with positional
/// `$1`, `$2`, ... placeholders while preserving identifiers and `$N` parameters.
#[must_use]
pub fn sanitize_sql(sql: &str) -> String {
    let bytes = sql.as_bytes();
    let mut out = String::with_capacity(sql.len());
    let mut param_idx = 1usize;
    let mut i = 0usize;

    while i < bytes.len() {
        let b = bytes[i];
        if b.is_ascii_whitespace() {
            if !out.ends_with(' ') && !out.is_empty() {
                out.push(' ');
            }
            i += 1;
            continue;
        }
        if b == b'\'' {
            i += 1;
            while i < bytes.len() {
                if bytes[i] == b'\'' {
                    if i + 1 < bytes.len() && bytes[i + 1] == b'\'' {
                        i += 2;
                        continue;
                    }
                    i += 1;
                    break;
                }
                i += 1;
            }
            out.push('$');
            out.push_str(&param_idx.to_string());
            param_idx += 1;
            continue;
        }
        if b == b'$' {
            let start = i;
            i += 1;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
            out.push_str(&sql[start..i]);
            if i > start + 1 {
                if let Ok(n) = sql[start + 1..i].parse::<usize>() {
                    param_idx = param_idx.max(n + 1);
                }
            }
            continue;
        }
        let prev_is_ident = out
            .as_bytes()
            .last()
            .is_some_and(|&c| c.is_ascii_alphanumeric() || c == b'_' || c == b'$');
        if b.is_ascii_digit() && !prev_is_ident {
            i += 1;
            while i < bytes.len()
                && (bytes[i].is_ascii_hexdigit()
                    || bytes[i] == b'.'
                    || bytes[i] == b'x'
                    || bytes[i] == b'X')
            {
                i += 1;
            }
            out.push('$');
            out.push_str(&param_idx.to_string());
            param_idx += 1;
            continue;
        }
        // Advance one valid UTF-8 char boundary safely
        let ch = sql[i..].chars().next().unwrap_or(' ');
        out.push(ch);
        i += ch.len_utf8();
    }
    while out.ends_with(' ') || out.ends_with(';') {
        out.pop();
    }
    out
}

fn extract_sql_verb(fp: &str) -> String {
    fp.split_whitespace()
        .next()
        .unwrap_or("SQL")
        .to_ascii_uppercase()
}
