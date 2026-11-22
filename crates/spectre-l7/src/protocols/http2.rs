use std::collections::HashMap;

use crate::classifier::HTTP2_PREFACE;
use crate::protocols::grpc::inspect_grpc_frame;
use crate::protocols::hpack::HpackDecoder;
use crate::protocols::TimestampStream;
use crate::span::{ConnMeta, L7Protocol, L7Span};

const FRAME_DATA: u8 = 0x0;
const FRAME_HEADERS: u8 = 0x1;
const FRAME_RST_STREAM: u8 = 0x3;
const FRAME_SETTINGS: u8 = 0x4;
const FRAME_CONTINUATION: u8 = 0x9;

const FLAG_END_STREAM: u8 = 0x01;
const FLAG_END_HEADERS: u8 = 0x04;
const FLAG_PADDED: u8 = 0x08;
const FLAG_PRIORITY: u8 = 0x20;

const MAX_H2_FRAME_PAYLOAD: usize = 1_048_576;
const MAX_GRPC_BODY_CAPTURE: usize = 16_384;

#[derive(Debug, Default, Clone)]
struct H2StreamState {
    method: Option<String>,
    path: Option<String>,
    authority: Option<String>,
    user_agent: Option<String>,
    traceparent: Option<String>,
    req_content_type: Option<String>,
    resp_content_type: Option<String>,
    status_code: Option<u16>,
    grpc_status: Option<i32>,
    request_bytes: usize,
    response_bytes: usize,
    start_ns: Option<u64>,
    first_byte_ns: Option<u64>,
    end_ns: Option<u64>,
    req_body_preview: Vec<u8>,
    resp_body_preview: Vec<u8>,
    saw_resp_headers: bool,
}

#[derive(Debug)]
struct DirState {
    preface_checked: bool,
    hpack: HpackDecoder,
    pending_header_stream: Option<u32>,
    pending_header_buf: Vec<u8>,
}

impl Default for DirState {
    fn default() -> Self {
        Self {
            preface_checked: false,
            hpack: HpackDecoder::new(4096),
            pending_header_stream: None,
            pending_header_buf: Vec::new(),
        }
    }
}

#[derive(Debug, Default)]
pub struct Http2Decoder {
    egress_state: DirState,
    ingress_state: DirState,
    streams: HashMap<u32, H2StreamState>,
    next_span_id: u64,
    pub warnings: Vec<String>,
}

impl Http2Decoder {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn egress_dynamic_table(&self) -> Vec<(String, String)> {
        self.egress_state.hpack.dynamic_table_entries()
    }

    #[must_use]
    pub fn ingress_dynamic_table(&self) -> Vec<(String, String)> {
        self.ingress_state.hpack.dynamic_table_entries()
    }

    pub fn process(
        &mut self,
        meta: ConnMeta,
        egress: &mut TimestampStream,
        ingress: &mut TimestampStream,
        out_spans: &mut Vec<L7Span>,
    ) {
        self.process_dir(true, meta, egress, out_spans);
        self.process_dir(false, meta, ingress, out_spans);
    }

    fn process_dir(
        &mut self,
        is_egress: bool,
        meta: ConnMeta,
        stream: &mut TimestampStream,
        out_spans: &mut Vec<L7Span>,
    ) {
        if is_egress && !self.egress_state.preface_checked {
            let buf = stream.as_slice();
            if buf.len() >= HTTP2_PREFACE.len() {
                if buf.starts_with(HTTP2_PREFACE) {
                    stream.consume(HTTP2_PREFACE.len());
                }
                self.egress_state.preface_checked = true;
            } else if HTTP2_PREFACE.starts_with(buf) {
                return;
            } else {
                self.egress_state.preface_checked = true;
            }
        }

        loop {
            let buf = stream.as_slice();
            if buf.len() < 9 {
                break;
            }
            let len = ((buf[0] as usize) << 16) | ((buf[1] as usize) << 8) | (buf[2] as usize);
            let ftype = buf[3];
            let flags = buf[4];
            let sid = u32::from_be_bytes([buf[5], buf[6], buf[7], buf[8]]) & 0x7FFF_FFFF;

            if len > MAX_H2_FRAME_PAYLOAD {
                stream.consume(1);
                continue;
            }
            let total = 9 + len;
            if buf.len() < total {
                break;
            }

            let payload = &buf[9..total];
            let (ts_start, ts_end) = stream.range_ts(total);

            match ftype {
                FRAME_SETTINGS => {
                    if (flags & 0x01) == 0 && sid == 0 {
                        for chunk in payload.as_chunks::<6>().0 {
                            let id = u16::from_be_bytes([chunk[0], chunk[1]]);
                            let val = u32::from_be_bytes([chunk[2], chunk[3], chunk[4], chunk[5]]);
                            if id == 1 {
                                let target = if is_egress {
                                    &mut self.ingress_state
                                } else {
                                    &mut self.egress_state
                                };
                                target.hpack.set_settings_max_table_size(val as usize);
                            }
                        }
                    }
                }
                FRAME_HEADERS => {
                    let frag = extract_header_fragment(payload, flags);
                    if let Some(frag_bytes) = frag {
                        let decoded_opt = {
                            let dstate = if is_egress {
                                &mut self.egress_state
                            } else {
                                &mut self.ingress_state
                            };
                            dstate.pending_header_stream = Some(sid);
                            dstate.pending_header_buf.clear();
                            if frag_bytes.len() <= 128 * 1024 {
                                dstate.pending_header_buf.extend_from_slice(frag_bytes);
                            }
                            if (flags & FLAG_END_HEADERS) != 0 {
                                let block = std::mem::take(&mut dstate.pending_header_buf);
                                dstate.pending_header_stream = None;
                                Some(dstate.hpack.decode_block(&block))
                            } else {
                                None
                            }
                        };
                        match decoded_opt {
                            Some(Ok(hdrs)) => {
                                self.apply_decoded_headers(
                                    is_egress,
                                    sid,
                                    total,
                                    (flags & FLAG_END_STREAM) != 0,
                                    ts_start,
                                    ts_end,
                                    &hdrs,
                                    meta,
                                    out_spans,
                                );
                            }
                            Some(Err(_)) => {
                                self.warnings
                                    .push(format!("HPACK decode error on stream {sid}"));
                            }
                            None => {
                                if let Some(st) = self.streams.get_mut(&sid) {
                                    if is_egress {
                                        st.request_bytes += total;
                                    } else {
                                        st.response_bytes += total;
                                    }
                                }
                            }
                        }
                    }
                }
                FRAME_CONTINUATION => {
                    let decoded_opt = {
                        let dstate = if is_egress {
                            &mut self.egress_state
                        } else {
                            &mut self.ingress_state
                        };
                        if dstate.pending_header_stream == Some(sid) {
                            if dstate.pending_header_buf.len() + payload.len() <= 128 * 1024 {
                                dstate.pending_header_buf.extend_from_slice(payload);
                            }
                            if (flags & FLAG_END_HEADERS) != 0 {
                                let block = std::mem::take(&mut dstate.pending_header_buf);
                                dstate.pending_header_stream = None;
                                Some(dstate.hpack.decode_block(&block))
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    };
                    if let Some(Ok(hdrs)) = decoded_opt {
                        self.apply_decoded_headers(
                            is_egress,
                            sid,
                            total,
                            (flags & FLAG_END_STREAM) != 0,
                            ts_start,
                            ts_end,
                            &hdrs,
                            meta,
                            out_spans,
                        );
                    }
                }
                FRAME_DATA if sid > 0 => {
                    let data = extract_data_payload(payload, flags);
                    let st = self.streams.entry(sid).or_default();
                    if is_egress {
                        if st.start_ns.is_none() {
                            st.start_ns = Some(ts_start);
                        }
                        st.request_bytes += total;
                        if st.req_body_preview.len() < MAX_GRPC_BODY_CAPTURE {
                            let take =
                                (MAX_GRPC_BODY_CAPTURE - st.req_body_preview.len()).min(data.len());
                            st.req_body_preview.extend_from_slice(&data[..take]);
                        }
                    } else {
                        if st.first_byte_ns.is_none() {
                            st.first_byte_ns = Some(ts_start);
                        }
                        st.response_bytes += total;
                        st.end_ns = Some(ts_end);
                        if st.resp_body_preview.len() < MAX_GRPC_BODY_CAPTURE {
                            let take = (MAX_GRPC_BODY_CAPTURE - st.resp_body_preview.len())
                                .min(data.len());
                            st.resp_body_preview.extend_from_slice(&data[..take]);
                        }
                        if (flags & FLAG_END_STREAM) != 0 {
                            self.finalize_stream(sid, meta, None, out_spans);
                        }
                    }
                }
                FRAME_RST_STREAM if sid > 0 && payload.len() >= 4 => {
                    let err_code =
                        u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                    self.finalize_stream(sid, meta, Some((err_code, ts_end)), out_spans);
                }
                _ => {}
            }

            stream.consume(total);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_decoded_headers(
        &mut self,
        is_egress: bool,
        sid: u32,
        frame_bytes: usize,
        end_stream: bool,
        ts_start: u64,
        ts_end: u64,
        headers: &[(String, String)],
        meta: ConnMeta,
        out_spans: &mut Vec<L7Span>,
    ) {
        let st = self.streams.entry(sid).or_default();
        if is_egress {
            if st.start_ns.is_none() {
                st.start_ns = Some(ts_start);
            }
            st.request_bytes += frame_bytes;
            for (k, v) in headers {
                match k.as_str() {
                    ":method" => st.method = Some(v.clone()),
                    ":path" => st.path = Some(v.clone()),
                    ":authority" | "host" => st.authority = Some(v.clone()),
                    "user-agent" => st.user_agent = Some(v.clone()),
                    "traceparent" => st.traceparent = Some(v.clone()),
                    "content-type" => st.req_content_type = Some(v.clone()),
                    _ => {}
                }
            }
        } else {
            if st.first_byte_ns.is_none() {
                st.first_byte_ns = Some(ts_start);
            }
            st.response_bytes += frame_bytes;
            st.end_ns = Some(ts_end);
            for (k, v) in headers {
                match k.as_str() {
                    ":status" => st.status_code = v.parse::<u16>().ok(),
                    "content-type" => st.resp_content_type = Some(v.clone()),
                    "grpc-status" => st.grpc_status = v.parse::<i32>().ok(),
                    _ => {}
                }
            }
            st.saw_resp_headers = true;
            if end_stream {
                self.finalize_stream(sid, meta, None, out_spans);
            }
        }
    }

    fn finalize_stream(
        &mut self,
        sid: u32,
        meta: ConnMeta,
        rst: Option<(u32, u64)>,
        out_spans: &mut Vec<L7Span>,
    ) {
        let ConnMeta {
            conn_id,
            pid,
            fd,
            tls_source,
        } = meta;
        let Some(st) = self.streams.remove(&sid) else {
            return;
        };
        if !st.saw_resp_headers && rst.is_none() {
            return;
        }
        self.next_span_id += 1;

        let path = st.path.unwrap_or_else(|| "/".to_owned());
        let is_grpc = st
            .req_content_type
            .as_deref()
            .is_some_and(|s| s.starts_with("application/grpc"))
            || st
                .resp_content_type
                .as_deref()
                .is_some_and(|s| s.starts_with("application/grpc"))
            || st.grpc_status.is_some();

        let status_code = st.status_code.unwrap_or_else(|| {
            if rst.is_some_and(|(e, _)| e != 0) {
                502
            } else {
                200
            }
        });
        let first_byte_ns = st
            .first_byte_ns
            .or_else(|| rst.map(|(_, t)| t))
            .unwrap_or(0);
        let end_ns = st
            .end_ns
            .or_else(|| rst.map(|(_, t)| t))
            .unwrap_or(first_byte_ns);
        let start_ns = st.start_ns.unwrap_or(first_byte_ns);

        let grpc_info = if is_grpc {
            let inspect_buf = if !st.req_body_preview.is_empty() {
                &st.req_body_preview
            } else {
                &st.resp_body_preview
            };
            Some(inspect_grpc_frame(&path, st.grpc_status, inspect_buf))
        } else {
            None
        };

        let is_err = status_code >= 500
            || st.grpc_status.is_some_and(|g| g != 0)
            || rst.is_some_and(|(c, _)| c != 0);
        let detail = if let Some((c, _)) = rst.filter(|(c, _)| *c != 0) {
            Some(format!("RST_STREAM({c})"))
        } else if let Some(gs) = st.grpc_status.filter(|&g| g != 0) {
            Some(format!("grpc-status={gs}"))
        } else {
            is_err.then(|| format!("HTTP2 {status_code}"))
        };

        out_spans.push(L7Span {
            span_id: self.next_span_id,
            conn_id,
            pid,
            fd,
            protocol: if is_grpc {
                L7Protocol::Grpc
            } else {
                L7Protocol::Http2
            },
            method: st.method.unwrap_or_else(|| "POST".to_owned()),
            path_or_query: path,
            host: st.authority,
            user_agent: st.user_agent,
            status_code,
            request_bytes: st.request_bytes,
            response_bytes: st.response_bytes,
            start_ns,
            first_byte_ns,
            end_ns,
            latency_ns: end_ns.saturating_sub(start_ns),
            traceparent: st.traceparent,
            grpc: grpc_info,
            sql_fingerprint: None,
            redis_key_prefix: None,
            error: is_err,
            error_detail: detail,
            tls_source,
        });
    }
}

fn extract_header_fragment(payload: &[u8], flags: u8) -> Option<&[u8]> {
    let mut start = 0usize;
    let mut end = payload.len();
    if (flags & FLAG_PADDED) != 0 {
        let pad = usize::from(*payload.first()?);
        start += 1;
        end = end.checked_sub(pad)?;
    }
    if (flags & FLAG_PRIORITY) != 0 {
        start = start.checked_add(5)?;
    }
    (start <= end).then(|| &payload[start..end])
}

fn extract_data_payload(payload: &[u8], flags: u8) -> &[u8] {
    if (flags & FLAG_PADDED) == 0 {
        return payload;
    }
    let Some(&pad) = payload.first() else {
        return &[];
    };
    let end = payload.len().saturating_sub(usize::from(pad));
    if 1 <= end {
        &payload[1..end]
    } else {
        &[]
    }
}
