use crate::span::L7Protocol;

pub const HTTP2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

const HTTP1_PREFIXES: &[&[u8]] = &[
    b"GET ",
    b"POST ",
    b"PUT ",
    b"DELETE ",
    b"HEAD ",
    b"OPTIONS ",
    b"PATCH ",
    b"CONNECT ",
    b"TRACE ",
    b"HTTP/1.1 ",
    b"HTTP/1.0 ",
];

/// Classify L7 protocol from initial egress and/or ingress byte buffers without panicking.
#[must_use]
pub fn classify_protocol(egress: &[u8], ingress: &[u8]) -> L7Protocol {
    if is_http2_prefix(egress) || is_http2_server_preface(ingress) {
        return L7Protocol::Http2;
    }

    for &buf in &[egress, ingress] {
        if HTTP1_PREFIXES.iter().any(|p| buf.starts_with(p)) {
            return L7Protocol::Http1;
        }
    }

    if is_redis_prefix(egress) || is_redis_prefix(ingress) {
        return L7Protocol::Redis;
    }

    if is_postgres_prefix(egress) || is_postgres_backend_prefix(ingress) {
        return L7Protocol::Postgres;
    }

    L7Protocol::Unknown
}

fn is_http2_prefix(buf: &[u8]) -> bool {
    if buf.is_empty() {
        return false;
    }
    let cmp_len = buf.len().min(HTTP2_PREFACE.len());
    if buf.len() >= HTTP2_PREFACE.len() && buf.starts_with(HTTP2_PREFACE) {
        return true;
    }
    // Avoid misclassifying other protocols on very short partial HTTP/2 prefix
    if cmp_len >= 6 && HTTP2_PREFACE.starts_with(&buf[..cmp_len]) {
        return true;
    }
    // Direct HTTP/2 frame when client started mid-connection without preface (e.g. SETTINGS or HEADERS)
    is_valid_h2_frame_start(buf)
}

fn is_http2_server_preface(buf: &[u8]) -> bool {
    is_valid_h2_frame_start(buf)
}

fn is_valid_h2_frame_start(buf: &[u8]) -> bool {
    if buf.len() < 9 {
        return false;
    }
    let len = ((buf[0] as usize) << 16) | ((buf[1] as usize) << 8) | (buf[2] as usize);
    let ty = buf[3];
    let flags = buf[4];
    let sid = u32::from_be_bytes([buf[5], buf[6], buf[7], buf[8]]) & 0x7FFF_FFFF;
    match ty {
        // SETTINGS (type=4): stream_id == 0, flags <= 1, payload multiple of 6
        4 => sid == 0 && flags <= 0x01 && len <= 16_384 && len.is_multiple_of(6),
        // HEADERS (type=1): stream_id > 0
        1 => sid > 0 && len <= 16_384 && flags <= 0x2D,
        _ => false,
    }
}

fn is_redis_prefix(buf: &[u8]) -> bool {
    let Some(&first) = buf.first() else {
        return false;
    };
    if !matches!(first, b'*' | b'+' | b'-' | b':' | b'$' | b'%' | b'~') {
        return false;
    }
    // Check first CRLF or clean numeric start to distinguish from arbitrary binary
    let scan_end = buf.len().min(64);
    let has_crlf = buf[..scan_end].windows(2).any(|w| w == b"\r\n");
    if matches!(first, b'*' | b'$' | b':' | b'%' | b'~') {
        let rest = &buf[1..scan_end];
        let digits_ok = rest
            .first()
            .is_some_and(|b| b.is_ascii_digit() || *b == b'-');
        return digits_ok && has_crlf;
    }
    has_crlf
        && buf[1..scan_end]
            .iter()
            .take_while(|&&b| b != b'\r')
            .all(|&b| b.is_ascii())
}

fn is_postgres_prefix(buf: &[u8]) -> bool {
    if buf.len() >= 8 {
        let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let proto = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        // PostgreSQL v3 Startup (196608 = 0x0003_0000) or SSLRequest (80877103) or CancelRequest (80877102)
        if (8..=16_384).contains(&len) && matches!(proto, 196_608 | 80_877_103 | 80_877_102) {
            return true;
        }
    }
    if buf.len() >= 5 {
        let tag = buf[0];
        let len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
        if matches!(
            tag,
            b'Q' | b'P' | b'B' | b'E' | b'D' | b'S' | b'H' | b'X' | b'C'
        ) && (4..=1_048_576).contains(&len)
        {
            return true;
        }
    }
    false
}

fn is_postgres_backend_prefix(buf: &[u8]) -> bool {
    if buf.len() >= 5 {
        let tag = buf[0];
        let len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
        if matches!(
            tag,
            b'R' | b'K'
                | b'S'
                | b'T'
                | b'D'
                | b'C'
                | b'Z'
                | b'E'
                | b'N'
                | b'1'
                | b'2'
                | b'3'
                | b'n'
                | b't'
        ) && (4..=1_048_576).contains(&len)
        {
            return true;
        }
    }
    false
}
