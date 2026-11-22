use crate::span::{GrpcInspectInfo, ProtobufFieldSummary};

const MAX_PROTO_FIELDS: usize = 32;

/// Decode a gRPC `:path` (`/package.Service/Method`) into `(service, method)`.
#[must_use]
pub fn split_grpc_path(path: &str) -> (String, String) {
    let trimmed = path.trim_start_matches('/');
    match trimmed.split_once('/') {
        Some((svc, m)) => (svc.to_owned(), m.to_owned()),
        None => (String::new(), trimmed.to_owned()),
    }
}

/// Inspect a 5-byte length-prefixed gRPC frame (`[compressed: u8][len: u32 BE][protobuf payload]`)
/// without recursion or unbounded allocations.
#[must_use]
pub fn inspect_grpc_frame(path: &str, grpc_status: Option<i32>, body: &[u8]) -> GrpcInspectInfo {
    let (service, method) = split_grpc_path(path);
    if body.len() < 5 {
        return GrpcInspectInfo {
            service,
            method,
            compressed: false,
            message_len: 0,
            grpc_status,
            proto_tags: Vec::new(),
        };
    }

    let compressed = body[0] != 0;
    let message_len = u32::from_be_bytes([body[1], body[2], body[3], body[4]]);
    let avail_end = body.len().min(5usize.saturating_add(message_len as usize));
    let proto_tags = if compressed {
        Vec::new()
    } else {
        inspect_protobuf_fields(&body[5..avail_end])
    };

    GrpcInspectInfo {
        service,
        method,
        compressed,
        message_len,
        grpc_status,
        proto_tags,
    }
}

/// Non-recursive top-level Protobuf wire tag inspector (bounds-checked, max 32 fields).
#[must_use]
pub fn inspect_protobuf_fields(mut bytes: &[u8]) -> Vec<ProtobufFieldSummary> {
    let mut fields = Vec::new();
    while !bytes.is_empty() && fields.len() < MAX_PROTO_FIELDS {
        let Some((tag, rest)) = read_varint(bytes) else {
            break;
        };
        let field_number = tag >> 3;
        let wire_type = (tag & 0x07) as u8;
        if field_number == 0 {
            break;
        }
        bytes = rest;

        match wire_type {
            0 => {
                let Some((val, r)) = read_varint(bytes) else {
                    break;
                };
                bytes = r;
                fields.push(ProtobufFieldSummary {
                    field_number,
                    wire_type,
                    summary: format!("varint({val})"),
                });
            }
            1 => {
                if bytes.len() < 8 {
                    break;
                }
                let val = u64::from_le_bytes(bytes[..8].try_into().unwrap_or([0; 8]));
                bytes = &bytes[8..];
                fields.push(ProtobufFieldSummary {
                    field_number,
                    wire_type,
                    summary: format!("fixed64({val:#x})"),
                });
            }
            2 => {
                let Some((len_u64, r)) = read_varint(bytes) else {
                    break;
                };
                let len = usize::try_from(len_u64).unwrap_or(usize::MAX);
                if len > r.len() {
                    break;
                }
                let slice = &r[..len];
                bytes = &r[len..];
                let preview = if let Ok(s) = std::str::from_utf8(slice) {
                    if s.chars().all(|c| !c.is_control()) && !s.is_empty() {
                        format!("str({:?})", &s[..s.len().min(48)])
                    } else {
                        format!("bytes({len}B)")
                    }
                } else {
                    format!("bytes({len}B)")
                };
                fields.push(ProtobufFieldSummary {
                    field_number,
                    wire_type,
                    summary: preview,
                });
            }
            5 => {
                if bytes.len() < 4 {
                    break;
                }
                let val = u32::from_le_bytes(bytes[..4].try_into().unwrap_or([0; 4]));
                bytes = &bytes[4..];
                fields.push(ProtobufFieldSummary {
                    field_number,
                    wire_type,
                    summary: format!("fixed32({val:#x})"),
                });
            }
            _ => break,
        }
    }
    fields
}

fn read_varint(bytes: &[u8]) -> Option<(u64, &[u8])> {
    let mut acc: u64 = 0;
    for (idx, &b) in bytes.iter().take(10).enumerate() {
        acc |= u64::from(b & 0x7F) << (idx * 7);
        if (b & 0x80) == 0 {
            return Some((acc, &bytes[idx + 1..]));
        }
    }
    None
}
