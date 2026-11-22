use std::collections::VecDeque;
use std::sync::OnceLock;

pub const RFC7541_STATIC_TABLE: &[(&str, &str)] = &[
    (":authority", ""),                   // 1
    (":method", "GET"),                   // 2
    (":method", "POST"),                  // 3
    (":path", "/"),                       // 4
    (":path", "/index.html"),             // 5
    (":scheme", "http"),                  // 6
    (":scheme", "https"),                 // 7
    (":status", "200"),                   // 8
    (":status", "204"),                   // 9
    (":status", "206"),                   // 10
    (":status", "304"),                   // 11
    (":status", "400"),                   // 12
    (":status", "404"),                   // 13
    (":status", "500"),                   // 14
    ("accept-charset", ""),               // 15
    ("accept-encoding", "gzip, deflate"), // 16
    ("accept-language", ""),              // 17
    ("accept-ranges", ""),                // 18
    ("accept", ""),                       // 19
    ("access-control-allow-origin", ""),  // 20
    ("age", ""),                          // 21
    ("allow", ""),                        // 22
    ("authorization", ""),                // 23
    ("cache-control", ""),                // 24
    ("content-disposition", ""),          // 25
    ("content-encoding", ""),             // 26
    ("content-language", ""),             // 27
    ("content-length", ""),               // 28
    ("content-location", ""),             // 29
    ("content-range", ""),                // 30
    ("content-type", ""),                 // 31
    ("cookie", ""),                       // 32
    ("date", ""),                         // 33
    ("etag", ""),                         // 34
    ("expect", ""),                       // 35
    ("expires", ""),                      // 36
    ("from", ""),                         // 37
    ("host", ""),                         // 38
    ("if-match", ""),                     // 39
    ("if-modified-since", ""),            // 40
    ("if-none-match", ""),                // 41
    ("if-range", ""),                     // 42
    ("if-unmodified-since", ""),          // 43
    ("last-modified", ""),                // 44
    ("link", ""),                         // 45
    ("location", ""),                     // 46
    ("max-forwards", ""),                 // 47
    ("proxy-authenticate", ""),           // 48
    ("proxy-authorization", ""),          // 49
    ("range", ""),                        // 50
    ("referer", ""),                      // 51
    ("refresh", ""),                      // 52
    ("retry-after", ""),                  // 53
    ("server", ""),                       // 54
    ("set-cookie", ""),                   // 55
    ("strict-transport-security", ""),    // 56
    ("transfer-encoding", ""),            // 57
    ("user-agent", ""),                   // 58
    ("vary", ""),                         // 59
    ("via", ""),                          // 60
    ("www-authenticate", ""),             // 61
];

/// Canonical RFC 7541 Appendix B Huffman codes `(code, bit_len)` for symbols `0..=255`.
pub const RFC7541_HUFFMAN: [(u32, u8); 256] = [
    (0x1ff8, 13),
    (0x7fffd8, 23),
    (0xfffffe2, 28),
    (0xfffffe3, 28),
    (0xfffffe4, 28),
    (0xfffffe5, 28),
    (0xfffffe6, 28),
    (0xfffffe7, 28),
    (0xfffffe8, 28),
    (0xffffea, 24),
    (0x3ffffffc, 30),
    (0xfffffe9, 28),
    (0xfffffea, 28),
    (0x3ffffffd, 30),
    (0xfffffeb, 28),
    (0xfffffec, 28),
    (0xfffffed, 28),
    (0xfffffee, 28),
    (0xfffffef, 28),
    (0xffffff0, 28),
    (0xffffff1, 28),
    (0xffffff2, 28),
    (0x3ffffffe, 30),
    (0xffffff3, 28),
    (0xffffff4, 28),
    (0xffffff5, 28),
    (0xffffff6, 28),
    (0xffffff7, 28),
    (0xffffff8, 28),
    (0xffffff9, 28),
    (0xffffffa, 28),
    (0xffffffb, 28),
    (0x14, 6),
    (0x3f8, 10),
    (0x3f9, 10),
    (0xffa, 12),
    (0x1ff9, 13),
    (0x15, 6),
    (0xf8, 8),
    (0x7fa, 11),
    (0x3fa, 10),
    (0x3fb, 10),
    (0xf9, 8),
    (0x7fb, 11),
    (0xfa, 8),
    (0x16, 6),
    (0x17, 6),
    (0x18, 6),
    (0x0, 5),
    (0x1, 5),
    (0x2, 5),
    (0x19, 6),
    (0x1a, 6),
    (0x1b, 6),
    (0x1c, 6),
    (0x1d, 6),
    (0x1e, 6),
    (0x1f, 6),
    (0x5c, 7),
    (0xfb, 8),
    (0x7ffc, 15),
    (0x20, 6),
    (0xffb, 12),
    (0x3fc, 10),
    (0x1ffa, 13),
    (0x21, 6),
    (0x5d, 7),
    (0x5e, 7),
    (0x5f, 7),
    (0x60, 7),
    (0x61, 7),
    (0x62, 7),
    (0x63, 7),
    (0x64, 7),
    (0x65, 7),
    (0x66, 7),
    (0x67, 7),
    (0x68, 7),
    (0x69, 7),
    (0x6a, 7),
    (0x6b, 7),
    (0x6c, 7),
    (0x6d, 7),
    (0x6e, 7),
    (0x6f, 7),
    (0x70, 7),
    (0x71, 7),
    (0x72, 7),
    (0xfc, 8),
    (0x73, 7),
    (0xfd, 8),
    (0x1ffb, 13),
    (0x7fff0, 19),
    (0x1ffc, 13),
    (0x3ffc, 14),
    (0x22, 6),
    (0x7ffd, 15),
    (0x3, 5),
    (0x23, 6),
    (0x4, 5),
    (0x24, 6),
    (0x5, 5),
    (0x25, 6),
    (0x26, 6),
    (0x27, 6),
    (0x6, 5),
    (0x74, 7),
    (0x75, 7),
    (0x28, 6),
    (0x29, 6),
    (0x2a, 6),
    (0x7, 5),
    (0x2b, 6),
    (0x76, 7),
    (0x2c, 6),
    (0x8, 5),
    (0x9, 5),
    (0x2d, 6),
    (0x77, 7),
    (0x78, 7),
    (0x79, 7),
    (0x7a, 7),
    (0x7b, 7),
    (0x7ffe, 15),
    (0x7fc, 11),
    (0x3ffd, 14),
    (0x1ffd, 13),
    (0xffffffc, 28),
    (0xfffe6, 20),
    (0x3fffd2, 22),
    (0xfffe7, 20),
    (0xfffe8, 20),
    (0x3fffd3, 22),
    (0x3fffd4, 22),
    (0x3fffd5, 22),
    (0x7fffd9, 23),
    (0x3fffd6, 22),
    (0x7fffda, 23),
    (0x7fffdb, 23),
    (0x7fffdc, 23),
    (0x7fffdd, 23),
    (0x7fffde, 23),
    (0xffffeb, 24),
    (0x7fffdf, 23),
    (0xffffec, 24),
    (0xffffed, 24),
    (0x3fffd7, 22),
    (0x7fffe0, 23),
    (0xffffee, 24),
    (0x7fffe1, 23),
    (0x7fffe2, 23),
    (0x7fffe3, 23),
    (0x7fffe4, 23),
    (0x1fffdc, 21),
    (0x3fffd8, 22),
    (0x7fffe5, 23),
    (0x3fffd9, 22),
    (0x7fffe6, 23),
    (0x7fffe7, 23),
    (0xffffef, 24),
    (0x3fffda, 22),
    (0x1fffdd, 21),
    (0xfffe9, 20),
    (0x3fffdb, 22),
    (0x3fffdc, 22),
    (0x7fffe8, 23),
    (0x7fffe9, 23),
    (0x1fffde, 21),
    (0x7fffea, 23),
    (0x3fffdd, 22),
    (0x3fffde, 22),
    (0xfffff0, 24),
    (0x1fffdf, 21),
    (0x3fffdf, 22),
    (0x7fffeb, 23),
    (0x7fffec, 23),
    (0x1fffe0, 21),
    (0x1fffe1, 21),
    (0x3fffe0, 22),
    (0x1fffe2, 21),
    (0x7fffed, 23),
    (0x3fffe1, 22),
    (0x7fffee, 23),
    (0x7fffef, 23),
    (0xfffea, 20),
    (0x3fffe2, 22),
    (0x3fffe3, 22),
    (0x3fffe4, 22),
    (0x7ffff0, 23),
    (0x3fffe5, 22),
    (0x3fffe6, 22),
    (0x7ffff1, 23),
    (0x3ffffe0, 26),
    (0x3ffffe1, 26),
    (0xfffeb, 20),
    (0x7fff1, 19),
    (0x3fffe7, 22),
    (0x7ffff2, 23),
    (0x3fffe8, 22),
    (0x1ffffec, 25),
    (0x3ffffe2, 26),
    (0x3ffffe3, 26),
    (0x3ffffe4, 26),
    (0x7ffffde, 27),
    (0x7ffffdf, 27),
    (0x3ffffe5, 26),
    (0xfffff1, 24),
    (0x1ffffed, 25),
    (0x7fff2, 19),
    (0x1fffe3, 21),
    (0x3ffffe6, 26),
    (0x7ffffe0, 27),
    (0x7ffffe1, 27),
    (0x3ffffe7, 26),
    (0x7ffffe2, 27),
    (0xfffff2, 24),
    (0x1fffe4, 21),
    (0x1fffe5, 21),
    (0x3ffffe8, 26),
    (0x3ffffe9, 26),
    (0xffffffd, 28),
    (0x7ffffe3, 27),
    (0x7ffffe4, 27),
    (0x7ffffe5, 27),
    (0xfffec, 20),
    (0xfffff3, 24),
    (0xfffed, 20),
    (0x1fffe6, 21),
    (0x3fffe9, 22),
    (0x1fffe7, 21),
    (0x1fffe8, 21),
    (0x7ffff3, 23),
    (0x3fffea, 22),
    (0x3fffeb, 22),
    (0x1ffffee, 25),
    (0x1ffffef, 25),
    (0xfffff4, 24),
    (0xfffff5, 24),
    (0x3ffffea, 26),
    (0x7ffff4, 23),
    (0x3ffffeb, 26),
    (0x7ffffe6, 27),
    (0x3ffffec, 26),
    (0x3ffffed, 26),
    (0x7ffffe7, 27),
    (0x7ffffe8, 27),
    (0x7ffffe9, 27),
    (0x7ffffea, 27),
    (0x7ffffeb, 27),
    (0xffffffe, 28),
    (0x7ffffec, 27),
    (0x7ffffed, 27),
    (0x7ffffee, 27),
    (0x7ffffef, 27),
    (0x7fffff0, 27),
    (0x3ffffee, 26),
];

#[derive(Debug, Clone, Copy)]
struct HuffNode {
    child: [u16; 2],
    sym: i16, // -1 internal, 0..=255 byte, 256 EOS
}

fn huffman_trie() -> &'static [HuffNode] {
    static TRIE: OnceLock<Vec<HuffNode>> = OnceLock::new();
    TRIE.get_or_init(|| {
        let mut nodes = vec![HuffNode {
            child: [0, 0],
            sym: -1,
        }];
        let mut insert = |code: u32, len: u8, sym: i16| {
            let mut cur = 0usize;
            for bit_pos in (0..len).rev() {
                let b = ((code >> bit_pos) & 1) as usize;
                let nxt = if nodes[cur].child[b] == 0 {
                    let id = nodes.len();
                    nodes.push(HuffNode {
                        child: [0, 0],
                        sym: -1,
                    });
                    nodes[cur].child[b] = id as u16;
                    id
                } else {
                    nodes[cur].child[b] as usize
                };
                cur = nxt;
            }
            nodes[cur].sym = sym;
        };
        for (sym, &(code, len)) in RFC7541_HUFFMAN.iter().enumerate() {
            insert(code, len, sym as i16);
        }
        insert(0x3fff_ffff, 30, 256); // EOS
        nodes
    })
}

/// Encode bytes with RFC 7541 Appendix B Huffman coding (used cleanly in RFC test vectors & fuzzing).
#[must_use]
pub fn huffman_encode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut acc: u64 = 0;
    let mut bits: u8 = 0;
    for &b in input {
        let (code, len) = RFC7541_HUFFMAN[b as usize];
        acc = (acc << len) | u64::from(code);
        bits += len;
        while bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xFF) as u8);
            acc &= (1u64 << bits) - 1;
        }
    }
    if bits > 0 {
        let rem = 8 - bits;
        let pad = (1u64 << rem) - 1;
        out.push((((acc << rem) | pad) & 0xFF) as u8);
    }
    out
}

/// Decode RFC 7541 Appendix B Huffman-encoded slice, rejecting EOS or non-1s padding strictly.
pub fn huffman_decode(encoded: &[u8]) -> Result<Vec<u8>, &'static str> {
    if encoded.len() > 256 * 1024 {
        return Err("HPACK Huffman string exceeds max allowed size");
    }
    let trie = huffman_trie();
    let mut out = Vec::with_capacity(encoded.len() * 2);
    let mut node = 0usize;
    let mut cur_bits = 0u8;
    let mut all_ones_since_sym = true;

    for &byte in encoded {
        for bit_idx in (0..8).rev() {
            let bit = usize::from((byte >> bit_idx) & 1);
            if bit == 0 {
                all_ones_since_sym = false;
            }
            let next = trie[node].child[bit] as usize;
            if next == 0 {
                return Err("invalid HPACK Huffman bit sequence");
            }
            cur_bits += 1;
            let sym = trie[next].sym;
            if sym == 256 {
                return Err("HPACK Huffman EOS symbol decoded");
            } else if sym >= 0 {
                out.push(sym as u8);
                node = 0;
                cur_bits = 0;
                all_ones_since_sym = true;
            } else {
                node = next;
            }
        }
    }

    if node != 0 && (cur_bits > 7 || !all_ones_since_sym) {
        return Err("invalid trailing HPACK Huffman padding");
    }
    Ok(out)
}

#[derive(Debug, Clone)]
pub struct HpackDecoder {
    dynamic: VecDeque<(String, String)>,
    dynamic_bytes: usize,
    max_dynamic_bytes: usize,
    max_allowed_bytes: usize,
}

impl Default for HpackDecoder {
    fn default() -> Self {
        Self::new(4096)
    }
}

impl HpackDecoder {
    #[must_use]
    pub fn new(initial_max_table_size: usize) -> Self {
        Self {
            dynamic: VecDeque::new(),
            dynamic_bytes: 0,
            max_dynamic_bytes: initial_max_table_size.min(65536),
            max_allowed_bytes: initial_max_table_size.min(65536),
        }
    }

    pub fn set_settings_max_table_size(&mut self, max_size: usize) {
        let clamped = max_size.min(65536);
        self.max_allowed_bytes = clamped;
        if self.max_dynamic_bytes > clamped {
            self.max_dynamic_bytes = clamped;
            self.evict();
        }
    }

    #[must_use]
    pub fn dynamic_table_entries(&self) -> Vec<(String, String)> {
        self.dynamic.iter().cloned().collect()
    }

    #[must_use]
    pub fn dynamic_bytes(&self) -> usize {
        self.dynamic_bytes
    }

    fn insert_dynamic(&mut self, name: String, value: String) {
        let entry_size = name.len().saturating_add(value.len()).saturating_add(32);
        self.dynamic.push_front((name, value));
        self.dynamic_bytes = self.dynamic_bytes.saturating_add(entry_size);
        self.evict();
    }

    fn evict(&mut self) {
        while self.dynamic_bytes > self.max_dynamic_bytes {
            let Some((k, v)) = self.dynamic.pop_back() else {
                self.dynamic_bytes = 0;
                break;
            };
            let entry_size = k.len().saturating_add(v.len()).saturating_add(32);
            self.dynamic_bytes = self.dynamic_bytes.saturating_sub(entry_size);
        }
    }

    fn lookup_index(&self, index: usize) -> Result<(&str, &str), &'static str> {
        if index == 0 {
            return Err("HPACK index 0 is invalid");
        }
        let static_len = RFC7541_STATIC_TABLE.len();
        if index <= static_len {
            return Ok(RFC7541_STATIC_TABLE[index - 1]);
        }
        let dyn_idx = index - static_len - 1;
        let (k, v) = self
            .dynamic
            .get(dyn_idx)
            .ok_or("HPACK index out of range")?;
        Ok((k.as_str(), v.as_str()))
    }

    /// Decode an HPACK header block completely, mutating the live FIFO dynamic table.
    pub fn decode_block(
        &mut self,
        mut input: &[u8],
    ) -> Result<Vec<(String, String)>, &'static str> {
        let mut headers = Vec::new();
        let mut saw_non_table_update = false;

        while !input.is_empty() {
            let b = input[0];
            if (b & 0x80) != 0 {
                // 6.1 Indexed Header Field (1xxxxxxx)
                saw_non_table_update = true;
                let (idx, rest) = decode_int(input, 7)?;
                input = rest;
                let (k, v) = self.lookup_index(idx)?;
                headers.push((k.to_owned(), v.to_owned()));
            } else if (b & 0xC0) == 0x40 {
                // 6.2.1 Literal Header Field with Incremental Indexing (01xxxxxx)
                saw_non_table_update = true;
                let (idx, rest) = decode_int(input, 6)?;
                let (name, rest) = if idx == 0 {
                    decode_str(rest)?
                } else {
                    let (k, _) = self.lookup_index(idx)?;
                    (k.to_owned(), rest)
                };
                let (val, rest) = decode_str(rest)?;
                input = rest;
                self.insert_dynamic(name.clone(), val.clone());
                headers.push((name, val));
            } else if (b & 0xE0) == 0x20 {
                // 6.3 Dynamic Table Size Update (001xxxxx)
                if saw_non_table_update {
                    return Err("dynamic table size update after header field");
                }
                let (new_sz, rest) = decode_int(input, 5)?;
                input = rest;
                if new_sz > self.max_allowed_bytes {
                    return Err("dynamic table size update exceeds SETTINGS_HEADER_TABLE_SIZE");
                }
                self.max_dynamic_bytes = new_sz;
                self.evict();
            } else {
                // 6.2.2 Without Indexing (0000xxxx) / 6.2.3 Never Indexed (0001xxxx)
                saw_non_table_update = true;
                let (idx, rest) = decode_int(input, 4)?;
                let (name, rest) = if idx == 0 {
                    decode_str(rest)?
                } else {
                    let (k, _) = self.lookup_index(idx)?;
                    (k.to_owned(), rest)
                };
                let (val, rest) = decode_str(rest)?;
                input = rest;
                headers.push((name, val));
            }
        }
        Ok(headers)
    }
}

/// RFC 7541 Section 5.1 N-bit integer prefix decoder (checked arithmetic, 0 panics).
pub fn decode_int(data: &[u8], prefix_bits: u8) -> Result<(usize, &[u8]), &'static str> {
    let Some((&first, mut rest)) = data.split_first() else {
        return Err("truncated HPACK integer");
    };
    let mask = ((1u16 << prefix_bits) - 1) as u8;
    let mut val = usize::from(first & mask);
    if val < usize::from(mask) {
        return Ok((val, rest));
    }

    let mut shift = 0u32;
    loop {
        let Some((&b, next_rest)) = rest.split_first() else {
            return Err("truncated HPACK varint continuation");
        };
        rest = next_rest;
        if shift >= 28 {
            return Err("HPACK integer overflow");
        }
        let add = usize::from(b & 0x7F)
            .checked_shl(shift)
            .ok_or("HPACK integer shift overflow")?;
        val = val.checked_add(add).ok_or("HPACK integer add overflow")?;
        shift += 7;
        if (b & 0x80) == 0 {
            break;
        }
    }
    Ok((val, rest))
}

fn decode_str(data: &[u8]) -> Result<(String, &[u8]), &'static str> {
    let Some(&first) = data.first() else {
        return Err("truncated HPACK string");
    };
    let is_huffman = (first & 0x80) != 0;
    let (len, rest) = decode_int(data, 7)?;
    if len > 256 * 1024 || len > rest.len() {
        return Err("truncated or oversized HPACK string literal");
    }
    let raw = &rest[..len];
    let after = &rest[len..];
    let decoded = if is_huffman {
        let bytes = huffman_decode(raw)?;
        String::from_utf8_lossy(&bytes).into_owned()
    } else {
        String::from_utf8_lossy(raw).into_owned()
    };
    Ok((decoded, after))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        clean
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
            .collect()
    }

    #[test]
    fn rfc7541_appendix_c4_and_c6_exact_vectors() {
        // RFC 7541 Appendix C.4 Request Examples with Huffman Coding
        let mut dec = HpackDecoder::new(4096);
        let c4_1 = unhex("8286 8441 8cf1 e3c2 e5f2 3a6b a0ab 90f4 ff");
        let h1 = dec.decode_block(&c4_1).unwrap();
        assert_eq!(
            h1,
            vec![
                (":method".to_owned(), "GET".to_owned()),
                (":scheme".to_owned(), "http".to_owned()),
                (":path".to_owned(), "/".to_owned()),
                (":authority".to_owned(), "www.example.com".to_owned()),
            ]
        );
        assert_eq!(dec.dynamic_table_entries().len(), 1);
        assert_eq!(dec.dynamic_bytes(), 57);

        let c4_2 = unhex("8286 84be 5886 a8eb 1064 9cbf");
        let h2 = dec.decode_block(&c4_2).unwrap();
        assert_eq!(
            h2,
            vec![
                (":method".to_owned(), "GET".to_owned()),
                (":scheme".to_owned(), "http".to_owned()),
                (":path".to_owned(), "/".to_owned()),
                (":authority".to_owned(), "www.example.com".to_owned()),
                ("cache-control".to_owned(), "no-cache".to_owned()),
            ]
        );

        let c4_3 = unhex("8287 85bf 4088 25a8 49e9 5ba9 7d7f 8925 a849 e95b b8e8 b4bf");
        let h3 = dec.decode_block(&c4_3).unwrap();
        assert_eq!(
            h3.last().unwrap(),
            &("custom-key".to_owned(), "custom-value".to_owned())
        );

        // RFC 7541 Appendix C.6 Response with eviction at table size 256
        let mut rdec = HpackDecoder::new(256);
        let c6_1 = unhex(
            "4882 6402 5885 aec3 771a 4b61 96d0 7abe 9410 54d4 44a8 2005 9504 0b81 66e0 82a6 2d1b ff6e 919d 29ad 1718 63c7 8f0b 97c8 e9ae 82ae 43d3",
        );
        let rh1 = rdec.decode_block(&c6_1).unwrap();
        assert_eq!(rh1[0], (":status".to_owned(), "302".to_owned()));
        assert_eq!(rh1[1], ("cache-control".to_owned(), "private".to_owned()));
        assert_eq!(
            rh1[2],
            (
                "date".to_owned(),
                "Mon, 21 Oct 2013 20:13:21 GMT".to_owned()
            )
        );
        assert_eq!(
            rh1[3],
            ("location".to_owned(), "https://www.example.com".to_owned())
        );
        assert_eq!(rdec.dynamic_bytes(), 222);

        // Dynamic eviction upon 307 update + roundtrip huffman_encode parity
        let sample = b"application/grpc+proto; charset=utf-8";
        let enc = huffman_encode(sample);
        assert_eq!(huffman_decode(&enc).unwrap(), sample);
    }
}
