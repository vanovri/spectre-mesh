use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelSym {
    pub addr: u64,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcMapRegion {
    pub start: u64,
    pub end: u64,
    pub file_offset: u64,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfSymRange {
    pub start_file_off: u64,
    pub end_file_off: u64,
    pub name: String,
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FileCacheKey {
    path: String,
    len: u64,
    mtime_nanos: u128,
}

#[derive(Debug, Default)]
pub struct SymbolResolver {
    kallsyms: Vec<KernelSym>,
    pid_maps: HashMap<u32, Vec<ProcMapRegion>>,
    #[cfg(not(target_arch = "wasm32"))]
    elf_cache: HashMap<FileCacheKey, Vec<ElfSymRange>>,
    #[cfg(not(target_arch = "wasm32"))]
    path_last_key: HashMap<String, FileCacheKey>,
}

impl SymbolResolver {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn load_host_kallsyms(&mut self) {
        if let Ok(raw) = std::fs::read_to_string("/proc/kallsyms") {
            self.kallsyms = parse_kallsyms(&raw);
        }
    }

    pub fn refresh_pid_maps(&mut self, pid: u32) {
        let path = format!("/proc/{pid}/maps");
        if let Ok(raw) = std::fs::read_to_string(path) {
            self.pid_maps.insert(pid, parse_proc_maps_regions(&raw));
        }
    }

    #[must_use]
    pub fn resolve_kernel_ip(&self, ip: u64) -> String {
        resolve_kernel_addr(&self.kallsyms, ip).unwrap_or_else(|| format!("[k] {ip:#x}"))
    }

    pub fn resolve_user_ip(&mut self, pid: u32, ip: u64) -> String {
        if !self.pid_maps.contains_key(&pid) {
            self.refresh_pid_maps(pid);
        }
        let Some(regions) = self.pid_maps.get(&pid) else {
            return format!("{ip:#x}");
        };
        let Some(reg) = regions.iter().find(|r| ip >= r.start && ip < r.end) else {
            // Re-scan once in case dlopen/jit mapped new executable segments
            self.refresh_pid_maps(pid);
            let Some(regions2) = self.pid_maps.get(&pid) else {
                return format!("{ip:#x}");
            };
            let Some(reg2) = regions2.iter().find(|r| ip >= r.start && ip < r.end) else {
                return format!("{ip:#x}");
            };
            let path = reg2.path.clone();
            let file_off = (ip - reg2.start) + reg2.file_offset;
            return self.resolve_elf_file_offset(&path, file_off);
        };

        let path = reg.path.clone();
        let file_off = (ip - reg.start) + reg.file_offset;
        self.resolve_elf_file_offset(&path, file_off)
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn resolve_elf_file_offset(&mut self, path: &str, file_off: u64) -> String {
        self.ensure_elf_loaded(path);
        if let Some(key) = self.path_last_key.get(path) {
            if let Some(ranges) = self.elf_cache.get(key) {
                let idx = ranges.partition_point(|r| r.start_file_off <= file_off);
                if idx > 0 {
                    let sym = &ranges[idx - 1];
                    if file_off < sym.end_file_off {
                        return sym.name.clone();
                    }
                }
            }
        }
        let base = Path::new(path)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("bin");
        format!("{base}+{file_off:#x}")
    }

    #[cfg(target_arch = "wasm32")]
    fn resolve_elf_file_offset(&mut self, path: &str, file_off: u64) -> String {
        let base = Path::new(path)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("bin");
        format!("{base}+{file_off:#x}")
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn ensure_elf_loaded(&mut self, path: &str) {
        let Ok(meta) = std::fs::metadata(path) else {
            return;
        };
        let len = meta.len();
        let mtime_nanos = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_nanos());

        let key = FileCacheKey {
            path: path.to_owned(),
            len,
            mtime_nanos,
        };
        if self.elf_cache.contains_key(&key) {
            self.path_last_key.insert(path.to_owned(), key);
            return;
        }
        let Ok(bytes) = std::fs::read(path) else {
            return;
        };
        let ranges = parse_elf_symbol_ranges(&bytes);
        self.elf_cache.insert(key.clone(), ranges);
        self.path_last_key.insert(path.to_owned(), key);
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn parse_elf_symbol_ranges(bytes: &[u8]) -> Vec<ElfSymRange> {
    let Ok(elf) = spectre_elf_btf::Elf64Object::parse(bytes) else {
        return Vec::new();
    };
    let mut out = Vec::new();

    for sym in elf.symbols.iter().chain(elf.dyn_symbols.iter()) {
        if sym.sym_type() != 2 || sym.st_value == 0 || sym.name.is_empty() {
            continue;
        }
        let Some(start_off) = elf.vaddr_to_file_offset(sym.st_value) else {
            continue;
        };
        let size = sym.st_size.max(1);
        out.push(ElfSymRange {
            start_file_off: start_off,
            end_file_off: start_off.saturating_add(size),
            name: demangle_symbol(&sym.name),
        });
    }

    if let Ok(go_funcs) = elf.parse_gopclntab() {
        for gf in go_funcs {
            if let Some(start_off) = gf.file_offset {
                let sz = gf.end_vaddr.saturating_sub(gf.entry_vaddr).max(1);
                out.push(ElfSymRange {
                    start_file_off: start_off,
                    end_file_off: start_off.saturating_add(sz),
                    name: gf.name,
                });
            }
        }
    }

    out.sort_by_key(|r| (r.start_file_off, std::cmp::Reverse(r.end_file_off)));
    // Deduplicate identical start offsets
    out.dedup_by_key(|r| r.start_file_off);
    // Clamp upper bounds to next symbol start when st_size was unset (=1)
    for i in 0..out.len().saturating_sub(1) {
        let next_start = out[i + 1].start_file_off;
        if out[i].end_file_off <= out[i].start_file_off + 1 && next_start > out[i].start_file_off {
            out[i].end_file_off = next_start;
        }
    }
    out
}

/// Parse `/proc/kallsyms` text into a sorted address table (skipping redacted `0` addresses).
#[must_use]
pub fn parse_kallsyms(raw: &str) -> Vec<KernelSym> {
    let mut out = Vec::new();
    for line in raw.lines() {
        let mut parts = line.split_whitespace();
        let Some(addr_hex) = parts.next() else {
            continue;
        };
        let Some(_kind) = parts.next() else {
            continue;
        };
        let Some(name) = parts.next() else {
            continue;
        };
        if let Ok(addr) = u64::from_str_radix(addr_hex, 16) {
            if addr != 0 {
                out.push(KernelSym {
                    addr,
                    name: name.to_owned(),
                });
            }
        }
    }
    out.sort_by_key(|k| k.addr);
    out.dedup_by_key(|k| k.addr);
    out
}

#[must_use]
pub fn resolve_kernel_addr(syms: &[KernelSym], addr: u64) -> Option<String> {
    let idx = syms.partition_point(|s| s.addr <= addr);
    if idx == 0 {
        return None;
    }
    let sym = &syms[idx - 1];
    // Reject absurdly distant matches (> 512 KB away from nearest kernel symbol)
    if addr.saturating_sub(sym.addr) > 512 * 1024 {
        return None;
    }
    Some(format!("[k] {}", sym.name))
}

/// Parse `/proc/<pid>/maps` executable file-backed mappings (`VA [start..end) -> file_offset`).
#[must_use]
pub fn parse_proc_maps_regions(raw: &str) -> Vec<ProcMapRegion> {
    let mut regions = Vec::new();
    for line in raw.lines() {
        let mut cols = line.split_whitespace();
        let Some(range) = cols.next() else {
            continue;
        };
        let Some(perms) = cols.next() else {
            continue;
        };
        if !perms.contains('x') {
            continue;
        }
        let Some(off_hex) = cols.next() else {
            continue;
        };
        let _dev = cols.next();
        let _inode = cols.next();
        let Some(first_path) = cols.next() else {
            continue;
        };
        let path: String = std::iter::once(first_path)
            .chain(cols)
            .collect::<Vec<_>>()
            .join(" ");
        if !path.starts_with('/') || path.ends_with("(deleted)") {
            continue;
        }
        let Some((s_hex, e_hex)) = range.split_once('-') else {
            continue;
        };
        if let (Ok(start), Ok(end), Ok(file_offset)) = (
            u64::from_str_radix(s_hex, 16),
            u64::from_str_radix(e_hex, 16),
            u64::from_str_radix(off_hex, 16),
        ) {
            regions.push(ProcMapRegion {
                start,
                end,
                file_offset,
                path,
            });
        }
    }
    regions.sort_by_key(|r| r.start);
    regions
}

/// Demangle common Rust legacy (`_ZN...E`), Rust v0 (`_R...`), and simple C++ Itanium symbols.
#[must_use]
pub fn demangle_symbol(mangled: &str) -> String {
    if let Some(rest) = mangled
        .strip_prefix("_ZN")
        .or_else(|| mangled.strip_prefix("ZN"))
    {
        if let Some(decoded) = demangle_itanium_path(rest) {
            return decoded;
        }
    }
    if mangled.starts_with("_R") {
        let cleaned: Vec<&str> = mangled
            .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .filter(|s| s.len() >= 3 && !s.starts_with("_R"))
            .collect();
        if !cleaned.is_empty() {
            return cleaned.join("::");
        }
    }
    if let Some(rest) = mangled.strip_prefix("_Z") {
        if let Some(decoded) = demangle_itanium_path(rest) {
            return decoded;
        }
    }
    mangled.to_owned()
}

fn demangle_itanium_path(mut s: &str) -> Option<String> {
    let mut parts: Vec<String> = Vec::new();
    while !s.is_empty() {
        if s.starts_with('E') {
            break;
        }
        let digit_end = s.bytes().take_while(|b| b.is_ascii_digit()).count();
        if digit_end == 0 {
            break;
        }
        let len: usize = s[..digit_end].parse().ok()?;
        let after_len = &s[digit_end..];
        if after_len.len() < len {
            break;
        }
        let raw_seg = &after_len[..len];
        parts.push(decode_rust_legacy_escapes(raw_seg));
        s = &after_len[len..];
    }
    if parts.is_empty() {
        return None;
    }
    // Strip trailing Rust hash segment `h<16-hex-digits>`
    if parts.last().is_some_and(|p| {
        p.len() == 17 && p.starts_with('h') && p[1..].bytes().all(|b| b.is_ascii_hexdigit())
    }) {
        parts.pop();
    }
    (!parts.is_empty()).then(|| parts.join("::"))
}

fn decode_rust_legacy_escapes(seg: &str) -> String {
    let seg = seg.strip_prefix("_$").unwrap_or(seg);
    seg.replace("$SP$", "@")
        .replace("$BP$", "*")
        .replace("$RF$", "&")
        .replace("$LT$", "<")
        .replace("$GT$", ">")
        .replace("$LP$", "(")
        .replace("$RP$", ")")
        .replace("$C$", ",")
        .replace("$u20$", " ")
        .replace("..", "::")
}
