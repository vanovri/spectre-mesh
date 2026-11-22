#!/usr/bin/env node
/**
 * SpectreMesh Strict Live Telemetry Emitter (Wave 0/1 Canonical Contract Parity)
 *
 * Single source of truth (zero hardcoded metrics):
 *   1. docs/benchmarks/ebpf_perf.md        (--report)
 *   2. PROGRESS.md                         (--progress)
 *   3. Cargo.toml / crates/*               (cratesCount + #![deny(unsafe_code)] audit)
 *   4. studio/src/wasm/spectre_wasm_bg.wasm (raw & gzip / 1024 + magic bytes + SHA-256)
 *
 * Default output:
 *   studio/public/telemetry/summary.json
 *
 * Negative contract test:
 *   node scripts/emit_telemetry_summary.mjs --report Cargo.toml --out .telemetry-logs/neg.json --strict
 *   -> EXIT 1, no output file created.
 */

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import zlib from 'node:zlib';
import { execFileSync } from 'node:child_process';

const ROOT = process.cwd();
const WASM_MAGIC_HEX = '0061736d';

function parseArgs(argv) {
  const opts = {
    reportPath:
      process.env.SPECTRE_PERF_MD ?? path.join(ROOT, 'docs/benchmarks/ebpf_perf.md'),
    progressPath: process.env.SPECTRE_PROGRESS_MD ?? path.join(ROOT, 'PROGRESS.md'),
    wasmPath: process.env.SPECTRE_WASM_PATH ?? null,
    outPath:
      process.env.SPECTRE_SUMMARY_OUT ??
      path.join(ROOT, 'studio/public/telemetry/summary.json'),
    strict: false,
    verifyOnly: false,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--report' || arg === '--perf') {
      const next = argv[++i];
      if (!next) throw new Error(`Flag ${arg} requires a file path`);
      opts.reportPath = path.resolve(next);
    } else if (arg === '--progress') {
      const next = argv[++i];
      if (!next) throw new Error('Flag --progress requires a file path');
      opts.progressPath = path.resolve(next);
    } else if (arg === '--wasm') {
      const next = argv[++i];
      if (!next) throw new Error('Flag --wasm requires a file path');
      opts.wasmPath = path.resolve(next);
    } else if (arg === '--out') {
      const next = argv[++i];
      if (!next) throw new Error('Flag --out requires a file path');
      opts.outPath = path.resolve(next);
    } else if (arg === '--strict') {
      opts.strict = true;
    } else if (arg === '--verify') {
      opts.verifyOnly = true;
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }
  return opts;
}

function sha256Hex(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

function roundTo(value, decimals) {
  const factor = 10 ** decimals;
  return Math.round(value * factor) / factor;
}

function toPosixRel(absPath) {
  return path.relative(ROOT, absPath).replace(/\\/g, '/');
}

function stripDecorators(text) {
  return text.replace(/\x1B\[[0-9;]*[A-Za-z]/g, '').replace(/[`*]/g, '');
}

function parseFloatStrict(raw, label) {
  const s = String(raw).trim().replace(/[\s_]/g, '');
  if (!s) throw new Error(`[PARSE_FAIL] Empty numeric token for "${label}"`);
  let normalized = s;
  if (s.includes('.') && s.includes(',')) {
    normalized =
      s.lastIndexOf(',') > s.lastIndexOf('.')
        ? s.replace(/\./g, '').replace(',', '.')
        : s.replace(/,/g, '');
  } else if (s.includes(',')) {
    normalized = /^\d{1,3}(,\d{3})+$/.test(s) ? s.replace(/,/g, '') : s.replace(',', '.');
  } else if (/^\d{1,3}(\.\d{3}){2,}$/.test(s)) {
    normalized = s.replace(/\./g, '');
  }
  const num = Number(normalized);
  if (!Number.isFinite(num)) {
    throw new Error(`[PARSE_FAIL] Non-finite number for "${label}": "${raw}"`);
  }
  return num;
}

function parseIntStrict(raw, label) {
  const cleaned = String(raw).trim().replace(/[.,_\s]/g, '');
  if (!/^\d+$/.test(cleaned)) {
    throw new Error(`[PARSE_FAIL] Invalid integer for "${label}": "${raw}"`);
  }
  const num = Number.parseInt(cleaned, 10);
  if (!Number.isSafeInteger(num)) {
    throw new Error(`[PARSE_FAIL] Integer overflow for "${label}": "${raw}"`);
  }
  return num;
}

function formatInt(n) {
  return new Intl.NumberFormat('en-US', { maximumFractionDigits: 0 }).format(n);
}

function matchOptional(text, patterns) {
  for (const regex of patterns) {
    const match = text.match(regex);
    if (match) return match;
  }
  return null;
}

function extractRequired(text, patterns, label, sourceFile, errors) {
  const match = matchOptional(text, patterns);
  if (!match) {
    errors.push(`Missing required metric [${label}] in ${toPosixRel(sourceFile)}`);
    return null;
  }
  return match;
}

function inspectWorkspaceCrates() {
  const cargoTomlPath = path.join(ROOT, 'Cargo.toml');
  if (!fs.existsSync(cargoTomlPath)) {
    return { count: 0, denyUnsafeCount: 0, members: [] };
  }
  const content = fs.readFileSync(cargoTomlPath, 'utf8');
  const wsSection = content.match(/\[workspace\]([\s\S]*?)(?:\n\[[^\]]+\]|$)/);
  const membersMatch = wsSection ? wsSection[1].match(/members\s*=\s*\[([\s\S]*?)\]/) : null;
  const rawEntries = membersMatch
    ? [...membersMatch[1].matchAll(/"([^"]+)"/g)].map((m) => m[1].trim())
    : [];

  const members = [];
  for (const rel of rawEntries) {
    if (fs.existsSync(path.join(ROOT, rel, 'Cargo.toml'))) {
      members.push(rel);
    }
  }
  members.sort();

  let denyUnsafeCount = 0;
  for (const rel of members) {
    const libRs = path.join(ROOT, rel, 'src', 'lib.rs');
    if (!fs.existsSync(libRs)) continue;
    const head = fs.readFileSync(libRs, 'utf8').slice(0, 1500);
    if (/#!\[deny\(unsafe_code\)\]/.test(head)) {
      denyUnsafeCount += 1;
    }
  }
  return { count: members.length, denyUnsafeCount, members };
}

function discoverWasmBinary(explicitPath) {
  if (explicitPath) {
    if (!fs.existsSync(explicitPath)) {
      throw new Error(`[WASM_MISSING] Explicit WASM file not found: ${explicitPath}`);
    }
    return explicitPath;
  }

  const candidates = [
    path.join(ROOT, 'studio/src/wasm/spectre_wasm_bg.wasm'),
    path.join(ROOT, 'studio/src/wasm-pkg/spectre_wasm_bg.wasm'),
    path.join(ROOT, 'crates/spectre-wasm/pkg/spectre_wasm_bg.wasm'),
    path.join(ROOT, 'studio/public/wasm/spectre_wasm_bg.wasm'),
  ];

  for (const candidate of candidates) {
    if (fs.existsSync(candidate) && fs.statSync(candidate).size > 0) {
      return candidate;
    }
  }

  const distAssets = path.join(ROOT, 'studio/dist/labs/spectre/assets');
  if (fs.existsSync(distAssets)) {
    const found = fs
      .readdirSync(distAssets)
      .filter((name) => /^spectre_wasm_bg.*\.wasm$/i.test(name))
      .sort();
    if (found.length > 0) {
      return path.join(distAssets, found[0]);
    }
  }

  throw new Error(
    '[WASM_MISSING] Compiled spectre_wasm_bg.wasm not found. Run "make wasm-studio" or pass --wasm <path>.'
  );
}

function measureWasmBinary(wasmPath) {
  const rawBuf = fs.readFileSync(wasmPath);
  const magicHex = rawBuf.subarray(0, 4).toString('hex');
  if (magicHex !== WASM_MAGIC_HEX) {
    throw new Error(
      `[WASM_INVALID] Invalid WASM magic bytes (${magicHex}, expected ${WASM_MAGIC_HEX}) in ${wasmPath}`
    );
  }
  const gzipBuf = zlib.gzipSync(rawBuf, { level: 9 });
  return {
    relPath: toPosixRel(wasmPath),
    sha256: sha256Hex(rawBuf),
    bytes: rawBuf.byteLength,
    kb: roundTo(rawBuf.byteLength / 1024, 2),
    siKb: roundTo(rawBuf.byteLength / 1000, 2),
    gzipBytes: gzipBuf.byteLength,
    gzipKb: roundTo(gzipBuf.byteLength / 1024, 2),
    gzipSiKb: roundTo(gzipBuf.byteLength / 1000, 2),
  };
}

function getGitMeta() {
  const runGit = (args) => {
    try {
      return execFileSync('git', args, { cwd: ROOT, encoding: 'utf8' }).trim();
    } catch {
      return null;
    }
  };
  const statusOut = runGit(['status', '--porcelain']);
  return {
    commitSha: runGit(['rev-parse', '--short', 'HEAD']),
    workingTreeClean: statusOut !== null ? statusOut.length === 0 : false,
  };
}

/**
 * Parse docs/benchmarks/ebpf_perf.md (zero hardcoded numbers).
 */
function parseEbpfPerfMd(mdRaw, filePath, errors) {
  const clean = stripDecorators(mdRaw);

  const hostMatch = matchOptional(mdRaw, [/Host:\*\*\s*`([^`]+)`\s*\(`([^`]+)`\)/i]);
  const osArch = hostMatch ? `${hostMatch[1]}/${hostMatch[2]}` : null;

  const benchCommitMatch = matchOptional(mdRaw, [/Commit:\*\*\s*`([0-9a-f]+)`/i]);
  const benchCommitSha = benchCommitMatch ? benchCommitMatch[1] : null;

  // Row 1: XDP Kernel (xdp_net.bpf.o) | BPF_PROG_TEST_RUN (500000 pkts) | 10.10 Mpps | 99.00 ns/pkt | ...
  const xdpKernelMatch = extractRequired(
    clean,
    [
      /\|\s*XDP Kernel\s*\(xdp_net\.bpf\.o\)\s*\|\s*BPF_PROG_TEST_RUN\s*\(([\d,]+)\s*pkts\)\s*\|\s*([\d.]+)\s*Mpps\s*\|\s*([\d.]+)\s*ns\/pkt\s*\|/i,
    ],
    'xdpKernelPerf',
    filePath,
    errors
  );
  const xdpKernelPackets = xdpKernelMatch
    ? parseIntStrict(xdpKernelMatch[1], 'xdpKernelPackets')
    : null;
  const xdpKernelMpps = xdpKernelMatch
    ? parseFloatStrict(xdpKernelMatch[2], 'xdpKernelMpps')
    : null;
  const xdpKernelNsPerPkt = xdpKernelMatch
    ? parseFloatStrict(xdpKernelMatch[3], 'xdpKernelNsPerPkt')
    : null;

  // Row 2: Rust BpfVm XDP | Pure-Rust ISA v3 VM (100000 pkts) | 8.23 Mpps | 121.57 ns/pkt | ...
  const bpfVmMatch = extractRequired(
    clean,
    [
      /\|\s*Rust BpfVm XDP\s*\|\s*Pure-Rust ISA v3 VM\s*\(([\d,]+)\s*pkts\)\s*\|\s*([\d.]+)\s*Mpps\s*\|\s*([\d.]+)\s*ns\/pkt\s*\|/i,
    ],
    'bpfVmPerf',
    filePath,
    errors
  );
  const bpfVmPackets = bpfVmMatch ? parseIntStrict(bpfVmMatch[1], 'bpfVmPackets') : null;
  const bpfVmMpps = bpfVmMatch ? parseFloatStrict(bpfVmMatch[2], 'bpfVmMpps') : null;
  const bpfVmNsPerPkt = bpfVmMatch ? parseFloatStrict(bpfVmMatch[3], 'bpfVmNsPerPkt') : null;

  // Row 3: Lock-Free BPF_MAP_TYPE_RINGBUF | m01_ringbuf_test.bpf.o (100000 evts) | 23.3 k evt/s (0.5 MB/s) | 4296.05 ms total | 0 drops |
  const ringbufMatch = extractRequired(
    clean,
    [
      /\|\s*Lock-Free BPF_MAP_TYPE_RINGBUF\s*\|\s*[^|]*?\(([\d,]+)\s*evts\)\s*\|\s*([\d.]+)\s*k evt\/s\s*\(([\d.]+)\s*MB\/s\)\s*\|\s*([\d.]+)\s*ms total\s*\|\s*(\d+)\s*drops\s*\|/i,
    ],
    'ringbufPerf',
    filePath,
    errors
  );
  const ringbufEvents = ringbufMatch ? parseIntStrict(ringbufMatch[1], 'ringbufEvents') : null;
  const ringbufKEvtPerSec = ringbufMatch
    ? parseFloatStrict(ringbufMatch[2], 'ringbufKEvtPerSec')
    : null;
  const ringbufMbPerSec = ringbufMatch
    ? parseFloatStrict(ringbufMatch[3], 'ringbufMbPerSec')
    : null;
  const ringbufElapsedMs = ringbufMatch
    ? parseFloatStrict(ringbufMatch[4], 'ringbufElapsedMs')
    : null;
  const ringbufDrops = ringbufMatch ? parseIntStrict(ringbufMatch[5], 'ringbufDrops') : null;

  // Row 4: OpenSSL 3.5.5 TLS 1.3 Uprobe | 2000 persistent req/resp (TCP_NODELAY) | Baseline 74.28 us/req -> Attached 123.27 us/req | +48.99 us/req delta | 0 drops, 0 MITM certs |
  const tlsMatch = extractRequired(
    clean,
    [
      /\|\s*OpenSSL\s+([\d.]+)\s+TLS 1\.3 Uprobe\s*\|\s*([\d,]+)\s+persistent req\/resp[^|]*\|\s*Baseline\s+([\d.]+)\s*us\/req\s*->\s*Attached\s+([\d.]+)\s*us\/req\s*\|\s*\+?([\d.]+)\s*us\/req delta\s*\|\s*(\d+)\s*drops,\s*(\d+)\s*MITM certs\s*\|/i,
    ],
    'tlsUprobePerf',
    filePath,
    errors
  );
  const opensslVersion = tlsMatch ? tlsMatch[1] : null;
  const tlsUprobeRequests = tlsMatch ? parseIntStrict(tlsMatch[2], 'tlsUprobeRequests') : null;
  const tlsBaselineUsPerReq = tlsMatch
    ? parseFloatStrict(tlsMatch[3], 'tlsBaselineUsPerReq')
    : null;
  const tlsAttachedUsPerReq = tlsMatch
    ? parseFloatStrict(tlsMatch[4], 'tlsAttachedUsPerReq')
    : null;
  const tlsUprobeDeltaUs = tlsMatch ? parseFloatStrict(tlsMatch[5], 'tlsUprobeDeltaUs') : null;
  const tlsRingbufDrops = tlsMatch ? parseIntStrict(tlsMatch[6], 'tlsRingbufDrops') : null;
  const tlsMitmCerts = tlsMatch ? parseIntStrict(tlsMatch[7], 'tlsMitmCerts') : null;

  // Row 5: spectre-l7 Streaming Dissector | HTTP/1.1 + HTTP/2 + PG v3 + Redis (20000 reqs) | 1094.9 k req/s (69.7 MB/s) | 913.3 ns/req | ...
  const l7Match = extractRequired(
    clean,
    [
      /\|\s*spectre-l7 Streaming Dissector\s*\|\s*[^|]*?\(([\d,]+)\s*reqs\)\s*\|\s*([\d.]+)\s*k req\/s\s*\(([\d.]+)\s*MB\/s\)\s*\|\s*([\d.]+)\s*ns\/req\s*\|/i,
    ],
    'l7DissectorPerf',
    filePath,
    errors
  );
  const l7DissectorRequests = l7Match ? parseIntStrict(l7Match[1], 'l7DissectorRequests') : null;
  const l7DissectorKReqPerSec = l7Match
    ? parseFloatStrict(l7Match[2], 'l7DissectorKReqPerSec')
    : null;
  const l7DissectorMbPerSec = l7Match
    ? parseFloatStrict(l7Match[3], 'l7DissectorMbPerSec')
    : null;
  const l7DissectorNsPerReq = l7Match
    ? parseFloatStrict(l7Match[4], 'l7DissectorNsPerReq')
    : null;

  // Row 6: spectre-verifier Static Analysis | 2000 static verifications + 6 ELF probes | 3.3 k verifs/s | 302.48 us/prog | 0 false accepts vs Linux 6.18 |
  const verifierMatch = extractRequired(
    clean,
    [
      /\|\s*spectre-verifier Static Analysis\s*\|\s*([\d,]+)\s*static verifications\s*\+\s*(\d+)\s*ELF probes\s*\|\s*([\d.]+)\s*k verifs\/s\s*\|\s*([\d.]+)\s*us\/prog\s*\|\s*(\d+)\s*false accepts/i,
    ],
    'verifierPerf',
    filePath,
    errors
  );
  const verifierPrograms = verifierMatch
    ? parseIntStrict(verifierMatch[1], 'verifierPrograms')
    : null;
  const bpfProbesCount = verifierMatch
    ? parseIntStrict(verifierMatch[2], 'bpfProbesCount')
    : null;
  const verifierKVerifsPerSec = verifierMatch
    ? parseFloatStrict(verifierMatch[3], 'verifierKVerifsPerSec')
    : null;
  const verifierUsPerProg = verifierMatch
    ? parseFloatStrict(verifierMatch[4], 'verifierUsPerProg')
    : null;
  const verifierFalseAccepts = verifierMatch
    ? parseIntStrict(verifierMatch[5], 'verifierFalseAccepts')
    : null;

  return {
    osArch,
    benchCommitSha,
    xdpKernelPackets,
    xdpKernelMpps,
    xdpKernelNsPerPkt,
    bpfVmPackets,
    bpfVmMpps,
    bpfVmNsPerPkt,
    ringbufEvents,
    ringbufKEvtPerSec,
    ringbufMbPerSec,
    ringbufElapsedMs,
    ringbufDrops,
    opensslVersion,
    tlsUprobeRequests,
    tlsBaselineUsPerReq,
    tlsAttachedUsPerReq,
    tlsUprobeDeltaUs,
    tlsRingbufDrops,
    tlsMitmCerts,
    l7DissectorRequests,
    l7DissectorKReqPerSec,
    l7DissectorMbPerSec,
    l7DissectorNsPerReq,
    verifierPrograms,
    bpfProbesCount,
    verifierKVerifsPerSec,
    verifierUsPerProg,
    verifierFalseAccepts,
  };
}

/**
 * Parse PROGRESS.md for M01-M09 verification proofs (never picking stale M08 bench numbers).
 */
function parseProgressMd(mdRaw, filePath, errors) {
  const clean = stripDecorators(mdRaw);

  const kernelMatch = matchOptional(mdRaw, [/Linux\s+([\d.]+-[^\s`]+)/i]);
  const kernelRelease = kernelMatch ? kernelMatch[1] : null;

  const miriMatch = extractRequired(
    clean,
    [/(\d+)\s*\/\s*(\d+)\s*Miri\s*\((\d+)\s*UB\)/i],
    'miriProof',
    filePath,
    errors
  );
  const miriPassed = miriMatch ? parseIntStrict(miriMatch[1], 'miriPassed') : null;
  const miriTotal = miriMatch ? parseIntStrict(miriMatch[2], 'miriTotal') : null;
  const miriUbCount = miriMatch ? parseIntStrict(miriMatch[3], 'miriUbCount') : null;

  const elfFuzzMatch = extractRequired(
    clean,
    [/([\d,]+)\s*hostile ELF\/BTF fuzz\s*(\d+)\s*panics/i],
    'elfBtfFuzz',
    filePath,
    errors
  );
  const elfFuzzInputs = elfFuzzMatch ? parseIntStrict(elfFuzzMatch[1], 'elfFuzzInputs') : null;
  const elfFuzzPanics = elfFuzzMatch ? parseIntStrict(elfFuzzMatch[2], 'elfFuzzPanics') : null;

  const verifierSuiteMatch = extractRequired(
    clean,
    [/(\d+)\s*\/\s*(\d+)\s*\((\d+)\s*false accepts/i],
    'verifierKernelOracle',
    filePath,
    errors
  );
  const verifierKernelPassed = verifierSuiteMatch
    ? parseIntStrict(verifierSuiteMatch[1], 'verifierKernelPassed')
    : null;
  const verifierKernelTotal = verifierSuiteMatch
    ? parseIntStrict(verifierSuiteMatch[2], 'verifierKernelTotal')
    : null;
  const verifierKernelFalseAccepts = verifierSuiteMatch
    ? parseIntStrict(verifierSuiteMatch[3], 'verifierKernelFalseAccepts')
    : null;

  const goMatch = matchOptional(clean, [/Go\s+([\d.]+)\s+(\d+)\s*goroutines/i]);
  const goVersion = goMatch ? goMatch[1] : null;
  const goGoroutinesTested = goMatch ? parseIntStrict(goMatch[2], 'goGoroutinesTested') : null;

  const l7FuzzMatch = extractRequired(
    clean,
    [/([\d,]+)\s*adversarial fuzz\s*(\d+)\s*panics/i],
    'l7Fuzz',
    filePath,
    errors
  );
  const l7FuzzInputs = l7FuzzMatch ? parseIntStrict(l7FuzzMatch[1], 'l7FuzzInputs') : null;
  const l7FuzzPanics = l7FuzzMatch ? parseIntStrict(l7FuzzMatch[2], 'l7FuzzPanics') : null;

  const onCpuMatch = matchOptional(clean, [/99Hz On-CPU\s*\((\d+)\s*\/\s*(\d+)\s*=\s*([\d.]+)%/i]);
  const profilerOnCpuPct = onCpuMatch ? parseFloatStrict(onCpuMatch[3], 'profilerOnCpuPct') : null;

  const offCpuMatch = matchOptional(clean, [/Off-CPU\s*\([\d.]+s\/[\d.]+s\s*=\s*([\d.]+)%/i]);
  const profilerOffCpuPct = offCpuMatch
    ? parseFloatStrict(offCpuMatch[1], 'profilerOffCpuPct')
    : null;

  const m07RowMatch = extractRequired(
    clean,
    [
      /\|\s*M07\s*\|[^\n]*?([\d,]+)\s*\/\s*([\d,]+)\s*reqs recovered\s*\((\d+)\s*mismatches,\s*(\d+)\s*RingBuf drops,\s*(\d+)\s*Go stack crashes,\s*(\d+)\s*XDP SYN drops,\s*FDs:\s*(\d+)->(\d+)\)/i,
    ],
    'meshOracleM07Proof',
    filePath,
    errors
  );
  const meshOracleRecovered = m07RowMatch
    ? parseIntStrict(m07RowMatch[1], 'meshOracleRecovered')
    : null;
  const meshOracleTotal = m07RowMatch ? parseIntStrict(m07RowMatch[2], 'meshOracleTotal') : null;
  const meshOracleMismatches = m07RowMatch
    ? parseIntStrict(m07RowMatch[3], 'meshOracleMismatches')
    : null;
  const meshOracleRingbufDrops = m07RowMatch
    ? parseIntStrict(m07RowMatch[4], 'meshOracleRingbufDrops')
    : null;
  const meshOracleGoCrashes = m07RowMatch
    ? parseIntStrict(m07RowMatch[5], 'meshOracleGoCrashes')
    : null;
  const meshOracleXdpSynDrops = m07RowMatch
    ? parseIntStrict(m07RowMatch[6], 'meshOracleXdpSynDrops')
    : null;
  const meshOracleFdsBefore = m07RowMatch
    ? parseIntStrict(m07RowMatch[7], 'meshOracleFdsBefore')
    : null;
  const meshOracleFdsAfter = m07RowMatch
    ? parseIntStrict(m07RowMatch[8], 'meshOracleFdsAfter')
    : null;

  const m09RowMatch = extractRequired(
    clean,
    [/\|\s*M09\s*\|[^\n]*?(\d+)\s*\/\s*(\d+)\s*Vitest[^\n]*?([\d,]+)\s*\/\s*([\d,]+)\s*oracle\s*([\d.]+)s/i],
    'm09FinalGate',
    filePath,
    errors
  );
  const studioVitestPassed = m09RowMatch
    ? parseIntStrict(m09RowMatch[1], 'studioVitestPassed')
    : null;
  const studioVitestTotal = m09RowMatch
    ? parseIntStrict(m09RowMatch[2], 'studioVitestTotal')
    : null;
  const m09OracleRecovered = m09RowMatch
    ? parseIntStrict(m09RowMatch[3], 'm09OracleRecovered')
    : null;
  const m09OracleTotal = m09RowMatch ? parseIntStrict(m09RowMatch[4], 'm09OracleTotal') : null;
  const meshOracleDurationSec = m09RowMatch
    ? parseFloatStrict(m09RowMatch[5], 'meshOracleDurationSec')
    : null;

  return {
    kernelRelease,
    miriPassed,
    miriTotal,
    miriUbCount,
    elfFuzzInputs,
    elfFuzzPanics,
    verifierKernelPassed,
    verifierKernelTotal,
    verifierKernelFalseAccepts,
    goVersion,
    goGoroutinesTested,
    l7FuzzInputs,
    l7FuzzPanics,
    profilerOnCpuPct,
    profilerOffCpuPct,
    meshOracleRecovered: m09OracleRecovered ?? meshOracleRecovered,
    meshOracleTotal: m09OracleTotal ?? meshOracleTotal,
    meshOracleMismatches,
    meshOracleRingbufDrops,
    meshOracleGoCrashes,
    meshOracleXdpSynDrops,
    meshOracleFdsBefore,
    meshOracleFdsAfter,
    meshOracleDurationSec,
    studioVitestPassed,
    studioVitestTotal,
  };
}

function buildSummary(opts) {
  const errors = [];

  if (!fs.existsSync(opts.reportPath)) {
    throw new Error(`[INPUT_MISSING] Benchmark report not found: ${opts.reportPath}`);
  }
  if (!fs.existsSync(opts.progressPath)) {
    throw new Error(`[INPUT_MISSING] Progress ledger not found: ${opts.progressPath}`);
  }

  const reportBuf = fs.readFileSync(opts.reportPath);
  const progressBuf = fs.readFileSync(opts.progressPath);
  const reportText = reportBuf.toString('utf8');
  const progressText = progressBuf.toString('utf8');

  const wasmPath = discoverWasmBinary(opts.wasmPath);
  const wasmInfo = measureWasmBinary(wasmPath);
  const git = getGitMeta();
  const ws = inspectWorkspaceCrates();

  if (ws.count <= 0) {
    errors.push('No valid crates found in [workspace].members of Cargo.toml');
  }
  if (!git.commitSha) {
    errors.push('Unable to resolve git commitSha');
  }

  const perf = parseEbpfPerfMd(reportText, opts.reportPath, errors);
  const prog = parseProgressMd(progressText, opts.progressPath, errors);

  // Hard correctness, safety & anti-drift invariants
  if (perf.xdpKernelMpps !== null && !(perf.xdpKernelMpps > 0)) {
    errors.push(`xdpKernelMpps must be > 0 (got ${perf.xdpKernelMpps})`);
  }
  if (perf.bpfVmMpps !== null && !(perf.bpfVmMpps > 0)) {
    errors.push(`bpfVmMpps must be > 0 (got ${perf.bpfVmMpps})`);
  }
  if (perf.ringbufDrops !== null && perf.ringbufDrops !== 0) {
    errors.push(`RingBuf drops != 0 (${perf.ringbufDrops})`);
  }
  if (perf.tlsRingbufDrops !== null && perf.tlsRingbufDrops !== 0) {
    errors.push(`TLS uprobe RingBuf drops != 0 (${perf.tlsRingbufDrops})`);
  }
  if (perf.tlsMitmCerts !== null && perf.tlsMitmCerts !== 0) {
    errors.push(`TLS uprobe MITM certs != 0 (${perf.tlsMitmCerts})`);
  }
  if (perf.verifierFalseAccepts !== null && perf.verifierFalseAccepts !== 0) {
    errors.push(`Verifier false accepts != 0 (${perf.verifierFalseAccepts})`);
  }
  if (prog.miriUbCount !== null && prog.miriUbCount !== 0) {
    errors.push(`Miri UB violation: miriUbCount=${prog.miriUbCount}`);
  }
  if (prog.elfFuzzPanics !== null && prog.elfFuzzPanics !== 0) {
    errors.push(`ELF/BTF fuzz panics != 0 (${prog.elfFuzzPanics})`);
  }
  if (prog.l7FuzzPanics !== null && prog.l7FuzzPanics !== 0) {
    errors.push(`L7 fuzz panics != 0 (${prog.l7FuzzPanics})`);
  }
  if (
    prog.verifierKernelTotal !== null &&
    (prog.verifierKernelTotal < 120 ||
      prog.verifierKernelPassed !== prog.verifierKernelTotal ||
      prog.verifierKernelFalseAccepts !== 0)
  ) {
    errors.push(
      `Verifier kernel oracle incomplete: ${prog.verifierKernelPassed}/${prog.verifierKernelTotal} (falseAccepts=${prog.verifierKernelFalseAccepts})`
    );
  }
  if (
    prog.meshOracleTotal !== null &&
    (prog.meshOracleTotal < 50000 ||
      prog.meshOracleRecovered !== prog.meshOracleTotal ||
      prog.meshOracleMismatches !== 0 ||
      prog.meshOracleRingbufDrops !== 0 ||
      prog.meshOracleGoCrashes !== 0)
  ) {
    errors.push(
      `Live mesh oracle failed: ${prog.meshOracleRecovered}/${prog.meshOracleTotal} (mismatches=${prog.meshOracleMismatches}, drops=${prog.meshOracleRingbufDrops}, goCrashes=${prog.meshOracleGoCrashes})`
    );
  }
  if (
    prog.meshOracleFdsBefore !== null &&
    prog.meshOracleFdsAfter !== null &&
    prog.meshOracleFdsBefore !== prog.meshOracleFdsAfter
  ) {
    errors.push(
      `FD leak detected in mesh oracle: ${prog.meshOracleFdsBefore} -> ${prog.meshOracleFdsAfter}`
    );
  }
  if (
    prog.studioVitestTotal !== null &&
    (prog.studioVitestTotal <= 0 || prog.studioVitestPassed !== prog.studioVitestTotal)
  ) {
    errors.push(`Studio Vitest failed: ${prog.studioVitestPassed}/${prog.studioVitestTotal}`);
  }

  if (errors.length > 0 && opts.strict) {
    throw new Error(`[STRICT_GATE_FAILED] Refusing to write summary.json:\n - ${errors.join('\n - ')}`);
  }

  const status = errors.length === 0 ? 'VERIFIED_LIVE' : 'PARTIAL_VERIFY';

  return {
    schemaVersion: '1.0.0',
    slug: 'spectre',
    status,
    commitSha: git.commitSha,
    workingTreeClean: git.workingTreeClean,
    verifiedAt: new Date().toISOString(),
    wasmAssetPath: '/labs/spectre/assets/spectre_wasm_bg.wasm',
    wasmSizeKb: wasmInfo.kb,
    wasmSizeBytes: wasmInfo.bytes,
    wasmGzipKb: wasmInfo.gzipKb,
    cratesCount: ws.count,
    headlineMetrics: [
      {
        id: 'xdp_packet_filter',
        label: 'XDP Kernel / BpfVm',
        value:
          perf.xdpKernelMpps !== null && perf.xdpKernelNsPerPkt !== null
            ? `${perf.xdpKernelMpps.toFixed(2)} Mpps (${perf.xdpKernelNsPerPkt.toFixed(2)} ns/pkt)`
            : null,
      },
      {
        id: 'l7_tls_uprobe',
        label: 'L7 Decode & TLS 1.3',
        value:
          perf.l7DissectorKReqPerSec !== null && perf.tlsUprobeDeltaUs !== null
            ? `${perf.l7DissectorKReqPerSec.toFixed(1)}k req/s (+${perf.tlsUprobeDeltaUs.toFixed(2)} us)`
            : null,
      },
      {
        id: 'mesh_oracle_verifier',
        label: 'Live Mesh Oracle & Verifier',
        value:
          prog.meshOracleRecovered !== null &&
          prog.meshOracleTotal !== null &&
          perf.ringbufDrops !== null
            ? `${formatInt(prog.meshOracleRecovered)}/${formatInt(prog.meshOracleTotal)} (${perf.ringbufDrops} drops)`
            : null,
      },
    ],
    extendedProof: {
      osArch: perf.osArch,
      kernelRelease: prog.kernelRelease,
      benchCommitSha: perf.benchCommitSha,
      opensslVersion: perf.opensslVersion,
      goVersion: prog.goVersion,
      goGoroutinesTested: prog.goGoroutinesTested,
      bpfProbesCount: perf.bpfProbesCount,
      denyUnsafeCratesCount: ws.denyUnsafeCount,
      xdpKernelPackets: perf.xdpKernelPackets,
      xdpKernelMpps: perf.xdpKernelMpps,
      xdpKernelNsPerPkt: perf.xdpKernelNsPerPkt,
      bpfVmPackets: perf.bpfVmPackets,
      bpfVmMpps: perf.bpfVmMpps,
      bpfVmNsPerPkt: perf.bpfVmNsPerPkt,
      ringbufEvents: perf.ringbufEvents,
      ringbufKEvtPerSec: perf.ringbufKEvtPerSec,
      ringbufMbPerSec: perf.ringbufMbPerSec,
      ringbufElapsedMs: perf.ringbufElapsedMs,
      ringbufDrops: perf.ringbufDrops,
      tlsUprobeRequests: perf.tlsUprobeRequests,
      tlsBaselineUsPerReq: perf.tlsBaselineUsPerReq,
      tlsAttachedUsPerReq: perf.tlsAttachedUsPerReq,
      tlsUprobeDeltaUs: perf.tlsUprobeDeltaUs,
      tlsRingbufDrops: perf.tlsRingbufDrops,
      tlsMitmCerts: perf.tlsMitmCerts,
      l7DissectorRequests: perf.l7DissectorRequests,
      l7DissectorKReqPerSec: perf.l7DissectorKReqPerSec,
      l7DissectorMbPerSec: perf.l7DissectorMbPerSec,
      l7DissectorNsPerReq: perf.l7DissectorNsPerReq,
      verifierPrograms: perf.verifierPrograms,
      verifierKVerifsPerSec: perf.verifierKVerifsPerSec,
      verifierUsPerProg: perf.verifierUsPerProg,
      verifierFalseAccepts: perf.verifierFalseAccepts,
      verifierKernelPassed: prog.verifierKernelPassed,
      verifierKernelTotal: prog.verifierKernelTotal,
      elfFuzzInputs: prog.elfFuzzInputs,
      l7FuzzInputs: prog.l7FuzzInputs,
      fuzzPanics: (prog.elfFuzzPanics ?? 0) + (prog.l7FuzzPanics ?? 0),
      miriPassed: prog.miriPassed,
      miriTotal: prog.miriTotal,
      miriUbCount: prog.miriUbCount,
      profilerOnCpuPct: prog.profilerOnCpuPct,
      profilerOffCpuPct: prog.profilerOffCpuPct,
      meshOracleRecovered: prog.meshOracleRecovered,
      meshOracleTotal: prog.meshOracleTotal,
      meshOracleMismatches: prog.meshOracleMismatches,
      meshOracleRingbufDrops: prog.meshOracleRingbufDrops,
      meshOracleGoCrashes: prog.meshOracleGoCrashes,
      meshOracleXdpSynDrops: prog.meshOracleXdpSynDrops,
      meshOracleFdsBefore: prog.meshOracleFdsBefore,
      meshOracleFdsAfter: prog.meshOracleFdsAfter,
      meshOracleDurationSec: prog.meshOracleDurationSec,
      studioVitestPassed: prog.studioVitestPassed,
      studioVitestTotal: prog.studioVitestTotal,
      wasmGzipBytes: wasmInfo.gzipBytes,
      wasmSiKb: wasmInfo.siKb,
      wasmGzipSiKb: wasmInfo.gzipSiKb,
    },
    provenance: {
      reportSha256: sha256Hex(reportBuf),
      progressSha256: sha256Hex(progressBuf),
      sourceFiles: [toPosixRel(opts.reportPath), toPosixRel(opts.progressPath)],
      wasmSourcePath: wasmInfo.relPath,
      wasmSha256: wasmInfo.sha256,
      missingOrWarnings: errors,
    },
  };
}

function stripVolatile(obj) {
  return {
    schemaVersion: obj.schemaVersion,
    slug: obj.slug,
    status: obj.status,
    wasmAssetPath: obj.wasmAssetPath,
    wasmSizeKb: obj.wasmSizeKb,
    wasmSizeBytes: obj.wasmSizeBytes,
    wasmGzipKb: obj.wasmGzipKb,
    cratesCount: obj.cratesCount,
    headlineMetrics: obj.headlineMetrics,
    extendedProof: obj.extendedProof,
    provenance: obj.provenance,
  };
}

function verifyExistingSummary(opts, freshSummary) {
  if (!fs.existsSync(opts.outPath)) {
    throw new Error(`[VERIFY_FAIL] Summary file not found: ${opts.outPath}`);
  }
  const existing = JSON.parse(fs.readFileSync(opts.outPath, 'utf8'));
  if (existing.status !== 'VERIFIED_LIVE') {
    throw new Error(`[VERIFY_FAIL] Existing summary status is ${existing.status}, expected VERIFIED_LIVE`);
  }
  if (!Array.isArray(existing.provenance?.missingOrWarnings) || existing.provenance.missingOrWarnings.length > 0) {
    throw new Error(
      `[VERIFY_FAIL] summary.json has non-empty missingOrWarnings: ${JSON.stringify(existing.provenance?.missingOrWarnings)}`
    );
  }
  if (JSON.stringify(stripVolatile(existing)) !== JSON.stringify(stripVolatile(freshSummary))) {
    throw new Error(
      `[DRIFT_DETECTED] ${toPosixRel(opts.outPath)} is out of sync with ebpf_perf/PROGRESS/WASM artifacts. Run "make telemetry-summary".`
    );
  }
}

function writeAtomicJson(outPath, payload) {
  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  const tmpPath = `${outPath}.tmp.${process.pid}`;
  try {
    fs.writeFileSync(tmpPath, `${JSON.stringify(payload, null, 2)}\n`, 'utf8');
    fs.renameSync(tmpPath, outPath);
  } catch (err) {
    if (fs.existsSync(tmpPath)) fs.unlinkSync(tmpPath);
    throw err;
  }
}

function main() {
  const opts = parseArgs(process.argv.slice(2));
  const summary = buildSummary(opts);

  if (opts.verifyOnly) {
    verifyExistingSummary(opts, summary);
    console.log(
      `[OK] verify-live (slug=${summary.slug}, commit=${summary.commitSha}, crates=${summary.cratesCount}, ` +
        `denyUnsafe=${summary.extendedProof.denyUnsafeCratesCount}/${summary.cratesCount}, ` +
        `XDP=${summary.extendedProof.xdpKernelMpps} Mpps, BpfVm=${summary.extendedProof.bpfVmMpps} Mpps, ` +
        `L7=${summary.extendedProof.l7DissectorKReqPerSec}k req/s, TLS=+${summary.extendedProof.tlsUprobeDeltaUs} us, ` +
        `oracle=${summary.extendedProof.meshOracleRecovered}/${summary.extendedProof.meshOracleTotal}, ` +
        `wasm=${summary.wasmSizeKb} KB / ${summary.wasmGzipKb} KB gzip).`
    );
    return;
  }

  writeAtomicJson(opts.outPath, summary);
  console.log(
    `[telemetry] Wrote ${toPosixRel(opts.outPath)} (slug=${summary.slug}, status=${summary.status}, ` +
      `commit=${summary.commitSha}, crates=${summary.cratesCount}, ` +
      `wasm=${summary.wasmSizeKb} KB / ${summary.wasmGzipKb} KB gzip, sha256=${summary.provenance.reportSha256.slice(0, 12)})`
  );
}

try {
  main();
} catch (err) {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
}
