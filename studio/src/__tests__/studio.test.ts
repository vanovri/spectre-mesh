import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

import {
  SYSTEMS_LAB_TABS,
  WASM_SIMD128_PROBE,
  formatHexPreview,
  utf8ToHex,
} from '../lib/protocol';
import { parseTelemetrySummary } from '../lib/telemetry';

describe('SpectreMesh Studio contracts', () => {
  it('validates LabTelemetrySummary JSON schema written by spectre-bench', () => {
    const summaryPath = resolve(__dirname, '../../public/telemetry/summary.json');
    const raw = JSON.parse(readFileSync(summaryPath, 'utf-8')) as unknown;
    const summary = parseTelemetrySummary(raw);
    expect(summary.schemaVersion).toBe(1);
    expect(summary.slug).toBe('spectre');
    expect(summary.secondaryMetrics).toHaveLength(3);
    expect(Number(summary.headlineMetric.value)).toBeGreaterThan(0);
  });

  it('includes valid 29-byte WASM SIMD128 binary probe and active spectre dock tab', () => {
    expect(WASM_SIMD128_PROBE.length).toBe(29);
    // WASM magic header `\0asm`
    expect(Array.from(WASM_SIMD128_PROBE.slice(0, 4))).toEqual([0x00, 0x61, 0x73, 0x6d]);
    // Contains SIMD prefix opcode `0xfd`
    expect(Array.from(WASM_SIMD128_PROBE)).toContain(0xfd);

    const spectre = SYSTEMS_LAB_TABS.find((t) => t.slug === 'spectre');
    expect(spectre).toBeDefined();
    expect(spectre?.href).toBe('/labs/spectre/');
    expect(SYSTEMS_LAB_TABS).toHaveLength(6);
  });

  it('encodes UTF-8 payloads and truncates hex previews cleanly', () => {
    const hex = utf8ToHex('GET / HTTP/1.1');
    expect(hex).toBe('474554202f20485454502f312e31');
    expect(formatHexPreview(hex, 12)).toBe('474554202f20... (14 B)');
  });
});
