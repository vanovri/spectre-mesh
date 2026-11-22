export type LabSlug =
  | 'vectradb'
  | 'kronos'
  | 'aegis'
  | 'novaserve'
  | 'spectre'
  | 'dst-kv';

export interface LabTabMeta {
  slug: LabSlug;
  label: string;
  href: string;
  accent: string;
}

export const SYSTEMS_LAB_TABS: readonly LabTabMeta[] = [
  { slug: 'vectradb', label: 'VectraDB', href: '/labs/vectradb/', accent: '#38bdf8' },
  { slug: 'kronos', label: 'Kronos', href: '/labs/kronos/', accent: '#34d399' },
  { slug: 'aegis', label: 'Aegis', href: '/labs/aegis/', accent: '#a78bfa' },
  { slug: 'novaserve', label: 'NovaServe', href: '/labs/novaserve/', accent: '#fb7185' },
  { slug: 'spectre', label: 'SpectreMesh', href: '/labs/spectre/', accent: '#22d3ee' },
  { slug: 'dst-kv', label: 'DST-KV', href: '/labs/dst-kv/', accent: '#fbbf24' },
];

// Minimal valid 29-byte WebAssembly module probing WebAssembly SIMD128 (`v128` + `i8x16.splat`)
export const WASM_SIMD128_PROBE = new Uint8Array([
  0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
  0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7b,
  0x03, 0x02, 0x01, 0x00,
  0x0a, 0x08, 0x01, 0x06, 0x00, 0x41, 0x00, 0xfd, 0x0f, 0x0b,
]);

export type WorkerRequest =
  | { id: number; kind: 'presets' }
  | { id: number; kind: 'verify'; bytecodeHex: string }
  | { id: number; kind: 'xdp'; bytecodeHex: string; packetHex: string }
  | { id: number; kind: 'dissect'; protocolHint: string; egressHex: string; ingressHex: string }
  | { id: number; kind: 'flamegraph'; title: string; unit: string; folded: string; baselineFolded?: string };

export type WorkerPayload = WorkerRequest extends infer U
  ? U extends WorkerRequest
    ? Omit<U, 'id'>
    : never
  : never;

export type WorkerResponse =
  | { id: number; ok: true; data: unknown }
  | { id: number; ok: false; error: string };

export function utf8ToHex(text: string): string {
  const bytes = new TextEncoder().encode(text);
  let out = '';
  for (const b of bytes) {
    out += b.toString(16).padStart(2, '0');
  }
  return out;
}

export function formatHexPreview(hex: string, maxChars = 72): string {
  const clean = hex.replace(/[^0-9a-fA-F]/g, '').toLowerCase();
  if (clean.length <= maxChars) return clean;
  return `${clean.slice(0, maxChars)}... (${clean.length / 2} B)`;
}
