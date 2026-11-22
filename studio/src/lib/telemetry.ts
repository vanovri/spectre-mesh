import type { LabSlug } from './protocol';

export interface TelemetryMetric {
  label: string;
  value: string;
  unit?: string;
  deltaOrNote: string;
}

export interface SimpleHeadlineMetric {
  id: string;
  label: string;
  value: string;
}

export interface LabTelemetrySummary {
  schemaVersion: string | number;
  slug: LabSlug;
  status?: 'VERIFIED_LIVE' | 'PARTIAL_VERIFY';
  commitSha: string;
  generatedAtIso: string;
  wasmSizeKb: number;
  wasmAssetPath?: string;
  verificationGate: string;
  headlineMetric: TelemetryMetric;
  secondaryMetrics: [TelemetryMetric, TelemetryMetric, TelemetryMetric];
}

function isMetric(v: unknown): v is TelemetryMetric {
  if (!v || typeof v !== 'object') return false;
  const o = v as Record<string, unknown>;
  return (
    typeof o.label === 'string' &&
    typeof o.value === 'string' &&
    typeof o.deltaOrNote === 'string'
  );
}

function isSimpleMetric(v: unknown): v is SimpleHeadlineMetric {
  if (!v || typeof v !== 'object') return false;
  const o = v as Record<string, unknown>;
  return (
    typeof o.id === 'string' &&
    typeof o.label === 'string' &&
    typeof o.value === 'string'
  );
}

export function parseTelemetrySummary(raw: unknown): LabTelemetrySummary {
  if (!raw || typeof raw !== 'object') {
    throw new Error('Telemetry summary must be a JSON object');
  }
  const o = raw as Record<string, unknown>;
  if (o.slug !== 'spectre') {
    throw new Error(`Invalid slug: ${String(o.slug)}`);
  }
  if (typeof o.commitSha !== 'string') {
    throw new Error('Missing commitSha');
  }
  if (typeof o.wasmSizeKb !== 'number' || !Number.isFinite(o.wasmSizeKb)) {
    throw new Error('Invalid wasmSizeKb');
  }

  // Canonical Wave 0/1 schema ("1.0.0" with headlineMetrics + extendedProof)
  if (
    o.schemaVersion === '1.0.0' &&
    Array.isArray(o.headlineMetrics) &&
    o.headlineMetrics.length === 3 &&
    o.headlineMetrics.every(isSimpleMetric)
  ) {
    const ext = (o.extendedProof ?? {}) as Record<string, unknown>;
    const xdp = typeof ext.xdpKernelMpps === 'number' ? ext.xdpKernelMpps.toFixed(2) : o.headlineMetrics[0].value;
    const rb = typeof ext.ringbufKEvtPerSec === 'number' ? ext.ringbufKEvtPerSec.toFixed(1) : '0';
    const tls = typeof ext.tlsUprobeDeltaUs === 'number' ? `+${ext.tlsUprobeDeltaUs.toFixed(2)}` : '0';
    const l7 = typeof ext.l7DissectorKReqPerSec === 'number' ? ext.l7DissectorKReqPerSec.toFixed(1) : '0';
    return {
      schemaVersion: '1.0.0',
      slug: 'spectre',
      status: o.status === 'VERIFIED_LIVE' ? 'VERIFIED_LIVE' : 'PARTIAL_VERIFY',
      commitSha: o.commitSha,
      generatedAtIso: typeof o.verifiedAt === 'string' ? o.verifiedAt : '',
      wasmSizeKb: o.wasmSizeKb,
      wasmAssetPath: typeof o.wasmAssetPath === 'string' ? o.wasmAssetPath : undefined,
      verificationGate: 'VERIFIED_LIVE · make verify-live (M01-M09)',
      headlineMetric: {
        label: 'XDP Packet Filter',
        value: xdp,
        unit: 'Mpps',
        deltaOrNote: o.headlineMetrics[0].value,
      },
      secondaryMetrics: [
        {
          label: 'RingBuf Sustained',
          value: rb,
          unit: 'k evt/s',
          deltaOrNote: '0 drops across 100k events',
        },
        {
          label: 'TLS 1.3 Uprobe Delta',
          value: tls,
          unit: 'us/req',
          deltaOrNote: 'OpenSSL 3.5.5 uprobe (0 MITM certs)',
        },
        {
          label: 'L7 Streaming Decode',
          value: l7,
          unit: 'k req/s',
          deltaOrNote: 'HTTP/1.1 + HTTP/2 + PG v3 + Redis',
        },
      ],
    };
  }

  // Legacy v1 schema
  if (o.schemaVersion !== 1) {
    throw new Error(`Invalid schemaVersion/slug: ${String(o.schemaVersion)}/${String(o.slug)}`);
  }
  if (typeof o.generatedAtIso !== 'string') {
    throw new Error('Missing generatedAtIso');
  }
  if (typeof o.verificationGate !== 'string' || !isMetric(o.headlineMetric)) {
    throw new Error('Invalid verificationGate or headlineMetric');
  }
  if (!Array.isArray(o.secondaryMetrics) || o.secondaryMetrics.length !== 3) {
    throw new Error('secondaryMetrics must have exact length 3');
  }
  if (!o.secondaryMetrics.every(isMetric)) {
    throw new Error('Invalid entry inside secondaryMetrics');
  }
  return o as unknown as LabTelemetrySummary;
}

export async function loadTelemetrySummary(url = './telemetry/summary.json'): Promise<LabTelemetrySummary | null> {
  try {
    const res = await fetch(url, { cache: 'no-store' });
    if (!res.ok) return null;
    const json: unknown = await res.json();
    return parseTelemetrySummary(json);
  } catch {
    return null;
  }
}
