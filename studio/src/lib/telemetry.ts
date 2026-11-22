import type { LabSlug } from './protocol';

export interface TelemetryMetric {
  label: string;
  value: string;
  unit?: string;
  deltaOrNote: string;
}

export interface LabTelemetrySummary {
  schemaVersion: 1;
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

export function parseTelemetrySummary(raw: unknown): LabTelemetrySummary {
  if (!raw || typeof raw !== 'object') {
    throw new Error('Telemetry summary must be a JSON object');
  }
  const o = raw as Record<string, unknown>;
  if (o.schemaVersion !== 1 || o.slug !== 'spectre') {
    throw new Error(`Invalid schemaVersion/slug: ${String(o.schemaVersion)}/${String(o.slug)}`);
  }
  if (typeof o.commitSha !== 'string' || typeof o.generatedAtIso !== 'string') {
    throw new Error('Missing commitSha or generatedAtIso');
  }
  if (typeof o.wasmSizeKb !== 'number' || !Number.isFinite(o.wasmSizeKb)) {
    throw new Error('Invalid wasmSizeKb');
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
