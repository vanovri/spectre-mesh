import './styles.css';
import { registerSystemsLabDock } from './components/systems-lab-dock';
import type { WorkerPayload, WorkerRequest, WorkerResponse } from './lib/protocol';
import { loadTelemetrySummary } from './lib/telemetry';

interface EbpfPreset {
  id: string;
  label: string;
  expectedVerdict: string;
  bytecodeHex: string;
  samplePacketHex: string;
}
interface L7Preset {
  id: string;
  label: string;
  protocolHint: string;
  egressHex: string;
  ingressHex: string;
}
interface FlamePreset {
  id: string;
  label: string;
  title: string;
  unit: string;
  folded: string;
  baselineFolded?: string | null;
}
interface PresetCatalog {
  ebpf: EbpfPreset[];
  l7: L7Preset[];
  flamegraphs: FlamePreset[];
}

registerSystemsLabDock();

const worker = new Worker(new URL('./worker/spectre.worker.ts', import.meta.url), {
  type: 'module',
});

let reqCounter = 1;
const pending = new Map<number, { resolve: (v: unknown) => void; reject: (e: Error) => void }>();

worker.onmessage = (ev: MessageEvent<WorkerResponse>) => {
  const msg = ev.data;
  const entry = pending.get(msg.id);
  if (!entry) return;
  pending.delete(msg.id);
  if (msg.ok) {
    entry.resolve(msg.data);
  } else {
    entry.reject(new Error(msg.error));
  }
};

function callWorker<T>(req: WorkerPayload): Promise<T> {
  const id = reqCounter++;
  return new Promise<T>((resolve, reject) => {
    pending.set(id, { resolve: resolve as (v: unknown) => void, reject });
    worker.postMessage({ ...req, id } as WorkerRequest);
  });
}

function byId<T extends HTMLElement>(id: string): T {
  const el = document.getElementById(id);
  if (!el) throw new Error(`Missing element #${id}`);
  return el as T;
}

async function hydrateTelemetry(): Promise<void> {
  const summary = await loadTelemetrySummary('./telemetry/summary.json');
  if (!summary) return;
  const dock = document.getElementById('lab-dock');
  if (dock) {
    dock.setAttribute('wasm-kb', String(summary.wasmSizeKb));
    dock.setAttribute('gate', summary.verificationGate);
  }
  byId('m-xdp').textContent = `${summary.headlineMetric.value} ${summary.headlineMetric.unit ?? ''}`.trim();
  byId('m-rb').textContent = `${summary.secondaryMetrics[0].value} ${summary.secondaryMetrics[0].unit ?? ''}`.trim();
  byId('m-tls').textContent = `${summary.secondaryMetrics[1].value} ${summary.secondaryMetrics[1].unit ?? ''}`.trim();
  byId('m-l7').textContent = `${summary.secondaryMetrics[2].value} ${summary.secondaryMetrics[2].unit ?? ''}`.trim();
}

function setupTabs(): void {
  const buttons = document.querySelectorAll<HTMLButtonElement>('.tab-btn');
  const panels = document.querySelectorAll<HTMLElement>('.panel');
  buttons.forEach((btn) => {
    btn.addEventListener('click', () => {
      const target = btn.dataset.tab;
      buttons.forEach((b) => {
        const active = b.dataset.tab === target;
        b.classList.toggle('active', active);
        b.setAttribute('aria-selected', String(active));
      });
      panels.forEach((p) => {
        p.classList.toggle('active', p.id === `panel-${target}`);
      });
    });
  });
}

async function main(): Promise<void> {
  setupTabs();
  void hydrateTelemetry();

  const catalog = await callWorker<PresetCatalog>({ kind: 'presets' });

  const ebpfSelect = byId<HTMLSelectElement>('ebpf-preset-select');
  const ebpfBytecode = byId<HTMLTextAreaElement>('ebpf-bytecode');
  const ebpfPacket = byId<HTMLTextAreaElement>('ebpf-packet');
  const ebpfDisasm = byId<HTMLPreElement>('ebpf-disasm');
  const ebpfVerdict = byId<HTMLDivElement>('ebpf-verdict');
  const ebpfTrace = byId<HTMLPreElement>('ebpf-trace');

  catalog.ebpf.forEach((p) => {
    const opt = document.createElement('option');
    opt.value = p.id;
    opt.textContent = p.label;
    ebpfSelect.appendChild(opt);
  });

  const runVerifier = async () => {
    const hex = ebpfBytecode.value;
    const pkt = ebpfPacket.value;
    const res = await callWorker<{
      accepted: boolean;
      disassembly: Array<{ pc: number; text: string }>;
      report: {
        verdict: string;
        insns_processed: number;
        max_stack_depth: number;
        error: unknown;
        trace: Array<{ pc: number; insn_text: string; regs: string[]; note: string }>;
      };
    }>({ kind: 'verify', bytecodeHex: hex });

    ebpfDisasm.textContent = res.disassembly.map((d) => `${String(d.pc).padStart(3, '0')}: ${d.text}`).join('\n');
    let simLabel = 'Not executed (Rejected by verifier)';
    if (res.accepted) {
      const sim = await callWorker<{ actionLabel: string; result: { cycles: number; return_code: number } }>({
        kind: 'xdp',
        bytecodeHex: hex,
        packetHex: pkt,
      });
      simLabel = `XDP VM Action: ${sim.actionLabel} (rc=${sim.result.return_code}, ${sim.result.cycles} cycles)`;
    }

    ebpfVerdict.className = `verdict-banner ${res.accepted ? 'accept' : 'reject'}`;
    ebpfVerdict.textContent = `${res.accepted ? 'ACCEPT' : 'REJECT'} | insns=${res.report.insns_processed} | stack=${res.report.max_stack_depth}B | ${simLabel}` +
      (res.report.error ? ` | Err: ${JSON.stringify(res.report.error)}` : '');

    ebpfTrace.textContent = res.report.trace
      .map((s) => `[pc=${s.pc}] ${s.insn_text}\n  r0=${s.regs[0]} r1=${s.regs[1]} r2=${s.regs[2]} r3=${s.regs[3]} | ${s.note}`)
      .join('\n');
  };

  ebpfSelect.addEventListener('change', () => {
    const p = catalog.ebpf.find((x) => x.id === ebpfSelect.value);
    if (p) {
      ebpfBytecode.value = p.bytecodeHex;
      ebpfPacket.value = p.samplePacketHex;
      void runVerifier();
    }
  });
  byId('btn-verify').addEventListener('click', () => void runVerifier());
  if (catalog.ebpf[0]) {
    ebpfBytecode.value = catalog.ebpf[0].bytecodeHex;
    ebpfPacket.value = catalog.ebpf[0].samplePacketHex;
    void runVerifier();
  }

  // Workbench 2: L7 Dissector
  const l7Select = byId<HTMLSelectElement>('l7-preset-select');
  const l7Hint = byId<HTMLSelectElement>('l7-hint');
  const l7Egress = byId<HTMLTextAreaElement>('l7-egress');
  const l7Ingress = byId<HTMLTextAreaElement>('l7-ingress');
  const l7Output = byId<HTMLPreElement>('l7-output');

  catalog.l7.forEach((p) => {
    const opt = document.createElement('option');
    opt.value = p.id;
    opt.textContent = p.label;
    l7Select.appendChild(opt);
  });

  const runDissect = async () => {
    const rep = await callWorker<unknown>({
      kind: 'dissect',
      protocolHint: l7Hint.value,
      egressHex: l7Egress.value,
      ingressHex: l7Ingress.value,
    });
    l7Output.textContent = JSON.stringify(rep, null, 2);
  };

  l7Select.addEventListener('change', () => {
    const p = catalog.l7.find((x) => x.id === l7Select.value);
    if (p) {
      l7Hint.value = p.protocolHint;
      l7Egress.value = p.egressHex;
      l7Ingress.value = p.ingressHex;
      void runDissect();
    }
  });
  byId('btn-dissect').addEventListener('click', () => void runDissect());
  if (catalog.l7[0]) {
    l7Hint.value = catalog.l7[0].protocolHint;
    l7Egress.value = catalog.l7[0].egressHex;
    l7Ingress.value = catalog.l7[0].ingressHex;
    void runDissect();
  }

  // Workbench 3: Differential Flamegraph Studio
  const fgSelect = byId<HTMLSelectElement>('fg-preset-select');
  const fgFolded = byId<HTMLTextAreaElement>('fg-folded');
  const fgBaseline = byId<HTMLTextAreaElement>('fg-baseline');
  const fgWrap = byId<HTMLDivElement>('fg-svg-wrap');

  catalog.flamegraphs.forEach((p) => {
    const opt = document.createElement('option');
    opt.value = p.id;
    opt.textContent = p.label;
    fgSelect.appendChild(opt);
  });

  const runFlame = async () => {
    const p = catalog.flamegraphs.find((x) => x.id === fgSelect.value) ?? catalog.flamegraphs[0];
    const res = await callWorker<{ svg: string }>({
      kind: 'flamegraph',
      title: p?.title ?? 'SpectreMesh Profile',
      unit: p?.unit ?? 'ns',
      folded: fgFolded.value,
      baselineFolded: fgBaseline.value.trim() ? fgBaseline.value : undefined,
    });
    fgWrap.innerHTML = res.svg;
  };

  fgSelect.addEventListener('change', () => {
    const p = catalog.flamegraphs.find((x) => x.id === fgSelect.value);
    if (p) {
      fgFolded.value = p.folded;
      fgBaseline.value = p.baselineFolded ?? '';
      void runFlame();
    }
  });
  byId('btn-flamegraph').addEventListener('click', () => void runFlame());
  if (catalog.flamegraphs[0]) {
    fgFolded.value = catalog.flamegraphs[0].folded;
    fgBaseline.value = catalog.flamegraphs[0].baselineFolded ?? '';
    void runFlame();
  }
}

void main();
