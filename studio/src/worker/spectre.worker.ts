import init, {
  build_flamegraph_from_folded,
  dissect_l7_payload,
  preset_catalog,
  run_xdp_simulation,
  verify_ebpf_program,
} from '../wasm/spectre_wasm.js';
import type { WorkerRequest, WorkerResponse } from '../lib/protocol';

let readyPromise: Promise<void> | null = null;

async function ensureReady(): Promise<void> {
  if (!readyPromise) {
    readyPromise = init().then(() => undefined);
  }
  await readyPromise;
}

self.onmessage = async (event: MessageEvent<WorkerRequest>) => {
  const msg = event.data;
  try {
    await ensureReady();
    let data: unknown;
    switch (msg.kind) {
      case 'presets':
        data = preset_catalog();
        break;
      case 'verify':
        data = verify_ebpf_program(msg.bytecodeHex);
        break;
      case 'xdp':
        data = run_xdp_simulation(msg.bytecodeHex, msg.packetHex);
        break;
      case 'dissect':
        data = dissect_l7_payload(msg.protocolHint, msg.egressHex, msg.ingressHex);
        break;
      case 'flamegraph':
        data = build_flamegraph_from_folded(
          msg.title,
          msg.unit,
          msg.folded,
          msg.baselineFolded ?? null,
        );
        break;
    }
    const resp: WorkerResponse = { id: msg.id, ok: true, data };
    self.postMessage(resp);
  } catch (err) {
    const resp: WorkerResponse = {
      id: msg.id,
      ok: false,
      error: err instanceof Error ? err.message : String(err),
    };
    self.postMessage(resp);
  }
};
