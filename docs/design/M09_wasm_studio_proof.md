# M09 Design — WebAssembly eBPF Verifier, L7 Dissector & Flamegraph Studio (`crates/spectre-wasm`, `studio/`)

## 1. Architecture
Module M09 compiles our pure-Rust `#![deny(unsafe_code)]` kernel observability engines (`spectre-verifier`, `spectre-l7`, `spectre-profile`) to `wasm32-unknown-unknown` with `+simd128` + `wasm-opt -O3 --enable-simd`, packaged as a standalone Vite + TypeScript WebWorker SPA served under `/labs/spectre/`:

- **Browser Worker Sandbox (`studio/src/worker/spectre.worker.ts`):** All WASM initialization (`init()`) and bytecode/packet/flamegraph computation executes inside a dedicated WebWorker so UI rendering stays 60fps.
- **`crates/spectre-wasm` (`#![deny(unsafe_code)]`):** Exposes typed `#[wasm_bindgen]` entrypoints (`verify_ebpf_program`, `run_xdp_simulation`, `dissect_l7_payload`, `build_flamegraph_from_folded`, `preset_catalog`) backed by cross-platform unit-tested core helpers.
- **Systems Lab Navigation Dock (`<systems-lab-dock active="spectre" />`):** Autonomous Shadow DOM WebComponent matching the `wasm-multizone-gateway` contract (live WASM SIMD128 probe, active lab state, and `./telemetry/summary.json` hydration).

## 2. Interactive Studio Workbenches
1. **eBPF Static Verifier & XDP Packet Sandbox:** Paste raw eBPF bytecode hex or select built-in Valid/Hostile presets (`xdp_valid_ipv4_tcp`, `hostile_pkt_oob_no_bounds`, `hostile_back_edge_loop`, `hostile_uninit_r2_read`); inspects instruction disassembly, per-step `Tnum` bitmask + `[umin..umax]` register abstract states, `Accept`/`Reject` verdict, and concrete XDP VM action (`XDP_PASS` / `XDP_DROP`) on raw L2/L3/L4 packet hex.
2. **Zero-Copy Streaming L7 / HPACK / gRPC / PG v3 / Redis Dissector:** Decodes raw egress + ingress streams into correlated spans, HTTP/2 HPACK dynamic table snapshots, gRPC protobuf tag summaries, SQL positional `$1` fingerprints, and Redis key-prefix redactions.
3. **Interactive Differential Flamegraph Studio:** Renders Brendan Gregg `.folded` On-CPU & Off-CPU profiles (or Red/Blue baseline-vs-regressed differential flamegraphs) into interactive SVG + ranked hotspot breakdown.

## 3. Build & Verification Contracts
- `make wasm-studio` compiles with `RUSTFLAGS="-C target-feature=+simd128"`, runs `wasm-bindgen 0.2.130 --target web`, optimizes via `wasm-opt -O3 --enable-simd`, stamps exact optimized `wasmSizeKb` into `studio/public/telemetry/summary.json`, runs `npm run test:run` (Vitest), and builds `studio/dist/labs/spectre/` (`base: '/labs/spectre/'`, `assetsInlineLimit: 0`).
- `make verify-all` chains `build-probes`, `check`, `test`, `fuzz-l7-elf`, `mesh-oracle` (50,000 requests), `bench`, and `wasm-studio`.
