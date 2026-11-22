/* tslint:disable */
/* eslint-disable */

export function build_flamegraph_from_folded(title: string, unit: string, folded: string, baseline_folded?: string | null): any;

export function dissect_l7_payload(protocol_hint: string, egress_hex: string, ingress_hex: string): any;

export function preset_catalog(): any;

export function run_xdp_simulation(hex_or_preset: string, packet_hex: string): any;

export function verify_ebpf_program(hex_or_preset: string): any;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly build_flamegraph_from_folded: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number, number];
    readonly dissect_l7_payload: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number];
    readonly preset_catalog: () => [number, number, number];
    readonly run_xdp_simulation: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly verify_ebpf_program: (a: number, b: number) => [number, number, number];
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
