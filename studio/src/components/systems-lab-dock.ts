import { SYSTEMS_LAB_TABS, WASM_SIMD128_PROBE, type LabSlug } from '../lib/protocol';

function supportsWasmSimd(): boolean {
  try {
    return typeof WebAssembly === 'object' && WebAssembly.validate(WASM_SIMD128_PROBE);
  } catch {
    return false;
  }
}

export function registerSystemsLabDock(): void {
  if (typeof HTMLElement === 'undefined' || typeof customElements === 'undefined') {
    return;
  }
  if (customElements.get('systems-lab-dock')) {
    return;
  }

  class SystemsLabDockElement extends HTMLElement {
    static get observedAttributes(): string[] {
      return ['active', 'wasm-kb', 'gate'];
    }

    private readonly root: ShadowRoot;

    constructor() {
      super();
      this.root = this.attachShadow({ mode: 'open' });
      this.render();
    }

    attributeChangedCallback(): void {
      this.render();
    }

    private render(): void {
      const active = (this.getAttribute('active') ?? 'spectre') as LabSlug;
      const wasmKb = this.getAttribute('wasm-kb') ?? '—';
      const gate = this.getAttribute('gate') ?? 'M01-M09';
      const simd = supportsWasmSimd() ? 'SIMD128' : 'Scalar';

      const links = SYSTEMS_LAB_TABS.map((tab) => {
        const isCurrent = tab.slug === active;
        return `<a class="tab ${isCurrent ? 'active' : ''}" href="${tab.href}" data-slug="${tab.slug}" style="--accent:${tab.accent}">
          <span class="dot"></span>${tab.label}
        </a>`;
      }).join('');

      this.root.innerHTML = `
        <style>
          :host {
            display: block;
            position: sticky;
            top: 0;
            z-index: 100;
            font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
          }
          .bar {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
            min-height: 40px;
            padding: 0 16px;
            background: #090d14;
            border-bottom: 1px solid rgba(148, 163, 184, 0.16);
            color: #94a3b8;
            font-size: 12px;
            overflow-x: auto;
          }
          .left, .right {
            display: flex;
            align-items: center;
            gap: 6px;
            white-space: nowrap;
          }
          .home {
            color: #f8fafc;
            font-weight: 700;
            text-decoration: none;
            padding-right: 10px;
            margin-right: 4px;
            border-right: 1px solid rgba(148, 163, 184, 0.2);
          }
          .tab {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 5px 9px;
            border-radius: 5px;
            color: #94a3b8;
            text-decoration: none;
            border: 1px solid transparent;
          }
          .tab:hover { color: #f8fafc; background: rgba(255, 255, 255, 0.04); }
          .tab.active {
            color: #ecfeff;
            background: rgba(34, 211, 238, 0.12);
            border-color: rgba(34, 211, 238, 0.45);
          }
          .dot {
            width: 6px;
            height: 6px;
            border-radius: 999px;
            background: var(--accent);
          }
          .pill {
            padding: 3px 8px;
            border-radius: 999px;
            border: 1px solid rgba(34, 211, 238, 0.35);
            background: rgba(15, 23, 42, 0.85);
            color: #cbd5e1;
            font-size: 11px;
          }
        </style>
        <div class="bar">
          <div class="left">
            <a class="home" href="/">Systems Lab</a>
            ${links}
          </div>
          <div class="right">
            <span class="pill">${simd}</span>
            <span class="pill">${wasmKb} KB WASM</span>
            <span class="pill">${gate}</span>
          </div>
        </div>
      `;
    }
  }

  customElements.define('systems-lab-dock', SystemsLabDockElement);
}
