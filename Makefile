# SpectreMesh Master Verification & Build Makefile
SHELL := /bin/bash

CARGO ?= cargo
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
NPM ?= npm
DOCKER_IMAGE ?= spectre-verify
PROBE_BUILD_DIR := probes/build
ARCH := $(shell uname -m)
TARGET_ARCH := $(if $(filter aarch64 arm64,$(ARCH)),__TARGET_ARCH_arm64,__TARGET_ARCH_x86)
BPF_CFLAGS := -target bpf -O2 -g -Wall -Werror -D$(TARGET_ARCH) -Iprobes/include -I/usr/include -I/usr/include/x86_64-linux-gnu

PROBE_SRCS := $(wildcard probes/*.bpf.c)
PROBE_OBJS := $(patsubst probes/%.bpf.c,$(PROBE_BUILD_DIR)/%.bpf.o,$(PROBE_SRCS))

TELEMETRY_SCRIPT := scripts/emit_telemetry_summary.mjs
TELEMETRY_OUT    := studio/public/telemetry/summary.json
TELEMETRY_LOGDIR := .telemetry-logs
PERF_REPORT      := docs/benchmarks/ebpf_perf.md
PROGRESS_LEDGER  := PROGRESS.md
SPECTRE_WASM_PATH ?=

.PHONY: all build-probes check test fuzz-l7-elf mesh-oracle bench wasm-studio telemetry-summary verify-all verify-live docker-verify clean

all: verify-all

$(PROBE_BUILD_DIR):
	mkdir -p $(PROBE_BUILD_DIR)

$(PROBE_BUILD_DIR)/%.bpf.o: probes/%.bpf.c $(wildcard probes/include/*.h) | $(PROBE_BUILD_DIR)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(LLVM_STRIP) -g $@ || true

build-probes: $(PROBE_OBJS)
	@echo "Built probes: $(PROBE_OBJS)"

check:
	$(CARGO) fmt --all -- --check
	$(CARGO) clippy --workspace --all-targets -- -D warnings
	@if grep -rnE 'todo!\(|unimplemented!\(|#\[ignore\]' crates/; then \
		echo "ERROR: Forbidden stub/ignore macro detected in crates/"; \
		exit 1; \
	fi

test: build-probes
	$(CARGO) test --workspace --release

fuzz-l7-elf:
	$(CARGO) test --release -p spectre-elf-btf --test fuzz_elf_btf
	$(CARGO) test --release -p spectre-l7 --test fuzz_l7_protocols

mesh-oracle: build-probes
	$(CARGO) run --release -p spectre-oracle --bin spectre-oracle -- --requests 50000

bench: build-probes
	$(CARGO) run --release -p spectre-daemon --bin spectre-bench -- \
		--output-md docs/benchmarks/ebpf_perf.md \
		--output-json docs/benchmarks/ebpf_perf.json \
		--telemetry-json studio/public/telemetry/summary.json

wasm-studio:
	RUSTFLAGS="-C target-feature=+simd128" $(CARGO) build --release -p spectre-wasm --target wasm32-unknown-unknown
	wasm-bindgen --target web --out-dir studio/src/wasm $${CARGO_TARGET_DIR:-target}/wasm32-unknown-unknown/release/spectre_wasm.wasm
	wasm-opt -O3 --enable-simd studio/src/wasm/spectre_wasm_bg.wasm -o studio/src/wasm/spectre_wasm_bg.wasm
	$(MAKE) telemetry-summary
	cd studio && $(NPM) install --no-audit --no-fund && $(NPM) run test:run && $(NPM) run build

telemetry-summary:
	@echo "==> Emitting SpectreMesh VERIFIED_LIVE telemetry summary (camelCase, /1024 KB)..."
	@node $(TELEMETRY_SCRIPT) \
		--report $(PERF_REPORT) \
		--progress $(PROGRESS_LEDGER) \
		--out $(TELEMETRY_OUT) \
		$(if $(SPECTRE_WASM_PATH),--wasm $(SPECTRE_WASM_PATH),) \
		--strict

verify-all: build-probes check test fuzz-l7-elf mesh-oracle bench wasm-studio
	@echo "================================================================"
	@echo " SpectreMesh M01-M09 Full Verification Gate: 100% GREEN         "
	@echo "================================================================"

verify-live: verify-all telemetry-summary
	@echo "==> Verifying summary.json parity (--verify --strict)..."
	@node $(TELEMETRY_SCRIPT) \
		--report $(PERF_REPORT) \
		--progress $(PROGRESS_LEDGER) \
		--out $(TELEMETRY_OUT) \
		$(if $(SPECTRE_WASM_PATH),--wasm $(SPECTRE_WASM_PATH),) \
		--verify --strict
	@echo "==> Running negative strict contract test (--report Cargo.toml --strict)..."
	@mkdir -p $(TELEMETRY_LOGDIR)
	@rm -f $(TELEMETRY_LOGDIR)/negative-summary.json
	@if node $(TELEMETRY_SCRIPT) \
		--report Cargo.toml \
		--progress $(PROGRESS_LEDGER) \
		--out $(TELEMETRY_LOGDIR)/negative-summary.json \
		$(if $(SPECTRE_WASM_PATH),--wasm $(SPECTRE_WASM_PATH),) \
		--strict > $(TELEMETRY_LOGDIR)/negative-test.log 2>&1; then \
		echo "ERROR: Negative strict test unexpectedly exited 0"; \
		exit 1; \
	fi
	@if [ -e "$(TELEMETRY_LOGDIR)/negative-summary.json" ]; then \
		echo "ERROR: Negative strict test created output file"; \
		exit 1; \
	fi
	@echo "==> Negative strict test PASSED (EXIT 1, no output file created)."
	@echo "==> SpectreMesh VERIFIED_LIVE gate PASSED."

docker-verify:
	docker build -f Dockerfile.linux-verify -t $(DOCKER_IMAGE) .
	docker run --rm --privileged $(DOCKER_IMAGE) make verify-all

clean:
	$(CARGO) clean
	rm -rf $(PROBE_BUILD_DIR) studio/dist studio/src/wasm
