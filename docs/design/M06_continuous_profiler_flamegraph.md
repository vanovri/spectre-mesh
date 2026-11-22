# M06 Design Spec — `probes/profiler.bpf.c` & `crates/spectre-profile`

## 1. Objective
Provide <1% overhead continuous On-CPU (99 Hz `perf_event`) and Off-CPU (`sched/sched_switch`) kernel+user stack profiling, pure-Rust ASLR ELF + `.gopclntab` + `/proc/kallsyms` symbolization, and interactive Differential Flamegraph rendering (`.folded`, standalone SVG, JSON).

## 2. Linux 6.18 Kernel Telemetry & PID Namespace Design
- **On-CPU Sampler (`SEC("perf_event")`):**
  - Attached per online CPU core via `SYS_perf_event_open(PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CPU_CLOCK, sample_freq=99 Hz)`.
  - Captures `bpf_get_stackid(ctx, &stack_traces, 0)` (kernel) and `BPF_F_USER_STACK` (user) into `BPF_MAP_TYPE_STACK_TRACE` (`127 x u64 = 1016 B` matched against `/proc/sys/kernel/perf_event_max_stack`).
  - Aggregates sample counts in kernel hash map `oncpu_counts` keyed by `(ns_pid, kern_stack_id, user_stack_id, comm[16])` (zero RingBuf wakeup traffic).
- **Off-CPU Latency Profiler (`SEC("tp/sched/sched_switch")`):**
  - Struct layout verified against `/sys/kernel/tracing/events/sched/sched_switch/format`: `prev_comm[16]@8`, `prev_pid@24`, `prev_prio@28`, `prev_state@32`, `next_comm[16]@40`, `next_pid@56`, `next_prio@60`.
  - When `prev_state != 0`, captures `ns_pid = spectre_current_pid_tgid(0) >> 32` while `current == prev`, captures kernel + user stack IDs at block time, and stores into `offcpu_start` keyed by init-ns `raw prev_pid`.
  - When `next_pid` schedules back in, looks up `offcpu_start[next_pid]` (init-ns key matches identically across namespaces!), deletes entry, and accumulates `delta_ns >= 100,000` (100 µs threshold) into `offcpu_ns`.

## 3. Pure-Rust Symbolizer & Differential Flamegraph
- **Kernel Symbols:** `/proc/kallsyms` parsed into sorted `Vec<KernelSym>` for $O(\log N)$ binary search.
- **Userspace ASLR Resolution:** Parses `/proc/<pid>/maps` (`vaddr - region.start + region.offset -> file_off`) paired with `Elf64Object::vaddr_to_file_offset` across `.symtab`, `.dynsym`, and `.gopclntab`, cached by `(path, dev, ino, size, mtime)`.
- **Differential Mode:** Compares baseline vs regressed folded stacks (`delta_value`, `delta_pct`), coloring regressions in red and speedups in blue in both standalone SVG and JSON output consumed by `M09` Studio.
