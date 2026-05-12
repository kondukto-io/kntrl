# Changelog

All notable changes to this project will be documented in this file.

## [v0.2.1] - 2026-04-01

### Fixed
- **trace_fork CO-RE relocation failure on kernel 6.17+**: Switched `trace_fork` from
  `tracepoint/sched/sched_process_fork` to `tp_btf/sched_process_fork`. The old approach
  accessed fields on `struct trace_event_raw_sched_process_fork`, which is often absent
  from the target kernel's BTF, causing libbpf to emit poison value `0xBAD2310` and fail
  program loading. The new approach uses BTF-enabled raw tracepoints with `BPF_PROG` macro,
  receiving `struct task_struct *parent, *child` directly — these are always present in
  kernel BTF and CO-RE relocations resolve reliably across all kernels 5.5+.

## [v0.2.0] - 2026-03-28

### Added
- Modular eBPF sensor architecture (network, process, DNS, file, SNI, cgroup)
- Process execution blocking and file write protection
- Cloud upload via NATS streaming
- OPA policy engine with hot-reload (SIGHUP)
- GitHub Action integration (`kntrl-action`)
- SVG logo suite with Invicti palette
