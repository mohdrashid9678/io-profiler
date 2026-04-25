# eBPF System I/O Profiler

A high-performance system I/O profiler built in Go using eBPF. This tool traces 
i/o operations across the entire Linux kernel with minimal overhead 
by leveraging kernel tracepoints and BPF Hash Maps.

## Core OS Concepts
- **eBPF (CO-RE):** Compile Once, Run Everywhere logic using BTF.
- **Kernel Tracepoints:** Stable hooks into the `sys_enter_read` syscall.
- **Userspace/Kernel Communication:** Efficient data aggregation via BPF Maps.

## Prerequisites
- Linux Kernel 5.4+ (with BTF enabled)
- Clang/LLVM
- Go 1.18+
- `libbpf-dev`

## Quick Start
```bash
# Generate BPF bindings, build, and run
chmod +x run.sh
./run.sh