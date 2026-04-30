# eBPF System I/O Profiler

A high-performance, real-time system I/O profiler built in Go and C. This tool leverages Linux **eBPF (Extended Berkeley Packet Filter)** to trace filesystem and network activity across the entire kernel with near-zero overhead.

Unlike basic tracers, this tool hooks into **syscall exit tracepoints** to capture the actual number of bytes transferred.

## Key Features
- **Accurate Accounting:** Hooks into `sys_exit` tracepoints to capture the actual return value of syscalls (bytes successfully moved).
- **Unified I/O View:** Monitors both Disk Reads (`read`) and Network I/O (`sendto` / `recvfrom`) in a single dashboard.
- **Process Aggregation:** Automatically merges multi-threaded activity and child processes into a single, clean process-level view.
- **Human-Readable Metrics:** Automatic scaling of units (B, KB, MB, GB) for real-time monitoring.
- **Zero Overhead:** Data aggregation happens in kernel-space via BPF Hash Maps, preventing the "context-switch tax" found in tools like `strace`.

## Prerequisites
The tool requires a modern Linux environment:
- **Kernel:** 5.4+ (5.15+ recommended for full CO-RE support).
- **BTF Enabled:** Your kernel must be compiled with `CONFIG_DEBUG_INFO_BTF=y`. Verify with `ls /sys/kernel/btf/vmlinux`.
- **Dependencies:** 
  - `clang`, `llvm` (for BPF bytecode compilation)
  - `libbpf-dev`
  - `bpftool` (to generate local kernel headers)
  - `go 1.18+`

## Local Setup & Installation

### 1. Install the dependencies
```bash
sudo sudo apt install -y build-essential clang llvm libelf-dev libbpf-dev gcc-multilib-dev
```

### 2. Generate Kernel Headers
eBPF needs to know your specific kernel's memory structures. Generate the `vmlinux.h` file for your current system:
```bash
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
```

### 3. Get required go package
go get [github.com/cilium/ebpf/cmd/bpf2go](https://github.com/cilium/ebpf/cmd/bpf2go)

### 4. Using the automation script
chmod +x run.sh
./run.sh
