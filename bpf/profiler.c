// +build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// This struct holds our accounting data.
struct data_t {
    u64 bytes;
    char comm[16]; // TASK_COMM_LEN is 16 in the Linux kernel
};

// Map for tracking Disk Reads
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, struct data_t);
} disk_stats SEC(".maps");

// Map for tracking Network I/O (Send + Recv combined)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, struct data_t);
} net_stats SEC(".maps");

// Internal helper to update maps. We use __always_inline so the compiler
// pastes this code into the tracepoints (eBPF doesn't support traditional function calls well).
static __always_inline void update_stats(void *map, u32 pid, long ret) {
    // If the syscall failed (ret < 0) or transferred 0 bytes, ignore it.
    if (ret <= 0) {
        return;
    }

    struct data_t *val = bpf_map_lookup_elem(map, &pid);
    if (val) {
        // Use an atomic add to prevent race conditions when multiple threads 
        // of the same process are running on different CPUs.
        __sync_fetch_and_add(&val->bytes, (u64)ret);
    } else {
        struct data_t zero = {0};
        zero.bytes = (u64)ret;
        // Grab the process name from the task_struct currently on the CPU.
        bpf_get_current_comm(&zero.comm, sizeof(zero.comm));
        bpf_map_update_elem(map, &pid, &zero, BPF_ANY);
    }
}

// Hooking the EXIT of the read syscall. 
// At this point, the kernel has finished the work and the return value (ret) 
// tells us exactly how many bytes were read.
SEC("tracepoint/syscalls/sys_exit_read")
int handle_disk_read_exit(struct trace_event_raw_sys_exit *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    update_stats(&disk_stats, pid, ctx->ret);
    return 0;
}

// Hooking the EXIT of sendto (Network Egress)
SEC("tracepoint/syscalls/sys_exit_sendto")
int handle_net_send_exit(struct trace_event_raw_sys_exit *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    update_stats(&net_stats, pid, ctx->ret);
    return 0;
}

// Hooking the EXIT of recvfrom (Network Ingress)
SEC("tracepoint/syscalls/sys_exit_recvfrom")
int handle_net_recv_exit(struct trace_event_raw_sys_exit *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    update_stats(&net_stats, pid, ctx->ret);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";