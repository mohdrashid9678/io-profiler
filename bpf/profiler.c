// +build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// Define the Map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);   // PID
    __type(value, u64); // Bytes count
} io_stats SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_read")
int handle_read_enter(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    size_t count = ctx->args[2]; // The 3rd argument to read() is 'count'

    u64 *val = bpf_map_lookup_elem(&io_stats, &pid);
    if (val) {
        __sync_fetch_and_add(val, count);
    } else {
        u64 initial_count = count;
        bpf_map_update_elem(&io_stats, &pid, &initial_count, BPF_ANY);
    }
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";