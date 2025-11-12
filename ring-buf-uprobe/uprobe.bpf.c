#define BPF_NO_GLOBAL_DATA
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>


struct event {
    __u32 pid;
    char msg[64];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);  // 1MB buffer size
} events SEC(".maps");

SEC("uprobe/target_func")
int do_uprobe_trace(struct pt_regs *ctx)
{
	struct event *e;
	// Reserve space in the ring buffer
	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		return 0;
	}
	// Fill event data
	e->pid = bpf_get_current_pid_tgid() >> 32;
	bpf_probe_read_user_str(&e->msg, sizeof(e->msg), "target_func was called");
	// Submit event to ring buffer
	bpf_ringbuf_submit(e, 0);
	bpf_printk("target_func called.\n");
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
