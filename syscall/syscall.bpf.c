#define BPF_NO_GLOBAL_DATA
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

SEC("tracepoint/syscalls/sys_enter_write")
int do_syscall_trace(void *ctx)
{
	bpf_printk("calling syscall write.\n");
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
