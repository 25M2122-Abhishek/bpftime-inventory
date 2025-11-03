#define BPF_NO_GLOBAL_DATA
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* section name only needs to start with "uprobe/"; exact path:symbol
 * resolution is done at attach time by the userspace loader program.
 */
SEC("uprobe/target_func")
int do_uprobe_trace(struct pt_regs *ctx)
{
	bpf_printk("target_func called.\n");
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
