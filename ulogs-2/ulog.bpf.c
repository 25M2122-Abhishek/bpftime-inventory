#define BPF_NO_GLOBAL_DATA
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "data.h"

/* section name only needs to start with "uprobe/"; exact path:symbol
 * resolution is done at attach time by the userspace loader program.
 */
SEC("uprobe/target_func")
int do_uprobe_trace(struct pt_regs *ctx)
{
	data_t* d = (data_t*)PT_REGS_PARM1(ctx);

	bpf_printk("probe: a: %d\n", d->a);
	bpf_printk("probe: b: %d\n", d->b);
	// bpf_printk("probe: str address: %p, str len: %lu\n", d->str, d->len);
	// bpf_printk("probe: str content: %s\n", d->str);

	// print string from user space memory
	char str_buf[64] = {};
	bpf_probe_read_user_str(str_buf, sizeof(str_buf), d->str);
	bpf_printk("probe: str content: %s %d\n", str_buf, (int)(int*)(str_buf+d->len));

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
