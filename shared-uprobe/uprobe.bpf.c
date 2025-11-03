#define BPF_NO_GLOBAL_DATA
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* Shared counter map: array with a single entry (index 0).
 * This map will be backed by kernel maps when running in kernel mode,
 * or by bpftime userspace shared memory when running under bpftime agent.
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, uint32_t);
    __type(value, uint64_t);
} shared_counter SEC(".maps");

/* section name only needs to start with "uprobe/"; exact path:symbol
 * resolution is done at attach time by the userspace loader program.
 */
SEC("uprobe/target_func")
int do_uprobe_trace(struct pt_regs *ctx)
{
    uint32_t key = 0;
    uint64_t *val;

    /* increment the shared counter (if present) */
    val = bpf_map_lookup_elem(&shared_counter, &key);
    if (val) {
        /* Use a simple atomic increment; __sync_fetch_and_add is supported in BPF */
        __sync_fetch_and_add(val, 1);
    }

    /* still print for debug (visible in trace_pipe if kernel executes) */
    bpf_printk("target_func called.\n");
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
