#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} ringbuf SEC(".maps");

struct event {
    __u32 pkt_sz;
};

SEC("xdp")
int xdp_pass(struct xdp_md* ctx)
{
    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;

    __u32 pkt_sz = (__u32)(data_end - data);
    struct event *e = bpf_ringbuf_reserve(&ringbuf, sizeof(struct event), 0);
    if (!e)
        return XDP_PASS;

    e->pkt_sz = pkt_sz;
    bpf_ringbuf_submit(e, 0);
    return XDP_PASS;
}