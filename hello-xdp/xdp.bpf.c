#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int xdp_pass(struct xdp_md* ctx)
{
    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;
    
    __u32 pkt_sz = (__u32)(data_end - data);
    bpf_printk("Packet size: %u bytes\n", pkt_sz);
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";