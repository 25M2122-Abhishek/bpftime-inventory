#include <stdlib.h>
#include <stdio.h>
#include <linux/if_link.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <unistd.h>
#include <signal.h>

struct event {
    __u32 pkt_sz;
};

static volatile bool exiting = false;

// Signal handler sets flag instead of calling exit
static void handle_sigint(int sig) {
    exiting = true;
}

// Callback for ring buffer events
static int handle_event(void *ctx, void *data, size_t len) {
    struct event *e = data;
    printf("Packet size: %u bytes\n", e->pkt_sz);
    return 0;
}

// Libbpf print function
static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args) {
    return vfprintf(stderr, format, args);
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <BPF_FILE> <INTERFACE>\n", argv[0]);
        return 1;
    }

    const char *bpf_file = argv[1];
    const char *iface_name = argv[2];

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);
    signal(SIGINT, handle_sigint);

    // Open and load BPF object
    struct bpf_object *obj = bpf_object__open_file(bpf_file, NULL);
    if (!obj) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load BPF object\n");
        return 1;
    }

    // Find XDP program
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "xdp_pass");
    if (!prog) {
        fprintf(stderr, "Failed to find XDP program\n");
        return 1;
    }

    int prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        fprintf(stderr, "Failed to get program FD\n");
        return 1;
    }

    // Attach XDP program to interface
    int ifindex = if_nametoindex(iface_name);
    if (!ifindex) {
        fprintf(stderr, "Invalid interface: %s\n", iface_name);
        return 1;
    }

    struct bpf_link *link = bpf_program__attach_xdp(prog, ifindex);
    if (libbpf_get_error(link)) {
        fprintf(stderr, "Failed to attach XDP program\n");
        return 1;
    }

    printf("XDP program attached to interface %s\n", iface_name);

    // Find ring buffer map
    struct bpf_map *ringbuf_map = bpf_object__find_map_by_name(obj, "ringbuf");
    if (!ringbuf_map) {
        fprintf(stderr, "Failed to find ring buffer map\n");
        return 1;
    }

    // Create ring buffer
    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(ringbuf_map), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        return 1;
    }

    printf("Listening for packet sizes... Ctrl+C to exit.\n");

    // Poll ring buffer until exit signal
    while (!exiting) {
        int err = ring_buffer__poll(rb, 100 /* ms */);
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }

    printf("\nDetaching XDP program and cleaning up...\n");

    // Clean up
    ring_buffer__free(rb);
    bpf_link__destroy(link);
    bpf_object__close(obj);

    return 0;
}

