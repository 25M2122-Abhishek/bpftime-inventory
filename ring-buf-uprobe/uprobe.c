// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <stdint.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include <stdlib.h>
#include "uprobe.skel.h"
#include <inttypes.h>

#define warn(...) fprintf(stderr, __VA_ARGS__)

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
						   va_list args)
{
	return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

struct event
{
	__u32 pid;
	char msg[64];
};

// Ring buffer callback function
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	struct event *e = data;
	printf("PID: %d, Message: %s\n", e->pid, e->msg);
	return 0;
}

int main(int argc, char **argv)
{
	struct uprobe_bpf *skel = NULL;
	int err = 0;
	const char *target_path = "./victim";
	const char *target_symbol = "target_func";
	pid_t pid = -1;

	struct ring_buffer *rb = NULL;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	if (argc == 2)
	{
		pid = atoi(argv[1]);
		printf("Attached pid : %d\n", pid);
	}

	/* Open BPF application (skeleton) */
	skel = uprobe_bpf__open();
	if (!skel)
	{
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/* Load & verify BPF programs */
	err = uprobe_bpf__load(skel);
	if (err)
	{
		fprintf(stderr, "Failed to load and verify BPF skeleton: %d\n", err);
		goto cleanup;
	}

	/* Explicit attach */
	LIBBPF_OPTS(bpf_uprobe_opts, attach_opts, .func_name = target_symbol,
				.retprobe = false);

	struct bpf_link *link = bpf_program__attach_uprobe_opts(
		skel->progs.do_uprobe_trace, pid, target_path, 0, &attach_opts);
	if (!link)
	{
		fprintf(stderr, "Failed to attach uprobe to %s:%s\n", target_path, target_symbol);
		err = -1;
		goto cleanup;
	}

	printf("Attached uprobe to %s:%s\n", target_path, target_symbol);
	rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
	if (!rb)
	{
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	printf("Listening for events...\n");

	while (!exiting)
	{
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR)
			break;
		if (err < 0)
		{
			fprintf(stderr, "Error polling ring buffer: %d\n", err);
			break;
		}
		/* if err == 0, timeout occurred */
	}

cleanup:
	if (link)
		bpf_link__destroy(link);
	uprobe_bpf__destroy(skel);
	ring_buffer__free(rb);

	return err < 0 ? -err : 0;
}
