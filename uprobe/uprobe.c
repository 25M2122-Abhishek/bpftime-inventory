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

int main(int argc, char **argv)
{
	struct uprobe_bpf *skel = NULL;
	int err = 0;
	const char *target_path = "./victim";
	const char *target_symbol = "target_func";

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Open BPF application (skeleton) */
	skel = uprobe_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/* Load & verify BPF programs */
	err = uprobe_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton: %d\n", err);
		goto cleanup;
	}

	/* Explicit attach */
	LIBBPF_OPTS(bpf_uprobe_opts, attach_opts, .func_name = target_symbol,
		    .retprobe = false);

	struct bpf_link *link = bpf_program__attach_uprobe_opts(
		skel->progs.do_uprobe_trace, -1, target_path, 0, &attach_opts);
	if (!link) {
		fprintf(stderr, "Failed to attach uprobe to %s:%s\n", target_path, target_symbol);
		err = -1;
		goto cleanup;
	}

	printf("Attached uprobe to %s:%s\n", target_path, target_symbol);

	while (!exiting) {
		sleep(1);
	}

cleanup:
	if (link)
		bpf_link__destroy(link);
	uprobe_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}
