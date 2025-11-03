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

	/* 
		Set up libbpf errors and debug info callback. 
		So libbpf messages are routed to your libbpf_print_fn and printed to stderr. 
		You will see those libbpf: lines when you execute the uprobe.c i.e userspace loader.
	*/

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

	/* 
		LIBBPF_OPTS macro used to declare and initialize an options struct in a compact, safe way
		bpf_uprobe_opts - struct type that holds optional parameters for attaching uprobes.
		attach_opts - instance name struct bpf_uprobe_opts
		.func_name - target_symbol sets the name of the symbol to attach to (a string).
		.retprobe = false sets whether this is a return probe (uretprobe) or not. false => normal entry uprobe
	*/
	LIBBPF_OPTS(bpf_uprobe_opts, attach_opts, .func_name = target_symbol,
		    .retprobe = false);
	
	/* 
		Explicit attach 
		skel->progs.do_uprobe_trace - The specific compiled eBPF program you want run when the probe fires (from your skeleton)
		pid == -1 -> "attach to the binary image at path target_path" i.e
					  this is a global probe attached to that executable file 
					  (any process that executes that binary will hit the probe).
		pid >= 0 -> you can attach to a specific running process’s instance (a probe attached to a given PID's mapping). 
					Use pid when you want to probe a particular process instance instead of the binary as a whole.
	*/
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
