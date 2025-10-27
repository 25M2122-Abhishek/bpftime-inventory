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
#include "uprobe-override.skel.h"
#include <inttypes.h>
#include "attach_override.h"

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
	struct uprobe_override_bpf *skel;
	int err;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Load and verify BPF application */
	skel = uprobe_override_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Load & verify BPF programs */
	err = uprobe_override_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}
	err = bpf_prog_attach_uprobe_with_override(
		bpf_program__fd(skel->progs.do_uprobe_override_patch), "./victim",
		"target_func");
	if (err) {
		fprintf(stderr, "Failed to attach BPF program\n");
		goto cleanup;
	}
	while (!exiting) {
		sleep(1);
	}
cleanup:
	/* Clean up */
	uprobe_override_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}












































// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
// #include <signal.h>
// #include <stdio.h>
// #include <time.h>
// #include <stdint.h>
// #include <sys/resource.h>
// #include <bpf/libbpf.h>
// #include <bpf/bpf.h>
// #include <unistd.h>
// #include <stdlib.h>
// #include "uprobe-override.skel.h"
// #include <inttypes.h>

// #define warn(...) fprintf(stderr, __VA_ARGS__)

// static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
// 			   va_list args)
// {
// 	return vfprintf(stderr, format, args);
// }

// static volatile bool exiting = false;

// static void sig_handler(int sig)
// {
// 	exiting = true;
// }

// int main(int argc, char **argv)
// {
// 	struct uprobe_override_bpf *skel = NULL;
// 	int err = 0;
// 	const char *target_path = "./victim";
// 	const char *target_symbol = "target_func";

// 	/* Set up libbpf errors and debug info callback */
// 	libbpf_set_print(libbpf_print_fn);

// 	/* Cleaner handling of Ctrl-C */
// 	signal(SIGINT, sig_handler);
// 	signal(SIGTERM, sig_handler);

// 	/* Open BPF application (skeleton) */
// 	skel = uprobe_override_bpf__open();
// 	if (!skel) {
// 		fprintf(stderr, "Failed to open BPF skeleton\n");
// 		return 1;
// 	}

// 	/* Load & verify BPF programs */
// 	err = uprobe_override_bpf__load(skel);
// 	if (err) {
// 		fprintf(stderr, "Failed to load and verify BPF skeleton: %d\n", err);
// 		goto cleanup;
// 	}

// 	/* Explicit attach */
// 	LIBBPF_OPTS(bpf_uprobe_opts, attach_opts, .func_name = target_symbol,
// 		    .retprobe = true);

// 	struct bpf_link *link = bpf_program__attach_uprobe_opts(
// 		skel->progs.do_uprobe_override_patch, -1, target_path, 0, &attach_opts);
// 	if (!link) {
// 		fprintf(stderr, "Failed to attach uprobe to %s:%s\n", target_path, target_symbol);
// 		err = -1;
// 		goto cleanup;
// 	}

// 	printf("Attached uprobe to %s:%s\n", target_path, target_symbol);

// 	while (!exiting) {
// 		sleep(1);
// 	}

// cleanup:
// 	if (link)
// 		bpf_link__destroy(link);
// 	uprobe_override_bpf__destroy(skel);

// 	return err < 0 ? -err : 0;
// }

