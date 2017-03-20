/*
 * Copyright (c) 2016, Linaro Limited
 * Copyright (c) 2014, STMicroelectronics International N.V.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#include <err.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <adbg.h>
#include "xtest_test.h"
#include "xtest_helpers.h"

/* include here shandalone tests */
#include "crypto_common.h"


ADBG_SUITE_DEFINE(regression);
ADBG_SUITE_DEFINE(benchmark);

char *_device = NULL;
unsigned int level = 0;
static const char glevel[] = "0";
static const char gsuitename[] = "regression";

void usage(char *program);

void usage(char *program)
{
	printf("Usage: %s <options> [[-w] <test-id>]...\n", program);
	printf("       %s <applet> [options...]\n", program);
	printf("\n");
	printf("options:\n");
	printf("\t-d <device-type>   default not set, use any\n");
	printf("\t-l <level>         test suite level: [0-15]\n");
	printf("\t-t <test_suite>    available test suite: regression, benchmark\n");
	printf("\t                   default value = %s\n", gsuitename);
	printf("\t-h                 show usage\n");
	printf("\t[-w] <test-id>     the name(s) of the tests to be run. A substring match is\n");
	printf("\t                   performed, unless -w (wildcard) is given in which case\n");
	printf("\t                   the following <test-id> is parsed as a shell wildcard.\n");
	printf("\t                   If no <test-id> is given, all tests are run.\n");
	printf("\t                   Test names are formatted like: <test_suite>_<id>, where\n");
	printf("\t                   <id> is a 4- or 5-digit number\n");
	printf("applets:\n");
	printf("\t--sha-perf         SHA performance testing tool for OP-TEE\n");
	printf("\t--sha-perf -h      show usage of SHA performance testing tool\n");
	printf("\n");
	printf("\t--aes-perf         AES performance testing tool for OP-TEE\n");
	printf("\t--aes-perf -h      show usage of AES performance testing tool\n");
	printf("\n");
#ifdef CFG_SECURE_DATA_PATH
	printf("\t--sdp-basic        Basic Secure Data Path test setup for OP-TEE ('-h' for usage)\n");
#endif
	printf("\n");
	printf("examples:\n");
	printf("\txtest 4001 4003\n");
	printf("\t                   run regression tests 4001 and 4003\n");
	printf("\txtest -w '*2\?\?\?'\n");
	printf("\t                   run regression tests in the 2k series (but not the 20k ones)\n");
	printf("\txtest -w '200[13]' 4002\n");
	printf("\t                   run regression tests 2001, 2003 and 4002\n");
	printf("\n");
}

int main(int argc, char *argv[])
{
	int opt;
	int index;
	int ret;
	char *p = (char *)glevel;
	char *test_suite = (char *)gsuitename;
	bool wildcard = false;

	opterr = 0;

	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
		warn("signal(SIGPIPE, SIG_IGN)");

	if (signal(SIGHUP, SIG_IGN) == SIG_ERR)
		warn("signal(SIGPIPE, SIG_IGN)");

	if (argc > 1 && !strcmp(argv[1], "--sha-perf"))
		return sha_perf_runner_cmd_parser(argc-1, &argv[1]);
	else if (argc > 1 && !strcmp(argv[1], "--aes-perf"))
		return aes_perf_runner_cmd_parser(argc-1, &argv[1]);
#ifdef CFG_SECURE_DATA_PATH
	else if (argc > 1 && !strcmp(argv[1], "--sdp-basic"))
		return sdp_basic_runner_cmd_parser(argc-1, &argv[1]);
#endif

	while ((opt = getopt(argc, argv, "d:l:t:h")) != -1)
		switch (opt) {
		case 'd':
			_device = optarg;
			break;
		case 'l':
			p = optarg;
			break;
		case 't':
			test_suite = optarg;
			break;
		case 'h':
			usage(argv[0]);
			return 0;
		case '?':
			if (optopt == 'w') {
				/*
				 * -w is not an option processed here, it is
				 * part of the test IDs
				 */
				optind--;
				goto next;
			}
			/* option not recognized */
			usage(argv[0]);
			return -1;
		default:
			usage(argv[0]);
			return -1;
 		}
next:
	for (index = optind; index < argc; index++) {
		if (!strcmp(argv[index], "-w")) {
			wildcard = true;
			continue;
		}
		printf("Test ID: %s%s\n", wildcard ? "-w " : "", argv[index]);
		wildcard = false;
	}

	if (p)
		level = atoi(p);
	else
		level = 0;
	printf("Run test suite with level=%d\n", level);

	printf("\nTEE test application started with device [%s]\n", _device);

	xtest_teec_ctx_init();

	if (strcmp(test_suite, "regression") == 0)
		ret = Do_ADBG_RunSuite(&ADBG_Suite_regression,
				       argc - optind, argv + optind);
	else if (strcmp(test_suite, "benchmark") == 0)
		ret = Do_ADBG_RunSuite(&ADBG_Suite_benchmark,
				       argc - optind, argv + optind);
	else {
		fprintf(stderr, "No test suite found: %s\n", test_suite);
		ret = -1;
	}

	xtest_teec_ctx_deinit();

	printf("TEE test application done!\n");
	return ret;
}
