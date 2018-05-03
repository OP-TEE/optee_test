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
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef OPENSSL_FOUND
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#endif

#include <adbg.h>
#include "xtest_test.h"
#include "xtest_helpers.h"

/* include here shandalone tests */
#include "crypto_common.h"
#include "install_ta.h"


ADBG_SUITE_DEFINE(benchmark);
#ifdef WITH_GP_TESTS
ADBG_SUITE_DEFINE(gp);
#endif
ADBG_SUITE_DEFINE(regression);

char *_device = NULL;
unsigned int level = 0;
static const char glevel[] = "0";
#ifdef WITH_GP_TESTS
static char gsuitename[] = "regression+gp";
#else
static char gsuitename[] = "regression";
#endif

void usage(char *program);

void usage(char *program)
{
	printf("Usage: %s <options> <test_id>\n", program);
	printf("\n");
	printf("options:\n");
	printf("\t-d <device-type>   TEE device path. Default not set (use any)\n");
	printf("\t-l <level>         Test level [0-15].  Values higher than 0 enable\n");
	printf("\t                   optional tests. Default: 0. All tests: 15.\n");
	printf("\t-t <test_suite>    Available test suites: regression benchmark");
#ifdef WITH_GP_TESTS
	printf(" gp");
#endif
	printf("\n");
	printf("\t                   To run several suites, use multiple names\n");
	printf("\t                   separated by a '+')\n");
	printf("\t                   Default value: '%s'\n", gsuitename);
	printf("\t-h                 Show usage\n");
	printf("applets:\n");
	printf("\t--sha-perf [opts]  SHA performance testing tool (-h for usage)\n");
	printf("\t--aes-perf [opts]  AES performance testing tool (-h for usage)\n");
#ifdef CFG_SECSTOR_TA_MGMT_PTA
	printf("\t--install-ta [directory or list of TAs]\n");
	printf("\t                   Install TAs\n");
#endif
#ifdef CFG_SECURE_DATA_PATH
	printf("\t--sdp-basic [opts] Basic Secure Data Path test setup ('-h' for usage)\n");
#endif
	printf("\n");
}

static void init_ossl(void)
{
#ifdef OPENSSL_FOUND
	OPENSSL_init();
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();
#endif
}

int main(int argc, char *argv[])
{
	int opt;
	int index;
	TEEC_Result tee_res;
	int ret;
	char *p = (char *)glevel;
	char *test_suite = (char *)gsuitename;
	char *token;
	ADBG_Suite_Definition_t all = { .SuiteID_p = NULL,
				.cases = TAILQ_HEAD_INITIALIZER(all.cases), };

	opterr = 0;

	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
		warn("signal(SIGPIPE, SIG_IGN)");

	if (signal(SIGHUP, SIG_IGN) == SIG_ERR)
		warn("signal(SIGPIPE, SIG_IGN)");

	init_ossl();

	if (argc > 1 && !strcmp(argv[1], "--sha-perf"))
		return sha_perf_runner_cmd_parser(argc-1, &argv[1]);
	else if (argc > 1 && !strcmp(argv[1], "--aes-perf"))
		return aes_perf_runner_cmd_parser(argc-1, &argv[1]);
#ifdef CFG_SECSTOR_TA_MGMT_PTA
	else if (argc > 1 && !strcmp(argv[1], "--install-ta"))
		return install_ta_runner_cmd_parser(argc - 1, argv + 1);
#endif
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
		default:
			usage(argv[0]);
			return -1;
 		}

	for (index = optind; index < argc; index++)
		printf("Test ID: %s\n", argv[index]);

	if (p)
		level = atoi(p);
	else
		level = 0;
	printf("Run test suite with level=%d\n", level);

	printf("\nTEE test application started with device [%s]\n", _device);

	tee_res = xtest_teec_ctx_init();
	if (tee_res != TEEC_SUCCESS) {
		fprintf(stderr, "Failed to open TEE context: 0x%" PRIx32 "\n",
								tee_res);
		return -1;
	}

	/* Concatenate all the selected suites into 'all' */
	for (token = test_suite; ; token = NULL) {

		token = strtok(token, "+");
		if (!token)
			break;

		if (!strcmp(token, "regression"))
			ret = Do_ADBG_AppendToSuite(&all, &ADBG_Suite_regression);
		else if (!strcmp(token, "benchmark"))
			ret = Do_ADBG_AppendToSuite(&all, &ADBG_Suite_benchmark);
#ifdef WITH_GP_TESTS
		else if (!strcmp(token, "gp"))
			ret = Do_ADBG_AppendToSuite(&all, &ADBG_Suite_gp);
#endif
		else {
			fprintf(stderr, "Unkown test suite: %s\n", token);
			ret = -1;
		}
		if (ret < 0)
			goto err;
	}

	/* Run the tests */
	ret = Do_ADBG_RunSuite(&all, argc - optind, argv + optind);

err:
	free((void *)all.SuiteID_p);
	xtest_teec_ctx_deinit();

	printf("TEE test application done!\n");
	return ret;
}
