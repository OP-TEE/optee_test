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
#include <sys/utsname.h>
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
#include "stats.h"


ADBG_SUITE_DEFINE(benchmark);
#ifdef WITH_GP_TESTS
ADBG_SUITE_DEFINE(gp);
#endif
#ifdef CFG_PKCS11_TA
ADBG_SUITE_DEFINE(pkcs11);
#endif
ADBG_SUITE_DEFINE(regression);

char *_device = NULL;
unsigned int level = 0;
static const char glevel[] = "0";

/* By default bypass kernel version using UINT_MAX */
unsigned int xtest_kernel_major = UINT_MAX;
unsigned int xtest_kernel_minor = UINT_MAX;

#ifdef WITH_GP_TESTS
#define GP_SUITE	"+gp"
#else
#define GP_SUITE	""
#endif

#ifdef CFG_PKCS11_TA
#define PKCS11_SUITE	"+pkcs11"
#else
#define PKCS11_SUITE	""
#endif

static char gsuitename[] = "regression" GP_SUITE PKCS11_SUITE;

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
#ifdef CFG_PKCS11_TA
	printf(" pkcs11");
#endif
	printf("\n");
	printf("\t                   To run several suites, use multiple names\n");
	printf("\t                   separated by a '+')\n");
	printf("\t                   Default value: '%s'\n", gsuitename);
	printf("\t-h                 Show usage\n");
	printf("\t-k                 Skip test cases that Linux kernel may not\n");
	printf("\t                   support. Checks kernel version with uname.\n");
#ifdef CFG_XTEST_KERNEL_RESTRICTIONS
	printf("\t                   Force enabled by configuration switch!\n");
#endif
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
	printf("\t--stats [opts]     Various statistics ('-h' for usage)\n");
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

static int set_kernel_restriction(void)
{
	struct utsname os_name = { };
	int major = 0;
	int minor = 0;

	if (uname(&os_name)) {
		printf("Error: uname() failed\n");
		return -1;
	}

	if (strcmp(os_name.sysname, "Linux")) {
		fprintf(stderr, "Error: unrecognized uname.sysname %s\n",
			os_name.sysname);
		return -1;
	}

	if (sscanf(os_name.release, "%u.%u.", &major, &minor) != 2) {
		fprintf(stderr, "Error: unrecognized uname.release %s\n",
			os_name.release);
		return -1;
	}

	if (cmp_kernel_version(major, minor,
			       KERNEL_MAJOR_MIN, KERNEL_MINOR_MIN) < 0)
		printf("Warning: version %u.%u too early for OP-TEE\n",
		       major, minor);

	if (cmp_kernel_version(major, minor,
			       KERNEL_MAJOR_NEXT, KERNEL_MINOR_NEXT) >= 0)
		printf("Warning: unknown next kernel %u.%u.\n",
		       major, minor);

	xtest_kernel_major = major;
	xtest_kernel_minor = minor;

	printf("Test restricted to mainline kernel %u.%u\n",
	       xtest_kernel_major, xtest_kernel_minor);

	return 0;
}

int main(int argc, char *argv[])
{
	int opt = 0;
	int index = 0;
	TEEC_Result tee_res = TEEC_ERROR_GENERIC;
	int ret = 0;
	char *p = (char *)glevel;
	char *test_suite = (char *)gsuitename;
	char *token = NULL;
	ADBG_Suite_Definition_t all = {
		.SuiteID_p = NULL,
		.cases = TAILQ_HEAD_INITIALIZER(all.cases),
	};
	int kernel_restrictions = 0;

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
	else if (argc > 1 && !strcmp(argv[1], "--stats"))
		return stats_runner_cmd_parser(argc - 1, &argv[1]);

#ifdef CFG_XTEST_KERNEL_RESTRICTIONS
	kernel_restrictions = 1;
#endif

	while ((opt = getopt(argc, argv, "d:l:t:h:k")) != -1) {
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
		case 'k':
			kernel_restrictions = 1;
			break;
		default:
			usage(argv[0]);
			return -1;
		}
	}

	if (kernel_restrictions && set_kernel_restriction())
		return -1;

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
#ifdef CFG_PKCS11_TA
		else if (!strcmp(token, "pkcs11"))
			ret = Do_ADBG_AppendToSuite(&all, &ADBG_Suite_pkcs11);
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
