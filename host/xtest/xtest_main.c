/*
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <adbg.h>
#include "xtest_test.h"
#include "xtest_helpers.h"

/* include here shandalone tests */
#include "crypto_common.h"

#ifdef WITH_GP_TESTS
#include "adbg_entry_declare.h"
#endif

ADBG_SUITE_DECLARE(XTEST_TEE_TEST)

/*ADBG Suite definition.*/
ADBG_SUITE_DEFINE_BEGIN(XTEST_TEE_TEST)
ADBG_SUITE_ENTRY(XTEST_TEE_1001)
ADBG_SUITE_ENTRY(XTEST_TEE_1004)
ADBG_SUITE_ENTRY(XTEST_TEE_1005)
ADBG_SUITE_ENTRY(XTEST_TEE_1006)
ADBG_SUITE_ENTRY(XTEST_TEE_1007)
ADBG_SUITE_ENTRY(XTEST_TEE_1008)
ADBG_SUITE_ENTRY(XTEST_TEE_1009)
ADBG_SUITE_ENTRY(XTEST_TEE_1010)
ADBG_SUITE_ENTRY(XTEST_TEE_1011)
ADBG_SUITE_ENTRY(XTEST_TEE_1012)
ADBG_SUITE_ENTRY(XTEST_TEE_1013)
ADBG_SUITE_ENTRY(XTEST_TEE_4001)
ADBG_SUITE_ENTRY(XTEST_TEE_4002)
ADBG_SUITE_ENTRY(XTEST_TEE_4003_NO_XTS)
ADBG_SUITE_ENTRY(XTEST_TEE_4003_XTS)
ADBG_SUITE_ENTRY(XTEST_TEE_4004)
ADBG_SUITE_ENTRY(XTEST_TEE_4005)
ADBG_SUITE_ENTRY(XTEST_TEE_4006)
ADBG_SUITE_ENTRY(XTEST_TEE_4007)
ADBG_SUITE_ENTRY(XTEST_TEE_4008)
ADBG_SUITE_ENTRY(XTEST_TEE_4009)
ADBG_SUITE_ENTRY(XTEST_TEE_4010)
ADBG_SUITE_ENTRY(XTEST_TEE_4011)
ADBG_SUITE_ENTRY(XTEST_TEE_5006)
#ifdef USER_SPACE
ADBG_SUITE_ENTRY(XTEST_TEE_6001)
ADBG_SUITE_ENTRY(XTEST_TEE_6002)
ADBG_SUITE_ENTRY(XTEST_TEE_6003)
ADBG_SUITE_ENTRY(XTEST_TEE_6004)
ADBG_SUITE_ENTRY(XTEST_TEE_6005)
ADBG_SUITE_ENTRY(XTEST_TEE_6006)
ADBG_SUITE_ENTRY(XTEST_TEE_6007)
ADBG_SUITE_ENTRY(XTEST_TEE_6008)
ADBG_SUITE_ENTRY(XTEST_TEE_6009)
ADBG_SUITE_ENTRY(XTEST_TEE_6010)
#ifdef WITH_GP_TESTS
ADBG_SUITE_ENTRY(XTEST_TEE_6011)
#endif
ADBG_SUITE_ENTRY(XTEST_TEE_6012)
ADBG_SUITE_ENTRY(XTEST_TEE_6013)
ADBG_SUITE_ENTRY(XTEST_TEE_6014)
ADBG_SUITE_ENTRY(XTEST_TEE_6015)
ADBG_SUITE_ENTRY(XTEST_TEE_6016)
ADBG_SUITE_ENTRY(XTEST_TEE_7001)
ADBG_SUITE_ENTRY(XTEST_TEE_7002)
ADBG_SUITE_ENTRY(XTEST_TEE_7003)
ADBG_SUITE_ENTRY(XTEST_TEE_7004)
ADBG_SUITE_ENTRY(XTEST_TEE_7005)
ADBG_SUITE_ENTRY(XTEST_TEE_7006)
ADBG_SUITE_ENTRY(XTEST_TEE_7007)
ADBG_SUITE_ENTRY(XTEST_TEE_7008)
ADBG_SUITE_ENTRY(XTEST_TEE_7009)
ADBG_SUITE_ENTRY(XTEST_TEE_7010)
ADBG_SUITE_ENTRY(XTEST_TEE_7013)
ADBG_SUITE_ENTRY(XTEST_TEE_7016)
ADBG_SUITE_ENTRY(XTEST_TEE_7017)
ADBG_SUITE_ENTRY(XTEST_TEE_7018)
ADBG_SUITE_ENTRY(XTEST_TEE_7019)
#ifdef WITH_GP_TESTS
ADBG_ENTRY_AUTO_GENERATED_TESTS()
#else
#endif
#endif /*USER_SPACE*/
ADBG_SUITE_ENTRY(XTEST_TEE_10001)
ADBG_SUITE_ENTRY(XTEST_TEE_10002)

#if defined(CFG_REE_FS)
ADBG_SUITE_ENTRY(XTEST_TEE_20001)
ADBG_SUITE_ENTRY(XTEST_TEE_20002)
ADBG_SUITE_ENTRY(XTEST_TEE_20003)
ADBG_SUITE_ENTRY(XTEST_TEE_20004)
ADBG_SUITE_ENTRY(XTEST_TEE_20021)
ADBG_SUITE_ENTRY(XTEST_TEE_20022)
ADBG_SUITE_ENTRY(XTEST_TEE_20023)

ADBG_SUITE_ENTRY(XTEST_TEE_20501)
ADBG_SUITE_ENTRY(XTEST_TEE_20502)
ADBG_SUITE_ENTRY(XTEST_TEE_20503)
ADBG_SUITE_ENTRY(XTEST_TEE_20521)
ADBG_SUITE_ENTRY(XTEST_TEE_20522)
ADBG_SUITE_ENTRY(XTEST_TEE_20523)
#endif /* defined(CFG_REE_FS) */

ADBG_SUITE_DEFINE_END()


ADBG_SUITE_DECLARE(XTEST_TEE_BENCHMARK)
ADBG_SUITE_DEFINE_BEGIN(XTEST_TEE_BENCHMARK)

/* Storage benchmarks */
ADBG_SUITE_ENTRY(XTEST_TEE_BENCHMARK_1001)
ADBG_SUITE_ENTRY(XTEST_TEE_BENCHMARK_1002)
ADBG_SUITE_ENTRY(XTEST_TEE_BENCHMARK_1003)

/* SHA benchmarks */
ADBG_SUITE_ENTRY(XTEST_TEE_BENCHMARK_2001)
ADBG_SUITE_ENTRY(XTEST_TEE_BENCHMARK_2002)

/* AES benchmarks */
ADBG_SUITE_ENTRY(XTEST_TEE_BENCHMARK_2011)
ADBG_SUITE_ENTRY(XTEST_TEE_BENCHMARK_2012)
ADBG_SUITE_DEFINE_END()


char *_device = NULL;
unsigned int level = 0;
static const char glevel[] = "0";
static const char gsuitename[] = "regression";

void usage(char *program);

void usage(char *program)
{
	printf("Usage: %s <options> <test_id>\n", program);
	printf("\n");
	printf("options:\n");
	printf("\t-d <device-type>   default not set, use any\n");
	printf("\t-l <level>         test suite level: [0-15]\n");
	printf("\t-t <test_suite>    available test suite: regression, benchmark\n");
	printf("\t                   default value = %s\n", gsuitename);
	printf("\t-h                 show usage\n");
	printf("applets:\n");
	printf("\t--sha-perf         SHA performance testing tool for OP-TEE\n");
	printf("\t--sha perf -h      show usage of SHA performance testing tool\n");
	printf("\n");
	printf("\t--aes-perf         AES performance testing tool for OP-TEE\n");
	printf("\t--aes perf -h      show usage of AES performance testing tool\n");
	printf("\n");
}

int main(int argc, char *argv[])
{
	int opt;
	int index;
	int ret;
	char *p = (char *)glevel;
	char *test_suite = (char *)gsuitename;

	opterr = 0;

	if (argc > 1 && !strcmp(argv[1], "--sha-perf"))
		return sha_perf_runner_cmd_parser(argc-1, &argv[1]);
	else if (argc > 1 && !strcmp(argv[1], "--aes-perf"))
		return aes_perf_runner_cmd_parser(argc-1, &argv[1]);

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

	xtest_teec_ctx_init();

	if (strcmp(test_suite, "regression") == 0)
		ret = Do_ADBG_RunSuite(&ADBG_Suite_XTEST_TEE_TEST, argc - optind, (argv + optind));
	else if (strcmp(test_suite, "benchmark") == 0)
		ret = Do_ADBG_RunSuite(&ADBG_Suite_XTEST_TEE_BENCHMARK, argc - optind, (argv + optind));
	else {
		fprintf(stderr, "No test suite found: %s\n", test_suite);
		ret = -1;
	}

	xtest_teec_ctx_deinit();

	printf("TEE test application done!\n");
	return ret;
}
