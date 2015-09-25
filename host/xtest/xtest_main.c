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
#ifdef WITH_GP_TESTS
#include "adbg_entry_declare.h"
#endif

ADBG_SUITE_DECLARE(XTEST_TEE_TEST)

/*ADBG Suite definition.*/
ADBG_SUITE_DEFINE_BEGIN(XTEST_TEE_TEST, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_1001, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_1004, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_1005, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_1006, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_1007, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_1008, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_1009, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_1010, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_1011, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_1012, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_4001, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_4002, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_4003_NO_XTS, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_4003_XTS, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_4004, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_4005, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_4006, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_4007, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_4008, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_4009, NULL)
/* FVP    ADBG_SUITE_ENTRY(XTEST_TEE_5006, NULL) */
#ifdef USER_SPACE
ADBG_SUITE_ENTRY(XTEST_TEE_6001, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_6002, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_6003, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_6004, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_6005, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_6006, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_6007, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_6008, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_6009, NULL)
#ifdef WITH_GP_TESTS
ADBG_SUITE_ENTRY(XTEST_TEE_6010, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_6011, NULL)
#endif
ADBG_SUITE_ENTRY(XTEST_TEE_7001, NULL)
/* FVP    ADBG_SUITE_ENTRY(XTEST_TEE_7002, NULL) */
ADBG_SUITE_ENTRY(XTEST_TEE_7003, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_7004, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_7005, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_7006, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_7007, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_7008, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_7009, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_7010, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_7013, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_7016, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_7017, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_7018, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_7019, NULL)
#ifdef WITH_GP_TESTS
ADBG_ENTRY_AUTO_GENERATED_TESTS()
#else
#endif
#endif /*USER_SPACE*/
ADBG_SUITE_ENTRY(XTEST_TEE_10001, NULL)
ADBG_SUITE_ENTRY(XTEST_TEE_10002, NULL)
ADBG_SUITE_DEFINE_END()

static const char gdevname_tz[] = "opteearmtz00";
char *_device = (char *)gdevname_tz;
unsigned int level = 0;
static const char glevel[] = "0";

void usage(char *program);

void usage(char *program)
{
	printf("Usage: %s <options> <test_id>\n", program);
	printf("\n");
	printf("options:\n");
	printf("\t-d <device>        default value = %s\n", gdevname_tz);
	printf("\t-l <level>         test suite level: [0-15]\n");
	printf("\t                   default value = %s\n", glevel);
	printf("\t-h                 show usage\n");
	printf("\n");
}

int main(int argc, char *argv[])
{
	int opt;
	int index;
	int ret;
	char *p = (char *)glevel;

	while ((opt = getopt(argc, argv, "d:l:h")) != -1) {
		switch (opt) {
		case 'd':
			_device = optarg;
			break;
		case 'l':
			p = optarg;
			break;
		case 'h':
			usage(argv[0]);
			return 0;
		default:
			usage(argv[0]);
			return -1;
 		}
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

	ret = Do_ADBG_RunSuite(&ADBG_Suite_XTEST_TEE_TEST, argc - optind, (argv + optind));

	xtest_teec_ctx_deinit();

	printf("TEE test application done!\n");
	return ret;
}
