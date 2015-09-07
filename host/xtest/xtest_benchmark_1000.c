/*
 * Copyright (c) 2015, Linaro Limited
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
#include <string.h>

#include "xtest_test.h"
#include "xtest_helpers.h"

#include <ta_bonnie.h>

static void xtest_tee_benchmark_1001(ADBG_Case_t *Case_p);
static void xtest_tee_benchmark_1002(ADBG_Case_t *Case_p);
static void xtest_tee_benchmark_1003(ADBG_Case_t *Case_p);
static void xtest_tee_benchmark_1004(ADBG_Case_t *Case_p);
static void xtest_tee_benchmark_1005(ADBG_Case_t *Case_p);
static void xtest_tee_benchmark_1006(ADBG_Case_t *Case_p);


static TEEC_Result run_test(enum bonnie_cmd cmd)
{
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	TEEC_Result res;
	TEEC_Session sess;
	uint32_t orig;

	res = xtest_teec_open_session(&sess, &bonnie_ta_uuid, NULL, &orig);
	if (res != TEEC_SUCCESS)
		return res;

	res = TEEC_InvokeCommand(&sess, cmd, &op, &orig);

	TEEC_CloseSession(&sess);

	return res;
}

static void xtest_tee_benchmark_1001(ADBG_Case_t *c)
{
	ADBG_EXPECT_TEEC_SUCCESS(c, run_test(TA_BONNIE_CMD_TEST_PUTC));
}

static void xtest_tee_benchmark_1002(ADBG_Case_t *c)
{
	ADBG_EXPECT_TEEC_SUCCESS(c, run_test(TA_BONNIE_CMD_TEST_REWRITE));
}

static void xtest_tee_benchmark_1003(ADBG_Case_t *c)
{
	ADBG_EXPECT_TEEC_SUCCESS(c, run_test(TA_BONNIE_CMD_TEST_FASTWRITE));
}

static void xtest_tee_benchmark_1004(ADBG_Case_t *c)
{
	ADBG_EXPECT_TEEC_SUCCESS(c, run_test(TA_BONNIE_CMD_TEST_GETC));
}

static void xtest_tee_benchmark_1005(ADBG_Case_t *c)
{
	ADBG_EXPECT_TEEC_SUCCESS(c, run_test(TA_BONNIE_CMD_TEST_FASTREAD));
}

static void xtest_tee_benchmark_1006(ADBG_Case_t *c)
{
	ADBG_EXPECT_TEEC_SUCCESS(c, run_test(TA_BONNIE_CMD_TEST_LSEEK));
}


ADBG_CASE_DEFINE(XTEST_TEE_BENCHMARK_1001, xtest_tee_benchmark_1001,
		/* Title */ "TEE Trusted Storage Performance Test (PUTC)",
		/* Short description */ "",
		/* Requirement IDs */ "",
		/* How to implement */ ""
		);

ADBG_CASE_DEFINE(XTEST_TEE_BENCHMARK_1002, xtest_tee_benchmark_1002,
		/* Title */ "TEE Trusted Storage Performance Test (REWRITE)",
		/* Short description */ "",
		/* Requirement IDs */ "",
		/* How to implement */ ""
		);

ADBG_CASE_DEFINE(XTEST_TEE_BENCHMARK_1003, xtest_tee_benchmark_1003,
		/* Title */ "TEE Trusted Storage Performance Test (FASTWRITE)",
		/* Short description */ "",
		/* Requirement IDs */ "",
		/* How to implement */ ""
		);

ADBG_CASE_DEFINE(XTEST_TEE_BENCHMARK_1004, xtest_tee_benchmark_1004,
		/* Title */ "TEE Trusted Storage Performance Test (GETC)",
		/* Short description */ "",
		/* Requirement IDs */ "",
		/* How to implement */ ""
		);

ADBG_CASE_DEFINE(XTEST_TEE_BENCHMARK_1005, xtest_tee_benchmark_1005,
		/* Title */ "TEE Trusted Storage Performance Test (FASTREAD)",
		/* Short description */ "",
		/* Requirement IDs */ "",
		/* How to implement */ ""
		);

ADBG_CASE_DEFINE(XTEST_TEE_BENCHMARK_1006, xtest_tee_benchmark_1006,
		/* Title */ "TEE Trusted Storage Performance Test (LSEEK)",
		/* Short description */ "",
		/* Requirement IDs */ "",
		/* How to implement */ ""
		);

