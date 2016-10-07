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
#include <stdlib.h>
#include <string.h>

#include "xtest_test.h"
#include "xtest_helpers.h"

#include <util.h>

#include "ta_latency_perf.h"
/* ----------------------------------------------------------------------- */
/* ------------------------- Auxiliary staff ----------------------------- */
/* ----------------------------------------------------------------------- */

/*
 * TEE client stuff
 */

static TEEC_Context ctx;
static TEEC_Session sess;

/* Misc auxilary functions */
static void tee_errx(const char *msg, TEEC_Result res)
{
	fprintf(stderr, "%s: 0x%08x", msg, res);
	exit (1);
}

static void tee_check_res(TEEC_Result res, const char *errmsg)
{
	if (res != TEEC_SUCCESS)
		tee_errx(errmsg, res);
}



static void open_latency_ta(void)
{
	TEEC_Result res;
	TEEC_UUID uuid = TA_LATENCY_PERF_UUID;
	uint32_t err_origin;

	res = TEEC_InitializeContext(NULL, &ctx);
	tee_check_res(res,"TEEC_InitializeContext");

	res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL,
			       NULL, &err_origin);
	tee_check_res(res,"TEEC_OpenSession");
}

static void close_latency_ta(void)
{
	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);
}


/* ----------------------------------------------------------------------- */
/* -------------------------- Latency tests  ----------------------------- */
/* ----------------------------------------------------------------------- */


static void xtest_tee_benchmark_3001(ADBG_Case_t *Case_p);

static void xtest_tee_benchmark_3001(ADBG_Case_t *c)
{
	TEEC_Operation op;
	TEEC_Result res;
	uint32_t err_origin;

	UNUSED(c);

	open_latency_ta();

	memset(&op, 0, sizeof(op));

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE,
					 TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(&sess, TA_LATENCY_PERF_CMD_NOP, &op, &err_origin);
	tee_check_res(res, "TEEC_InvokeCommand");

	close_latency_ta();

}

ADBG_CASE_DEFINE(XTEST_TEE_BENCHMARK_3001, xtest_tee_benchmark_3001,
		/* Title */
		"Normal world App->Secured world TA latency benchmark",
		/* Short description */
		"",
		/* Requirement IDs */ "",
		/* How to implement */ ""
		);

