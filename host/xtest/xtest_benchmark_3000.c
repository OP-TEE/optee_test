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
#include "latency_common.h"
/* ----------------------------------------------------------------------- */
/* ------------------------- Auxiliary staff ----------------------------- */
/* ----------------------------------------------------------------------- */

/*
 * TEE client stuff
 */

static TEEC_Context ctx;
static TEEC_Session sess;

/* Benchmark ringbuffer with timestamps */
TEE_BENCH_DEFINE_RINGBUF(ringbuf_shm)

static void errx(const char *msg, TEEC_Result res)
{
	fprintf(stderr, "%s: 0x%08x", msg, res);
	exit (1);
}

static void check_res(TEEC_Result res, const char *errmsg)
{
	if (res != TEEC_SUCCESS)
		errx(errmsg, res);
}

static void open_benchmark_ta(void)
{
	TEEC_Result res;
	TEEC_UUID uuid = TA_LATENCY_PERF_UUID;
	uint32_t err_origin;

	res = TEEC_InitializeContext(NULL, &ctx);
	check_res(res,"TEEC_InitializeContext");

	res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL,
			       NULL, &err_origin);
	check_res(res,"TEEC_OpenSession");
}

static void close_clear_ta(void)
{
	/*
	 * We're done with the TA, close the session and
	 * destroy the context.
	 *
	 * The TA will print "Goodbye!" in the log when the
	 * session is closed.
	 */

	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);

}


static const char *src_str(uint64_t source)
{
	switch (source) {
	case TEE_BENCH_CORE:
		return "TEE_OS_CORE";
	case TEE_BENCH_KMOD:
		return "TEE_KERN_MOD";
	case TEE_BENCH_CLIENT:
		return "TEE_CLIENT";
	case TEE_BENCH_DUMB_TA:
		return "TEE_DUMB_TA";
	default:
		return "???";
	}
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

	open_benchmark_ta();
	/* Allocate timestamps ringbuf */
	TEE_BENCH_ALLOC_RINGBUF(&ringbuf_shm, &ctx, ringbuf_failed);

	memset(&op, 0, sizeof(op));

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE,
					 TEEC_NONE,
					 TEEC_NONE, TEEC_MEMREF_PARTIAL_INOUT);

	op.params[TEE_BENCH_DEF_PARAM].memref.parent = &ringbuf_shm;
	op.params[TEE_BENCH_DEF_PARAM].memref.offset = 0;
	op.params[TEE_BENCH_DEF_PARAM].memref.size = TEE_BENCH_RB_SIZE;

	TEE_BENCH_ADD_TS(ringbuf_shm.buffer, TEE_BENCH_CLIENT);
	res = TEEC_InvokeCommand(&sess, TA_LATENCY_PERF_CMD_NOP, &op, &err_origin);
	check_res(res, "TEEC_InvokeCommand");

	TEE_BENCH_ADD_TS(ringbuf_shm.buffer, TEE_BENCH_CLIENT);

	TEE_BENCH_PRINT_RES(ringbuf_shm.buffer);

ringbuf_failed:
	close_clear_ta();

}

ADBG_CASE_DEFINE(XTEST_TEE_BENCHMARK_3001, xtest_tee_benchmark_3001,
		/* Title */
		"Normal world App->Secured world TA latency benchmark",
		/* Short description */
		"",
		/* Requirement IDs */ "",
		/* How to implement */ ""
		);

