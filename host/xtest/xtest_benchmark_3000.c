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
#include "tee_bench.h"

/* ----------------------------------------------------------------------- */
/* ------------------------- Auxiliary staff ----------------------------- */
/* ----------------------------------------------------------------------- */

#define BENCH_COUNT 1000

/*
 * TEE client stuff
 */

static TEEC_Context ctx;
static TEEC_Session sess;

static TEEC_SharedMemory ringbuf_shm = {
		.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT,
		.buffer = NULL,
		.size = TEE_BENCH_RB_SIZE
	};

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
	TEEC_ReleaseSharedMemory(&ringbuf_shm);
	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);
}

static uint64_t get_timestamp(void *ringbuffer, uint64_t src)
{
	struct tee_ringbuf *ringb = (struct tee_ringbuf *) ringbuffer;
	for (uint64_t ts_i = 0; ts_i < ringb->tm_ind; ts_i++) {
		if (ringb->stamps[ts_i].src == src)
			return ringb->stamps[ts_i].cnt;
	}
	return 0;
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
	uint64_t ccnt_diff;
	struct statistics stats;
	UNUSED(c);

	open_latency_ta();
	memset(&op, 0, sizeof(op));

	res = TEEC_AllocateSharedMemory(&ctx, &ringbuf_shm);
	tee_check_res(res, "TEEC_AllocateSharedMemory");

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE,
					 TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	op.params[TEE_BENCH_DEF_PARAM].memref.parent =
				&ringbuf_shm;
	op.params[TEE_BENCH_DEF_PARAM].memref.offset = 0;
	op.params[TEE_BENCH_DEF_PARAM].memref.size =
				TEE_BENCH_RB_SIZE;

	/* Benchmarking */
	for (int i = 0; i < BENCH_COUNT; i++) {
		memset(ringbuf_shm.buffer, 0, ringbuf_shm.size);

		res = TEEC_InvokeCommand(&sess, TA_LATENCY_PERF_CMD_NOP,
						&op, &err_origin);
		tee_check_res(res, "TEEC_InvokeCommand");

		ccnt_diff = get_timestamp(ringbuf_shm.buffer, TEE_BENCH_DUMB_TA) -
				get_timestamp(ringbuf_shm.buffer, TEE_BENCH_CLIENT_P1);
		
		update_stats(&stats, ccnt_diff);
	}

	printf("Results:\n");
	printf("Min=%" PRIu64 " cycles; Max=%" PRIu64 
			" cycles; Med=%" PRIu64 " cycles;\n",
	       (uint64_t)stats.min, (uint64_t)stats.max, (uint64_t)stats.m);

	close_latency_ta();

}

ADBG_CASE_DEFINE(XTEST_TEE_BENCHMARK_3001, xtest_tee_benchmark_3001,
		/* Title */
		"OP-TEE Client -> TA latency benchmark",
		/* Short description */
		"",
		/* Requirement IDs */ "",
		/* How to implement */ ""
		);

