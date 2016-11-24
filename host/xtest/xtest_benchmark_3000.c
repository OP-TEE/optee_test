/*
 * Copyright (c) 2016, Linaro Limited
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
/* ------------------------- Auxiliary stuff ----------------------------- */
/* ----------------------------------------------------------------------- */

#define BENCH_COUNT 1000
#define BENCH_DIVIDER 64

/*
 * TEE client stuff
 */

static TEEC_Context ctx;
static TEEC_Session sess;

static TEEC_SharedMemory timebuf_shm = {
		.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT,
		.buffer = NULL,
		.size = TEE_BENCH_RB_SIZE
	};

static const char *bench_str_src(uint64_t source)
{
	switch (source) {
	case TEE_BENCH_CORE:
		return "CORE";
	case TEE_BENCH_KMOD:
		return "KMOD";
	case TEE_BENCH_CLIENT:
		return "CLIENT";
	case TEE_BENCH_UTEE:
		return "UTEE";
	case TEE_BENCH_DUMB_TA:
		return "DUMB_TA";
	default:
		return "???";
	}
}

static void print_latency_stats(void *timebuffer, struct statistics *stats)
{
	struct tee_time_buf *timeb = (struct tee_time_buf *)timebuffer;
	uint64_t start = 0;

	printf("Latency statistics:\n");
	printf("===============================================================");
	printf("==============================================================\n");
	for (uint64_t ts_i = 0; ts_i < timeb->tm_ind; ts_i++) {
		if (!ts_i)
			start = timeb->stamps[ts_i].cnt;

		printf("| CCNT=%14" PRIu64 " | SRC=%-8s | PC=0x%016"
			PRIx64 " | Min=%14" PRIu64 " | Max=%14" PRIu64
			" | Med=%14" PRIu64 " |\n",
			(timeb->stamps[ts_i].cnt - start) * BENCH_DIVIDER,
			bench_str_src(timeb->stamps[ts_i].src),
			(timeb->stamps[ts_i].addr),
			(ts_i)?((uint64_t)stats[ts_i-1].min) * BENCH_DIVIDER : 0,
			(ts_i)?((uint64_t)stats[ts_i-1].max) * BENCH_DIVIDER : 0,
			(ts_i)?((uint64_t)stats[ts_i-1].m) * BENCH_DIVIDER : 0);
	}
	printf("===============================================================");
	printf("==============================================================\n");
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
	TEEC_ReleaseSharedMemory(&timebuf_shm);
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
	int64_t ccnt_diff;
	struct statistics stats[TEE_BENCH_MAX_STAMPS-1];
	struct tee_time_buf *timeb = NULL;
	UNUSED(c);

	open_latency_ta();
	memset(&op, 0, sizeof(op));
	memset(stats, 0, sizeof(stats));

	res = TEEC_AllocateSharedMemory(&ctx, &timebuf_shm);
	tee_check_res(res, "TEEC_AllocateSharedMemory");

	timeb = (struct tee_time_buf *)timebuf_shm.buffer;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE,
				TEEC_NONE, TEEC_NONE);
	op.params[TEE_BENCH_DEF_PARAM].memref.parent =
				&timebuf_shm;
	op.params[TEE_BENCH_DEF_PARAM].memref.offset = 0;
	op.params[TEE_BENCH_DEF_PARAM].memref.size =
				TEE_BENCH_RB_SIZE;

	/* Benchmarking */
	for (int i = 0; i < BENCH_COUNT; i++) {
		memset(timebuf_shm.buffer, 0, timebuf_shm.size);

		res = TEEC_InvokeCommand(&sess, TA_LATENCY_PERF_CMD_NOP,
						&op, &err_origin);
		tee_check_res(res, "TEEC_InvokeCommand");

		/* perform variance calculation for the each OP-TEE layer */
		for (uint64_t ts_i = 1; ts_i < timeb->tm_ind; ts_i++) {
			/* lets skip cases when counter overflows */
			if (timeb->stamps[ts_i].cnt < timeb->stamps[0].cnt)
					continue;
			ccnt_diff = timeb->stamps[ts_i].cnt -
						timeb->stamps[0].cnt;
			update_stats(&stats[ts_i-1], ccnt_diff);
		}
	}

	printf("Results:\n");
	print_latency_stats(timeb, stats);
	close_latency_ta();
}

/* ----------------------------------------------------------------------- */
/* ------------------------ ADBG Case defines  --------------------------- */
/* ----------------------------------------------------------------------- */
ADBG_CASE_DEFINE(XTEST_TEE_BENCHMARK_3001, xtest_tee_benchmark_3001,
		/* Title */
		"OP-TEE all-layers latecy benchmark",
		/* Short description */
		"",
		/* Requirement IDs */ "",
		/* How to implement */ ""
		);

