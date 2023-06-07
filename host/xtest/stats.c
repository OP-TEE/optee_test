// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2019, Linaro Limited
 */

#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fnmatch.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <tee_client_api.h>
#include <unistd.h>
#include "xtest_helpers.h"
#include "xtest_test.h"
#include "stats.h"

#define STATS_UUID { 0xd96a5b40, 0xe2c7, 0xb1af, \
			{ 0x87, 0x94, 0x10, 0x02, 0xa5, 0xd5, 0xc6, 0x1b } }

#define STATS_CMD_PAGER_STATS	0
#define STATS_CMD_ALLOC_STATS	1
#define STATS_CMD_MEMLEAK_STATS	2
#define STATS_CMD_TA_STATS	3

#define TEE_ALLOCATOR_DESC_LENGTH 32
struct malloc_stats {
	char desc[TEE_ALLOCATOR_DESC_LENGTH];
	uint32_t allocated;		  /* Bytes currently allocated */
	uint32_t max_allocated;		  /* Tracks max value of allocated */
	uint32_t size;			  /* Total size for this allocator */
	uint32_t num_alloc_fail;	  /* Number of failed alloc requests */
	uint32_t biggest_alloc_fail;	  /* Size of biggest failed alloc */
	uint32_t biggest_alloc_fail_used; /* Alloc bytes when above occurred */
};

struct ta_dump_stats {
	TEEC_UUID uuid;
	uint32_t panicked;	/* True if TA has panicked */
	uint32_t sess_count;	/* Number of opened session */
	struct malloc_stats heap;
};

static int usage(void)
{
	fprintf(stderr, "Usage: %s --stats [OPTION]\n", xtest_progname);
	fprintf(stderr, "Displays statistics from OP-TEE\n");
	fprintf(stderr, "Options:\n");
	fprintf(stderr, " -h|--help      Print this help and exit\n");
	fprintf(stderr, " --pager        Print pager statistics\n");
	fprintf(stderr, " --alloc        Print allocation statistics\n");
	fprintf(stderr, " --memleak      Dump memory leak data on secure console\n");
	fprintf(stderr, " --ta           Print loaded TAs context\n");

	return EXIT_FAILURE;
}

static void open_sess(TEEC_Context *ctx, TEEC_Session *sess)
{
	TEEC_UUID uuid = STATS_UUID;
	TEEC_Result res = TEEC_ERROR_GENERIC;
	uint32_t eo = 0;

	res = TEEC_InitializeContext(NULL, ctx);
	if (res)
		errx(EXIT_FAILURE, "TEEC_InitializeContext: %#"PRIx32, res);

	res = TEEC_OpenSession(ctx, sess, &uuid, TEEC_LOGIN_PUBLIC, NULL,
			       NULL, &eo);
	if (res)
		errx(EXIT_FAILURE,
		     "TEEC_OpenSession: res %#"PRIx32" err_orig %#"PRIx32,
			res, eo);
}

static int close_sess(TEEC_Context *ctx, TEEC_Session *sess)
{
	TEEC_CloseSession(sess);
	TEEC_FinalizeContext(ctx);

	return EXIT_SUCCESS;
}

static int stat_pager(int argc, char *argv[])
{
	TEEC_Context ctx = { };
	TEEC_Session sess = { };
	TEEC_Result res = TEEC_ERROR_GENERIC;
	uint32_t eo = 0;
	TEEC_Operation op = { };

	UNUSED(argv);
	if (argc != 1)
		return usage();

	open_sess(&ctx, &sess);

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT, TEEC_VALUE_OUTPUT,
					 TEEC_VALUE_OUTPUT, TEEC_NONE);

	res = TEEC_InvokeCommand(&sess, STATS_CMD_PAGER_STATS, &op, &eo);
	if (res)
		errx(EXIT_FAILURE,
		     "TEEC_InvokeCommand: res %#"PRIx32" err_orig %#"PRIx32,
		     res, eo);

	printf("Pager statistics (Number of):\n");
	printf("Unlocked pages:     %"PRId32"\n", op.params[0].value.a);
	printf("Page pool size:     %"PRId32"\n", op.params[0].value.b);
	printf("R/O faults:         %"PRId32"\n", op.params[1].value.a);
	printf("R/W faults:         %"PRId32"\n", op.params[1].value.b);
	printf("Hidden faults:      %"PRId32"\n", op.params[2].value.a);
	printf("Zi pages released:  %"PRId32"\n", op.params[2].value.b);

	return close_sess(&ctx, &sess);
}

static int stat_alloc(int argc, char *argv[])
{
	TEEC_Context ctx = { };
	TEEC_Session sess = { };
	TEEC_Result res = TEEC_ERROR_GENERIC;
	uint32_t eo = 0;
	TEEC_Operation op = { };
	struct malloc_stats *stats = NULL;
	size_t stats_size_bytes = 0;
	size_t n = 0;

	UNUSED(argv);
	if (argc != 1)
		return usage();

	open_sess(&ctx, &sess);

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE, TEEC_NONE);
	res = TEEC_InvokeCommand(&sess, STATS_CMD_ALLOC_STATS, &op, &eo);
	if (res != TEEC_ERROR_SHORT_BUFFER)
		errx(EXIT_FAILURE,
		     "TEEC_InvokeCommand: res %#"PRIx32" err_orig %#"PRIx32,
		     res, eo);

	stats_size_bytes = op.params[1].tmpref.size;
	if (stats_size_bytes % sizeof(*stats))
		errx(EXIT_FAILURE,
		     "STATS_CMD_PAGER_STATS: %zu not a multiple of %zu",
		     stats_size_bytes, sizeof(*stats));
	stats = calloc(1, stats_size_bytes);
	if (!stats)
		err(EXIT_FAILURE, "calloc(1, %zu)", stats_size_bytes);

	op.params[1].tmpref.buffer = stats;
	op.params[1].tmpref.size = stats_size_bytes;
	res = TEEC_InvokeCommand(&sess, STATS_CMD_ALLOC_STATS, &op, &eo);
	if (res)
		errx(EXIT_FAILURE,
		     "TEEC_InvokeCommand: res %#"PRIx32" err_orig %#"PRIx32,
		     res, eo);

	if (op.params[1].tmpref.size != stats_size_bytes)
		errx(EXIT_FAILURE,
		     "STATS_CMD_PAGER_STATS: expected size %zu, got %zu",
		     stats_size_bytes, op.params[1].tmpref.size);

	for (n = 0; n < stats_size_bytes / sizeof(*stats); n++) {
		if (n)
			printf("\n");
		printf("Pool:                %*s\n",
		       (int)strnlen(stats[n].desc, sizeof(stats[n].desc)),
		       stats[n].desc);
		printf("Bytes allocated:                       %"PRId32"\n",
		       stats[n].allocated);
		printf("Max bytes allocated:                   %"PRId32"\n",
		       stats[n].max_allocated);
		printf("Size of pool:                          %"PRId32"\n",
		       stats[n].size);
		printf("Number of failed allocations:          %"PRId32"\n",
		       stats[n].num_alloc_fail);
		printf("Size of larges allocation failure:     %"PRId32"\n",
		       stats[n].biggest_alloc_fail);
		printf("Total bytes allocated at that failure: %"PRId32"\n",
		       stats[n].biggest_alloc_fail_used);
	}

	free(stats);

	return close_sess(&ctx, &sess);
}

static int stat_memleak(int argc, char *argv[])
{
	TEEC_Context ctx = { };
	TEEC_Session sess = { };
	TEEC_Result res = TEEC_ERROR_GENERIC;
	uint32_t eo = 0;

	UNUSED(argv);
	if (argc != 1)
		return usage();

	open_sess(&ctx, &sess);

	res = TEEC_InvokeCommand(&sess, STATS_CMD_MEMLEAK_STATS, NULL, &eo);
	if (res)
		errx(EXIT_FAILURE,
		     "TEEC_InvokeCommand: res %#"PRIx32" err_orig %#"PRIx32,
		     res, eo);

	return close_sess(&ctx, &sess);
}

static int stat_loaded_ta(int argc, char *argv[])
{
	TEEC_Context ctx = { };
	TEEC_Session sess = { };
	TEEC_Result res = TEEC_ERROR_GENERIC;
	uint32_t eo = 0;
	TEEC_Operation op = { };
	void *buff = NULL;
	struct ta_dump_stats *stats = NULL;
	size_t stats_size_bytes = 0;
	size_t n = 0;
	uint32_t retry_count = 10;

	UNUSED(argv);
	if (argc != 1)
		return usage();

	open_sess(&ctx, &sess);
retry:
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE, TEEC_NONE, TEEC_NONE);
	res = TEEC_InvokeCommand(&sess, STATS_CMD_TA_STATS, &op, &eo);
	if (res != TEEC_ERROR_SHORT_BUFFER)
		errx(EXIT_FAILURE,
		     "TEEC_InvokeCommand: res %#"PRIx32" err_orig %#"PRIx32,
		     res, eo);

	stats_size_bytes = op.params[0].tmpref.size;
	if (stats_size_bytes == 0) {
		printf("No loaded TA found");
		goto out;
	}

	if (stats_size_bytes % sizeof(*stats))
		errx(EXIT_FAILURE,
		     "STATS_CMD_TA_STATS: %zu not a multiple of %zu",
		     stats_size_bytes, sizeof(*stats));

	/* Always allocate two more in case TA loaded after size querying */
	stats_size_bytes += 2 * sizeof(*stats);

	stats = realloc(buff, stats_size_bytes);
	if (!stats)
		errx(EXIT_FAILURE, "realloc(%zu) failed", stats_size_bytes);
	buff = stats;

	op.params[0].tmpref.buffer = stats;
	op.params[0].tmpref.size = stats_size_bytes;
	res = TEEC_InvokeCommand(&sess, STATS_CMD_TA_STATS, &op, &eo);
	if (res == TEEC_ERROR_SHORT_BUFFER && retry_count > 0) {
		retry_count--;
		goto retry;
	}

	if (res)
		errx(EXIT_FAILURE,
		     "TEEC_InvokeCommand: res %#"PRIx32" err_orig %#"PRIx32,
		     res, eo);

	for (n = 0; n < op.params[0].tmpref.size / sizeof(*stats); n++) {
		if (n)
			printf("\n");
		printf("ta(%08x-%04x-%04x-%02x%02x%02x%02x%02x%02x%02x%02x)\n",
			stats[n].uuid.timeLow, stats[n].uuid.timeMid,
			stats[n].uuid.timeHiAndVersion,
			stats[n].uuid.clockSeqAndNode[0],
			stats[n].uuid.clockSeqAndNode[1],
			stats[n].uuid.clockSeqAndNode[2],
			stats[n].uuid.clockSeqAndNode[3],
			stats[n].uuid.clockSeqAndNode[4],
			stats[n].uuid.clockSeqAndNode[5],
			stats[n].uuid.clockSeqAndNode[6],
			stats[n].uuid.clockSeqAndNode[7]);
		printf("\tpanicked(%"PRId32") -- True if TA has panicked\n",
			stats[n].panicked);
		printf("\tsession number(%"PRId32")\n", stats[n].sess_count);
		printf("\tHeap Status:\n");
		printf("\t\tBytes allocated:                       %"PRId32"\n",
		       stats[n].heap.allocated);
		printf("\t\tMax bytes allocated:                   %"PRId32"\n",
		       stats[n].heap.max_allocated);
		printf("\t\tSize of pool:                          %"PRId32"\n",
		       stats[n].heap.size);
		printf("\t\tNumber of failed allocations:          %"PRId32"\n",
		       stats[n].heap.num_alloc_fail);
		printf("\t\tSize of larges allocation failure:     %"PRId32"\n",
		       stats[n].heap.biggest_alloc_fail);
		printf("\t\tTotal bytes allocated at that failure: %"PRId32"\n",
		       stats[n].heap.biggest_alloc_fail_used);
	}

out:
	free(buff);
	return close_sess(&ctx, &sess);
}

int stats_runner_cmd_parser(int argc, char *argv[])
{
	if (argc > 1) {
		if (!strcmp(argv[1], "--pager"))
			return stat_pager(argc - 1, argv + 1);
		if (!strcmp(argv[1], "--alloc"))
			return stat_alloc(argc - 1, argv + 1);
		if (!strcmp(argv[1], "--memleak"))
			return stat_memleak(argc - 1, argv + 1);
		if (!strcmp(argv[1], "--ta"))
			return stat_loaded_ta(argc - 1, argv + 1);
	}

	return usage();
}
