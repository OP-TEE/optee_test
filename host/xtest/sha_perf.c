/*
 * Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#include <adbg.h>
#include <tee_client_api.h>
#include "crypto_common.h"

/*
 * TEE client stuff
 */

static TEEC_Context ctx;
static TEEC_Session sess;
static TEEC_SharedMemory in_shm = {
	.flags = TEEC_MEM_INPUT
};
static TEEC_SharedMemory out_shm = {
	.flags = TEEC_MEM_OUTPUT
};

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

static void open_ta(void)
{
	TEEC_Result res;
	TEEC_UUID uuid = TA_SHA_PERF_UUID;
	uint32_t err_origin;

	res = TEEC_InitializeContext(NULL, &ctx);
	check_res(res,"TEEC_InitializeContext");

	res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL,
			       NULL, &err_origin);
	check_res(res,"TEEC_OpenSession");
}

/*
 * Statistics
 *
 * We want to compute min, max, mean and standard deviation of processing time
 */

struct statistics {
	int n;
	double m;
	double M2;
	double min;
	double max;
	int initialized;
};

/* Take new sample into account (Knuth/Welford algorithm) */
static void update_stats(struct statistics *s, uint64_t t)
{
	double x = (double)t;
	double delta = x - s->m;

	s->n++;
	s->m += delta/s->n;
	s->M2 += delta*(x - s->m);
	if (!s->initialized) {
		s->min = s->max = x;
		s->initialized = 1;
	} else {
		if (s->min > x)
			s->min = x;
		if (s->max < x)
			s->max = x;
	}
}

static double stddev(struct statistics *s)
{
	if (s->n < 2)
		return NAN;
	return sqrt(s->M2/s->n);
}

static const char *algo_str(uint32_t algo)
{
	switch (algo) {
	case TA_SHA_SHA1:
		return "SHA1";
	case TA_SHA_SHA224:
		return "SHA224";
	case TA_SHA_SHA256:
		return "SHA256";
	case TA_SHA_SHA384:
		return "SHA384";
	case TA_SHA_SHA512:
		return "SHA512";
	default:
		return "???";
	}
}

static int hash_size(uint32_t algo)
{
	switch (algo) {
	case TA_SHA_SHA1:
		return 20;
	case TA_SHA_SHA224:
		return 28;
	case TA_SHA_SHA256:
		return 32;
	case TA_SHA_SHA384:
		return 48;
	case TA_SHA_SHA512:
		return 64;
	default:
		return 0;
	}
}

#define _TO_STR(x) #x
#define TO_STR(x) _TO_STR(x)


static void alloc_shm(size_t sz, uint32_t algo, int offset)
{
	TEEC_Result res;

	in_shm.buffer = NULL;
	in_shm.size = sz + offset;
	res = TEEC_AllocateSharedMemory(&ctx, &in_shm);
	check_res(res, "TEEC_AllocateSharedMemory");

	out_shm.buffer = NULL;
	out_shm.size = hash_size(algo);
	res = TEEC_AllocateSharedMemory(&ctx, &out_shm);
	check_res(res, "TEEC_AllocateSharedMemory");
}

static void free_shm(void)
{
	TEEC_ReleaseSharedMemory(&in_shm);
	TEEC_ReleaseSharedMemory(&out_shm);
}

static ssize_t read_random(void *in, size_t rsize)
{
	static int rnd;
	ssize_t s;

	if (!rnd) {
		rnd = open("/dev/urandom", O_RDONLY);
		if (rnd < 0) {
			perror("open");
			return 1;
		}
	}
	s = read(rnd, in, rsize);
	if (s < 0) {
		perror("read");
		return 1;
	}
	if ((size_t)s != rsize) {
		printf("read: requested %zu bytes, got %zd\n",
		       rsize, s);
	}
	return 0;
}

static long get_current_time(struct timespec *ts)
{
	if (clock_gettime(CLOCK_MONOTONIC, ts) < 0) {
		perror("clock_gettime");
		exit(1);
	}
	return 0;
}

static uint64_t timespec_diff_ns(struct timespec *start, struct timespec *end)
{
	uint64_t ns = 0;

	if (end->tv_nsec < start->tv_nsec) {
		ns += 1000000000 * (end->tv_sec - start->tv_sec - 1);
		ns += 1000000000 - start->tv_nsec + end->tv_nsec;
	} else {
		ns += 1000000000 * (end->tv_sec - start->tv_sec);
		ns += end->tv_nsec - start->tv_nsec;
	}
	return ns;
}

static uint64_t run_test_once(void *in, size_t size,  int random_in, TEEC_Operation *op)
{
	struct timespec t0, t1;
	TEEC_Result res;
	uint32_t ret_origin;

	if (random_in)
		read_random(in, size);
	get_current_time(&t0);
	res = TEEC_InvokeCommand(&sess, TA_SHA_PERF_CMD_PROCESS, op,
				 &ret_origin);
	check_res(res, "TEEC_InvokeCommand");
	get_current_time(&t1);

	return timespec_diff_ns(&t0, &t1);
}

static void prepare_op(int algo)
{
	TEEC_Result res;
	uint32_t ret_origin;
	TEEC_Operation op;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].value.a = algo;
	res = TEEC_InvokeCommand(&sess, TA_SHA_PERF_CMD_PREPARE_OP, &op,
				 &ret_origin);
	check_res(res, "TEEC_InvokeCommand");
}

static void do_warmup(int warmup)
{
	struct timespec t0, t;
	int i;

	get_current_time(&t0);
	do {
		for (i = 0; i < 100000; i++)
			;
		get_current_time(&t);
	} while (timespec_diff_ns(&t0, &t) < (uint64_t)warmup * 1000000000);
}

static const char *yesno(int v)
{
	return (v ? "yes" : "no");
}

static double mb_per_sec(size_t size, double usec)
{
	return (1000000000/usec)*((double)size/(1024*1024));
}

/* Hash test: buffer of size byte. Run test n times.
 * Entry point for running SHA benchmark 
 * Params: 
 * algo - Algorithm
 * size - Buffer size
 * n - Number of measurements
 * l - Amount of inner loops
 * random_in - Get input from /dev/urandom
 * offset - Buffer offset wrt. alloc-ed address
 * warmup - Start with a-second busy loop
 * verbosity - Verbosity level 
 * */
extern void sha_perf_run_test(int algo, size_t size, unsigned int n, 
				unsigned int l, int random_in, int offset, 
				int warmup, int verbosity)
{
	uint64_t t;
	struct statistics stats;
	TEEC_Operation op;
	int n0 = n;
	struct timespec ts;

	vverbose("sha-perf version %s\n", TO_STR(VERSION));
	if (clock_getres(CLOCK_MONOTONIC, &ts) < 0) {
		perror("clock_getres");
		return;
	}
	vverbose("Clock resolution is %lu ns\n", ts.tv_sec*1000000000 +
		ts.tv_nsec);

	open_ta();
	prepare_op(algo);
	
	
	alloc_shm(size, algo, offset);

	if (!random_in)
		memset((uint8_t *)in_shm.buffer + offset, 0, size);

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INPUT,
					 TEEC_MEMREF_PARTIAL_OUTPUT,
					 TEEC_VALUE_INPUT, TEEC_NONE);
	op.params[0].memref.parent = &in_shm;
	op.params[0].memref.offset = 0;
	op.params[0].memref.size = size + offset;
	op.params[1].memref.parent = &out_shm;
	op.params[1].memref.offset = 0;
	op.params[1].memref.size = hash_size(algo);
	op.params[2].value.a = l;
	op.params[2].value.b = offset;

	verbose("Starting test: %s, size=%zu bytes, ",
		algo_str(algo), size);
	verbose("random=%s, ", yesno(random_in));
	verbose("unaligned=%s, ", yesno(offset));
	verbose("inner loops=%u, loops=%u, warm-up=%u s\n", l, n, warmup);

	if (warmup)
		do_warmup(warmup);

	memset(&stats, 0, sizeof(stats));
	while (n-- > 0) {
		t = run_test_once((uint8_t *)in_shm.buffer + offset, size, random_in, &op);
		update_stats(&stats, t);
		if (n % (n0/10) == 0)
			vverbose("#");
	}
	vverbose("\n");
	printf("min=%gμs max=%gμs mean=%gμs stddev=%gμs (%gMiB/s)\n",
	       stats.min/1000, stats.max/1000, stats.m/1000,
	       stddev(&stats)/1000, mb_per_sec(size, stats.m));
	free_shm();
}

static void usage(const char *progname, 
				/* Default params */
				int algo, size_t size, int warmup, int l, int n)
{
	fprintf(stderr, "SHA performance testing tool for OP-TEE (%s)\n\n",
		TO_STR(VERSION));
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "  %s -h\n", progname);
	fprintf(stderr, "  %s [-v] [-a algo] ", progname);
	fprintf(stderr, "[-s bufsize] [-r] [-n loops] [-l iloops] ");
	fprintf(stderr, "[-w warmup_time]\n");
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "  -h    Print this help and exit\n");
	fprintf(stderr, "  -l    Inner loop iterations (TA hashes ");
	fprintf(stderr, "the buffer <x> times) [%u]\n", l);
	fprintf(stderr, "  -a    Algorithm (SHA1, SHA224, SHA256, SHA384, ");
	fprintf(stderr, "SHA512) [%s]\n", algo_str(algo));
	fprintf(stderr, "  -n    Outer loop iterations [%u]\n", n);
	fprintf(stderr, "  -r    Get input data from /dev/urandom ");
	fprintf(stderr, "(otherwise use zero-filled buffer)\n");
	fprintf(stderr, "  -s    Buffer size (process <x> bytes at a time) ");
	fprintf(stderr, "[%zu]\n", size);
	fprintf(stderr, "  -u    Use unaligned buffer (odd address)\n");
	fprintf(stderr, "  -v    Be verbose (use twice for greater effect)\n");
	fprintf(stderr, "  -w    Warm-up time in seconds: execute a busy ");
	fprintf(stderr, "loop before the test\n");
	fprintf(stderr, "        to mitigate the effects of cpufreq etc. ");
	fprintf(stderr, "[%u]\n", warmup);
}

#define NEXT_ARG(i) \
	do { \
		if (++i == argc) { \
			fprintf(stderr, "%s: %s: missing argument\n", \
				argv[0], argv[i-1]); \
			return 1; \
		} \
	} while (0);



extern int sha_perf_runner_cmd_parser(int argc, char *argv[])
{
	int i;
	
	/* Command line params */
	size_t size = 1024;	/* Buffer size (-s) */
	unsigned int n = CRYPTO_DEF_COUNT;/* Number of measurements (-n)*/
	unsigned int l = CRYPTO_DEF_LOOPS;	/* Inner loops (-l) */
	int verbosity = CRYPTO_DEF_VERBOSITY;	/* Verbosity (-v) */
	int algo = TA_SHA_SHA1;	/* Algorithm (-a) */
	/* Get input data from /dev/urandom (-r) */
	int random_in = CRYPTO_USE_RANDOM;
	/* Start with a 2-second busy loop (-w) */
	int warmup = CRYPTO_DEF_WARMUP;
	int offset = 0; /* Buffer offset wrt. alloc'ed address (-u) */


	/* Parse command line */
	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-h")) {
			usage(argv[0], algo, size, warmup, l, n);
			return 0;
		}
	}
	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-l")) {
			NEXT_ARG(i);
			l = atoi(argv[i]);
		} else if (!strcmp(argv[i], "-a")) {
			NEXT_ARG(i);
			if (!strcasecmp(argv[i], "SHA1"))
				algo = TA_SHA_SHA1;
			else if (!strcasecmp(argv[i], "SHA224"))
				algo = TA_SHA_SHA224;
			else if (!strcasecmp(argv[i], "SHA256"))
				algo = TA_SHA_SHA256;
			else if (!strcasecmp(argv[i], "SHA384"))
				algo = TA_SHA_SHA384;
			else if (!strcasecmp(argv[i], "SHA512"))
				algo = TA_SHA_SHA512;
			else {
				fprintf(stderr, "%s, invalid algorithm\n",
					argv[0]);
				usage(argv[0], algo, size, warmup, l, n);
				return 1;
			}
		} else if (!strcmp(argv[i], "-n")) {
			NEXT_ARG(i);
			n = atoi(argv[i]);
		} else if (!strcmp(argv[i], "-r")) {
			random_in = 1;
		} else if (!strcmp(argv[i], "-s")) {
			NEXT_ARG(i);
			size = atoi(argv[i]);
		} else if (!strcmp(argv[i], "-u")) {
			offset = 1;
		} else if (!strcmp(argv[i], "-v")) {
			verbosity++;
		} else if (!strcmp(argv[i], "-w")) {
			NEXT_ARG(i);
			warmup = atoi(argv[i]);
		} else {
			fprintf(stderr, "%s: invalid argument: %s\n",
				argv[0], argv[i]);
			usage(argv[0], algo, size, warmup, l, n);
			return 1;
		}
	}
	
	sha_perf_run_test(algo, size, n, l, random_in, offset, warmup, verbosity);

	return 0;
}
