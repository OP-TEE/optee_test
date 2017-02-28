/*
 * Copyright (c) 2015-2016, Linaro Limited
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

#include <fcntl.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <tee_client_api.h>
#include <tee_client_api_extensions.h>
#include <time.h>
#include <unistd.h>

#include "ta_sdp_perf.h"
#include "crypto_common.h"

#include "include/uapi/linux/ion.h"

#define DEFAULT_ION_HEAP_TYPE	ION_HEAP_TYPE_UNMAPPED

static TEEC_Context ctx;
static TEEC_Session sess;
static int verbosity;

int sdp_basic_test(size_t len, unsigned int loop, int verbosity);

/*
 * Resources in case using secure buffers.
 *
 * SDP_BUFFER_DISABLE		buffer not allocated in secure share memory
 * SDP_BUFFER_REGISTER		secure buffer, registered to TEE at TA invoc.
 * SDP_BUFFER_PREREGISTERED	secure buffer, registered once to TEE.
 *
 * Default tested decryption from TEE: nonsec input buf, secure output buf.
 */
#define SDP_BUFFER_DISABLE		0
#define SDP_BUFFER_REGISTER		1
#define SDP_BUFFER_PREREGISTERED	2

static int input_sdp_buffer = SDP_BUFFER_DISABLE;
static int input_sdp_fd;
static int output_sdp_buffer = SDP_BUFFER_PREREGISTERED;
static int output_sdp_fd;
static int ion_heap = DEFAULT_ION_HEAP_TYPE;

static const char *buf_status_str(int buf)
{
	static const char prereg[] = "Secure memory, registered once to TEE";
	static const char reg[] = "Secure memory, registered at each TEE invoke";
	static const char unsec[] = "Non secure memory";
	static const char inval[] = "UNEXPECTED";

	switch (buf) {
	case SDP_BUFFER_PREREGISTERED:
		return prereg;
	case SDP_BUFFER_REGISTER:
		return reg;
	case SDP_BUFFER_DISABLE:
		return unsec;
	default:
		return inval;
	}
}

/*
 * in_shm and out_shm are both IN/OUT to support dynamically choosing
 * in_place == 1 or in_place == 0.
 */
static TEEC_SharedMemory in_shm = {
	.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT
};
static TEEC_SharedMemory out_shm = {
	.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT
};

static void errx(const char *msg, TEEC_Result res)
{
	fprintf(stderr, "%s: 0x%08x\n", msg, res);
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
	TEEC_UUID uuid = TA_SDP_PERF_UUID;
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

static const char *mode_str(uint32_t mode)
{
	switch (mode) {
	case TA_SDP_ECB:
		return "ECB";
	case TA_SDP_CBC:
		return "CBC";
	case TA_SDP_CTR:
		return "CTR";
	case TA_SDP_XTS:
		return "XTS";
	default:
		return "???";
	}
}

/* reuse allocate_ion_buffer() from 'sdp_basic.c' */
#define _TO_STR(x) #x
#define TO_STR(x) _TO_STR(x)

static void usage(const char *progname, int keysize, int mode,
				size_t size, int warmup,
				unsigned int l, unsigned int n)
{
	fprintf(stderr, "Usage: %s [OPTIONS]\n", progname);
	fprintf(stderr, "Testing AES performance over OP-TEE SDP buffers\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "  -h|--help Print this help and exit\n");
	fprintf(stderr, "  -v        Be verbose (use twice for greater effect)\n");
	fprintf(stderr, "  -m MODE   AES mode: ECB, CBC, CTR, XTS [%s]\n", mode_str(mode));
	fprintf(stderr, "  -d        Test AES decryption instead of encryption\n");
	fprintf(stderr, "  -k SIZE   Key size in bits: 128, 192 or 256 [%u]\n", keysize);
	fprintf(stderr, "  -s SIZE   Test buffer size in bytes [%zu]\n", size);
	fprintf(stderr, "  -l LOOP   Inner loop iterations (TA calls TEE_CipherUpdate() <x> times) [%u]\n", l);
	fprintf(stderr, "  -n LOOP   Outer test loop iterations [%u]\n", n);
	fprintf(stderr, "  -r        Get input data from /dev/urandom (otherwise use zero-filled buffer)\n");
	fprintf(stderr, "  -I...     AES input test buffer management [%s]\n", buf_status_str(input_sdp_buffer));
	fprintf(stderr, "  -O...     AES output test buffer management [%s]\n", buf_status_str(output_sdp_buffer));
	fprintf(stderr, "            -Id / -Od : allocate a non secure buffer\n");
	fprintf(stderr, "            -Ir / -Or : secure buffer, registered at each TA invokation\n");
	fprintf(stderr, "            -IR / -OR : secure buffer, registered once in TEE\n");
	fprintf(stderr, "  --ion-heap ID    set target ION heap ID [%d]\n", ion_heap);
	fprintf(stderr, "  -i|--in-place    Use same buffer for input and output (decrypt in place)\n");
	fprintf(stderr, "  -w|--warmup SEC  Warm-up time in seconds [%u]\n", warmup);
}

int allocate_ion_buffer(size_t size, int ion_heap);
static int allocate_sdp_buffer(size_t size)
{
	return allocate_ion_buffer(size, ion_heap);
}

static void register_shm(TEEC_SharedMemory *shm, int fd)
{
	TEEC_Result res = TEEC_RegisterSharedMemoryFileDescriptor(&ctx, shm, fd);

	check_res(res, "TEEC_RegisterSharedMemoryFileDescriptor");
}

/* initial test buffer allocation (eventual registering to TEEC) */
static void alloc_shm(size_t sz, int in_place)
{
	TEEC_Result res;

	if (input_sdp_buffer != SDP_BUFFER_DISABLE) {
		input_sdp_fd = allocate_sdp_buffer(sz);
		if (input_sdp_buffer == SDP_BUFFER_PREREGISTERED) {
			register_shm(&in_shm, input_sdp_fd);
			close(input_sdp_fd);
		}
	} else {
		in_shm.buffer = NULL;
		in_shm.size = sz;
		res = TEEC_AllocateSharedMemory(&ctx, &in_shm);
		check_res(res, "TEEC_AllocateSharedMemory");
	}

	if (in_place)
		return;

	if (output_sdp_buffer != SDP_BUFFER_DISABLE) {
		output_sdp_fd = allocate_sdp_buffer(sz);
		if (output_sdp_buffer == SDP_BUFFER_PREREGISTERED) {
			register_shm(&out_shm, output_sdp_fd);
			close(output_sdp_fd);
		}
	} else {
		out_shm.buffer = NULL;
		out_shm.size = sz;
		res = TEEC_AllocateSharedMemory(&ctx, &out_shm);
		check_res(res, "TEEC_AllocateSharedMemory");
	}
}

/* final test buffer release */
static void free_shm(int in_place)
{
	if (input_sdp_buffer == SDP_BUFFER_PREREGISTERED)
		close(input_sdp_buffer);
	if (input_sdp_buffer != SDP_BUFFER_REGISTER)
		TEEC_ReleaseSharedMemory(&in_shm);

	if (in_place)
		return;

	if (output_sdp_buffer == SDP_BUFFER_PREREGISTERED)
		close(output_sdp_buffer);
	if (output_sdp_buffer != SDP_BUFFER_REGISTER)
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
		verbose("read: requested %zu bytes, got %zd\n", rsize, s);
	}

	return 0;
}

static void get_current_time(struct timespec *ts)
{
	if (clock_gettime(CLOCK_MONOTONIC, ts) < 0) {
		perror("clock_gettime");
		exit(1);
	}
}

static uint64_t timespec_to_ns(struct timespec *ts)
{
	return ((uint64_t)ts->tv_sec * 1000000000) + ts->tv_nsec;
}

static uint64_t timespec_diff_ns(struct timespec *start, struct timespec *end)
{
	return timespec_to_ns(end) - timespec_to_ns(start);
}

static void run_feed_input(void *in, size_t size, int random_in)
{
	if (random_in && (input_sdp_buffer != SDP_BUFFER_DISABLE)) {
		char *data = mmap(NULL, size, PROT_WRITE, MAP_SHARED,
						input_sdp_fd, 0);

		if (data != MAP_FAILED) {
			read_random(data, size);
			munmap(data, size);
		}
	} else if (random_in)
		read_random(in, size);
}

static void prepare_key(int decrypt, int keysize, int mode)
{
	TEEC_Result res;
	uint32_t ret_origin;
	TEEC_Operation op;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_VALUE_INPUT,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].value.a = decrypt;
	op.params[0].value.b = keysize;
	op.params[1].value.a = mode;
	res = TEEC_InvokeCommand(&sess, TA_SDP_PERF_CMD_PREPARE_KEY, &op,
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

/* Encryption test: buffer of tsize byte. Run test n times. */
static void sdp_perf_run_test(int mode, int keysize, int decrypt, size_t size,
				unsigned int n, unsigned int l, int random_in,
				int in_place, int warmup, int verbosity_level)
{
	struct statistics stats;
	struct timespec ts;
	TEEC_Operation op;
	int n0 = n;

	verbosity = verbosity_level;

	if (clock_getres(CLOCK_MONOTONIC, &ts) < 0) {
		perror("clock_getres");
		return;
	}
	vverbose("Clock resolution is %lu ns\n",
					ts.tv_sec * 1000000000 + ts.tv_nsec);
	vverbose("input test buffer:  %s\n", buf_status_str(input_sdp_buffer));
	vverbose("output test buffer: %s\n", buf_status_str(output_sdp_buffer));

	open_ta();
	prepare_key(decrypt, keysize, mode);

	memset(&stats, 0, sizeof(stats));

	alloc_shm(size, in_place);

	if (!random_in && (input_sdp_buffer != SDP_BUFFER_DISABLE)) {
		char *data = mmap(NULL, size, PROT_WRITE, MAP_SHARED,
						input_sdp_fd, 0);

		if (data == MAP_FAILED) {
			printf("Warning: cannot mmap SDP input buffer\n");
		} else {
			memset(in_shm.buffer, 0, size);
			munmap(data, size);
		}
	} else if (!random_in)
		memset(in_shm.buffer, 0, size);

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INPUT,
					 TEEC_MEMREF_PARTIAL_OUTPUT,
					 TEEC_VALUE_INPUT, TEEC_NONE);
	op.params[0].memref.parent = &in_shm;
	op.params[0].memref.size = size;
	op.params[1].memref.parent = in_place ? &in_shm : &out_shm;
	op.params[1].memref.size = size;
	op.params[2].value.a = l;

	verbose("Starting test: %s, %scrypt, keysize=%u bits, size=%zu bytes, ",
		mode_str(mode), (decrypt ? "de" : "en"), keysize, size);
	verbose("random=%s, ", yesno(random_in));
	verbose("in place=%s, ", yesno(in_place));
	verbose("inner loops=%u, loops=%u, warm-up=%u s\n", l, n, warmup);

	if (warmup)
		do_warmup(warmup);

	while (n-- > 0) {
		TEEC_Result res;
		uint32_t ret_origin;
		struct timespec t0, t1;

		run_feed_input(in_shm.buffer, size, random_in);

		get_current_time(&t0);

		if (input_sdp_buffer == SDP_BUFFER_REGISTER)
			register_shm(&in_shm, input_sdp_fd);
		if (output_sdp_buffer == SDP_BUFFER_REGISTER)
			register_shm(&out_shm, output_sdp_fd);

		res = TEEC_InvokeCommand(&sess, TA_SDP_PERF_CMD_PROCESS,
					 &op, &ret_origin);
		check_res(res, "TEEC_InvokeCommand");

		if (input_sdp_buffer == SDP_BUFFER_REGISTER)
			TEEC_ReleaseSharedMemory(&in_shm);
		if (output_sdp_buffer == SDP_BUFFER_REGISTER)
			TEEC_ReleaseSharedMemory(&out_shm);

		get_current_time(&t1);

		update_stats(&stats, timespec_diff_ns(&t0, &t1));
		if (n % (n0/10) == 0)
			vverbose("#");
	}
	vverbose("\n");
	printf("min=%gus max=%gus mean=%gus stddev=%gus (%gMiB/s)\n",
	       stats.min/1000, stats.max/1000, stats.m/1000,
	       stddev(&stats)/1000, mb_per_sec(size, stats.m));

	free_shm(in_place);
}

#define NEXT_ARG(i) \
	do { \
		if (++i == argc) { \
			fprintf(stderr, "%s: %s: missing argument\n", \
				argv[0], argv[i-1]); \
			return 1; \
		} \
	} while (0);

int sdp_perf_runner_cmd_parser(int argc, char *argv[])
{
	int i;

	/*
	* Command line parameters
	*/

	size_t size = 1024;	/* Buffer size (-s) */
	unsigned int n = CRYPTO_DEF_COUNT; /*Number of measurements (-n)*/
	unsigned int l = CRYPTO_DEF_LOOPS; /* Inner loops (-l) */
	int verbosity_level = CRYPTO_DEF_VERBOSITY;	/* Verbosity (-v) */
	int decrypt = 0;		/* Encrypt by default, -d to decrypt */
	int keysize = AES_128;	/* AES key size (-k) */
	int mode = TA_AES_ECB;	/* AES mode (-m) */
	/* Get input data from /dev/urandom (-r) */
	int random_in = CRYPTO_USE_RANDOM;
	/* Use same buffer for in and out (-i) */
	int in_place = AES_PERF_INPLACE;
	int warmup = CRYPTO_DEF_WARMUP;	/* Start with a 2-second busy loop (-w) */

	/* Parse command line */
	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
			usage(argv[0], keysize, mode, size, warmup, l, n);
			return 0;
		}
	}
	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-d")) {
			decrypt = 1;
		} else if (!strcmp(argv[i], "--in-place") ||
			   !strcmp(argv[i], "-i")) {
			in_place = 1;
		} else if (!strcmp(argv[i], "-k")) {
			NEXT_ARG(i);
			keysize = atoi(argv[i]);
			if (keysize != AES_128 && keysize != AES_192 &&
				keysize != AES_256) {
				fprintf(stderr, "%s: invalid key size\n",
					argv[0]);
				usage(argv[0], keysize, mode, size, warmup, l, n);
				return 1;
			}
		} else if (!strcmp(argv[i], "-l")) {
			NEXT_ARG(i);
			l = atoi(argv[i]);
		} else if (!strcmp(argv[i], "-m")) {
			NEXT_ARG(i);
			if (!strcasecmp(argv[i], "ECB"))
				mode = TA_SDP_ECB;
			else if (!strcasecmp(argv[i], "CBC"))
				mode = TA_SDP_CBC;
			else if (!strcasecmp(argv[i], "CTR"))
				mode = TA_SDP_CTR;
			else if (!strcasecmp(argv[i], "XTS"))
				mode = TA_SDP_XTS;
			else {
				fprintf(stderr, "%s, invalid mode\n",
					argv[0]);
				usage(argv[0], keysize, mode, size, warmup, l, n);
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
		} else if (!strcmp(argv[i], "-IR")) {
			input_sdp_buffer = SDP_BUFFER_PREREGISTERED;
		} else if (!strcmp(argv[i], "-OR")) {
			output_sdp_buffer = SDP_BUFFER_PREREGISTERED;
		} else if (!strcmp(argv[i], "-Ir")) {
			input_sdp_buffer = SDP_BUFFER_REGISTER;
		} else if (!strcmp(argv[i], "-Or")) {
			output_sdp_buffer = SDP_BUFFER_REGISTER;
		} else if (!strcmp(argv[i], "-Id")) {
			input_sdp_buffer = SDP_BUFFER_DISABLE;
		} else if (!strcmp(argv[i], "-Od")) {
			output_sdp_buffer = SDP_BUFFER_DISABLE;
		} else if (!strcmp(argv[i], "-v")) {
			verbosity_level++;
		} else if (!strcmp(argv[i], "--ion-heap")) {
			NEXT_ARG(i);
			ion_heap = atoi(argv[i]);
		} else if (!strcmp(argv[i], "--warmup") ||
			   !strcmp(argv[i], "-w")) {
			NEXT_ARG(i);
			warmup = atoi(argv[i]);
		} else {
			fprintf(stderr, "%s: invalid argument: %s\n",
				argv[0], argv[i]);
			usage(argv[0], keysize, mode, size, warmup, l, n);
			return 1;
		}
	}
	if (size & (16 - 1)) {
		fprintf(stderr, "invalid buffer size argument, must be a multiple of 16\n\n");
			usage(argv[0], keysize, mode, size, warmup, l, n);
			return 1;
	}

	verbosity = verbosity_level;

	sdp_perf_run_test(mode, keysize, decrypt, size, n, l, random_in,
					in_place, warmup, verbosity_level);

	return 0;
}
