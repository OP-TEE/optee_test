// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2024, Huawei Technologies Co., Ltd
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
#include <utee_defines.h>

#include "crypto_common.h"
#include "xtest_helpers.h"

static TEEC_Context ctx;
static TEEC_Session sess;

static TEEC_SharedMemory in_shm = {
	.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT
};
static TEEC_SharedMemory out_shm = {
	.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT
};
static TEEC_SharedMemory hash_shm = {
	.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT
};

static void errx(const char *msg, TEEC_Result res, uint32_t *orig)
{
	fprintf(stderr, "%s: 0x%08x", msg, res);
	if (orig)
		fprintf(stderr, " (orig=%d)", (int)*orig);
	fprintf(stderr, "\n");
	exit(1);
}

static void check_res(TEEC_Result res, const char *errmsg, uint32_t *orig)
{
	if (res != TEEC_SUCCESS)
		errx(errmsg, res, orig);
}

#define CHECK(res, name, action) do {			\
		if ((res) != 0) {			\
			printf(name ": 0x%08x", (res));	\
			action				\
		}					\
	} while(0)

static void open_ta(void)
{
	TEEC_UUID uuid = TA_CRYPTO_PERF_UUID;
	TEEC_Result res = TEEC_ERROR_GENERIC;
	uint32_t err_origin = 0;

	res = TEEC_InitializeContext(NULL, &ctx);
	check_res(res, "TEEC_InitializeContext", NULL);

	res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL,
			       NULL, &err_origin);
	check_res(res, "TEEC_OpenSession", &err_origin);
}

static void close_ta(void)
{
	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);
}

/*
 * Statistics
 *
 * We want to compute min, max, mean and standard deviation of processing time
 */

struct statistics {
	int n;
	double m;
	double m2;
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
	s->m += delta / s->n;
	s->m2 += delta * (x - s->m);
	if (!s->initialized) {
		s->min = x;
		s->max = x;
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

	return sqrt(s->m2 / s->n);
}

static void usage(const char *progname, uint32_t width_bits, uint32_t main_algo,
		  uint32_t mode, uint32_t salt_len, uint32_t size,
		  uint32_t crypto_algo, int warmup, uint32_t l, uint32_t n)
{
	fprintf(stderr, "Usage: %s [-h]\n", progname);
	fprintf(stderr, "Usage: %s [-a] [-k SIZE]", progname);
	fprintf(stderr, " [-a algo] [-n LOOP] [-r|--no-inited] [-d WIDTH_BITS]");
	fprintf(stderr, " [-k SIZE] [-a crypto_algo] [-s salt_len] [-v [-v]] [-w SEC]");
	fprintf(stderr, "\n");
	fprintf(stderr, "Asymmetric performance testing tool for OP-TEE\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "  -h|--help        Print this help and exit\n");
	fprintf(stderr, "  -a ALGO          Asymmetric algorithm [DH]\n");
	fprintf(stderr, "                   DH, RSA_GENKEYPAIR, RSA_NOPAD_ENCRYPT, RSA_NOPAD_DECRYPT\n");
	fprintf(stderr, "                   RSAES_PKCS1_V1_5_ENCRYPT, RSAES_PKCS1_V1_5_DECRYPT\n");
	fprintf(stderr, "                   RSAES_PKCS1_OAEP_SHA1_ENCRYPT, RSAES_PKCS1_OAEP_SHA1_DECRYPT\n");
	fprintf(stderr, "                   RSAES_PKCS1_OAEP_SHA224_ENCRYPT, RSAES_PKCS1_OAEP_SHA224_DECRYPT\n");
	fprintf(stderr, "                   RSAES_PKCS1_OAEP_SHA256_ENCRYPT, RSAES_PKCS1_OAEP_SHA256_DECRYPT\n");
	fprintf(stderr, "                   RSAES_PKCS1_OAEP_SHA384_ENCRYPT, RSAES_PKCS1_OAEP_SHA384_DECRYPT\n");
	fprintf(stderr, "                   RSAES_PKCS1_OAEP_SHA512_ENCRYPT, RSAES_PKCS1_OAEP_SHA512_DECRYPT\n");
	fprintf(stderr, "                   RSASSA_PKCS1_V1_5_SHA1_SIGN, RSASSA_PKCS1_V1_5_SHA1_VERIFY\n");
	fprintf(stderr, "                   RSASSA_PKCS1_V1_5_SHA224_SIGN, RSASSA_PKCS1_V1_5_SHA224_VERIFY\n");
	fprintf(stderr, "                   RSASSA_PKCS1_V1_5_SHA256_SIGN, RSASSA_PKCS1_V1_5_SHA256_VERIFY\n");
	fprintf(stderr, "                   RSASSA_PKCS1_V1_5_SHA384_SIGN, RSASSA_PKCS1_V1_5_SHA384_VERIFY\n");
	fprintf(stderr, "                   RSASSA_PKCS1_V1_5_SHA512_SIGN, RSASSA_PKCS1_V1_5_SHA512_VERIFY\n");
	fprintf(stderr, "                   RSASSA_PKCS1_PSS_MGF1_SHA1_SIGN, RSASSA_PKCS1_PSS_MGF1_SHA1_VERIFY\n");
	fprintf(stderr, "                   RSASSA_PKCS1_PSS_MGF1_SHA224_SIGN, RSASSA_PKCS1_PSS_MGF1_SHA224_VERIFY\n");
	fprintf(stderr, "                   RSASSA_PKCS1_PSS_MGF1_SHA256_SIGN, RSASSA_PKCS1_PSS_MGF1_SHA256_VERIFY\n");
	fprintf(stderr, "                   RSASSA_PKCS1_PSS_MGF1_SHA384_SIGN, RSASSA_PKCS1_PSS_MGF1_SHA384_VERIFY\n");
	fprintf(stderr, "                   RSASSA_PKCS1_PSS_MGF1_SHA512_SIGN, RSASSA_PKCS1_PSS_MGF1_SHA512_VERIFY\n");
	fprintf(stderr, "                   ECDSA_SIGN, ECDSA_VERIFY, ECDH, X25519, SM2_GENKEYPAIR, SM2_VERIFY\n");
	fprintf(stderr, "                   SM2_ENCRYPT, SM2_DECRYPT\n");
	fprintf(stderr, "  -l LOOP          Inner loop iterations [%u]\n", l);
	fprintf(stderr, "  -n LOOP          Outer test loop iterations [%u]\n", n);
	fprintf(stderr, "  -r|--random      Get input data from /dev/urandom (default: all zeros)\n");
	fprintf(stderr, "  -k SIZE          Plaintext byte length [%u]\n", size);
	fprintf(stderr, "  -d WIDTH_BITS    Private key size in bits [%u]\n", width_bits);
	fprintf(stderr, "                   ECC: 192, 224, 256, 384 or 521, DH: <= 2048, RSA: <= 4096\n");
	fprintf(stderr, "  -s SALT_LEN      Salt length in bytes (only when ALGO is one of RSA SSA_PKCS1_PSS_*)[%u]\n", salt_len);
	fprintf(stderr, "  -w|--warmup SEC  Warm-up time in seconds: execute a busy loop before [%d]\n", warmup);
	fprintf(stderr, "  -v               Be verbose (use twice for greater effect)\n");
}

static void allocate_shm(TEEC_SharedMemory *shm, size_t sz)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;

	shm->buffer = NULL;
	shm->size = sz;
	res = TEEC_AllocateSharedMemory(&ctx, shm);
	check_res(res, "TEEC_AllocateSharedMemory()", NULL);
}

/* initial test buffer allocation (eventual registering to TEEC) */
static void alloc_buffers(size_t sz)
{
	allocate_shm(&in_shm, sz);
	allocate_shm(&out_shm, TEE_MAX_OUT_SIZE);
	allocate_shm(&hash_shm, TEE_MAX_HASH_SIZE);
}

static void free_shm(void)
{
	TEEC_ReleaseSharedMemory(&in_shm);
	TEEC_ReleaseSharedMemory(&out_shm);
	TEEC_ReleaseSharedMemory(&hash_shm);
}

static ssize_t read_random(void *in, size_t rsize)
{
	static int rnd;
	ssize_t s = 0;

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
	if ((size_t)s != rsize)
		printf("read: requested %zu bytes, got %zd\n", rsize, s);

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

static void prepare_obj(int width_bits, uint32_t main_algo, int mode)
{
	uint32_t cmd = TA_CRYPTO_PERF_CMD_ASYM_PREPARE_OBJ;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	TEEC_Result res = TEEC_ERROR_GENERIC;
	uint32_t ret_origin = 0;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_VALUE_INPUT,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].value.a = main_algo;
	op.params[0].value.b = width_bits;
	op.params[1].value.a = mode;

	res = TEEC_InvokeCommand(&sess, cmd, &op, &ret_origin);
	check_res(res, "TEEC_InvokeCommand()", &ret_origin);
}

static void prepare_hash(int size, uint32_t main_algo)
{
	uint32_t cmd = TA_CRYPTO_PERF_CMD_ASYM_PREPARE_HASH;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	TEEC_Result res = TEEC_ERROR_GENERIC;
	uint32_t ret_origin = 0;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_PARTIAL_INPUT,
					 TEEC_MEMREF_PARTIAL_INOUT, TEEC_NONE);
	op.params[0].value.a = main_algo;
	op.params[1].memref.parent = &in_shm;
	op.params[1].memref.size = size;
	op.params[2].memref.parent = &hash_shm;
	op.params[2].memref.size = hash_shm.size;

	res = TEEC_InvokeCommand(&sess, cmd, &op, &ret_origin);
	check_res(res, "TEEC_InvokeCommand()", &ret_origin);
	hash_shm.size = op.params[2].memref.size;
}

static void prepare_attrs(uint8_t *buf, size_t blen)
{
	uint32_t cmd = TA_CRYPTO_PERF_CMD_ASYM_PREPARE_ATTRS;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	TEEC_Result res = TEEC_ERROR_GENERIC;
	uint32_t ret_origin = 0;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT,
					 TEEC_NONE, TEEC_NONE, TEEC_NONE);

	op.params[0].tmpref.buffer = buf;
	op.params[0].tmpref.size = blen;

	res = TEEC_InvokeCommand(&sess, cmd, &op, &ret_origin);
	check_res(res, "TEEC_InvokeCommand()", &ret_origin);
}

static void free_attrs(void)
{
	uint32_t cmd = TA_CRYPTO_PERF_CMD_ASYM_FREE_ATTRS;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	TEEC_Result res = TEEC_ERROR_GENERIC;
	uint32_t ret_origin = 0;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(&sess, cmd, &op, &ret_origin);
	check_res(res, "TEEC_InvokeCommand()", &ret_origin);
}

static void prepare_keypair(int width_bits, uint8_t *buf, size_t blen,
			    uint32_t mode, uint32_t algo, uint32_t main_algo)
{
	uint32_t cmd = TA_CRYPTO_PERF_CMD_ASYM_PREPARE_KEYPAIR;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	TEEC_Result res = TEEC_ERROR_GENERIC;
	uint32_t ret_origin = 0;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_VALUE_INPUT,
					 TEEC_MEMREF_TEMP_INPUT, TEEC_NONE);
	op.params[0].value.a = width_bits;
	op.params[0].value.b = mode;
	op.params[1].value.a = main_algo;
	op.params[1].value.b = algo;
	op.params[2].tmpref.buffer = buf;
	op.params[2].tmpref.size = blen;

	res = TEEC_InvokeCommand(&sess, cmd, &op, &ret_origin);
	check_res(res, "TEEC_InvokeCommand()", &ret_origin);
}

static void prepare_enc_sign(uint32_t size, uint32_t mode,
			     uint8_t *buf, uint32_t blen)
{
	uint32_t cmd = TA_CRYPTO_PERF_CMD_ASYM_PREPARE_ENC_SIGN;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	TEEC_Result res = TEEC_ERROR_GENERIC;
	uint32_t ret_origin = 0;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INPUT,
					 TEEC_MEMREF_PARTIAL_OUTPUT,
					 TEEC_VALUE_INPUT,
					 TEEC_MEMREF_TEMP_INPUT);
	op.params[0].memref.parent = (mode == MODE_DECRYPT) ?
				     &in_shm : &hash_shm;
	op.params[0].memref.size = (mode == MODE_DECRYPT) ?
				   size : hash_shm.size;
	op.params[1].memref.parent = &out_shm;
	op.params[1].memref.size = out_shm.size;
	op.params[2].value.a = mode;
	op.params[3].tmpref.buffer = buf;
	op.params[3].tmpref.size = blen;

	res = TEEC_InvokeCommand(&sess, cmd, &op, &ret_origin);
	check_res(res, "TEEC_InvokeCommand()", &ret_origin);
	out_shm.size = op.params[1].memref.size;
}

static void do_warmup(int warmup)
{
	struct timespec t0 = { };
	struct timespec t = { };
	int i = 0;

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
	return (1000000000 / usec) * ((double)size / (1024 * 1024));
}

static uint32_t get_curve_id(uint32_t width_bits)
{
	switch (width_bits) {
	case ECC_CURVE_192:
		return TEE_ECC_CURVE_NIST_P192;
	case ECC_CURVE_224:
		return TEE_ECC_CURVE_NIST_P224;
	case ECC_CURVE_256:
		return TEE_ECC_CURVE_NIST_P256;
	case ECC_CURVE_384:
		return TEE_ECC_CURVE_NIST_P384;
	case ECC_CURVE_521:
		return TEE_ECC_CURVE_NIST_P521;
	default:
		fprintf(stderr, "ECC curve is not supported!\n");
	}

	return TEE_CRYPTO_ELEMENT_NONE;
}

static int asym_perf_run_test(int mode, size_t size, uint32_t n,
			      uint32_t l, int is_random, uint32_t warmup,
			      uint32_t verbosity, uint32_t width_bits,
			      uint32_t main_algo, uint32_t salt_len,
			      uint32_t algo)
{
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t cmd = TA_CRYPTO_PERF_CMD_ASYM_PROCESS;
	TEEC_Result res = TEEC_ERROR_GENERIC;
	uint8_t keygen_dh_p[DH_MAX_SIZE] = { };
	uint8_t keygen_dh_g[DH_G_SIZE] = { };
	TEE_Attribute params[4] = { };
	size_t param_count = 0;
	uint32_t curve_id = TEE_CRYPTO_ELEMENT_NONE;
	struct statistics stats = { };
	struct timespec ts = { };
	struct timespec t0 = { };
	struct timespec t1 = { };
	uint32_t ret_origin = 0;
	uint8_t *buf = NULL;
	size_t blen = 0;
	double sd = 0;
	int n0 = n;

	if (clock_getres(CLOCK_MONOTONIC, &ts) < 0) {
		perror("clock_getres");
		return -1;
	}

	verbose("random=%s, ", yesno(is_random == CRYPTO_USE_RANDOM));
	verbose("inner loops=%u, loops=%u, warm-up=%u s\n", l, n, warmup);
	vverbose("Clock resolution is %jd ns\n", (intmax_t)ts.tv_sec *
		 1000000000 + ts.tv_nsec);

	open_ta();

	alloc_buffers(size);
	if (is_random == CRYPTO_USE_ZEROS)
		memset((uint8_t *)in_shm.buffer, 0, size);
	else
		read_random(in_shm.buffer, size);
	if (mode == MODE_DECRYPT && main_algo == ALGO_RSA) {
		/* Ensure N > M */
		((unsigned char *)(in_shm.buffer))[0] = 0x00;
	}

	switch (main_algo) {
	case ALGO_DH:
		read_random(keygen_dh_p, BITS_TO_BYTES(width_bits));
		read_random(keygen_dh_g, DH_G_SIZE);
		/* make sure the p is full width */
		keygen_dh_p[0] |= 0x2;
		/* make sure keygen_dh_p is odd */
		keygen_dh_p[BITS_TO_BYTES(width_bits) - 1] |= 0x1;

		xtest_add_attr(&param_count, params, TEE_ATTR_DH_PRIME,
			       keygen_dh_p, BITS_TO_BYTES(width_bits));
		xtest_add_attr(&param_count, params, TEE_ATTR_DH_BASE,
			       keygen_dh_g, DH_G_SIZE);
		break;
	case ALGO_ECDSA:
	case ALGO_ECDH:
		curve_id = get_curve_id(width_bits);
		if (curve_id == TEE_CRYPTO_ELEMENT_NONE)
			goto out;
		xtest_add_attr_value(&param_count, params, TEE_ATTR_ECC_CURVE,
				     curve_id, 0);
		break;
	case ALGO_X25519:
		width_bits = WIDTH_BITS_25519;
		break;
	default:
		break;
	}

	prepare_obj(width_bits, main_algo, mode);

	res = pack_attrs(params, param_count, &buf, &blen);
	CHECK(res, "pack_attrs", goto out;);

	if (mode == MODE_GENKEYPAIR) {
		if (blen)
			prepare_attrs(buf, blen);

		cmd = TA_CRYPTO_PERF_CMD_ASYM_PROCESS_GEN_KEYPAIR;
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
						 TEEC_NONE, TEEC_NONE,
						 TEEC_NONE);
		op.params[0].value.a = width_bits;
		op.params[0].value.b = l;
	} else {
		prepare_keypair(width_bits, buf, blen, mode, algo, main_algo);

		if (mode == MODE_SIGN || mode == MODE_VERIFY)
			prepare_hash(size, main_algo);

		if (main_algo == ALGO_RSA && algo >= RSASSA_PKCS1_PSS_MGF1_SHA1) {
			params[0].attributeID = TEE_ATTR_RSA_PSS_SALT_LENGTH;
			params[0].content.value.a = salt_len;
			params[0].content.value.b = 0;
			param_count = 1;
			res = pack_attrs(params, param_count, &buf, &blen);
			CHECK(res, "pack_attrs", goto out;);
		}

		if (blen)
			prepare_attrs(buf, blen);

		cmd = TA_CRYPTO_PERF_CMD_ASYM_PROCESS;
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
						 TEEC_MEMREF_PARTIAL_INPUT,
						 TEEC_MEMREF_PARTIAL_OUTPUT,
						 TEEC_NONE);

		op.params[0].value.a = l;
		op.params[0].value.b = mode;

		switch (mode) {
		case MODE_ENCRYPT:
			op.params[1].memref.parent = &in_shm;
			op.params[1].memref.size = size;
			op.params[2].memref.parent = &out_shm;
			op.params[2].memref.size = out_shm.size;
			break;
		case MODE_SIGN:
			op.params[1].memref.parent = &hash_shm;
			op.params[1].memref.size = hash_shm.size;
			op.params[2].memref.parent = &out_shm;
			op.params[2].memref.size = out_shm.size;
			break;
		case MODE_DECRYPT:
			prepare_enc_sign(size, mode, buf, blen);
			op.params[1].memref.parent = &out_shm;
			op.params[1].memref.size = out_shm.size;
			op.params[2].memref.parent = &in_shm;
			op.params[2].memref.size = size;
			break;
		case MODE_VERIFY:
			prepare_enc_sign(size, mode, buf, blen);
			op.params[1].memref.parent = &hash_shm;
			op.params[1].memref.size = hash_shm.size;
			op.params[2].memref.parent = &out_shm;
			op.params[2].memref.size = out_shm.size;
			break;
		default:
			fprintf(stderr, "Unexpected mode value\n");
			goto out;
		}
	}

	if (warmup)
		do_warmup(warmup);

	while (n-- > 0) {
		if (mode == MODE_ENCRYPT && main_algo == ALGO_RSA) {
			/* Ensure N > M */
			((unsigned char *)(in_shm.buffer))[0] = 0x00;
			/*
			 * Avoid the problem that the last encryption result is
			 * shorter than the plaintext.
			 */
			op.params[3].memref.size = out_shm.size;
		}

		get_current_time(&t0);

		res = TEEC_InvokeCommand(&sess, cmd, &op, &ret_origin);

		check_res(res, "TEEC_InvokeCommand()", &ret_origin);

		get_current_time(&t1);

		update_stats(&stats, timespec_diff_ns(&t0, &t1));
		if (n % (n0 / 10) == 0)
			vverbose("#");
	}

	vverbose("\n");
	sd = stddev(&stats);
	printf("%.3f ms/op\n", stats.m / 1000000 / l);
	printf("min=%gus max=%gus mean=%gus stddev=%gus (cv %g%%) (%gMiB/s)\n",
		stats.min / 1000, stats.max / 1000, stats.m / 1000,
		sd / 1000, 100 * sd / stats.m, mb_per_sec(size, stats.m));
	verbose("2-sigma interval: %g..%gus (%g..%gMiB/s)\n",
		(stats.m - 2 * sd) / 1000, (stats.m + 2 * sd) / 1000,
		mb_per_sec(size, stats.m + 2 * sd),
		mb_per_sec(size, stats.m - 2 * sd));

out:
	free_attrs();
	free(buf);
	free_shm();
	close_ta();
	return res;
}

#define NEXT_ARG(i) \
	do { \
		if (++i == argc) { \
			fprintf(stderr, "%s: %s: missing argument\n", \
				argv[0], argv[i - 1]); \
			return 1; \
		} \
	} while (0)

#define USAGE() usage(argv[0], width_bits, main_algo, mode, \
		      salt_len, size, crypto_algo, warmup, l, n)

static int get_rsa_hash_len(uint32_t algo)
{
	switch (algo) {
	case RSAES_PKCS1_OAEP_SHA1:
	case RSASSA_PKCS1_V1_5_SHA1:
	case RSASSA_PKCS1_PSS_MGF1_SHA1:
		return SHA1_LEN;
	case RSAES_PKCS1_OAEP_SHA224:
	case RSASSA_PKCS1_V1_5_SHA224:
	case RSASSA_PKCS1_PSS_MGF1_SHA224:
		return SHA224_LEN;
	case RSAES_PKCS1_OAEP_SHA256:
	case RSASSA_PKCS1_V1_5_SHA256:
	case RSASSA_PKCS1_PSS_MGF1_SHA256:
		return SHA256_LEN;
	case RSAES_PKCS1_OAEP_SHA384:
	case RSASSA_PKCS1_V1_5_SHA384:
	case RSASSA_PKCS1_PSS_MGF1_SHA384:
		return SHA384_LEN;
	case RSAES_PKCS1_OAEP_SHA512:
	case RSASSA_PKCS1_V1_5_SHA512:
	case RSASSA_PKCS1_PSS_MGF1_SHA512:
		return SHA512_LEN;
	default:
		fprintf(stderr, "The algo[%u] is not valid!\n", algo);
	}

	return -1;
}

static int check_rsa_cipher_params(uint32_t crypto_algo, int width_bits, int size)
{
	int width_bytes = BITS_TO_BYTES(width_bits);
	int hash_len = 0;

	if (crypto_algo == RSA_NOPAD) {
		if (size > width_bytes) {
			fprintf(stderr, "The size or algo is not valid!\n");
			return -1;
		}
	} else if (crypto_algo == RSAES_PKCS1_V1_5) {
		if ((size + PKCS_V1_5_MIN) > width_bytes) {
			fprintf(stderr, "The size or algo is not valid!\n");
			return -1;
		}
	} else if (crypto_algo > RSAES_PKCS1_V1_5) {
		hash_len = get_rsa_hash_len(crypto_algo);
		if (hash_len == -1)
			return -1;

		if (OAEP_HASH_LEN(hash_len) >= (width_bytes - OAEP_OTHER_LEN)) {
			fprintf(stderr, "The width_bits or algo is not valid!\n");
			return -1;
		} else if (size > (width_bytes - OAEP_HASH_LEN(hash_len) -
			   OAEP_OTHER_LEN)) {
			fprintf(stderr, "The size or algo is not valid!\n");
			return -1;
		}
	} else {
		return -1;
	}

	return 0;
}

static int check_rsa_hash_params(uint32_t crypto_algo, int width_bits, int size,
				 int salt_len)
{
	int width_bytes = BITS_TO_BYTES(width_bits);
	int salt_temp = 0;
	int hash_len = get_rsa_hash_len(crypto_algo);

	if (hash_len == -1)
		return -1;

	switch (crypto_algo) {
	case RSASSA_PKCS1_V1_5_SHA1:
		if (width_bytes < hash_len + DERCODE_SHA1_LEN + PKCS_V1_5_MIN) {
			fprintf(stderr, "The size or algo is not valid!\n");
			return -1;
		}
		return 0;
	case RSASSA_PKCS1_V1_5_SHA224:
	case RSASSA_PKCS1_V1_5_SHA256:
	case RSASSA_PKCS1_V1_5_SHA384:
	case RSASSA_PKCS1_V1_5_SHA512:
		if (width_bytes < hash_len + DERCODE_SHA_LEN + PKCS_V1_5_MIN) {
			fprintf(stderr, "The size or algo is not valid!\n");
			return -1;
		}
		return 0;
	case RSASSA_PKCS1_PSS_MGF1_SHA1:
	case RSASSA_PKCS1_PSS_MGF1_SHA224:
	case RSASSA_PKCS1_PSS_MGF1_SHA256:
	case RSASSA_PKCS1_PSS_MGF1_SHA384:
	case RSASSA_PKCS1_PSS_MGF1_SHA512:
		salt_temp = (salt_len == 0 ? hash_len : salt_len);
		if (salt_temp > width_bytes ||
		    width_bytes < hash_len + salt_temp + PSS_OTHER_LEN) {
			fprintf(stderr, "The size or algo is not valid!\n");
			return -1;
		}
		return 0;
	default:
		return -1;
	}
}

int asym_perf_runner_cmd_parser(int argc, char *argv[])
{
	int verbosity = CRYPTO_DEF_VERBOSITY;
	int is_random = CRYPTO_USE_ZEROS;
	unsigned int n = CRYPTO_DEF_COUNT / 10;
	unsigned int l = CRYPTO_DEF_LOOPS;
	int warmup = CRYPTO_DEF_WARMUP;
	int mode = MODE_GENKEYPAIR;
	int width_bits = 2048;
	int main_algo = ALGO_DH;
	int crypto_algo = -1;
	int size = 256;
	int salt_len = 0;
	int i = 0;

	/* Parse command line */
	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
			USAGE();
			return 0;
		}
	}

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-a")) {
			NEXT_ARG(i);
			if (!strcasecmp(argv[i], "DH")) {
				main_algo = ALGO_DH;
				mode = MODE_GENKEYPAIR;
			} else if (!strcasecmp(argv[i], "RSA_GENKEYPAIR")) {
				main_algo = ALGO_RSA;
				mode = MODE_GENKEYPAIR;
			} else if (!strcasecmp(argv[i], "RSA_NOPAD_ENCRYPT")) {
				main_algo = ALGO_RSA;
				mode = MODE_ENCRYPT;
				crypto_algo = RSA_NOPAD;
			} else if (!strcasecmp(argv[i], "RSA_NOPAD_DECRYPT")) {
				main_algo = ALGO_RSA;
				mode = MODE_DECRYPT;
				crypto_algo = RSA_NOPAD;
			} else if (!strcasecmp(argv[i], "RSAES_PKCS1_V1_5_ENCRYPT")) {
				main_algo = ALGO_RSA;
				mode = MODE_ENCRYPT;
				crypto_algo = RSAES_PKCS1_V1_5;
				size -= PKCS_V1_5_MIN;
			} else if (!strcasecmp(argv[i], "RSAES_PKCS1_V1_5_DECRYPT")) {
				main_algo = ALGO_RSA;
				mode = MODE_DECRYPT;
				crypto_algo = RSAES_PKCS1_V1_5;
				size -= PKCS_V1_5_MIN;
			} else if (!strcasecmp(argv[i], "RSAES_PKCS1_OAEP_SHA1_ENCRYPT")) {
				main_algo = ALGO_RSA;
				mode = MODE_ENCRYPT;
				crypto_algo = RSAES_PKCS1_OAEP_SHA1;
				size -= OAEP_HASH_LEN(SHA1_LEN) + OAEP_OTHER_LEN;
			} else if (!strcasecmp(argv[i], "RSAES_PKCS1_OAEP_SHA1_DECRYPT")) {
				main_algo = ALGO_RSA;
				mode = MODE_DECRYPT;
				crypto_algo = RSAES_PKCS1_OAEP_SHA1;
				size -= OAEP_HASH_LEN(SHA1_LEN) + OAEP_OTHER_LEN;
			} else if (!strcasecmp(argv[i], "RSAES_PKCS1_OAEP_SHA224_ENCRYPT")) {
				main_algo = ALGO_RSA;
				mode = MODE_ENCRYPT;
				crypto_algo = RSAES_PKCS1_OAEP_SHA224;
				size -= OAEP_HASH_LEN(SHA224_LEN) + OAEP_OTHER_LEN;
			} else if (!strcasecmp(argv[i], "RSAES_PKCS1_OAEP_SHA224_DECRYPT")) {
				main_algo = ALGO_RSA;
				mode = MODE_DECRYPT;
				crypto_algo = RSAES_PKCS1_OAEP_SHA224;
				size -= OAEP_HASH_LEN(SHA224_LEN) + OAEP_OTHER_LEN;
			} else if (!strcasecmp(argv[i], "RSAES_PKCS1_OAEP_SHA256_ENCRYPT")) {
				main_algo = ALGO_RSA;
				mode = MODE_ENCRYPT;
				crypto_algo = RSAES_PKCS1_OAEP_SHA256;
				size -= OAEP_HASH_LEN(SHA256_LEN) + OAEP_OTHER_LEN;
			} else if (!strcasecmp(argv[i], "RSAES_PKCS1_OAEP_SHA256_DECRYPT")) {
				main_algo = ALGO_RSA;
				mode = MODE_DECRYPT;
				crypto_algo = RSAES_PKCS1_OAEP_SHA256;
				size -= OAEP_HASH_LEN(SHA256_LEN) + OAEP_OTHER_LEN;
			} else if (!strcasecmp(argv[i], "RSAES_PKCS1_OAEP_SHA384_ENCRYPT")) {
				main_algo = ALGO_RSA;
				mode = MODE_ENCRYPT;
				crypto_algo = RSAES_PKCS1_OAEP_SHA384;
				size -= OAEP_HASH_LEN(SHA384_LEN) + OAEP_OTHER_LEN;
			} else if (!strcasecmp(argv[i], "RSAES_PKCS1_OAEP_SHA384_DECRYPT")) {
				main_algo = ALGO_RSA;
				mode = MODE_DECRYPT;
				crypto_algo = RSAES_PKCS1_OAEP_SHA384;
				size -= OAEP_HASH_LEN(SHA384_LEN) + OAEP_OTHER_LEN;
			} else if (!strcasecmp(argv[i], "RSAES_PKCS1_OAEP_SHA512_ENCRYPT")) {
				main_algo = ALGO_RSA;
				mode = MODE_ENCRYPT;
				crypto_algo = RSAES_PKCS1_OAEP_SHA512;
				size -= OAEP_HASH_LEN(SHA512_LEN) + OAEP_OTHER_LEN;
			} else if (!strcasecmp(argv[i], "RSAES_PKCS1_OAEP_SHA512_DECRYPT")) {
				main_algo = ALGO_RSA;
				mode = MODE_DECRYPT;
				crypto_algo = RSAES_PKCS1_OAEP_SHA512;
				size -= OAEP_HASH_LEN(SHA512_LEN) + OAEP_OTHER_LEN;
			} else if (!strcasecmp(argv[i], "RSASSA_PKCS1_V1_5_SHA1_SIGN")) {
				main_algo = ALGO_RSA;
				mode = MODE_SIGN;
				crypto_algo = RSASSA_PKCS1_V1_5_SHA1;
			} else if (!strcasecmp(argv[i], "RSASSA_PKCS1_V1_5_SHA1_VERIFY")) {
				main_algo = ALGO_RSA;
				mode = MODE_VERIFY;
				crypto_algo = RSASSA_PKCS1_V1_5_SHA1;
			} else if (!strcasecmp(argv[i], "RSASSA_PKCS1_V1_5_SHA224_SIGN")) {
				main_algo = ALGO_RSA;
				mode = MODE_SIGN;
				crypto_algo = RSASSA_PKCS1_V1_5_SHA224;
			} else if (!strcasecmp(argv[i], "RSASSA_PKCS1_V1_5_SHA224_VERIFY")) {
				main_algo = ALGO_RSA;
				mode = MODE_VERIFY;
				crypto_algo = RSASSA_PKCS1_V1_5_SHA224;
			} else if (!strcasecmp(argv[i], "RSASSA_PKCS1_V1_5_SHA256_SIGN")) {
				main_algo = ALGO_RSA;
				mode = MODE_SIGN;
				crypto_algo = RSASSA_PKCS1_V1_5_SHA256;
			} else if (!strcasecmp(argv[i], "RSASSA_PKCS1_V1_5_SHA256_VERIFY")) {
				main_algo = ALGO_RSA;
				mode = MODE_VERIFY;
				crypto_algo = RSASSA_PKCS1_V1_5_SHA256;
			} else if (!strcasecmp(argv[i], "RSASSA_PKCS1_V1_5_SHA384_SIGN")) {
				main_algo = ALGO_RSA;
				mode = MODE_SIGN;
				crypto_algo = RSASSA_PKCS1_V1_5_SHA384;
			} else if (!strcasecmp(argv[i], "RSASSA_PKCS1_V1_5_SHA384_VERIFY")) {
				main_algo = ALGO_RSA;
				mode = MODE_VERIFY;
				crypto_algo = RSASSA_PKCS1_V1_5_SHA384;
			} else if (!strcasecmp(argv[i], "RSASSA_PKCS1_V1_5_SHA512_SIGN")) {
				main_algo = ALGO_RSA;
				mode = MODE_SIGN;
				crypto_algo = RSASSA_PKCS1_V1_5_SHA512;
			} else if (!strcasecmp(argv[i], "RSASSA_PKCS1_V1_5_SHA512_VERIFY")) {
				main_algo = ALGO_RSA;
				mode = MODE_VERIFY;
				crypto_algo = RSASSA_PKCS1_V1_5_SHA512;
			} else if (!strcasecmp(argv[i], "RSASSA_PKCS1_PSS_MGF1_SHA1_SIGN")) {
				main_algo = ALGO_RSA;
				mode = MODE_SIGN;
				crypto_algo = RSASSA_PKCS1_PSS_MGF1_SHA1;
			} else if (!strcasecmp(argv[i], "RSASSA_PKCS1_PSS_MGF1_SHA1_VERIFY")) {
				main_algo = ALGO_RSA;
				mode = MODE_VERIFY;
				crypto_algo = RSASSA_PKCS1_PSS_MGF1_SHA1;
			} else if (!strcasecmp(argv[i], "RSASSA_PKCS1_PSS_MGF1_SHA224_SIGN")) {
				main_algo = ALGO_RSA;
				mode = MODE_SIGN;
				crypto_algo = RSASSA_PKCS1_PSS_MGF1_SHA224;
			} else if (!strcasecmp(argv[i], "RSASSA_PKCS1_PSS_MGF1_SHA224_VERIFY")) {
				main_algo = ALGO_RSA;
				mode = MODE_VERIFY;
				crypto_algo = RSASSA_PKCS1_PSS_MGF1_SHA224;
			} else if (!strcasecmp(argv[i], "RSASSA_PKCS1_PSS_MGF1_SHA256_SIGN")) {
				main_algo = ALGO_RSA;
				mode = MODE_SIGN;
				crypto_algo = RSASSA_PKCS1_PSS_MGF1_SHA256;
			} else if (!strcasecmp(argv[i], "RSASSA_PKCS1_PSS_MGF1_SHA256_VERIFY")) {
				main_algo = ALGO_RSA;
				mode = MODE_VERIFY;
				crypto_algo = RSASSA_PKCS1_PSS_MGF1_SHA256;
			} else if (!strcasecmp(argv[i], "RSASSA_PKCS1_PSS_MGF1_SHA384_SIGN")) {
				main_algo = ALGO_RSA;
				mode = MODE_SIGN;
				crypto_algo = RSASSA_PKCS1_PSS_MGF1_SHA384;
			} else if (!strcasecmp(argv[i], "RSASSA_PKCS1_PSS_MGF1_SHA384_VERIFY")) {
				main_algo = ALGO_RSA;
				mode = MODE_VERIFY;
				crypto_algo = RSASSA_PKCS1_PSS_MGF1_SHA384;
			} else if (!strcasecmp(argv[i], "RSASSA_PKCS1_PSS_MGF1_SHA512_SIGN")) {
				main_algo = ALGO_RSA;
				mode = MODE_SIGN;
				crypto_algo = RSASSA_PKCS1_PSS_MGF1_SHA512;
			} else if (!strcasecmp(argv[i], "RSASSA_PKCS1_PSS_MGF1_SHA512_VERIFY")) {
				main_algo = ALGO_RSA;
				mode = MODE_VERIFY;
				crypto_algo = RSASSA_PKCS1_PSS_MGF1_SHA512;
			} else if (!strcasecmp(argv[i], "ECDSA_SIGN")) {
				main_algo = ALGO_ECDSA;
				mode = MODE_SIGN;
				width_bits = 256;
			} else if (!strcasecmp(argv[i], "ECDSA_VERIFY")) {
				main_algo = ALGO_ECDSA;
				mode = MODE_VERIFY;
				width_bits = 256;
			} else if (!strcasecmp(argv[i], "ECDH")) {
				main_algo = ALGO_ECDH;
				width_bits = 256;
				mode = MODE_GENKEYPAIR;
			} else if (!strcasecmp(argv[i], "X25519")) {
				main_algo = ALGO_X25519;
				width_bits = 256;
				mode = MODE_GENKEYPAIR;
			} else if (!strcasecmp(argv[i], "SM2_GENKEYPAIR")) {
				main_algo = ALGO_SM2;
				width_bits = 256;
				mode = MODE_GENKEYPAIR;
			} else if (!strcasecmp(argv[i], "SM2_SIGN")) {
				main_algo = ALGO_SM2;
				width_bits = 256;
				mode = MODE_SIGN;
			} else if (!strcasecmp(argv[i], "SM2_VERIFY")) {
				main_algo = ALGO_SM2;
				width_bits = 256;
				mode = MODE_VERIFY;
			} else if (!strcasecmp(argv[i], "SM2_ENCRYPT")) {
				main_algo = ALGO_SM2;
				width_bits = 256;
				mode = MODE_ENCRYPT;
			} else if (!strcasecmp(argv[i], "SM2_DECRYPT")) {
				main_algo = ALGO_SM2;
				width_bits = 256;
				mode = MODE_DECRYPT;
			} else {
				fprintf(stderr, "%s, invalid main_algo\n",
					argv[0]);
				USAGE();
				return 1;
			}
		} else if (!strcmp(argv[i], "-l")) {
			NEXT_ARG(i);
			l = atoi(argv[i]);
		} else if (!strcmp(argv[i], "-n")) {
			NEXT_ARG(i);
			n = atoi(argv[i]);
		} else if (!strcmp(argv[i], "--random") ||
			   !strcmp(argv[i], "-r")) {
			is_random = CRYPTO_USE_RANDOM;
		} else if (!strcmp(argv[i], "-k")) {
			NEXT_ARG(i);
			size = atoi(argv[i]);
		} else if (!strcmp(argv[i], "-d")) {
			NEXT_ARG(i);
			width_bits = atoi(argv[i]);
		} else if (!strcmp(argv[i], "-s")) {
			NEXT_ARG(i);
			salt_len = atoi(argv[i]);
		} else if (!strcmp(argv[i], "-v")) {
			verbosity++;
		} else if (!strcmp(argv[i], "--warmup") ||
			   !strcmp(argv[i], "-w")) {
			NEXT_ARG(i);
			warmup = atoi(argv[i]);
		} else {
			fprintf(stderr, "%s: invalid argument: %s\n",
				argv[0], argv[i]);
			USAGE();
			return 1;
		}
	}

	if (main_algo == ALGO_RSA) {
		if (mode == MODE_ENCRYPT || mode == MODE_DECRYPT) {
			if (check_rsa_cipher_params(crypto_algo, width_bits, size)) {
				USAGE();
				return -1;
			}
		} else if (mode == MODE_SIGN || mode == MODE_VERIFY) {
			if (check_rsa_hash_params(crypto_algo, width_bits, size,
						  salt_len)) {
				USAGE();
				return -1;
			}
		}
	}

	if (mode == MODE_GENKEYPAIR || main_algo == ALGO_SM2)
		size = BITS_TO_BYTES(width_bits);

	return asym_perf_run_test(mode, size, n, l, is_random, warmup,
				  verbosity, width_bits, main_algo,
				  salt_len, crypto_algo);
}
