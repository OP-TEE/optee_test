// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2023, Huawei Technologies Co., Ltd
 * All rights reserved.
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
#include <ta_asym_cipher_perf.h>
#include <tee_client_api.h>
#include <tee_client_api_extensions.h>
#include <time.h>
#include <unistd.h>

#include "crypto_common.h"
#include "xtest_helpers.h"
#include <utee_defines.h>

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
 exit (1);
}

static void check_res(TEEC_Result res, const char *errmsg, uint32_t *orig)
{
 if (res != TEEC_SUCCESS)
 errx(errmsg, res, orig);
}

#define CHECK(res, name, action) do { \
 if ((res) != TEE_SUCCESS) { \
 printf(name ": 0x%08x", (res)); \
 action \
 } \
 } while(0)

static void open_ta(void)
{
 TEEC_UUID uuid = TA_ASYM_CIPHER_PERF_UUID;
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
 s->m += delta / s->n;
 s->M2 += delta * (x - s->m);
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

 return sqrt(s->M2 / s->n);
}

static void usage(const char *progname, uint32_t width_bits, uint32_t tee_type,
   uint32_t mode, uint32_t salt_len, uint32_t size,
   uint32_t rsa_algo, int warmup, uint32_t l, uint32_t n)
{
 fprintf(stderr, "Usage: %s [-h]\n", progname);
 fprintf(stderr, "Usage: %s [-t] [-m] [-k SIZE]", progname);
 fprintf(stderr, " [-t tee_type] [-m mode] [-n LOOP] [-r|--no-inited] [-d WIDTH_BITS]");
 fprintf(stderr, " [-k SIZE] [-a rsa_algo] [-s salt_len] [-v [-v]] [-w SEC]");
 fprintf(stderr, "\n");
 fprintf(stderr, "Asymmetric Cipher performance testing tool for OP-TEE\n");
 fprintf(stderr, "\n");
 fprintf(stderr, "Options:\n");
 fprintf(stderr, "  -h|--help        Print this help and exit\n");
 fprintf(stderr, "  -t               Test asymmetric cipher TEE_TYPE [%u]\n", tee_type);
 fprintf(stderr, "                   1:DH    2:RSA    3:ECDSA    4:ECDH    5:X25519\n");
 fprintf(stderr, "  -m               Test asymmetric cipher mode [%u]\n", mode);
 fprintf(stderr, "                   0:EN    1:DE    2:SIGN    3:VERI    4:genkeypair\n");
 fprintf(stderr, "  -l LOOP          Inner loop iterations [%u]\n", l);
 fprintf(stderr, "  -n LOOP          Outer test loop iterations [%u]\n", n);
 fprintf(stderr, "  -r|--random      Get input data from /dev/urandom (default: all zeros)\n");
 fprintf(stderr, "  -k SIZE          Plaintext Length [%u]\n", size);
 fprintf(stderr, "  -d WIDTH_BITS    ECC:the width_bits only support 192/224/256/384/521 [%u]\n", width_bits);
 fprintf(stderr, "                   DH: width_bits <= 2048, RSA: width_bits <= 4096 [%u]\n", width_bits);
 fprintf(stderr, "  -a rsa_algo      if TEE_TYPE==RSA: [%u]\n", rsa_algo);
 fprintf(stderr, "                   EN/DE:        0: RSA_NOPAD                     1:  RSAES_PKCS1_V1_5              2: RSAES_PKCS1_OAEP_SHA1\n");
 fprintf(stderr, "                                 3: RSAES_PKCS1_OAEP_SHA224       4:  RSAES_PKCS1_OAEP_SHA256       5: RSAES_PKCS1_OAEP_SHA384\n");
 fprintf(stderr, "                                 6: RSAES_PKCS1_OAEP_SHA512\n");
 fprintf(stderr, "                   SIGN/VERSIGN: 0: RSASSA_PKCS1_V1_5_SHA1        1:  RSASSA_PKCS1_V1_5_SHA224      2: RSASSA_PKCS1_V1_5_SHA256\n");
 fprintf(stderr, "                                 3: RSASSA_PKCS1_V1_5_SHA384      4:  RSASSA_PKCS1_V1_5_SHA512      5: RSASSA_PKCS1_PSS_MGF1_SHA1\n");
 fprintf(stderr, "                                 6: RSASSA_PKCS1_PSS_MGF1_SHA224  7:  RSASSA_PKCS1_PSS_MGF1_SHA256  8: RSASSA_PKCS1_PSS_MGF1_SHA384\n");
 fprintf(stderr, "                                 9: RSASSA_PKCS1_PSS_MGF1_SHA512\n");
 fprintf(stderr, "  -s salt_len      only RSA SSA_PKCS1_PSS support! [%u]\n", salt_len);
 fprintf(stderr, "  -w|--warmup SEC  Warm-up time in seconds: execute a busy loop before [%d]\n", warmup);
 fprintf(stderr, "  -v            Be verbose (use twice for greater effect)\n");
}

static void allocate_shm(TEEC_SharedMemory *shm, size_t sz)
{
 TEEC_Result res = TEEC_ERROR_GENERIC;

 shm->buffer = NULL;
 shm->size = sz;
 res = TEEC_AllocateSharedMemory(&ctx, shm);
 check_res(res, "TEEC_AllocateSharedMemory", NULL);
}

/* initial test buffer allocation (eventual registering to TEEC) */
static void alloc_buffers(size_t sz, int verbosity)
{
 (void)verbosity;

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

static void prepare_obj(int width_bits, uint32_t tee_type)
{
 uint32_t cmd = TA_ASYM_CIPHER_PERF_CMD_PREPARE_OBJ;
 TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
 TEEC_Result res = TEEC_ERROR_GENERIC;
 uint32_t ret_origin = 0;

 op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE,
 TEEC_NONE);
 op.params[0].value.a = tee_type;
 op.params[0].value.b = width_bits;

 res = TEEC_InvokeCommand(&sess, cmd, &op, &ret_origin);
 check_res(res, "TEEC_InvokeCommand", &ret_origin);
}

static void prepare_hash(int size, uint32_t tee_type)
{
 uint32_t cmd = TA_ASYM_CIPHER_PERF_CMD_PREPARE_HASH;
 TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
 TEEC_Result res = TEEC_ERROR_GENERIC;
 uint32_t ret_origin = 0;

 op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
 TEEC_MEMREF_PARTIAL_INPUT,
 TEEC_MEMREF_PARTIAL_INOUT, TEEC_NONE);
 op.params[0].value.a = tee_type;
 op.params[1].memref.parent = &in_shm;
 op.params[1].memref.size = size;
 op.params[2].memref.parent = &hash_shm;
 op.params[2].memref.size = hash_shm.size;

 res = TEEC_InvokeCommand(&sess, cmd, &op, &ret_origin);
 check_res(res, "TEEC_InvokeCommand", &ret_origin);
 hash_shm.size = op.params[2].memref.size;
}

static void prepare_keypair(int width_bits, uint8_t *buf, size_t blen,
     uint32_t mode, uint32_t algo, uint32_t tee_type)
{
 uint32_t cmd = TA_ASYM_CIPHER_PERF_CMD_PREPARE_KEYPAIR;
 TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
 TEEC_Result res = TEEC_ERROR_GENERIC;
 uint32_t ret_origin = 0;

 op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_VALUE_INPUT,
 TEEC_MEMREF_TEMP_INPUT, TEEC_NONE);
 op.params[0].value.a = width_bits;
 op.params[0].value.b = mode;
 op.params[1].value.a = tee_type;
 op.params[1].value.b = algo;
 op.params[2].tmpref.buffer = buf;
 op.params[2].tmpref.size = blen;

 res = TEEC_InvokeCommand(&sess, cmd, &op, &ret_origin);
 check_res(res, "TEEC_InvokeCommand", &ret_origin);
}

static void prepare_enc_sign(uint32_t size, uint32_t mode, uint32_t is_random,
      uint8_t *buf, uint32_t blen)
{
 uint32_t cmd = TA_ASYM_CIPHER_PERF_CMD_PREPARE_ENC_SIGN;
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

 check_res(res, "TEEC_InvokeCommand", &ret_origin);

 out_shm.size = op.params[1].memref.size;

 return;
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
 uint32_t curve_id = TEE_ERROR_BAD_PARAMETERS;

 switch (width_bits) {
 case ECC_CURVE_192:
 curve_id = TEE_ECC_CURVE_NIST_P192;
 break;
 case ECC_CURVE_224:
 curve_id = TEE_ECC_CURVE_NIST_P224;
 break;
 case ECC_CURVE_256:
 curve_id = TEE_ECC_CURVE_NIST_P256;
 break;
 case ECC_CURVE_384:
 curve_id = TEE_ECC_CURVE_NIST_P384;
 break;
 case ECC_CURVE_521:
 curve_id = TEE_ECC_CURVE_NIST_P521;
 break;
 default:
 printf("ECC curve is not support!\n");
 break;
 }

 return curve_id;
}

static int asym_cipher_perf_run_test(int mode, size_t size, uint32_t n,
      uint32_t l, int is_random, uint32_t warmup,
      uint32_t verbosity, uint32_t width_bits,
      uint32_t tee_type, uint32_t salt_len,
      uint32_t algo)
{
 TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
 uint32_t cmd = TA_CIPHER_PERF_CMD_PROCESS;
 TEEC_Result res = TEEC_ERROR_GENERIC;
 uint8_t keygen_dh_p[DH_MAX_SIZE] = { };
 uint8_t keygen_dh_g[DH_G_SIZE] = { };
 TEE_Attribute params[4] = { };
 size_t param_count = 0;
 uint32_t curve_id = 0;
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

 if (tee_type == ECDSA || tee_type == ECDH) {
 curve_id = get_curve_id(width_bits);
 if (curve_id == TEE_ERROR_BAD_PARAMETERS)
 return TEE_ERROR_BAD_PARAMETERS;
 }

 open_ta();

 alloc_buffers(size, verbosity);
 if (is_random == CRYPTO_USE_ZEROS)
 memset((uint8_t *)in_shm.buffer, 0, size);
 else
 read_random(in_shm.buffer, size);
 if (mode == MODE_DECRYPT && tee_type == RSA)
 ((unsigned char *)(in_shm.buffer))[0] = 0x00;

 if (tee_type == X25519)
 width_bits = WIDTH_BITS_25519;

 prepare_obj(width_bits, tee_type);

 if (tee_type == DH) {
 read_random(keygen_dh_p, BITS_TO_BYTES(width_bits));
 read_random(keygen_dh_g, DH_G_SIZE);
 keygen_dh_p[0] |= 0x2; /* make sure the p is full width */
 /* make sure keygen_dh_p is odd */
 keygen_dh_p[BITS_TO_BYTES(width_bits) - 1] |= 0x1;

 xtest_add_attr(&param_count, params, TEE_ATTR_DH_PRIME,
        keygen_dh_p, BITS_TO_BYTES(width_bits));
 xtest_add_attr(&param_count, params, TEE_ATTR_DH_BASE,
        keygen_dh_g, DH_G_SIZE);
 } else if (tee_type == ECDSA || tee_type == ECDH) {
 xtest_add_attr_value(&param_count, params, TEE_ATTR_ECC_CURVE,
      curve_id, 0);
 }

 res = pack_attrs(params, param_count, &buf, &blen);
 CHECK(res, "pack_attrs", return res;);

 if (mode != MODE_GENKEYPAIR)
 prepare_keypair(width_bits, buf, blen, mode, algo, tee_type);

 if (mode == MODE_SIGN || mode == MODE_VERIFY)
 prepare_hash(size, tee_type);

 if (tee_type == RSA && salt_len > 0) {
 params[0].attributeID = TEE_ATTR_RSA_PSS_SALT_LENGTH;
 params[0].content.value.a = salt_len;
 params[0].content.value.b = 0;
 param_count = 1;
 res = pack_attrs(params, param_count, &buf, &blen);
 CHECK(res, "pack_attrs", return res;);
 }

 if (mode == MODE_GENKEYPAIR) {
 cmd = TA_ASYM_CIPHER_PERF_CMD_PROCESS_GEN_KEYPAIR;
 op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
 TEEC_MEMREF_TEMP_INOUT,
 TEEC_NONE, TEEC_NONE);
 op.params[0].value.a = width_bits;
 op.params[0].value.b = l;
 op.params[1].tmpref.buffer = buf;
 op.params[1].tmpref.size = blen;
 } else {
 cmd = TA_ASYM_CIPHER_PERF_CMD_PROCESS;
 op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
 TEEC_VALUE_INPUT,
 TEEC_MEMREF_PARTIAL_INPUT,
 TEEC_MEMREF_PARTIAL_OUTPUT);

 op.params[0].tmpref.buffer = buf;
 op.params[0].tmpref.size = blen;
 op.params[1].value.a = l;
 op.params[1].value.b = mode;
 op.params[2].memref.parent = (mode == MODE_ENCRYPT) ?
      &in_shm : &hash_shm;
 op.params[2].memref.size = (mode == MODE_ENCRYPT) ?
    size : hash_shm.size;
 op.params[3].memref.parent = &out_shm;
 op.params[3].memref.size = out_shm.size;

 if (mode == MODE_DECRYPT || mode == MODE_VERIFY) {
 prepare_enc_sign(size, mode, is_random, buf, blen);

 op.params[2].memref.parent = (mode == MODE_DECRYPT) ?
      &out_shm : &hash_shm;
 op.params[2].memref.size = (mode == MODE_DECRYPT) ?
    out_shm.size : hash_shm.size;
 op.params[3].memref.parent = (mode == MODE_DECRYPT) ?
      &in_shm : &out_shm;
 op.params[3].memref.size = (mode == MODE_DECRYPT) ?
    size : out_shm.size;
 }
 }

 if (warmup)
 do_warmup(warmup);

 while (n-- > 0) {
 if (mode == MODE_ENCRYPT && tee_type == RSA) {
 /* Make sure the N > M */
 ((unsigned char *)(in_shm.buffer))[0] = 0x00;
 /* Avoid the problem that the last encryption result is
 less than the plaintext. */
 op.params[3].memref.size = out_shm.size;
 }

 get_current_time(&t0);

 res = TEEC_InvokeCommand(&sess, cmd, &op, &ret_origin);

 check_res(res, "TEEC_InvokeCommand", &ret_origin);

 get_current_time(&t1);

 update_stats(&stats, timespec_diff_ns(&t0, &t1));
 if (n % (n0 / 10) == 0)
 vverbose("#");
 }

 vverbose("\n");
 sd = stddev(&stats);
 printf("min=%gus max=%gus mean=%gus stddev=%gus (cv %g%%) (%gMiB/s)\n",
 stats.min / 1000, stats.max / 1000, stats.m / 1000,
 sd / 1000, 100 * sd / stats.m, mb_per_sec(size, stats.m));
 verbose("2-sigma interval: %g..%gus (%g..%gMiB/s)\n",
 (stats.m - 2 * sd) / 1000, (stats.m + 2 * sd) / 1000,
 mb_per_sec(size, stats.m + 2 * sd),
 mb_per_sec(size, stats.m - 2 * sd));

 free_shm();
 free(buf);
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
 } while (0);

#define USAGE() usage(argv[0], width_bits, tee_type, mode, \
       salt_len, size, rsa_algo, warmup, l, n)

static int get_hash_len(uint32_t algo)
{
 switch (algo) {
 case RSAES_PKCS1_OAEP_SHA1:
 return SHA1_LEN;
 case RSAES_PKCS1_OAEP_SHA224:
 return SHA224_LEN;
 case RSAES_PKCS1_OAEP_SHA256:
 return SHA256_LEN;
 case RSAES_PKCS1_OAEP_SHA384:
 return SHA384_LEN;
 case RSAES_PKCS1_OAEP_SHA512:
 return SHA512_LEN;
 default:
 printf("The algo[%u] is err!\n", algo);
 }

 return -1;
}

static int get_hash_sign_len(uint32_t algo)
{
 switch (algo) {
 case RSASSA_PKCS1_V1_5_SHA1:
 case RSASSA_PKCS1_PSS_MGF1_SHA1:
 return SHA1_LEN;
 case RSASSA_PKCS1_V1_5_SHA224:
 case RSASSA_PKCS1_PSS_MGF1_SHA224:
 return SHA224_LEN;
 case RSASSA_PKCS1_V1_5_SHA256:
 case RSASSA_PKCS1_PSS_MGF1_SHA256:
 return SHA256_LEN;
 case RSASSA_PKCS1_V1_5_SHA384:
 case RSASSA_PKCS1_PSS_MGF1_SHA384:
 return SHA384_LEN;
 case RSASSA_PKCS1_V1_5_SHA512:
 case RSASSA_PKCS1_PSS_MGF1_SHA512:
 return SHA512_LEN;
 default:
 printf("The algo[%u] is err!\n", algo);
 }

 return -1;
}

static int check_rsa_cipher_params(uint32_t rsa_algo, int width_bits, int size)
{
 int width_bytes = BITS_TO_BYTES(width_bits);
 int hash_len = 0;

 if (rsa_algo == 0) {
 if (size > width_bytes) {
 printf("The size or algo is error\n");
 return -1;
 }
 } else if (rsa_algo == RSAES_PKCS1_V1_5) {
 if ((size + PKCS_V1_5_MIN) > width_bytes) {
 printf("The size or algo is error\n");
 return -1;
 }
 } else if (rsa_algo > RSAES_PKCS1_V1_5) {
 hash_len = get_hash_len(rsa_algo);
 if (hash_len == -1)
 return -1;

 if (OAEP_HASH_LEN(hash_len) >= (width_bytes - OAEP_OTHER_LEN)) {
 printf("The width_bits or algo is error\n");
 return -1;
 } else if (size > (width_bytes - OAEP_HASH_LEN(hash_len) -
    OAEP_OTHER_LEN)) {
 printf("The size or algo is error\n");
 return -1;
 }
 }

 return 0;
}

static int check_rsa_hash_params(uint32_t rsa_algo, int width_bits, int size,
 int salt_len)
{
 int width_bytes = BITS_TO_BYTES(width_bits);
 int salt_temp = 0;
 int hash_len = get_hash_sign_len(rsa_algo);
 if (hash_len == -1)
 return -1;

 if (rsa_algo == RSASSA_PKCS1_V1_5_SHA1 &&
     width_bytes < hash_len + DERCODE_SHA1_LEN + PKCS_V1_5_MIN) {
 printf("The size or algo is error/n");
 return -1;
 } else if (rsa_algo != RSASSA_PKCS1_V1_5_SHA1 &&
    rsa_algo <= RSASSA_PKCS1_V1_5_SHA512 &&
    width_bytes < hash_len + DERCODE_SHA_LEN + PKCS_V1_5_MIN) {
 printf("The size or algo is error\n");
 return -1;
 } else if (rsa_algo >= RSASSA_PKCS1_PSS_MGF1_SHA1 &&
    rsa_algo <= RSASSA_PKCS1_PSS_MGF1_SHA512) {
 salt_temp = (salt_len == 0 ? hash_len : salt_len);

 if (salt_temp > width_bytes ||
     width_bytes < hash_len + salt_temp + PSS_OTHER_LEN) {
 printf("The size or algo is error\n");
 return -1;
 }
 }

 return 0;
}

int asym_cipher_perf_runner_cmd_parser(int argc, char *argv[])
{
 int verbosity = CRYPTO_DEF_VERBOSITY;
 int is_random = CRYPTO_USE_ZEROS;
 unsigned int n = CRYPTO_DEF_COUNT;
 unsigned int l = CRYPTO_DEF_LOOPS;
 int warmup = CRYPTO_DEF_WARMUP;
 int mode = MODE_GENKEYPAIR;
 int width_bits = 1024;
 uint32_t tee_type = 0;
 uint32_t rsa_algo = 0;
 int size = 1024;
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
 if (!strcmp(argv[i], "-t")) {
 NEXT_ARG(i);
 tee_type = atoi(argv[i]);
 } else if (!strcmp(argv[i], "-m")) {
 NEXT_ARG(i);
 mode = atoi(argv[i]);
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
 } else if (!strcmp(argv[i], "-a")) {
 NEXT_ARG(i);
 rsa_algo = atoi(argv[i]);
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

 if (tee_type == RSA) {
 if (mode == MODE_ENCRYPT || mode == MODE_DECRYPT) {
 if (check_rsa_cipher_params(rsa_algo, width_bits, size))
 return -1;
 } else if (mode == MODE_SIGN || mode == MODE_VERIFY) {
 if (check_rsa_hash_params(rsa_algo, width_bits, size,
   salt_len))
 return -1;
 }
 }

 if (mode == MODE_GENKEYPAIR)
 size = BITS_TO_BYTES(width_bits);

 return asym_cipher_perf_run_test(mode, size, n, l, is_random, warmup,
 verbosity, width_bits, tee_type,
 salt_len, rsa_algo);
}
