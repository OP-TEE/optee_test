// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2020, ARM Limited. All rights reserved.
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#include <errno.h>
#include <limits.h>
#ifdef OPENSSL_FOUND
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#endif
#include <pta_attestation.h>
#include <pta_invoke_tests.h>
#include <pta_secstor_ta_mgmt.h>
#include <pthread.h>
#ifdef CFG_SECURE_DATA_PATH
#include <sdp_basic.h>
#endif
#include <sys/stat.h>
#include <signed_hdr.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <ta_arm_bti.h>
#include <ta_concurrent.h>
#include <ta_create_fail_test.h>
#include <ta_crypt.h>
#include <ta_miss_test.h>
#include <ta_os_test.h>
#include <ta_rpc_test.h>
#include <ta_sims_keepalive_test.h>
#include <ta_sims_test.h>
#include <ta_supp_plugin.h>
#include <ta_tpm_log_test.h>
#include <test_supp_plugin.h>
#include <unistd.h>
#include <utee_defines.h>
#include <util.h>

#include "ftpm_ta.h"
#include "xtest_helpers.h"
#include "xtest_test.h"
#include "xtest_uuid_helpers.h"

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

#define STATS_UUID \
	{ 0xd96a5b40, 0xe2c7, 0xb1af, \
		{ 0x87, 0x94, 0x10, 0x02, 0xa5, 0xd5, 0xc6, 0x1b } }

#define STATS_CMD_PAGER_STATS		0

#define PAGER_PAGE_COUNT_THRESHOLD	((128 * 1024) / 4096)

struct xtest_crypto_session {
	ADBG_Case_t *c;
	TEEC_Session *session;
	uint32_t cmd_id_sha256;
	uint32_t cmd_id_aes256ecb_encrypt;
	uint32_t cmd_id_aes256ecb_decrypt;
};

static bool optee_pager_with_small_pool(void)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_UUID uuid = STATS_UUID;
	TEEC_Context ctx = { };
	TEEC_Session sess = { };
	TEEC_Operation op = { };
	uint32_t eo = 0;
	bool rc = false;

	res = TEEC_InitializeContext(NULL, &ctx);
	if (res)
		return false;

	res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL,
			       NULL, &eo);
	if (res)
		goto out_ctx;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT, TEEC_VALUE_OUTPUT,
					 TEEC_VALUE_OUTPUT, TEEC_NONE);
	res = TEEC_InvokeCommand(&sess, STATS_CMD_PAGER_STATS, &op, &eo);
	if (res)
		goto out_sess;

	if (op.params[0].value.b &&
	    op.params[0].value.b <= PAGER_PAGE_COUNT_THRESHOLD)
		rc = true;

out_sess:
	TEEC_CloseSession(&sess);
out_ctx:
	TEEC_FinalizeContext(&ctx);

	return rc;
}

static void xtest_crypto_test(struct xtest_crypto_session *cs)
{
	uint32_t ret_orig = 0;
	uint8_t crypt_out[16] = { };
	uint8_t crypt_in[16] = { 22, 17 };

	crypt_in[15] = 60;

	Do_ADBG_BeginSubCase(cs->c, "AES encrypt");
	{
		TEEC_Operation op = TEEC_OPERATION_INITIALIZER;

		op.params[0].tmpref.buffer = crypt_in;
		op.params[0].tmpref.size = sizeof(crypt_in);
		op.params[1].tmpref.buffer = crypt_out;
		op.params[1].tmpref.size = sizeof(crypt_out);
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
						 TEEC_MEMREF_TEMP_OUTPUT,
						 TEEC_NONE, TEEC_NONE);

		(void)ADBG_EXPECT_TEEC_SUCCESS(cs->c,
					       TEEC_InvokeCommand(cs->session,
						cs->
						cmd_id_aes256ecb_encrypt,
						&op,
						&ret_orig));
	}
	Do_ADBG_EndSubCase(cs->c, "AES encrypt");

	Do_ADBG_BeginSubCase(cs->c, "AES decrypt");
	{
		TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
		uint8_t out[16] = { };

		op.params[0].tmpref.buffer = crypt_out;
		op.params[0].tmpref.size = sizeof(crypt_out);
		op.params[1].tmpref.buffer = out;
		op.params[1].tmpref.size = sizeof(out);
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
						 TEEC_MEMREF_TEMP_OUTPUT,
						 TEEC_NONE, TEEC_NONE);

		(void)ADBG_EXPECT_TEEC_SUCCESS(cs->c,
					       TEEC_InvokeCommand(cs->session,
						cs->
						cmd_id_aes256ecb_decrypt,
						&op,
						&ret_orig));

		if (!ADBG_EXPECT(cs->c, 0,
				 memcmp(crypt_in, out, sizeof(crypt_in)))) {
			Do_ADBG_Log("crypt_in:");
			Do_ADBG_HexLog(crypt_in, sizeof(crypt_in), 16);
			Do_ADBG_Log("out:");
			Do_ADBG_HexLog(out, sizeof(out), 16);
		}
	}
	Do_ADBG_EndSubCase(cs->c, "AES decrypt");

	Do_ADBG_BeginSubCase(cs->c, "SHA-256 test, 3 bytes input");
	{
		TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
		static const uint8_t sha256_in[] = { 'a', 'b', 'c' };
		static const uint8_t sha256_out[] = {
			0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
			0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
			0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
			0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
		};
		uint8_t out[32] = { };

		op.params[0].tmpref.buffer = (void *)sha256_in;
		op.params[0].tmpref.size = sizeof(sha256_in);
		op.params[1].tmpref.buffer = out;
		op.params[1].tmpref.size = sizeof(out);
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
						 TEEC_MEMREF_TEMP_OUTPUT,
						 TEEC_NONE, TEEC_NONE);

		(void)ADBG_EXPECT_TEEC_SUCCESS(cs->c,
					       TEEC_InvokeCommand(cs->session,
								  cs->
								  cmd_id_sha256,
								  &op,
								  &ret_orig));

		if (!ADBG_EXPECT(cs->c, 0, memcmp(sha256_out, out,
						  sizeof(sha256_out)))) {
			Do_ADBG_Log("sha256_out:");
			Do_ADBG_HexLog(sha256_out, sizeof(sha256_out), 16);
			Do_ADBG_Log("out:");
			Do_ADBG_HexLog(out, sizeof(out), 16);
		}
	}
	Do_ADBG_EndSubCase(cs->c, "SHA-256 test, 3 bytes input");

	Do_ADBG_BeginSubCase(cs->c, "AES-256 ECB encrypt (32B, fixed key)");
	{
		TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
		static const uint8_t in[] = {
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
			0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
			0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
		};
		static const uint8_t exp_out[] = {
			0x5A, 0x6E, 0x04, 0x57, 0x08, 0xFB, 0x71, 0x96,
			0xF0, 0x2E, 0x55, 0x3D, 0x02, 0xC3, 0xA6, 0x92,
			0xE9, 0xC3, 0xEF, 0x8A, 0xB2, 0x34, 0x53, 0xE6,
			0xF0, 0x74, 0x9C, 0xD6, 0x36, 0xE7, 0xA8, 0x8E
		};
		uint8_t out[sizeof(exp_out)] = { };

		op.params[0].tmpref.buffer = (void *)in;
		op.params[0].tmpref.size = sizeof(in);
		op.params[1].tmpref.buffer = out;
		op.params[1].tmpref.size = sizeof(out);
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
						 TEEC_MEMREF_TEMP_OUTPUT,
						 TEEC_NONE, TEEC_NONE);

		(void)ADBG_EXPECT_TEEC_SUCCESS(cs->c,
					TEEC_InvokeCommand(cs->session,
					cs->
					cmd_id_aes256ecb_encrypt,
					&op,
					&ret_orig));

		if (!ADBG_EXPECT(cs->c, 0,
				 memcmp(exp_out, out, sizeof(exp_out)))) {
			Do_ADBG_Log("exp_out:");
			Do_ADBG_HexLog(exp_out, sizeof(exp_out), 16);
			Do_ADBG_Log("out:");
			Do_ADBG_HexLog(out, sizeof(out), 16);
		}
	}
	Do_ADBG_EndSubCase(cs->c, "AES-256 ECB encrypt (32B, fixed key)");

	Do_ADBG_BeginSubCase(cs->c, "AES-256 ECB decrypt (32B, fixed key)");
	{
		TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
		static const uint8_t in[] = {
			0x5A, 0x6E, 0x04, 0x57, 0x08, 0xFB, 0x71, 0x96,
			0xF0, 0x2E, 0x55, 0x3D, 0x02, 0xC3, 0xA6, 0x92,
			0xE9, 0xC3, 0xEF, 0x8A, 0xB2, 0x34, 0x53, 0xE6,
			0xF0, 0x74, 0x9C, 0xD6, 0x36, 0xE7, 0xA8, 0x8E
		};
		static const uint8_t exp_out[] = {
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
			0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
			0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
		};
		uint8_t out[sizeof(exp_out)] = { };

		op.params[0].tmpref.buffer = (void *)in;
		op.params[0].tmpref.size = sizeof(in);
		op.params[1].tmpref.buffer = out;
		op.params[1].tmpref.size = sizeof(out);
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
						 TEEC_MEMREF_TEMP_OUTPUT,
						 TEEC_NONE, TEEC_NONE);

		(void)ADBG_EXPECT_TEEC_SUCCESS(cs->c,
				       TEEC_InvokeCommand(cs->session,
					cs->
					cmd_id_aes256ecb_decrypt,
					&op,
					&ret_orig));

		if (!ADBG_EXPECT(cs->c, 0,
				 memcmp(exp_out, out, sizeof(exp_out)))) {
			Do_ADBG_Log("exp_out:");
			Do_ADBG_HexLog(exp_out, sizeof(exp_out), 16);
			Do_ADBG_Log("out:");
			Do_ADBG_HexLog(out, sizeof(out), 16);
		}
	}
	Do_ADBG_EndSubCase(cs->c, "AES-256 ECB decrypt (32B, fixed key)");
}

static void xtest_tee_test_1001(ADBG_Case_t *c)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Session session = { };
	uint32_t ret_orig = 0;

	/* Pseudo TA is optional: warn and nicely exit if not found */
	res = xtest_teec_open_session(&session, &pta_invoke_tests_ta_uuid, NULL,
				      &ret_orig);
	if (res == TEEC_ERROR_ITEM_NOT_FOUND) {
		Do_ADBG_Log(" - 1001 -   skip test, pseudo TA not found");
		return;
	}
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		return;

	Do_ADBG_BeginSubCase(c, "Core self tests");

	res = TEEC_InvokeCommand(&session, PTA_INVOKE_TESTS_CMD_SELF_TESTS,
				 NULL, &ret_orig);
	ADBG_EXPECT_TEEC_SUCCESS(c, res);

	Do_ADBG_EndSubCase(c, "Core self tests");

	Do_ADBG_BeginSubCase(c, "Core dt_driver self tests");

	res = TEEC_InvokeCommand(&session, PTA_INVOKE_TESTS_CMD_DT_DRIVER_TESTS,
				 NULL, &ret_orig);
	ADBG_EXPECT_TEEC_SUCCESS(c, res);

	Do_ADBG_EndSubCase(c, "Core dt_driver self tests");

	Do_ADBG_BeginSubCase(c, "Core transfer list self tests");

	res = TEEC_InvokeCommand(&session,
				 PTA_INVOKE_TESTS_CMD_TRANSFER_LIST_TESTS, NULL,
				 &ret_orig);
	if (res == TEE_ERROR_NOT_SUPPORTED)
		Do_ADBG_Log("Transfer List tests not supported, skipping");
	else
		ADBG_EXPECT_TEEC_SUCCESS(c, res);

	Do_ADBG_EndSubCase(c, "Core transfer list self tests");

	TEEC_CloseSession(&session);
}
ADBG_CASE_DEFINE(regression, 1001, xtest_tee_test_1001, "Core self tests");

static void xtest_tee_test_1002(ADBG_Case_t *c)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Session session = { };
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig = 0;
	uint8_t buf[16 * 1024] = { };
	uint8_t exp_sum = 0;
	size_t n = 0;

	/* Pseudo TA is optional: warn and nicely exit if not found */
	res = xtest_teec_open_session(&session, &pta_invoke_tests_ta_uuid, NULL,
				      &ret_orig);
	if (res == TEEC_ERROR_ITEM_NOT_FOUND) {
		Do_ADBG_Log(" - 1002 -   skip test, pseudo TA not found");
		return;
	}
	ADBG_EXPECT_TEEC_SUCCESS(c, res);

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.size = sizeof(buf);
	op.params[0].tmpref.buffer = buf;

	for (n = 0; n < sizeof(buf); n++)
		buf[n] = n + 1;
	for (n = 0; n < sizeof(buf); n++)
		exp_sum += buf[n];

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, TEEC_InvokeCommand(
		&session, PTA_INVOKE_TESTS_CMD_PARAMS, &op, &ret_orig)))
		goto out;

	ADBG_EXPECT_COMPARE_SIGNED(c, exp_sum, ==, buf[0]);
out:
	TEEC_CloseSession(&session);
}
ADBG_CASE_DEFINE(regression, 1002, xtest_tee_test_1002, "PTA parameters");

struct test_1003_arg {
	uint32_t test_type;
	size_t repeat;
	size_t max_before_lockers;
	size_t max_during_lockers;
	size_t before_lockers;
	size_t during_lockers;
	TEEC_Result res;
	uint32_t error_orig;
};

static void *test_1003_thread(void *arg)
{
	struct test_1003_arg *a = arg;
	TEEC_Session session = { };
	size_t rounds = 64 * 1024;
	size_t n = 0;

	a->res = xtest_teec_open_session(&session, &pta_invoke_tests_ta_uuid,
					 NULL, &a->error_orig);
	if (a->res != TEEC_SUCCESS)
		return NULL;

	for (n = 0; n < a->repeat; n++) {
		TEEC_Operation op = TEEC_OPERATION_INITIALIZER;

		op.params[0].value.a = a->test_type;
		op.params[0].value.b = rounds;

		op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
						 TEEC_VALUE_OUTPUT,
						 TEEC_NONE, TEEC_NONE);
		a->res = TEEC_InvokeCommand(&session,
					    PTA_INVOKE_TESTS_CMD_MUTEX,
					    &op, &a->error_orig);
		if (a->test_type == PTA_MUTEX_TEST_WRITER &&
		    op.params[1].value.b != 1) {
			Do_ADBG_Log("n %zu %" PRIu32, n, op.params[1].value.b);
			a->res = TEEC_ERROR_BAD_STATE;
			a->error_orig = 42;
			break;
		}

		if (a->test_type == PTA_MUTEX_TEST_READER) {
			if (op.params[1].value.a > a->max_before_lockers)
				a->max_before_lockers = op.params[1].value.a;

			if (op.params[1].value.b > a->max_during_lockers)
				a->max_during_lockers = op.params[1].value.b;

			a->before_lockers += op.params[1].value.a;
			a->during_lockers += op.params[1].value.b;
		}
	}
	TEEC_CloseSession(&session);

	return NULL;
}

#define TEST_1003_THREAD_COUNT		(3 * 2)

static void xtest_tee_test_1003(ADBG_Case_t *c)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Session session = { };
	uint32_t ret_orig = 0;
	size_t repeat = 20;
	struct test_1003_arg arg[TEST_1003_THREAD_COUNT] = { };
	size_t max_read_concurrency = 0;
	size_t max_read_waiters = 0;
	size_t num_concurrent_read_lockers = 0;
	size_t num_concurrent_read_waiters = 0;
	size_t n = 0;
	size_t nt = TEST_1003_THREAD_COUNT;
	double mean_read_concurrency = 0;
	double mean_read_waiters = 0;
	size_t num_writers = 0;
	size_t num_readers = 0;
	pthread_t thr[TEST_1003_THREAD_COUNT] = { };

	/* Pseudo TA is optional: warn and nicely exit if not found */
	res = xtest_teec_open_session(&session, &pta_invoke_tests_ta_uuid, NULL,
				      &ret_orig);
	if (res == TEEC_ERROR_ITEM_NOT_FOUND) {
		Do_ADBG_Log(" - 1003 -   skip test, pseudo TA not found");
		return;
	}
	ADBG_EXPECT_TEEC_SUCCESS(c, res);
	TEEC_CloseSession(&session);

	for (n = 0; n < nt; n++) {
		if (n % 3) {
			arg[n].test_type = PTA_MUTEX_TEST_READER;
			num_readers++;
		} else {
			arg[n].test_type = PTA_MUTEX_TEST_WRITER;
			num_writers++;
		}
		arg[n].repeat = repeat;
		if (!ADBG_EXPECT(c, 0, pthread_create(thr + n, NULL,
						test_1003_thread, arg + n)))
			nt = n; /* break loop and start cleanup */
	}

	for (n = 0; n < nt; n++) {
		ADBG_EXPECT(c, 0, pthread_join(thr[n], NULL));
		if (!ADBG_EXPECT_TEEC_SUCCESS(c, arg[n].res))
			Do_ADBG_Log("error origin %" PRIu32,
				    arg[n].error_orig);
		if (arg[n].test_type == PTA_MUTEX_TEST_READER) {
			if (arg[n].max_during_lockers > max_read_concurrency)
				max_read_concurrency =
					arg[n].max_during_lockers;

			if (arg[n].max_before_lockers > max_read_waiters)
				max_read_waiters = arg[n].max_before_lockers;

			num_concurrent_read_lockers += arg[n].during_lockers;
			num_concurrent_read_waiters += arg[n].before_lockers;
		}
	}

	mean_read_concurrency = (double)num_concurrent_read_lockers /
				(double)(repeat * num_readers);
	mean_read_waiters = (double)num_concurrent_read_waiters /
			    (double)(repeat * num_readers);

	Do_ADBG_Log("    Number of parallel threads: %d (%zu writers and %zu readers)",
		    TEST_1003_THREAD_COUNT, num_writers, num_readers);
	Do_ADBG_Log("    Max read concurrency: %zu", max_read_concurrency);
	Do_ADBG_Log("    Max read waiters: %zu", max_read_waiters);
	Do_ADBG_Log("    Mean read concurrency: %g", mean_read_concurrency);
	Do_ADBG_Log("    Mean read waiting: %g", mean_read_waiters);
}
ADBG_CASE_DEFINE(regression, 1003, xtest_tee_test_1003,
		 "Core internal read/write mutex");

static void xtest_tee_test_1004(ADBG_Case_t *c)
{
	TEEC_Session session = { };
	uint32_t ret_orig = 0;
	struct xtest_crypto_session cs = { c, &session, TA_CRYPT_CMD_SHA256,
					   TA_CRYPT_CMD_AES256ECB_ENC,
					   TA_CRYPT_CMD_AES256ECB_DEC };

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, xtest_teec_open_session(
					      &session, &crypt_user_ta_uuid,
					      NULL, &ret_orig)))
		return;

	/* Run the "complete crypto test suite" */
	xtest_crypto_test(&cs);

	TEEC_CloseSession(&session);
}
ADBG_CASE_DEFINE(regression, 1004, xtest_tee_test_1004, "Test User Crypt TA");

static void xtest_tee_test_invalid_mem_access(ADBG_Case_t *c, unsigned int n)
{
	TEEC_Session session = { };
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig = 0;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		xtest_teec_open_session(&session, &os_test_ta_uuid, NULL,
		                        &ret_orig)))
		return;

	op.params[0].value.a = n;
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE,
					 TEEC_NONE);

	(void)ADBG_EXPECT_TEEC_RESULT(c,
		TEEC_ERROR_TARGET_DEAD,
		TEEC_InvokeCommand(&session, TA_OS_TEST_CMD_BAD_MEM_ACCESS, &op,
				   &ret_orig));

	(void)ADBG_EXPECT_TEEC_RESULT(c,
	        TEEC_ERROR_TARGET_DEAD,
	        TEEC_InvokeCommand(&session, TA_OS_TEST_CMD_BAD_MEM_ACCESS, &op,
					&ret_orig));

	(void)ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TEE, ret_orig);

	TEEC_CloseSession(&session);
}

static void xtest_tee_test_invalid_mem_access2(ADBG_Case_t *c, unsigned int n,
							       size_t size)
{
	TEEC_Session session = { };
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig = 0;
	TEEC_SharedMemory shm = { };

	shm.size = size;
	shm.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		TEEC_AllocateSharedMemory(&xtest_teec_ctx, &shm)))
		return;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		xtest_teec_open_session(&session, &os_test_ta_uuid, NULL,
		                        &ret_orig)))
		goto rel_shm;

	op.params[0].value.a = (uint32_t)n;
	op.params[1].memref.parent = &shm;
	op.params[1].memref.size = size;
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_MEMREF_WHOLE,
					 TEEC_NONE, TEEC_NONE);

	(void)ADBG_EXPECT_TEEC_RESULT(c,
		TEEC_ERROR_TARGET_DEAD,
		TEEC_InvokeCommand(&session, TA_OS_TEST_CMD_BAD_MEM_ACCESS, &op,
				   &ret_orig));

	(void)ADBG_EXPECT_TEEC_RESULT(c,
	        TEEC_ERROR_TARGET_DEAD,
	        TEEC_InvokeCommand(&session, TA_OS_TEST_CMD_BAD_MEM_ACCESS, &op,
					&ret_orig));

	(void)ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TEE, ret_orig);

	TEEC_CloseSession(&session);
rel_shm:
	TEEC_ReleaseSharedMemory(&shm);
}

static void xtest_tee_test_1005(ADBG_Case_t *c)
{
	uint32_t ret_orig = 0;
#define MAX_SESSIONS    3
	TEEC_Session sessions[MAX_SESSIONS];
	int i = 0;

	for (i = 0; i < MAX_SESSIONS; i++) {
		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			xtest_teec_open_session(&sessions[i],
						&concurrent_ta_uuid,
						NULL, &ret_orig)))
			break;
	}

	for (; --i >= 0; )
		TEEC_CloseSession(&sessions[i]);
}
ADBG_CASE_DEFINE(regression, 1005, xtest_tee_test_1005, "Many sessions");

static void xtest_tee_test_1006(ADBG_Case_t *c)
{
	TEEC_Session session = { };
	uint32_t ret_orig = 0;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint8_t buf[32] = { };

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		xtest_teec_open_session(&session, &os_test_ta_uuid, NULL,
					&ret_orig)))
		return;

	op.params[0].tmpref.buffer = buf;
	op.params[0].tmpref.size = sizeof(buf);
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	(void)ADBG_EXPECT_TEEC_SUCCESS(c,
		TEEC_InvokeCommand(&session, TA_OS_TEST_CMD_BASIC, &op,
				   &ret_orig));

	TEEC_CloseSession(&session);
}
ADBG_CASE_DEFINE(regression, 1006, xtest_tee_test_1006,
		"Test Basic OS features");

static void xtest_tee_test_1007(ADBG_Case_t *c)
{
	TEEC_Session session = { };
	uint32_t ret_orig = 0;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		xtest_teec_open_session(&session, &os_test_ta_uuid, NULL,
		                        &ret_orig)))
		return;

	(void)ADBG_EXPECT_TEEC_RESULT(c,
		TEEC_ERROR_TARGET_DEAD,
		TEEC_InvokeCommand(&session, TA_OS_TEST_CMD_PANIC, NULL,
				   &ret_orig));

	(void)ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TEE, ret_orig);

	(void)ADBG_EXPECT_TEEC_RESULT(c,
		TEEC_ERROR_TARGET_DEAD,
		TEEC_InvokeCommand(&session, TA_OS_TEST_CMD_INIT, NULL,
				   &ret_orig));

	(void)ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TEE, ret_orig);

	TEEC_CloseSession(&session);
}
ADBG_CASE_DEFINE(regression, 1007, xtest_tee_test_1007, "Test Panic");

#ifndef TA_DIR
# ifdef __ANDROID__
#define TA_DIR "/vendor/lib/optee_armtz"
# else
#define TA_DIR "/lib/optee_armtz"
# endif
#endif

static FILE *open_ta_file(const TEEC_UUID *uuid, const char *mode)
{
	char buf[PATH_MAX] = { };

	snprintf(buf, sizeof(buf),
		"%s/%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x.ta",
		TA_DIR, uuid->timeLow, uuid->timeMid, uuid->timeHiAndVersion,
		uuid->clockSeqAndNode[0], uuid->clockSeqAndNode[1],
		uuid->clockSeqAndNode[2], uuid->clockSeqAndNode[3],
		uuid->clockSeqAndNode[4], uuid->clockSeqAndNode[5],
		uuid->clockSeqAndNode[6], uuid->clockSeqAndNode[7]);

	return fopen(buf, mode);
}

static bool load_corrupt_ta(ADBG_Case_t *c, size_t offs, uint8_t mask)
{
	TEEC_Session session = { };
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	TEEC_UUID uuid = PTA_SECSTOR_TA_MGMT_UUID;
	TEEC_Result res = TEEC_ERROR_GENERIC;
	uint32_t ret_orig = 0;
	FILE *f = NULL;
	bool r = false;
	uint8_t *buf = NULL;
	size_t sz = 0;
	size_t fread_res = 0;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		xtest_teec_open_session(&session, &uuid, NULL, &ret_orig)))
		goto out;

	f = open_ta_file(&create_fail_test_ta_uuid, "rb");
	if (!ADBG_EXPECT_NOT_NULL(c, f))
		goto out;
	if (!ADBG_EXPECT_TRUE(c, !fseek(f, 0, SEEK_END)))
		goto out;
	sz = ftell(f);
	rewind(f);

	buf = malloc(sz);
	if (!ADBG_EXPECT_NOT_NULL(c, buf))
		goto out;

	fread_res = fread(buf, 1, sz, f);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, fread_res, ==, sz))
		goto out;

	fclose(f);
	f = NULL;

	buf[MIN(offs, sz)] ^= mask;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = buf;
	op.params[0].tmpref.size = sz;

	res = TEEC_InvokeCommand(&session, PTA_SECSTOR_TA_MGMT_BOOTSTRAP, &op,
				 &ret_orig);
	r = ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_SECURITY, res);
out:
	free(buf);
	if (f)
		fclose(f);
	TEEC_CloseSession(&session);
	return r;
}

static void test_1008_corrupt_ta(ADBG_Case_t *c)
{
	TEEC_UUID uuid = PTA_SECSTOR_TA_MGMT_UUID;
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Session session = { };
	uint32_t ret_orig = 0;

	res = xtest_teec_open_session(&session, &uuid, NULL, &ret_orig);
	if (res) {
		if (ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_ITEM_NOT_FOUND,
					    res))
			Do_ADBG_Log("PTA Secure Storage TA Management not found: skip test");
		return;
	}
	TEEC_CloseSession(&session);

	ADBG_EXPECT_TRUE(c,
		load_corrupt_ta(c, offsetof(struct shdr, magic), 1));
	ADBG_EXPECT_TRUE(c,
		load_corrupt_ta(c, offsetof(struct shdr, img_type), 1));
	ADBG_EXPECT_TRUE(c,
		load_corrupt_ta(c, offsetof(struct shdr, img_size), 1));
	ADBG_EXPECT_TRUE(c,
		load_corrupt_ta(c, offsetof(struct shdr, algo), 1));
	ADBG_EXPECT_TRUE(c,
		load_corrupt_ta(c, offsetof(struct shdr, hash_size), 1));
	ADBG_EXPECT_TRUE(c,
		load_corrupt_ta(c, offsetof(struct shdr, sig_size), 1));
	ADBG_EXPECT_TRUE(c,
		load_corrupt_ta(c, sizeof(struct shdr), 1)); /* hash */
	ADBG_EXPECT_TRUE(c,
		load_corrupt_ta(c, sizeof(struct shdr) + 32, 1)); /* sig */
	ADBG_EXPECT_TRUE(c, load_corrupt_ta(c, 3000, 1)); /* payload */
	ADBG_EXPECT_TRUE(c, load_corrupt_ta(c, 8000, 1)); /* payload */
}

static void xtest_tee_test_1008(ADBG_Case_t *c)
{
	TEEC_Session session = { };
	TEEC_Session session_crypt = { };
	uint32_t ret_orig = 0;

	Do_ADBG_BeginSubCase(c, "Invoke command");
	{
		if (ADBG_EXPECT_TEEC_SUCCESS(c,
			xtest_teec_open_session(&session, &os_test_ta_uuid,
			                        NULL, &ret_orig))) {

			(void)ADBG_EXPECT_TEEC_SUCCESS(c,
			    TEEC_InvokeCommand(&session, TA_OS_TEST_CMD_CLIENT,
			                       NULL, &ret_orig));
			TEEC_CloseSession(&session);
		}

	}
	Do_ADBG_EndSubCase(c, "Invoke command");

	Do_ADBG_BeginSubCase(c, "Invoke command with timeout");
	{
		TEEC_Operation op = TEEC_OPERATION_INITIALIZER;

		op.params[0].value.a = 2000;
		op.paramTypes = TEEC_PARAM_TYPES(
			TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);

		if (ADBG_EXPECT_TEEC_SUCCESS(c,
			xtest_teec_open_session(&session,
						&os_test_ta_uuid,
						NULL,
			                        &ret_orig))) {

			(void)ADBG_EXPECT_TEEC_SUCCESS(c,
			  TEEC_InvokeCommand(&session,
			                     TA_OS_TEST_CMD_CLIENT_WITH_TIMEOUT,
			                     &op, &ret_orig));
			TEEC_CloseSession(&session);
		}
	}
	Do_ADBG_EndSubCase(c, "Invoke command with timeout");

	Do_ADBG_BeginSubCase(c, "Create session fail");
	{
		size_t n = 0;

		for (n = 0; n < 100; n++) {
			Do_ADBG_Log("n = %zu", n);
			(void)ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_GENERIC,
				xtest_teec_open_session(&session_crypt,
					&create_fail_test_ta_uuid,
					NULL, &ret_orig));
			/* level > 0 may be used to detect/debug memory leaks */
			if (!level)
				break;
		}
	}
	Do_ADBG_EndSubCase(c, "Create session fail");

	Do_ADBG_BeginSubCase(c, "Load corrupt TA");
	test_1008_corrupt_ta(c);
	Do_ADBG_EndSubCase(c, "Load corrupt TA");
}
ADBG_CASE_DEFINE(regression, 1008, xtest_tee_test_1008,
		"TEE internal client API");

static void *cancellation_thread(void *arg)
{
	/*
	 * Sleep 0.5 seconds before cancellation to make sure that the other
	 * thread is in RPC_WAIT.
	 */
	(void)usleep(500000);
	TEEC_RequestCancellation(arg);
	return NULL;
}

static void xtest_tee_test_1009_subcase(ADBG_Case_t *c, const char *subcase,
                                        uint32_t timeout, bool cancel)
{
	TEEC_Session session = { };
	uint32_t ret_orig = 0;
	pthread_t thr;

	memset(&thr, 0, sizeof(thr));

	Do_ADBG_BeginSubCase(c, "%s", subcase);
	{
		TEEC_Operation op = TEEC_OPERATION_INITIALIZER;

		if (ADBG_EXPECT_TEEC_SUCCESS(c,
		         xtest_teec_open_session(&session, &os_test_ta_uuid,
		                                 NULL, &ret_orig))) {

			(void)ADBG_EXPECT_TEEC_ERROR_ORIGIN(c,
			           TEEC_ORIGIN_TRUSTED_APP,
			           ret_orig);

			op.params[0].value.a = timeout;
			op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
			                                 TEEC_NONE,
			                                 TEEC_NONE, TEEC_NONE);
			if (cancel) {
				(void)ADBG_EXPECT(c, 0,
				      pthread_create(&thr, NULL,
				                     cancellation_thread, &op));

				(void)ADBG_EXPECT_TEEC_RESULT(c,
				           TEEC_ERROR_CANCEL,
			                   TEEC_InvokeCommand(&session,
			                                 TA_OS_TEST_CMD_WAIT,
			                                  &op,
			                                  &ret_orig));
			} else

			(void)ADBG_EXPECT_TEEC_SUCCESS(c,
			           TEEC_InvokeCommand(&session,
			                              TA_OS_TEST_CMD_WAIT,
			                              &op,
			                              &ret_orig));
			if (cancel)
				(void)ADBG_EXPECT(c, 0, pthread_join(thr, NULL));

			TEEC_CloseSession(&session);
		}
	}
	Do_ADBG_EndSubCase(c, "%s", subcase);
}

static void xtest_tee_test_1009(ADBG_Case_t *c)
{
	xtest_tee_test_1009_subcase(c, "TEE Wait 0.1s", 100, false);
	xtest_tee_test_1009_subcase(c, "TEE Wait 0.5s", 500, false);
	xtest_tee_test_1009_subcase(c, "TEE Wait 2s cancel", 2000, true);
	xtest_tee_test_1009_subcase(c, "TEE Wait 2s", 2000, false);
}
ADBG_CASE_DEFINE(regression, 1009, xtest_tee_test_1009, "TEE Wait");

static void xtest_tee_test_1010(ADBG_Case_t *c)
{
	unsigned int n = 0;
	unsigned int idx = 0;
	size_t memref_sz[] = { 1024, 65536 };

	for (n = 1; n <= 7; n++) {
		Do_ADBG_BeginSubCase(c, "Invalid memory access %u", n);
		xtest_tee_test_invalid_mem_access(c, n);
		Do_ADBG_EndSubCase(c, "Invalid memory access %u", n);
	}

	for (idx = 0; idx < ARRAY_SIZE(memref_sz); idx++) {
		for (n = 1; n <= 5; n++) {
			Do_ADBG_BeginSubCase(c,
				"Invalid memory access %u with %zu bytes memref",
				n, memref_sz[idx]);
			xtest_tee_test_invalid_mem_access2(c, n, memref_sz[idx]);
			Do_ADBG_EndSubCase(c,
				"Invalid memory access %u with %zu bytes memref",
				n, memref_sz[idx]);
		}
	}
}
ADBG_CASE_DEFINE(regression, 1010, xtest_tee_test_1010,
		"Invalid memory access");

static void xtest_tee_test_1011(ADBG_Case_t *c)
{
	TEEC_Session session = { };
	uint32_t ret_orig = 0;
	struct xtest_crypto_session cs = {
		c, &session, TA_RPC_CMD_CRYPT_SHA256,
		TA_RPC_CMD_CRYPT_AES256ECB_ENC,
		TA_RPC_CMD_CRYPT_AES256ECB_DEC
	};
	struct xtest_crypto_session cs_privmem = {
		c, &session,
		TA_RPC_CMD_CRYPT_PRIVMEM_SHA256,
		TA_RPC_CMD_CRYPT_PRIVMEM_AES256ECB_ENC,
		TA_RPC_CMD_CRYPT_PRIVMEM_AES256ECB_DEC
	};
	TEEC_UUID uuid = rpc_test_ta_uuid;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		xtest_teec_open_session(&session, &uuid, NULL, &ret_orig)))
		return;

	Do_ADBG_BeginSubCase(c, "TA-to-TA via non-secure shared memory");
	/*
	 * Run the "complete crypto test suite" using TA-to-TA
	 * communication
	 */
	xtest_crypto_test(&cs);
	Do_ADBG_EndSubCase(c, "TA-to-TA via non-secure shared memory");

	Do_ADBG_BeginSubCase(c, "TA-to-TA via TA private memory");
	/*
	 * Run the "complete crypto test suite" using TA-to-TA
	 * communication via TA private memory.
	 */
	xtest_crypto_test(&cs_privmem);
	Do_ADBG_EndSubCase(c, "TA-to-TA via TA private memory");

	TEEC_CloseSession(&session);
}
ADBG_CASE_DEFINE(regression, 1011, xtest_tee_test_1011,
		"Test TA-to-TA features with User Crypt TA");

/*
 * Note that this test is failing when
 * - running twice in a raw
 * - and the user TA is statically linked
 * This is because the counter is not reseted when opening the first session
 * in case the TA is statically linked
 */
static void xtest_tee_test_1012(ADBG_Case_t *c)
{
	TEEC_Session session1 = { };
	TEEC_Session session2 = { };
	uint32_t ret_orig = 0;
	TEEC_UUID uuid = sims_test_ta_uuid;

	Do_ADBG_BeginSubCase(c, "Single Instance Multi Session");
	{
		TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
		static const uint8_t in[] = {
			0x5A, 0x6E, 0x04, 0x57, 0x08, 0xFB, 0x71, 0x96,
			0xF0, 0x2E, 0x55, 0x3D, 0x02, 0xC3, 0xA6, 0x92,
			0xE9, 0xC3, 0xEF, 0x8A, 0xB2, 0x34, 0x53, 0xE6,
			0xF0, 0x74, 0x9C, 0xD6, 0x36, 0xE7, 0xA8, 0x8E
		};
		uint8_t out[32] = { };
		int i = 0;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			xtest_teec_open_session(&session1, &uuid, NULL,
			                        &ret_orig)))
			return;

		op.params[0].value.a = 0;
		op.params[1].tmpref.buffer = (void *)in;
		op.params[1].tmpref.size = sizeof(in);
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
						 TEEC_MEMREF_TEMP_INPUT,
						 TEEC_NONE, TEEC_NONE);

		(void)ADBG_EXPECT_TEEC_SUCCESS(c,
			TEEC_InvokeCommand(&session1, TA_SIMS_CMD_WRITE, &op,
					   &ret_orig));

		for (i = 1; i < 3; i++) {
			if (!ADBG_EXPECT_TEEC_SUCCESS(c,
				xtest_teec_open_session(&session2, &uuid, NULL,
				                        &ret_orig)))
				continue;

			op.params[0].value.a = 0;
			op.params[1].tmpref.buffer = out;
			op.params[1].tmpref.size = sizeof(out);
			op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
						TEEC_MEMREF_TEMP_OUTPUT,
						TEEC_NONE, TEEC_NONE);

			(void)ADBG_EXPECT_TEEC_SUCCESS(c,
				TEEC_InvokeCommand(&session2, TA_SIMS_CMD_READ,
						   &op, &ret_orig));

			if (!ADBG_EXPECT_BUFFER(c, in, sizeof(in), out,
						sizeof(out))) {
				Do_ADBG_Log("in:");
				Do_ADBG_HexLog(in, sizeof(in), 16);
				Do_ADBG_Log("out:");
				Do_ADBG_HexLog(out, sizeof(out), 16);
			}

			op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT,
							 TEEC_NONE, TEEC_NONE,
							 TEEC_NONE);

			(void)ADBG_EXPECT_TEEC_SUCCESS(c,
				TEEC_InvokeCommand(&session1,
						   TA_SIMS_CMD_GET_COUNTER,
						   &op, &ret_orig));

			(void)ADBG_EXPECT(c, 0, op.params[0].value.a);

			(void)ADBG_EXPECT_TEEC_SUCCESS(c,
				TEEC_InvokeCommand(&session2,
						   TA_SIMS_CMD_GET_COUNTER, &op,
						   &ret_orig));

			(void)ADBG_EXPECT(c, i, op.params[0].value.a);
			TEEC_CloseSession(&session2);
		}

		memset(out, 0, sizeof(out));
		op.params[0].value.a = 0;
		op.params[1].tmpref.buffer = out;
		op.params[1].tmpref.size = sizeof(out);
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
						 TEEC_MEMREF_TEMP_OUTPUT,
						 TEEC_NONE, TEEC_NONE);

		(void)ADBG_EXPECT_TEEC_SUCCESS(c,
			TEEC_InvokeCommand(&session1, TA_SIMS_CMD_READ, &op,
					   &ret_orig));

		if (!ADBG_EXPECT(c, 0, memcmp(in, out, sizeof(in)))) {
			Do_ADBG_Log("in:");
			Do_ADBG_HexLog(in, sizeof(in), 16);
			Do_ADBG_Log("out:");
			Do_ADBG_HexLog(out, sizeof(out), 16);
		}

		TEEC_CloseSession(&session1);
	}
	Do_ADBG_EndSubCase(c, "Single Instance Multi Session");
}
ADBG_CASE_DEFINE(regression, 1012, xtest_tee_test_1012,
		"Test Single Instance Multi Session features with SIMS TA");

struct test_1013_thread_arg {
	const TEEC_UUID *uuid;
	uint32_t cmd;
	uint32_t repeat;
	TEEC_SharedMemory *shm;
	uint32_t error_orig;
	TEEC_Result res;
	uint32_t max_concurrency;
	const uint8_t *in;
	size_t in_len;
	uint8_t *out;
	size_t out_len;
};

static void *test_1013_thread(void *arg)
{
	struct test_1013_thread_arg *a = arg;
	TEEC_Session session = { };
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint8_t p2 = TEEC_NONE;
	uint8_t p3 = TEEC_NONE;

	a->res = xtest_teec_open_session(&session, a->uuid, NULL,
					 &a->error_orig);
	if (a->res != TEEC_SUCCESS)
		return NULL;

	op.params[0].memref.parent = a->shm;
	op.params[0].memref.size = a->shm->size;
	op.params[0].memref.offset = 0;
	op.params[1].value.a = a->repeat;
	op.params[1].value.b = 0;
	op.params[2].tmpref.buffer = (void *)a->in;
	op.params[2].tmpref.size = a->in_len;
	op.params[3].tmpref.buffer = a->out;
	op.params[3].tmpref.size = a->out_len;

	if (a->in_len)
		p2 = TEEC_MEMREF_TEMP_INPUT;
	if (a->out_len)
		p3 = TEEC_MEMREF_TEMP_OUTPUT;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INOUT,
					 TEEC_VALUE_INOUT, p2, p3);

	a->res = TEEC_InvokeCommand(&session, a->cmd, &op, &a->error_orig);
	a->max_concurrency = op.params[1].value.b;
	a->out_len = op.params[3].tmpref.size;
	TEEC_CloseSession(&session);
	return NULL;
}

#define NUM_THREADS 3

static void xtest_tee_test_1013_single(ADBG_Case_t *c, double *mean_concurrency,
				       const TEEC_UUID *uuid)
{
	size_t nt = 0;
	size_t n = 0;
	size_t repeat = 1000;
	TEEC_SharedMemory shm = { };
	size_t max_concurrency = 0;
	struct test_1013_thread_arg arg[NUM_THREADS] = { };
	static const uint8_t sha256_in[] = { 'a', 'b', 'c' };
	static const uint8_t sha256_out[] = {
		0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
		0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
		0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
		0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
	};
	uint8_t out[32] = { };
	pthread_t thr[NUM_THREADS] = { };
	bool skip = false;

	/* Decrease number of loops when pager has a small page pool */
	if (level == 0 && optee_pager_with_small_pool())
		repeat = 250;

	Do_ADBG_BeginSubCase(c, "Busy loop repeat %zu", repeat * 10);
	*mean_concurrency = 0;

	shm.size = sizeof(struct ta_concurrent_shm);
	shm.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		TEEC_AllocateSharedMemory(&xtest_teec_ctx, &shm)))
		return;

	memset(shm.buffer, 0, shm.size);
	max_concurrency = 0;
	nt = NUM_THREADS;

	for (n = 0; n < nt; n++) {
		arg[n].uuid = uuid;
		arg[n].cmd = TA_CONCURRENT_CMD_BUSY_LOOP;
		arg[n].repeat = repeat * 10;
		arg[n].shm = &shm;
		if (!ADBG_EXPECT(c, 0, pthread_create(thr + n, NULL,
						test_1013_thread, arg + n)))
			nt = n; /* break loop and start cleanup */
	}

	for (n = 0; n < nt; n++) {
		ADBG_EXPECT(c, 0, pthread_join(thr[n], NULL));
		if (arg[n].res == TEEC_ERROR_OUT_OF_MEMORY &&
		    !memcmp(uuid, &concurrent_large_ta_uuid, sizeof(*uuid))) {
			Do_ADBG_Log("TEEC_ERROR_OUT_OF_MEMORY - ignored");
			skip = true;
			continue;
		}
		ADBG_EXPECT_TEEC_SUCCESS(c, arg[n].res);
		if (arg[n].max_concurrency > max_concurrency)
			max_concurrency = arg[n].max_concurrency;
	}

	/*
	 * Concurrency can be limited by several factors, for instance in a
	 * single CPU system it's dependent on the Preemption Model used by
	 * the kernel (Preemptible Kernel (Low-Latency Desktop) gives the
	 * best result there).
	 */
	if (!skip) {
		(void)ADBG_EXPECT_COMPARE_UNSIGNED(c, max_concurrency, >, 0);
		(void)ADBG_EXPECT_COMPARE_UNSIGNED(c, max_concurrency, <=,
						   NUM_THREADS);
		*mean_concurrency += max_concurrency;
	}
	Do_ADBG_EndSubCase(c, "Busy loop repeat %zu", repeat * 10);

	Do_ADBG_BeginSubCase(c, "SHA-256 loop repeat %zu", repeat);
	memset(shm.buffer, 0, shm.size);
	memset(arg, 0, sizeof(arg));
	max_concurrency = 0;
	nt = NUM_THREADS;

	for (n = 0; n < nt; n++) {
		arg[n].uuid = uuid;
		arg[n].cmd = TA_CONCURRENT_CMD_SHA256;
		arg[n].repeat = repeat;
		arg[n].shm = &shm;
		arg[n].in = sha256_in;
		arg[n].in_len = sizeof(sha256_in);
		arg[n].out = out;
		arg[n].out_len = sizeof(out);
		if (!ADBG_EXPECT(c, 0, pthread_create(thr + n, NULL,
						test_1013_thread, arg + n)))
			nt = n; /* break loop and start cleanup */
	}

	for (n = 0; n < nt; n++) {
		ADBG_EXPECT(c, 0, pthread_join(thr[n], NULL));
		if (arg[n].res == TEEC_ERROR_OUT_OF_MEMORY &&
		    !memcmp(uuid, &concurrent_large_ta_uuid, sizeof(*uuid))) {
			Do_ADBG_Log("TEEC_ERROR_OUT_OF_MEMORY - ignored");
			continue;
		}
		if (ADBG_EXPECT_TEEC_SUCCESS(c, arg[n].res))
			ADBG_EXPECT_BUFFER(c, sha256_out, sizeof(sha256_out),
					   arg[n].out, arg[n].out_len);
		if (arg[n].max_concurrency > max_concurrency)
			max_concurrency = arg[n].max_concurrency;
	}
	*mean_concurrency += max_concurrency;
	Do_ADBG_EndSubCase(c, "SHA-256 loop repeat %zu", repeat);

	*mean_concurrency /= 2.0;
	TEEC_ReleaseSharedMemory(&shm);
}

static void xtest_tee_test_1013(ADBG_Case_t *c)
{
	int i = 0;
	double mean_concurrency = 0;
	double concurrency = 0;
	int nb_loops = 24;

	if (level == 0)
		nb_loops /= 2;

	Do_ADBG_BeginSubCase(c, "Using small concurrency TA");
	mean_concurrency = 0;
	for (i = 0; i < nb_loops; i++) {
		xtest_tee_test_1013_single(c, &concurrency,
					   &concurrent_ta_uuid);
		mean_concurrency += concurrency;
	}
	mean_concurrency /= nb_loops;

	Do_ADBG_Log("    Number of parallel threads: %d", NUM_THREADS);
	Do_ADBG_Log("    Mean concurrency: %g", mean_concurrency);
	Do_ADBG_EndSubCase(c, "Using small concurrency TA");

	Do_ADBG_BeginSubCase(c, "Using large concurrency TA");
	mean_concurrency = 0;
	for (i = 0; i < nb_loops; i++) {
		xtest_tee_test_1013_single(c, &concurrency,
					   &concurrent_large_ta_uuid);
		mean_concurrency += concurrency;
	}
	mean_concurrency /= nb_loops;

	Do_ADBG_Log("    Number of parallel threads: %d", NUM_THREADS);
	Do_ADBG_Log("    Mean concurrency: %g", mean_concurrency);
	Do_ADBG_EndSubCase(c, "Using large concurrency TA");
}
ADBG_CASE_DEFINE(regression, 1013, xtest_tee_test_1013,
		"Test concurrency with concurrent TA");

#ifdef CFG_SECURE_DATA_PATH
static void xtest_tee_test_1014(ADBG_Case_t *c)
{
	UNUSED(c);

	int size = 17000;
	int loop = 10;
	const char *heap_name = DEFAULT_HEAP_NAME;
	int rnd_offset = 1;
	int test = 0;
	int ret = 0;

	test = TEST_NS_TO_TA;
	Do_ADBG_BeginSubCase(c, "SDP: NonSecure client invokes a SDP TA");
	ret = sdp_basic_test(test, size, loop, heap_name, rnd_offset, 0);
	ADBG_EXPECT(c, 0, ret);
	Do_ADBG_EndSubCase(c, "SDP: NonSecure client invokes a SDP TA");

	test = TEST_TA_TO_TA;
	Do_ADBG_BeginSubCase(c, "SDP: SDP TA invokes a SDP TA");
	ret = sdp_basic_test(test, size, loop, heap_name, rnd_offset, 0);
	ADBG_EXPECT(c, 0, ret);
	Do_ADBG_EndSubCase(c, "SDP: SDP TA invokes a SDP TA");

	test = TEST_TA_TO_PTA;
	Do_ADBG_BeginSubCase(c, "SDP: SDP TA invokes a test pTA (invoke_tests.pta)");
	ret = sdp_basic_test(test, size, loop, heap_name, rnd_offset, 0);
	ADBG_EXPECT(c, 0, ret);
	Do_ADBG_EndSubCase(c, "SDP: SDP TA invokes a test pTA (invoke_tests.pta)");

	test = TEST_NS_TO_PTA;
	Do_ADBG_BeginSubCase(c, "SDP: NSec CA invokes a test pTA (invoke_tests.pta) (should fail)");
	ret = sdp_basic_test(test, size, loop, heap_name, rnd_offset, 0);
	ADBG_EXPECT(c, 1, ret);
	Do_ADBG_EndSubCase(c, "SDP: NSec CA invokes a test pTA (invoke_tests.pta) (should fail)");

	Do_ADBG_BeginSubCase(c, "SDP: Invoke TA with out of bounds SDP memref");
	ret = sdp_out_of_bounds_memref_test(size, heap_name, 0);
	ADBG_EXPECT(c, 0, ret);
	Do_ADBG_EndSubCase(c, NULL);
}
ADBG_CASE_DEFINE(regression, 1014, xtest_tee_test_1014,
		"Test secure data path against SDP TAs and pTAs");
#endif /*CFG_SECURE_DATA_PATH*/

#ifdef CFG_REE_FS
static void xtest_tee_test_1015(ADBG_Case_t *c)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Session session = { };
	uint32_t ret_orig = 0;

	/* Pseudo TA is optional: warn and nicely exit if not found */
	res = xtest_teec_open_session(&session, &pta_invoke_tests_ta_uuid, NULL,
				      &ret_orig);
	if (res == TEEC_ERROR_ITEM_NOT_FOUND) {
		Do_ADBG_Log(" - 1015 -   skip test, pseudo TA not found");
		return;
	}
	ADBG_EXPECT_TEEC_SUCCESS(c, res);

	ADBG_EXPECT_TEEC_SUCCESS(c,
		TEEC_InvokeCommand(&session, PTA_INVOKE_TESTS_CMD_FS_HTREE,
				   NULL, &ret_orig));
	TEEC_CloseSession(&session);
}
ADBG_CASE_DEFINE(regression, 1015, xtest_tee_test_1015,
		"FS hash-tree corner cases");
#endif /*CFG_REE_FS*/

static void xtest_tee_test_1016(ADBG_Case_t *c)
{
	TEEC_Session session = { };
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig = 0;
	int dummy = 0;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		xtest_teec_open_session(&session, &os_test_ta_uuid, NULL,
		                        &ret_orig)))
		return;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE,
					 TEEC_NONE);

	(void)ADBG_EXPECT_TEEC_SUCCESS(c,
		TEEC_InvokeCommand(&session, TA_OS_TEST_CMD_TA2TA_MEMREF, &op,
				   &ret_orig));

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_INOUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE);

	op.params[0].tmpref.buffer = &dummy;
	op.params[0].tmpref.size = 0;

	op.params[1].tmpref.buffer = &dummy;
	op.params[1].tmpref.size = 0;

	op.params[2].tmpref.buffer = &dummy;
	op.params[2].tmpref.size = 0;

	(void)ADBG_EXPECT_TEEC_SUCCESS(c,
		TEEC_InvokeCommand(&session, TA_OS_TEST_CMD_TA2TA_MEMREF_SIZE0,
				   &op, &ret_orig));

	TEEC_CloseSession(&session);
}
ADBG_CASE_DEFINE(regression, 1016, xtest_tee_test_1016,
		"Test TA to TA transfers (in/out/inout memrefs on the stack)");

static void xtest_tee_test_1017(ADBG_Case_t *c)
{
	TEEC_Session session = { };
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig = 0;
	TEEC_SharedMemory shm = { };
	size_t page_size = 4096;

	shm.size = 8 * page_size;
	shm.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		TEEC_AllocateSharedMemory(&xtest_teec_ctx, &shm)))
		return;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		xtest_teec_open_session(&session, &os_test_ta_uuid, NULL,
		                        &ret_orig)))
		goto out;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INPUT,
					 TEEC_MEMREF_PARTIAL_INPUT,
					 TEEC_MEMREF_PARTIAL_OUTPUT,
					 TEEC_MEMREF_PARTIAL_OUTPUT);

	/*
	 * The first two memrefs are supposed to be combined into in
	 * region and the last two memrefs should have one region each
	 * when the parameters are mapped for the TA.
	 */
	op.params[0].memref.parent = &shm;
	op.params[0].memref.size = page_size;
	op.params[0].memref.offset = 0;

	op.params[1].memref.parent = &shm;
	op.params[1].memref.size = page_size;
	op.params[1].memref.offset = page_size;

	op.params[2].memref.parent = &shm;
	op.params[2].memref.size = page_size;
	op.params[2].memref.offset = 4 * page_size;

	op.params[3].memref.parent = &shm;
	op.params[3].memref.size = 2 * page_size;
	op.params[3].memref.offset = 6 * page_size;

	(void)ADBG_EXPECT_TEEC_SUCCESS(c,
		TEEC_InvokeCommand(&session, TA_OS_TEST_CMD_PARAMS, &op,
				   &ret_orig));

	TEEC_CloseSession(&session);
out:
	TEEC_ReleaseSharedMemory(&shm);
}
ADBG_CASE_DEFINE(regression, 1017, xtest_tee_test_1017,
		"Test coalescing memrefs");

static void invoke_1byte_out_of_bounds(ADBG_Case_t *c, TEEC_Session *session,
				       TEEC_SharedMemory *shm)
{
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	TEEC_Result ret = TEEC_ERROR_GENERIC;
	uint32_t ret_orig = 0;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INPUT,
					 TEEC_NONE, TEEC_NONE, TEEC_NONE);

	op.params[0].memref.parent = shm;
	op.params[0].memref.size = shm->size / 2;
	op.params[0].memref.offset = shm->size - (shm->size / 2) + 1;

	ret = TEEC_InvokeCommand(session, TA_OS_TEST_CMD_PARAMS,
				 &op, &ret_orig);

	ADBG_EXPECT_COMPARE_UNSIGNED(c, ret_orig, !=, TEEC_ORIGIN_TRUSTED_APP);
	if (ret != TEEC_ERROR_BAD_PARAMETERS && ret != TEEC_ERROR_GENERIC) {
		ADBG_EXPECT(c, TEEC_ERROR_BAD_PARAMETERS, ret);
		ADBG_EXPECT(c, TEEC_ERROR_GENERIC, ret);
	}
}

static void xtest_tee_test_1018(ADBG_Case_t *c)
{
	TEEC_Session session = { };
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig = 0;
	TEEC_SharedMemory shm = { };
	TEEC_Result ret = TEEC_ERROR_GENERIC;
	size_t page_size = 4096;
	/* Intentionally not 4kB aligned and odd */
	uint8_t buffer[6001] = { };

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
				      xtest_teec_open_session(&session,
							      &os_test_ta_uuid,
							      NULL,
							      &ret_orig)))
		return;

	Do_ADBG_BeginSubCase(c, "Out of bounds > 4kB on allocated shm");

	shm.size = 8 * page_size;
	shm.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
				      TEEC_AllocateSharedMemory(&xtest_teec_ctx,
								&shm)))
		goto out;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INPUT,
					 TEEC_MEMREF_PARTIAL_INPUT,
					 TEEC_MEMREF_PARTIAL_OUTPUT,
					 TEEC_MEMREF_PARTIAL_OUTPUT);

	/*
	 * The first two memrefs are supposed to be combined into in
	 * region and the last two memrefs should have one region each
	 * when the parameters are mapped for the TA.
	 */
	op.params[0].memref.parent = &shm;
	op.params[0].memref.size = page_size;
	op.params[0].memref.offset = 0;

	op.params[1].memref.parent = &shm;
	op.params[1].memref.size = page_size;
	op.params[1].memref.offset = page_size;

	op.params[2].memref.parent = &shm;
	op.params[2].memref.size = page_size;
	op.params[2].memref.offset = 4 * page_size;

	op.params[3].memref.parent = &shm;
	op.params[3].memref.size = 3 * page_size;
	op.params[3].memref.offset = 6 * page_size;

	ret = TEEC_InvokeCommand(&session, TA_OS_TEST_CMD_PARAMS, &op,
				 &ret_orig);

	ADBG_EXPECT_COMPARE_UNSIGNED(c, ret_orig, !=, TEEC_ORIGIN_TRUSTED_APP);
	if (ret != TEEC_ERROR_BAD_PARAMETERS && ret != TEEC_ERROR_GENERIC) {
		ADBG_EXPECT(c, TEEC_ERROR_BAD_PARAMETERS, ret);
		ADBG_EXPECT(c, TEEC_ERROR_GENERIC, ret);
	}

	TEEC_ReleaseSharedMemory(&shm);
	Do_ADBG_EndSubCase(c, NULL);

	Do_ADBG_BeginSubCase(c, "Out of bounds by 1 byte on registered shm");

	memset(&shm, 0, sizeof(shm));
	shm.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
	shm.buffer = buffer;
	shm.size = sizeof(buffer);

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
				      TEEC_RegisterSharedMemory(&xtest_teec_ctx,
								&shm)))
		goto out;

	invoke_1byte_out_of_bounds(c, &session, &shm);

	TEEC_ReleaseSharedMemory(&shm);
	Do_ADBG_EndSubCase(c, NULL);

	Do_ADBG_BeginSubCase(c, "Out of bounds by 1 byte ref on allocated shm");

	memset(&shm, 0, sizeof(shm));
	shm.size = sizeof(buffer);
	shm.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
				      TEEC_AllocateSharedMemory(&xtest_teec_ctx,
								&shm)))
		goto out;

	invoke_1byte_out_of_bounds(c, &session, &shm);

	TEEC_ReleaseSharedMemory(&shm);
	Do_ADBG_EndSubCase(c, NULL);

out:
	TEEC_CloseSession(&session);
}
ADBG_CASE_DEFINE(regression, 1018, xtest_tee_test_1018,
		"Test memref out of bounds");

static void xtest_tee_test_1019(ADBG_Case_t *c)
{
	TEEC_Session session = { };
	uint32_t ret_orig = 0;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		xtest_teec_open_session(&session, &os_test_ta_uuid, NULL,
		                        &ret_orig)))
		return;

	(void)ADBG_EXPECT_TEEC_SUCCESS(c,
		TEEC_InvokeCommand(&session, TA_OS_TEST_CMD_CALL_LIB, NULL,
				   &ret_orig));

	(void)ADBG_EXPECT_TEEC_RESULT(c,
		TEEC_ERROR_TARGET_DEAD,
		TEEC_InvokeCommand(&session, TA_OS_TEST_CMD_CALL_LIB_PANIC,
				   NULL, &ret_orig));

	(void)ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TEE, ret_orig);

	TEEC_CloseSession(&session);
}
ADBG_CASE_DEFINE(regression, 1019, xtest_tee_test_1019,
		"Test dynamically linked TA");

static void xtest_tee_test_1020(ADBG_Case_t *c)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Session session = { };
	uint32_t ret_orig = 0;

	/* Pseudo TA is optional: warn and nicely exit if not found */
	res = xtest_teec_open_session(&session, &pta_invoke_tests_ta_uuid, NULL,
				      &ret_orig);
	if (res == TEEC_ERROR_ITEM_NOT_FOUND) {
		Do_ADBG_Log(" - 1020 -   skip test, pseudo TA not found");
		return;
	}
	ADBG_EXPECT_TEEC_SUCCESS(c, res);

	res = TEEC_InvokeCommand(&session, PTA_INVOKE_TESTS_CMD_LOCKDEP,
				 NULL, &ret_orig);
	if (res != TEEC_SUCCESS) {
		(void)ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TRUSTED_APP,
						    ret_orig);
		if (res == TEEC_ERROR_NOT_SUPPORTED) {
			Do_ADBG_Log(" - 1020 -   skip test, feature not "
				    "implemented");
			goto out;
		}
		/* Error */
		(void)ADBG_EXPECT_TEEC_SUCCESS(c, res);
	}
out:
	TEEC_CloseSession(&session);
}
ADBG_CASE_DEFINE(regression, 1020, xtest_tee_test_1020,
		"Test lockdep algorithm");

static TEEC_Result open_sec_session(TEEC_Session *session,
				    const TEEC_UUID *uuid)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig = 0;

	op.params[0].tmpref.buffer = (void *)uuid;
	op.params[0].tmpref.size = sizeof(*uuid);
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_NONE, TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(session, TA_SIMS_OPEN_TA_SESSION,
				 &op, &ret_orig);
	if (res != TEEC_SUCCESS)
		return TEEC_ERROR_GENERIC;

	return res;
}

static TEEC_Result sims_get_counter(TEEC_Session *session,
				    uint32_t *counter)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig = 0;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT,
					 TEEC_NONE, TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(session, TA_SIMS_CMD_GET_COUNTER,
				 &op, &ret_orig);
	if (res == TEEC_SUCCESS)
		*counter = op.params[0].value.a;

	return res;
}

static TEEC_Result trigger_panic(TEEC_Session *session,
				 const TEEC_UUID *uuid)
{
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig = 0;

	if (!uuid) {
		op.params[0].tmpref.buffer = NULL;
		op.params[0].tmpref.size = 0;
	} else {
		op.params[0].tmpref.buffer = (void *)uuid;
		op.params[0].tmpref.size = sizeof(*uuid);
	}
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_NONE, TEEC_NONE, TEEC_NONE);

	return TEEC_InvokeCommand(session, TA_SIMS_CMD_PANIC,
				  &op, &ret_orig);
}

static void test_panic_ca_to_ta(ADBG_Case_t *c, const TEEC_UUID *uuid,
				bool multi_instance)
{
	TEEC_Result exp_res = TEEC_ERROR_GENERIC;
	uint32_t counter = 0;
	uint32_t ret_orig = 0;
	uint32_t exp_counter = 0;
	TEEC_Session cs[3] = { };

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			xtest_teec_open_session(&cs[0], uuid, NULL,
						&ret_orig)))
		return;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			xtest_teec_open_session(&cs[1], uuid, NULL,
						&ret_orig)))
		goto bail0;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, sims_get_counter(&cs[0], &counter)))
		goto bail1;

	if (!ADBG_EXPECT(c, 0, counter))
		goto bail1;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, sims_get_counter(&cs[1], &counter)))
		goto bail1;

	exp_counter = multi_instance ? 0 : 1;
	if (!ADBG_EXPECT(c, exp_counter, counter))
		goto bail1;

	if (!ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_TARGET_DEAD,
				     trigger_panic(&cs[1], NULL)))
		goto bail1;

	exp_res = multi_instance ? TEEC_SUCCESS : TEEC_ERROR_TARGET_DEAD;
	if (!ADBG_EXPECT_TEEC_RESULT(c, exp_res,
				     sims_get_counter(&cs[0], &counter)))
		goto bail1;

	if (!ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_TARGET_DEAD,
				     sims_get_counter(&cs[1], &counter)))
		goto bail1;

	/* Attempt to open a session on panicked context */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			xtest_teec_open_session(&cs[1], uuid, NULL,
						&ret_orig)))
		goto bail1;

	/* Sanity check of still valid TA context */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			xtest_teec_open_session(&cs[2], uuid, NULL,
						&ret_orig)))
		goto bail1;

	/* Sanity check of still valid TA context */
	if (multi_instance) {
		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
				sims_get_counter(&cs[0], &counter)))
			goto bail2;

		if (!ADBG_EXPECT(c, 0, counter))
			goto bail2;
	}

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, sims_get_counter(&cs[2], &counter)))
		goto bail2;

	exp_counter = multi_instance ? 0 : 1;
	if (!ADBG_EXPECT(c, exp_counter, counter))
		goto bail2;

bail2:
	TEEC_CloseSession(&cs[2]);
bail1:
	TEEC_CloseSession(&cs[1]);
bail0:
	TEEC_CloseSession(&cs[0]);
}

static void test_panic_ta_to_ta(ADBG_Case_t *c, const TEEC_UUID *uuid1,
				const TEEC_UUID *uuid2)
{
	uint32_t ret_orig = 0;
	uint32_t counter = 0;
	TEEC_Session cs[3] = { };

	/* Test pre-conditions */
	/* 2.1 - CA opens a session toward TA1 */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			xtest_teec_open_session(&cs[0], uuid1, NULL,
						&ret_orig)))
		return;

	/* 2.2 - CA opens a session toward TA2 */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			xtest_teec_open_session(&cs[1], uuid2, NULL,
						&ret_orig)))
		goto bail0;

	/* 2.3 - TA1 opens a session toward TA2 */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, open_sec_session(&cs[0], uuid2)))
		goto bail1;

	/* 2.4 - CA invokes TA2 which panics */
	if (!ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_TARGET_DEAD,
				     trigger_panic(&cs[1], NULL)))
		goto bail1;

	/* Expected results */
	/* 2.5 - Expect CA->TA1 session is still alive */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, sims_get_counter(&cs[0], &counter)))
		goto bail1;

	/* 2.6 - Expect CA->TA2 session is properly released */
	if (!ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_TARGET_DEAD,
				     sims_get_counter(&cs[1], &counter)))
		goto bail1;

bail1:
	TEEC_CloseSession(&cs[1]);
bail0:
	TEEC_CloseSession(&cs[0]);

	memset(cs, 0, sizeof(cs));

	/* Test pre-conditions */
	/* 2.1 - CA opens a session toward TA1 */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			xtest_teec_open_session(&cs[0], uuid1, NULL,
						&ret_orig)))
		return;

	/* 2.2 - CA opens a session toward TA2 */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			xtest_teec_open_session(&cs[1], uuid2, NULL,
						&ret_orig)))
		goto bail2;

	/* 2.3 - TA1 opens a session toward TA2 */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, open_sec_session(&cs[0], uuid2)))
		goto bail3;

	/* 2.4 - CA invokes TA1 which invokes TA2 which panics */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, trigger_panic(&cs[0], uuid2)))
		goto bail3;

	/* Expected results */
	/* 2.5 - Expect CA->TA1 session is still alive */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, sims_get_counter(&cs[0], &counter)))
		goto bail3;

	/* 2.6 - Expect CA->TA2 session is properly released */
	if (!ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_TARGET_DEAD,
				     sims_get_counter(&cs[1], &counter)))
		goto bail3;

bail3:
	TEEC_CloseSession(&cs[1]);
bail2:
	TEEC_CloseSession(&cs[0]);
}

static void xtest_tee_test_1021(ADBG_Case_t *c)
{
	Do_ADBG_BeginSubCase(c, "Multiple Instances Single Session");
	test_panic_ca_to_ta(c, &miss_test_ta_uuid, true);
	Do_ADBG_EndSubCase(c, "Multiple Instances Single Session");

	Do_ADBG_BeginSubCase(c, "Single Instance Multi Sessions");
	test_panic_ca_to_ta(c, &sims_test_ta_uuid, false);
	Do_ADBG_EndSubCase(c, "Single Instance Multi Sessions");

	Do_ADBG_BeginSubCase(c, "Single Instance Multi Sessions Keep Alive");
	test_panic_ca_to_ta(c, &sims_keepalive_test_ta_uuid, false);
	Do_ADBG_EndSubCase(c, "Single Instance Multi Sessions Keep Alive");

	Do_ADBG_BeginSubCase(c, "Multi Sessions TA to TA");
	test_panic_ta_to_ta(c, &sims_test_ta_uuid,
			    &sims_keepalive_test_ta_uuid);
	Do_ADBG_EndSubCase(c, "Multi Sessions TA to TA");
}
ADBG_CASE_DEFINE(regression, 1021, xtest_tee_test_1021,
		 "Test panic context release");

static void xtest_tee_test_1022(ADBG_Case_t *c)
{
	TEEC_Session session = { 0 };
	uint32_t ret_orig = 0;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			xtest_teec_open_session(&session, &os_test_ta_uuid,
				NULL, &ret_orig)))
		return;

	(void)ADBG_EXPECT_TEEC_SUCCESS(c,
		TEEC_InvokeCommand(&session, TA_OS_TEST_CMD_CALL_LIB_DL, NULL,
				   &ret_orig));

	(void)ADBG_EXPECT_TEEC_RESULT(c,
		TEEC_ERROR_TARGET_DEAD,
		TEEC_InvokeCommand(&session, TA_OS_TEST_CMD_CALL_LIB_DL_PANIC,
				   NULL, &ret_orig));

	(void)ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TEE, ret_orig);

	TEEC_CloseSession(&session);
}
ADBG_CASE_DEFINE(regression, 1022, xtest_tee_test_1022,
		"Test dlopen()/dlsym()/dlclose() API");

/*
 * Testing the ELF initialization (.init_array)
 *
 * - The TA has a global variable which can also be accessed by the two shared
 *   libraries os_test_lib (linked with the TA) and os_test_lib_dl (loaded via
 *   dlopen())
 * - The TA and both libraries have initialization functions (declared with the
 *   "constructor" attribute) which perform the following:
 *     * The TA multiplies by 10 then adds 1
 *     * os_test_lib multiplies by 10 then adds 2
 *     * os_test_lib_dl multiplies by 10 then adds 3
 * By testing the variable value we make sure the initializations occurred in
 * the correct order.
 */
static void xtest_tee_test_1023(ADBG_Case_t *c)
{
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	TEEC_Session session = { 0 };
	uint32_t ret_orig = 0;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			xtest_teec_open_session(&session, &os_test_ta_uuid,
				NULL, &ret_orig)))
		return;

	(void)ADBG_EXPECT_TEEC_SUCCESS(c,
		TEEC_InvokeCommand(&session, TA_OS_TEST_CMD_GET_GLOBAL_VAR, &op,
				   &ret_orig));

	/* Expected: initialization of os_test_lib, then TA */
	(void)ADBG_EXPECT_COMPARE_SIGNED(c, op.params[0].value.a, ==, 21);

	(void)ADBG_EXPECT_TEEC_SUCCESS(c,
		TEEC_InvokeCommand(&session, TA_OS_TEST_CMD_CALL_LIB_DL, NULL,
				   &ret_orig));

	(void)ADBG_EXPECT_TEEC_SUCCESS(c,
		TEEC_InvokeCommand(&session, TA_OS_TEST_CMD_GET_GLOBAL_VAR, &op,
				   &ret_orig));

	/* Expected: initialization of os_test_lib_dl */
	(void)ADBG_EXPECT_COMPARE_SIGNED(c, op.params[0].value.a, ==, 213);

	TEEC_CloseSession(&session);
}
ADBG_CASE_DEFINE(regression, 1023, xtest_tee_test_1023,
		"Test ELF initialization (.init_array)");

#ifdef CFG_CORE_TPM_EVENT_LOG
static void xtest_tee_test_1024(ADBG_Case_t *c)
{
	TEEC_Session session = {};
	uint32_t ret_orig = 0;

	xtest_teec_open_session(&session, &tpm_log_test_ta_uuid,
				NULL, &ret_orig);

	Do_ADBG_BeginSubCase(c, "TPM test service invocation");
	ADBG_EXPECT_TEEC_SUCCESS(c, TEEC_InvokeCommand(&session,
				  TA_TPM_TEST_GET_LOG,
				  NULL, &ret_orig));
	Do_ADBG_EndSubCase(c, "TPM test service invocation");

	Do_ADBG_BeginSubCase(c, "TPM test passing short buffer");
	ADBG_EXPECT_TEEC_SUCCESS(c, TEEC_InvokeCommand(&session,
				  TA_TPM_TEST_SHORT_BUF,
				  NULL, &ret_orig));
	Do_ADBG_EndSubCase(c, "TPM test passing short buffer");

	TEEC_CloseSession(&session);
}

ADBG_CASE_DEFINE(regression, 1024, xtest_tee_test_1024,
		 "Test PTA_SYSTEM_GET_TPM_EVENT_LOG Service");
#endif /* CFG_CORE_TPM_EVENT_LOG */

static void xtest_tee_test_1025(ADBG_Case_t *c)
{
	TEEC_Session session = {};
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig = 0;
	uint8_t *empty_buf = NULL;
	TEEC_SharedMemory shm = { };
	TEEC_Result res = TEEC_ERROR_GENERIC;

	Do_ADBG_BeginSubCase(c, "Invalid NULL buffer memref registration");

	memset(&shm, 0, sizeof(shm));
	shm.flags = TEEC_MEM_INPUT;
	shm.buffer = NULL;
	shm.size = 0;

	ADBG_EXPECT(c, TEEC_ERROR_BAD_PARAMETERS,
		    TEEC_RegisterSharedMemory(&xtest_teec_ctx, &shm));

	memset(&shm, 0, sizeof(shm));
	shm.flags = TEEC_MEM_OUTPUT;
	shm.buffer = NULL;
	shm.size = 0;

	ADBG_EXPECT(c, TEEC_ERROR_BAD_PARAMETERS,
		    TEEC_RegisterSharedMemory(&xtest_teec_ctx, &shm));

	Do_ADBG_EndSubCase(c, "Invalid NULL buffer memref registration");

	if (!xtest_teec_ctx.imp.memref_null) {
		Do_ADBG_Log("Skip subcases: MEMREF_NULL capability not supported");
		return;
	}

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
				      xtest_teec_open_session(&session,
							      &os_test_ta_uuid,
							      NULL, &ret_orig)))
		return;

	empty_buf = malloc(1);
	if (!empty_buf) {
		(void)ADBG_EXPECT_TEEC_SUCCESS(c, TEEC_ERROR_OUT_OF_MEMORY);
		goto out_session;
	}

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_MEMREF_TEMP_OUTPUT);

	Do_ADBG_BeginSubCase(c,
			     "Input/Output MEMREF Buffer NULL - Size 0 bytes");

	op.params[0].tmpref.buffer = empty_buf;
	op.params[0].tmpref.size = 0;

	op.params[1].tmpref.buffer = NULL;
	op.params[1].tmpref.size = 0;

	op.params[2].tmpref.buffer = empty_buf;
	op.params[2].tmpref.size = 0;

	op.params[3].tmpref.buffer = NULL;
	op.params[3].tmpref.size = 0;

	ADBG_EXPECT(c, TEE_SUCCESS,
		    TEEC_InvokeCommand(&session,
				       TA_OS_TEST_CMD_NULL_MEMREF_PARAMS, &op,
				       &ret_orig));

	Do_ADBG_EndSubCase(c, "Input/Output MEMREF Buffer NULL - Size 0 bytes");

	Do_ADBG_BeginSubCase(c, "Input MEMREF Buffer NULL - Size non 0 bytes");

	op.params[0].tmpref.buffer = empty_buf;
	op.params[0].tmpref.size = 1;

	op.params[1].tmpref.buffer = NULL;
	op.params[1].tmpref.size = 0;

	op.params[2].tmpref.buffer = empty_buf;
	op.params[2].tmpref.size = 0;

	op.params[3].tmpref.buffer = NULL;
	op.params[3].tmpref.size = 0;

	ADBG_EXPECT(c, TEE_ERROR_BAD_PARAMETERS,
		    TEEC_InvokeCommand(&session,
				       TA_OS_TEST_CMD_NULL_MEMREF_PARAMS, &op,
				       &ret_orig));

	TEEC_CloseSession(&session);

	Do_ADBG_EndSubCase(c, "Input MEMREF Buffer NULL - Size non 0 bytes");

	Do_ADBG_BeginSubCase(c, "Input MEMREF Buffer NULL over PTA invocation");

	/* Pseudo TA is optional: warn and nicely exit if not found */
	res = xtest_teec_open_session(&session, &pta_invoke_tests_ta_uuid, NULL,
				      &ret_orig);
	if (res == TEEC_ERROR_ITEM_NOT_FOUND) {
		Do_ADBG_Log(" - 1025 -   skip test, pseudo TA not found");
		goto out;
	}
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		goto out;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = NULL;
	op.params[0].tmpref.size = 0;

	ADBG_EXPECT(c, TEE_SUCCESS,
		    TEEC_InvokeCommand(&session,
				       PTA_INVOKE_TESTS_CMD_MEMREF_NULL,
				       &op, &ret_orig));

out_session:
	TEEC_CloseSession(&session);
out:
	Do_ADBG_EndSubCase(c, NULL);
	free(empty_buf);
}
ADBG_CASE_DEFINE(regression, 1025, xtest_tee_test_1025,
		 "Test memref NULL and/or 0 bytes size");

#define TEE_UUID_NS_NAME_SIZE  128

/*
 * TEE Client UUID name space identifier (UUIDv4)
 *
 * Value here is random UUID that is allocated as name space identifier for
 * forming Client UUID's for TEE environment using UUIDv5 scheme.
 */
static const char *client_uuid_linux_ns = "58ac9ca0-2086-4683-a1b8-ec4bc08e01b6";

/* TEEC_LOGIN_PUBLIC's Client UUID is NIL UUID */
static TEEC_UUID client_uuid_public = { };

static void xtest_tee_test_1026(ADBG_Case_t *c)
{
	TEEC_Result result = TEEC_ERROR_GENERIC;
	uint32_t ret_orig = 0;
	TEEC_Session session = { };
	uint32_t login = UINT32_MAX;
	TEEC_UUID client_uuid = { };

	result = TEEC_OpenSession(&xtest_teec_ctx, &session, &os_test_ta_uuid,
				  TEEC_LOGIN_PUBLIC, NULL, NULL, &ret_orig);

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, result))
		return;

	result = ta_os_test_cmd_client_identity(&session, &login,
						&client_uuid);

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, result))
		goto out;

	ADBG_EXPECT_COMPARE_UNSIGNED(c, login, ==, TEEC_LOGIN_PUBLIC);

	ADBG_EXPECT_EQUAL(c, &client_uuid_public, &client_uuid,
			  sizeof(TEEC_UUID));

out:
	TEEC_CloseSession(&session);
}

ADBG_CASE_DEFINE(regression, 1026, xtest_tee_test_1026,
		 "Session: public login");

/*
 * regression_1027
 * Depends on OpenSSL
 * Depends on kernel commit c5b4312bea5d ("tee: optee: Add support for session
 * login client UUID generation")
 * https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=c5b4312bea5d
 *
 * xtest skips the test when not built with OpenSSL.
 */
static void xtest_tee_test_1027(ADBG_Case_t *c)
{
#ifdef OPENSSL_FOUND
	TEEC_Result result = TEEC_ERROR_GENERIC;
	uint32_t ret_orig = 0;
	TEEC_Session session = { };
	uint32_t login = UINT32_MAX;
	TEEC_UUID client_uuid = { };
	TEEC_UUID expected_client_uuid = { };
	TEEC_UUID uuid_ns = { };
	char uuid_name[TEE_UUID_NS_NAME_SIZE] = { };

	result = xtest_uuid_from_str(&uuid_ns, client_uuid_linux_ns);

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, result))
		return;

	sprintf(uuid_name, "uid=%x", geteuid());

	result = xtest_uuid_v5(&expected_client_uuid, &uuid_ns, uuid_name,
			       strlen(uuid_name));
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, result))
		return;

	result = TEEC_OpenSession(&xtest_teec_ctx, &session, &os_test_ta_uuid,
				  TEEC_LOGIN_USER, NULL, NULL, &ret_orig);

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, result))
		return;

	result = ta_os_test_cmd_client_identity(&session, &login,
						&client_uuid);

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, result))
		goto out;

	ADBG_EXPECT_COMPARE_UNSIGNED(c, login, ==, TEEC_LOGIN_USER);

	ADBG_EXPECT_EQUAL(c, &expected_client_uuid, &client_uuid,
			  sizeof(TEEC_UUID));

out:
	TEEC_CloseSession(&session);
#else /*!OPENSSL_FOUND*/
	UNUSED(c);
	UNUSED(client_uuid_linux_ns);
	/* xtest_uuid_v5() depends on OpenSSL */
	Do_ADBG_Log("OpenSSL not available, skipping test 1027");
#endif
}

ADBG_CASE_DEFINE(regression, 1027, xtest_tee_test_1027,
		 "Session: user login for current user");

/*
 * regression_1028
 * Depends on kernel commit c5b4312bea5d ("tee: optee: Add support for session
 * login client UUID generation")
 * https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=c5b4312bea5d
 *
 * xtest skips the test when not built with OpenSSL.
 */
static void xtest_tee_test_1028(ADBG_Case_t *c)
{
#ifdef OPENSSL_FOUND
	TEEC_Result result = TEEC_ERROR_GENERIC;
	uint32_t ret_orig = 0;
	TEEC_Session session = { };
	uint32_t login = UINT32_MAX;
	TEEC_UUID client_uuid = { };
	TEEC_UUID expected_client_uuid = { };
	TEEC_UUID uuid_ns = { };
	char uuid_name[TEE_UUID_NS_NAME_SIZE] = { };
	uint32_t group = 0;

	group = getegid();

	result = xtest_uuid_from_str(&uuid_ns, client_uuid_linux_ns);

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, result))
		return;

	sprintf(uuid_name, "gid=%x", group);

	result = xtest_uuid_v5(&expected_client_uuid, &uuid_ns, uuid_name,
			       strlen(uuid_name));
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, result))
		return;

	result = TEEC_OpenSession(&xtest_teec_ctx, &session, &os_test_ta_uuid,
				  TEEC_LOGIN_GROUP, &group, NULL, &ret_orig);

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, result))
		return;

	result = ta_os_test_cmd_client_identity(&session, &login,
						&client_uuid);

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, result))
		goto out;

	ADBG_EXPECT_COMPARE_UNSIGNED(c, login, ==, TEEC_LOGIN_GROUP);

	ADBG_EXPECT_EQUAL(c, &expected_client_uuid, &client_uuid,
			  sizeof(TEEC_UUID));

out:
	TEEC_CloseSession(&session);
#else /*!OPENSSL_FOUND*/
	UNUSED(c);
	/* xtest_uuid_v5() depends on OpenSSL */
	Do_ADBG_Log("OpenSSL not available, skipping test 1028");
#endif
}

ADBG_CASE_DEFINE(regression, 1028, xtest_tee_test_1028,
		 "Session: group login for current user's effective group");

static void xtest_tee_test_1029(ADBG_Case_t *c)
{
	TEEC_Result res = TEEC_SUCCESS;
	TEEC_Session session = { 0 };
	uint32_t ret_orig = 0;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			xtest_teec_open_session(&session, &os_test_ta_uuid,
						NULL, &ret_orig)))
		return;

	Do_ADBG_BeginSubCase(c, "TLS variables (main program)");
	res = TEEC_InvokeCommand(&session, TA_OS_TEST_CMD_TLS_TEST_MAIN, NULL,
				 &ret_orig);
	if (res == TEEC_ERROR_NOT_SUPPORTED)
		Do_ADBG_Log(" - 1029 -   skip test, "
			    "TA returned TEEC_ERROR_NOT_SUPPORTED");
	else
		ADBG_EXPECT_TEEC_SUCCESS(c, res);
	Do_ADBG_EndSubCase(c, "TLS variables (main program)");

	Do_ADBG_BeginSubCase(c, "TLS variables (shared library)");
	res = TEEC_InvokeCommand(&session, TA_OS_TEST_CMD_TLS_TEST_SHLIB, NULL,
				 &ret_orig);
	if (res == TEEC_ERROR_NOT_SUPPORTED)
		Do_ADBG_Log(" - 1029 -   skip test, "
			    "TA returned TEEC_ERROR_NOT_SUPPORTED");
	else
		ADBG_EXPECT_TEEC_SUCCESS(c, res);
	Do_ADBG_EndSubCase(c, "TLS variables (shared library)");

	TEEC_CloseSession(&session);
}
ADBG_CASE_DEFINE(regression, 1029, xtest_tee_test_1029,
		 "Test __thread attribute");

static void xtest_tee_test_1030(ADBG_Case_t *c)
{
	TEEC_Session session = { 0 };
	uint32_t ret_orig = 0;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			xtest_teec_open_session(&session, &os_test_ta_uuid,
						NULL, &ret_orig)))
		return;

	Do_ADBG_BeginSubCase(c, "Before dlopen()");
	ADBG_EXPECT_TEEC_SUCCESS(c,
		TEEC_InvokeCommand(&session, TA_OS_TEST_CMD_DL_PHDR, NULL,
				   &ret_orig));
	Do_ADBG_EndSubCase(c, "Before dlopen()");

	Do_ADBG_BeginSubCase(c, "After dlopen()");
	ADBG_EXPECT_TEEC_SUCCESS(c,
		TEEC_InvokeCommand(&session, TA_OS_TEST_CMD_DL_PHDR_DL, NULL,
				   &ret_orig));
	Do_ADBG_EndSubCase(c, "After dlopen()");

	TEEC_CloseSession(&session);
}
ADBG_CASE_DEFINE(regression, 1030, xtest_tee_test_1030,
		 "Test dl_iterate_phdr()");

#ifndef __clang__
static void xtest_tee_test_1031(ADBG_Case_t *c)
{
	TEEC_Result ret = TEE_SUCCESS;
	TEEC_Session session = { 0 };
	uint32_t ret_orig = 0;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			xtest_teec_open_session(&session, &os_test_ta_uuid,
						NULL, &ret_orig)))
		return;

	Do_ADBG_BeginSubCase(c, "Global object constructor (main program)");
	ret = TEEC_InvokeCommand(&session, TA_OS_TEST_CMD_CXX_CTOR_MAIN, NULL,
				   &ret_orig);
	if (ret == TEEC_ERROR_NOT_SUPPORTED) {
		printf("TA not built with C++ support, skipping C++ tests\n");
		Do_ADBG_EndSubCase(c, "Global object constructor (main program)");
		goto out;

	}
	ADBG_EXPECT_TEEC_SUCCESS(c, ret);
	Do_ADBG_EndSubCase(c, "Global object constructor (main program)");

	Do_ADBG_BeginSubCase(c, "Global object constructor (shared library)");
	ADBG_EXPECT_TEEC_SUCCESS(c,
		TEEC_InvokeCommand(&session, TA_OS_TEST_CMD_CXX_CTOR_SHLIB,
				   NULL, &ret_orig));
	Do_ADBG_EndSubCase(c, "Global object constructor (shared library)");

	Do_ADBG_BeginSubCase(c, "Global object constructor (dlopen()ed lib)");
	ADBG_EXPECT_TEEC_SUCCESS(c,
		TEEC_InvokeCommand(&session, TA_OS_TEST_CMD_CXX_CTOR_SHLIB_DL,
				   NULL, &ret_orig));
	Do_ADBG_EndSubCase(c, "Global object constructor (dlopen()ed lib)");

	Do_ADBG_BeginSubCase(c, "Exceptions (simple)");
	ADBG_EXPECT_TEEC_SUCCESS(c,
		TEEC_InvokeCommand(&session, TA_OS_TEST_CMD_CXX_EXC_MAIN, NULL,
				   &ret_orig));
	Do_ADBG_EndSubCase(c, "Exceptions (simple)");

	Do_ADBG_BeginSubCase(c, "Exceptions (mixed C/C++ frames)");
	ADBG_EXPECT_TEEC_SUCCESS(c,
		TEEC_InvokeCommand(&session, TA_OS_TEST_CMD_CXX_EXC_MIXED, NULL,
				   &ret_orig));
	Do_ADBG_EndSubCase(c, "Exceptions (mixed C/C++ frames)");
out:
	TEEC_CloseSession(&session);
}
ADBG_CASE_DEFINE(regression, 1031, xtest_tee_test_1031,
		 "Test C++ features");
#endif

static void xtest_tee_test_1032(ADBG_Case_t *c)
{
	TEEC_Result res = TEEC_SUCCESS;
	TEEC_Context ctx = { };
	TEEC_SharedMemory shm1 = {
		.buffer = xtest_tee_test_1032,
		.size = 32,
		.flags = TEEC_MEM_INPUT,
	};
	static const uint8_t dummy_data[32] = { 1, 2, 3, 4, };
	TEEC_SharedMemory shm2 = {
		.buffer = (void *)dummy_data,
		.size = sizeof(dummy_data),
		.flags = TEEC_MEM_INPUT,
	};

	res = TEEC_InitializeContext(xtest_tee_name, &ctx);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		return;

	res = TEEC_RegisterSharedMemory(&ctx, &shm1);
	if (ADBG_EXPECT_TEEC_SUCCESS(c, res))
		TEEC_ReleaseSharedMemory(&shm1);

	res = TEEC_RegisterSharedMemory(&ctx, &shm2);
	if (ADBG_EXPECT_TEEC_SUCCESS(c, res))
		TEEC_ReleaseSharedMemory(&shm2);

	TEEC_FinalizeContext(&ctx);
}
ADBG_CASE_DEFINE(regression, 1032, xtest_tee_test_1032,
		"Register read-only shared memory");

static void xtest_tee_test_1033(ADBG_Case_t *c)
{
	TEEC_Session session = { };
	uint32_t ret_orig = 0;

	/* TA will ping the test plugin during open session operation */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		xtest_teec_open_session(&session, &supp_plugin_test_ta_uuid,
					NULL, &ret_orig)))
		return;

	Do_ADBG_BeginSubCase(c, "Pass values to/from a plugin");
	{
		TEEC_Operation op = TEEC_OPERATION_INITIALIZER;

		op.params[0].value.a = 20;
		op.params[0].value.b = 10;
		op.params[1].value.a = '+';
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INOUT,
						 TEEC_VALUE_INPUT, TEEC_NONE,
						 TEEC_NONE);

		ADBG_EXPECT_TEEC_SUCCESS(c,
			TEEC_InvokeCommand(&session,
					   TA_SUPP_PLUGIN_CMD_PASS_VALUES, &op,
					   &ret_orig));
		ADBG_EXPECT(c, 30, op.params[0].value.a);

		/* reassign, because the values was changed during previous op */
		op.params[0].value.a = 20;
		op.params[0].value.b = 10;
		op.params[1].value.a = '-';
		ADBG_EXPECT_TEEC_SUCCESS(c,
			TEEC_InvokeCommand(&session,
					   TA_SUPP_PLUGIN_CMD_PASS_VALUES, &op,
					   &ret_orig));
		ADBG_EXPECT(c, 10, op.params[0].value.a);
	}
	Do_ADBG_EndSubCase(c, "Pass values to/from a plugin");

	Do_ADBG_BeginSubCase(c, "Pass array to a plugin");
	{
		TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
		uint8_t to_plugin[] = { 0, 1, 2, 3, 4, 5 };

		op.params[0].tmpref.buffer = to_plugin;
		op.params[0].tmpref.size = sizeof(to_plugin);
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT,
						 TEEC_VALUE_OUTPUT,
						 TEEC_NONE, TEEC_NONE);

		ADBG_EXPECT_TEEC_SUCCESS(c,
			TEEC_InvokeCommand(&session,
					   TA_SUPP_PLUGIN_CMD_WRITE_ARR,
					   &op, &ret_orig));

		/*
		 * The test plugin must calculate a sum of the input elements
		 * and store it to 'op.params[1].value.a'
		 */
		ADBG_EXPECT(c, 15, op.params[1].value.a);
	}
	Do_ADBG_EndSubCase(c, "Pass array to a plugin");

	Do_ADBG_BeginSubCase(c, "Get array from a plugin");
	{
		TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
		char from_plugin[64] = { };
		char expected_arr[] = "Array from plugin";
		size_t expectes_size = sizeof(expected_arr);

		op.params[0].tmpref.buffer = from_plugin;
		op.params[0].tmpref.size = sizeof(from_plugin);
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
						 TEEC_VALUE_OUTPUT, TEEC_NONE,
						 TEEC_NONE);
		ADBG_EXPECT_TEEC_SUCCESS(c,
			TEEC_InvokeCommand(&session,
					   TA_SUPP_PLUGIN_CMD_GET_ARR, &op,
					   &ret_orig));
		ADBG_EXPECT(c, expectes_size, op.params[1].value.a);
		ADBG_EXPECT_EQUAL(c, expected_arr, from_plugin, expectes_size);
	}
	Do_ADBG_EndSubCase(c, "Get array from a plugin");

	Do_ADBG_BeginSubCase(c, "Not allow bad input to a plugin");
	{
		TEEC_Operation op = TEEC_OPERATION_INITIALIZER;

		op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE,
						 TEEC_NONE, TEEC_NONE);
		ADBG_EXPECT_TEEC_RESULT(c, TEE_ERROR_BAD_PARAMETERS,
			TEEC_InvokeCommand(&session,
					   TA_SUPP_PLUGIN_CMD_BAD_UUID, &op,
					   &ret_orig));
		ADBG_EXPECT_TEEC_RESULT(c, TEE_ERROR_BAD_PARAMETERS,
			TEEC_InvokeCommand(&session,
					   TA_SUPP_PLUGIN_CMD_BAD_IN_DATA, &op,
					   &ret_orig));
		ADBG_EXPECT_TEEC_RESULT(c, TEE_ERROR_BAD_PARAMETERS,
			TEEC_InvokeCommand(&session,
					   TA_SUPP_PLUGIN_CMD_BAD_IN_LEN, &op,
					   &ret_orig));
	}
	Do_ADBG_EndSubCase(c, "Not allow bad input to a plugin");

	Do_ADBG_BeginSubCase(c, "Call an unknown plugin");
	{
		TEEC_Operation op = TEEC_OPERATION_INITIALIZER;

		op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE,
						 TEEC_NONE, TEEC_NONE);
		ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_ITEM_NOT_FOUND,
			TEEC_InvokeCommand(&session,
					   TA_SUPP_PLUGIN_CMD_UNKNOWN_UUID,
					   &op, &ret_orig));
	}
	Do_ADBG_EndSubCase(c, "Call an unknown plugin");

	TEEC_CloseSession(&session);
}
ADBG_CASE_DEFINE(regression, 1033, xtest_tee_test_1033,
		 "Test the supplicant plugin framework");

static void xtest_tee_test_1034(ADBG_Case_t *c)
{
	TEEC_Result res = TEEC_SUCCESS;
	TEEC_Session session = { };
	uint32_t ret_orig = 0;

	res = xtest_teec_open_session(&session, &large_ta_uuid, NULL,
				      &ret_orig);
	if (res == TEEC_ERROR_OUT_OF_MEMORY) {
		Do_ADBG_Log("TEEC_ERROR_OUT_OF_MEMORY - ignored");
		return;
	}
	ADBG_EXPECT_TEEC_SUCCESS(c, res);
	if (!res)
		TEEC_CloseSession(&session);
}
ADBG_CASE_DEFINE(regression, 1034, xtest_tee_test_1034,
		 "Test loading a large TA");

#if defined(CFG_TA_BTI)
struct bti_test {
	uint32_t cmd;
	uint32_t func;
};

#define BTI_TEST(caller_func, bti_func) {	\
		.cmd = caller_func,		\
		.func = bti_func,	\
	}

static const struct bti_test bti_cases_success[] = {
	BTI_TEST(TA_TEST_USING_BLR, TA_FUNC_BTI_C),
	BTI_TEST(TA_TEST_USING_BLR, TA_FUNC_BTI_JC),
	BTI_TEST(TA_TEST_USING_BR, TA_FUNC_BTI_J),
	BTI_TEST(TA_TEST_USING_BR, TA_FUNC_BTI_JC),
	BTI_TEST(TA_TEST_USING_BR_X16, TA_FUNC_BTI_C),
	BTI_TEST(TA_TEST_USING_BR_X16, TA_FUNC_BTI_J),
	BTI_TEST(TA_TEST_USING_BR_X16, TA_FUNC_BTI_JC),
};

static const struct bti_test bti_cases_panic[] = {
	BTI_TEST(TA_TEST_USING_BLR, TA_FUNC_BTI_J),
	BTI_TEST(TA_TEST_USING_BLR, TA_FUNC_BTI_NONE),
	BTI_TEST(TA_TEST_USING_BR, TA_FUNC_BTI_C),
	BTI_TEST(TA_TEST_USING_BR, TA_FUNC_BTI_NONE),
	BTI_TEST(TA_TEST_USING_BR_X16, TA_FUNC_BTI_NONE),
};

static void get_cpu_feature(ADBG_Case_t *c, bool *bti)
{
	TEEC_Session session = {};
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig = 0;
	TEEC_Result res;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT, TEEC_NONE, TEEC_NONE,
					 TEEC_NONE);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			xtest_teec_open_session(&session, &bti_test_ta_uuid,
						NULL, &ret_orig)))
		return;

	res = TEEC_InvokeCommand(&session, TA_FEAT_BTI_IMPLEMENTED, &op,
				 &ret_orig);
	if (!res) {
		if(op.params[0].value.a)
			*bti = true;
		Do_ADBG_Log("FEAT_BTI is %simplemented", *bti ? "" : "NOT ");
	}

	TEEC_CloseSession(&session);
}

static void xtest_tee_test_1035(ADBG_Case_t *c)
{
	TEEC_Session session = {};
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	struct bti_test const *test = NULL;
	uint32_t ret_orig = 0;
	TEEC_Result res;
	unsigned int n = 0;
	bool cpu_feature_bti = false;

	Do_ADBG_BeginSubCase(c, "BTI Implemented");
	get_cpu_feature(c, &cpu_feature_bti);
	Do_ADBG_EndSubCase(c, "BTI Implemented");

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE,
					 TEEC_NONE);

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			xtest_teec_open_session(&session, &bti_test_ta_uuid,
						NULL, &ret_orig)))
		return;

	Do_ADBG_BeginSubCase(c, "BTI Pass Cases");
	for (n = 0; n < ARRAY_SIZE(bti_cases_success); n++) {
		test = &bti_cases_success[n];

		op.params[0].value.a = test->func;

		res = TEEC_InvokeCommand(&session, test->cmd, &op, &ret_orig);
		if (res == TEEC_ERROR_NOT_IMPLEMENTED) {
			Do_ADBG_Log("Binary doesn't support BTI - skip tests");
			Do_ADBG_EndSubCase(c, "BTI Pass Cases");
			TEEC_CloseSession(&session);
			return;
		}

		Do_ADBG_BeginSubCase(c, "BTI Case %u", n);

		ADBG_EXPECT_TEEC_SUCCESS(c, res);

		Do_ADBG_EndSubCase(c, "BTI Case %u", n);
	}
	Do_ADBG_EndSubCase(c, "BTI Pass Cases");

	TEEC_CloseSession(&session);

	Do_ADBG_BeginSubCase(c, "BTI Exception Generation");
	for (n = 0; n < ARRAY_SIZE(bti_cases_panic); n++) {
		test = &bti_cases_panic[n];
		res = TEEC_SUCCESS;

		if (cpu_feature_bti)
			res = TEEC_ERROR_TARGET_DEAD;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			xtest_teec_open_session(&session, &bti_test_ta_uuid,
						NULL, &ret_orig)))
			goto out;

		Do_ADBG_BeginSubCase(c, "BTI Case %u", n);
		op.params[0].value.a = test->func;

		(void)ADBG_EXPECT_TEEC_RESULT(c, res,
		       TEEC_InvokeCommand(&session, test->cmd, &op, &ret_orig));

		if (cpu_feature_bti)
			(void)ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TEE,
							    ret_orig);

		Do_ADBG_EndSubCase(c, "BTI Case %u", n);

		TEEC_CloseSession(&session);
	}

out:
	Do_ADBG_EndSubCase(c, "BTI Exception Generation");
}
ADBG_CASE_DEFINE(regression, 1035, xtest_tee_test_1035, "Test BTI");
#endif

static void xtest_tee_test_1036(ADBG_Case_t *c)
{
	TEEC_Session session = { };
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig = 0;
	TEEC_Result res = TEEC_SUCCESS;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE,
					 TEEC_NONE);

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			xtest_teec_open_session(&session, &os_test_ta_uuid,
						NULL, &ret_orig)))
		return;

	Do_ADBG_BeginSubCase(c, "PAuth NOP test");

	res = TEEC_InvokeCommand(&session, TA_OS_TEST_CMD_PAUTH_NOP, &op,
				 &ret_orig);
	if (res == TEEC_ERROR_NOT_SUPPORTED) {
		Do_ADBG_Log("Binary doesn't support PAuth - skip tests");
		goto out;
	}

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		goto out;

	Do_ADBG_EndSubCase(c, "PAuth NOP test");

	Do_ADBG_BeginSubCase(c, "PAuth PAC corruption");

	ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_TARGET_DEAD,
			   TEEC_InvokeCommand(&session,
					      TA_OS_TEST_CMD_PAUTH_CORRUPT_PAC,
					      &op, &ret_orig));

	ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TEE, ret_orig);

	Do_ADBG_EndSubCase(c, "PAuth PAC corruption");

out:
	TEEC_CloseSession(&session);
}
ADBG_CASE_DEFINE(regression, 1036, xtest_tee_test_1036,
		 "Test PAuth (Pointer Authentication)");

#define ATT_MAX_KEYSZ 4096

#ifdef OPENSSL_FOUND
static RSA *att_key;
static size_t att_key_size;  /* Actual key size (modulus size) in bytes */

/*
 * buf = [ TA hash (32 bytes SHA256) | Signature (att_key_size bytes) ]
 * Signature = RSA_SSA_PKCS1_PSS_MGF1(SHA256([nonce | TA hash])
 */
static void check_signature(ADBG_Case_t *c, uint8_t *nonce, size_t nonce_size,
			    uint8_t *buf)
{
	unsigned char digest[SHA256_DIGEST_LENGTH] = { };
	unsigned char *sig = buf + SHA256_DIGEST_LENGTH;
	unsigned char *ta_hash = buf;
	uint8_t decr[ATT_MAX_KEYSZ / 8] = { };
	SHA256_CTX ctx = { };
	int salt_len = 32; /* Hard-coded in the PTA */
	int st = 0;

	if (!ADBG_EXPECT_NOT_NULL(c, att_key))
		return;

	SHA256_Init(&ctx);
	SHA256_Update(&ctx, nonce, nonce_size);
	SHA256_Update(&ctx, ta_hash, SHA256_DIGEST_LENGTH);
	SHA256_Final(digest, &ctx);

	st = RSA_public_decrypt(att_key_size, sig, decr, att_key,
				RSA_NO_PADDING);
	ADBG_EXPECT_COMPARE_SIGNED(c, st, >, 0);
	st = RSA_verify_PKCS1_PSS_mgf1(att_key, digest, EVP_sha256(),
				       EVP_sha256(), decr, salt_len);
	ADBG_EXPECT_COMPARE_SIGNED(c, st, >, 0);
}

static void free_att_key(void)
{
	RSA_free(att_key);
	att_key = NULL;
}

#if OPENSSL_VERSION_NUMBER < 0x10100000L
static int RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d)
{
	if ((r->n == NULL && n == NULL) || (r->e == NULL && e == NULL))
		return 0;

	if (n != NULL) {
		BN_free(r->n);
		r->n = n;
	}

	if (e != NULL) {
		BN_free(r->e);
		r->e = e;
	}

	if (d != NULL) {
		BN_free(r->d);
		r->d = d;
	}

	return 1;
}
#endif

static void set_att_key(ADBG_Case_t *c, uint8_t *e, size_t e_sz, uint8_t *n,
			size_t n_sz)
{
	BIGNUM *bn_e = NULL;
	BIGNUM *bn_n = NULL;
	int st = 0;

	att_key_size = n_sz;
	att_key = RSA_new();
	if (!ADBG_EXPECT_NOT_NULL(c, att_key))
		return;

	bn_e = BN_bin2bn(e, e_sz, NULL);
	if (!ADBG_EXPECT_NOT_NULL(c, bn_e))
		goto err;
	bn_n = BN_bin2bn(n, n_sz, NULL);
	if (!ADBG_EXPECT_NOT_NULL(c, bn_n))
		goto err;

	st = RSA_set0_key(att_key, bn_n, bn_e, BN_new());
	if (!ADBG_EXPECT_COMPARE_SIGNED(c, st, !=, 0))
		goto err;
	return;
err:
	free_att_key();
}
#else
#define check_signature(...)
#define set_att_key(...)
#define free_att_key()
#endif

/*
 * Verification of the output of the attestation PTA
 * - (If hash != NULL) check buf contains the expected hash
 * - (If OpenSSL is available) Check that the signature is valid
 */
static void check_measurement(ADBG_Case_t *c, uint8_t *nonce, size_t nonce_size,
			      uint8_t *hash, uint8_t *buf)
{
	(void)nonce;
	(void)nonce_size;

	if (hash)
		ADBG_EXPECT_BUFFER(c, hash, 32, buf, 32);

	check_signature(c, nonce, nonce_size, buf);
}

/* Invoke attestation PTA to return the public key */
static void get_att_public_key(ADBG_Case_t *c)
{
	uint8_t n[ATT_MAX_KEYSZ / 8] = { };
	uint8_t e[3] = { };  /* We know e == 65537... */
	size_t n_sz = sizeof(n);
	size_t e_sz = sizeof(e);
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	TEEC_UUID att_uuid = PTA_ATTESTATION_UUID;
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Session session = { };
	uint32_t ret_orig = 0;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_VALUE_OUTPUT, TEEC_NONE);
	op.params[0].tmpref.buffer = e;
	op.params[0].tmpref.size = e_sz;
	op.params[1].tmpref.buffer = n;
	op.params[1].tmpref.size = n_sz;

	res = xtest_teec_open_session(&session, &att_uuid, NULL, &ret_orig);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		return;

	res = TEEC_InvokeCommand(&session, PTA_ATTESTATION_GET_PUBKEY, &op,
				 &ret_orig);

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, op.params[2].value.a, ==,
				     TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256))
		goto out;

	e_sz = op.params[0].tmpref.size;
	n_sz = op.params[1].tmpref.size;
	set_att_key(c, e, e_sz, n, n_sz);
out:
	TEEC_CloseSession(&session);
}

/* Invoke attestation PTA to hash the TEE binary */
static void attestation_tee(ADBG_Case_t *c)
{
	uint8_t measurement[TEE_SHA256_HASH_SIZE + ATT_MAX_KEYSZ / 8] = { };
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint8_t nonce[4] = { 0x12, 0x34, 0x56, 0x78 };
	TEEC_UUID att_uuid = PTA_ATTESTATION_UUID;
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Session session = { };
	uint32_t ret_orig = 0;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = nonce;
	op.params[0].tmpref.size = sizeof(nonce);
	op.params[1].tmpref.buffer = measurement;
	op.params[1].tmpref.size = sizeof(measurement);

	res = xtest_teec_open_session(&session, &att_uuid, NULL, &ret_orig);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		return;

	/* Hash TEE and check signature */
	res = TEEC_InvokeCommand(&session, PTA_ATTESTATION_HASH_TEE_MEMORY, &op,
				 &ret_orig);
	ADBG_EXPECT_TEEC_SUCCESS(c, res);
	check_measurement(c, nonce, sizeof(nonce), NULL, measurement);

	TEEC_CloseSession(&session);
}

/* Invoke attestation PTA to obtain the digest contained in the some TA shdr */
static void attestation_ta_shdr(ADBG_Case_t *c)
{
	uint8_t measurement[TEE_SHA256_HASH_SIZE + ATT_MAX_KEYSZ / 8] = { };
	uint8_t nonce[6] = { 0xa0, 0x98, 0x76, 0x54, 0x32, 0x10 };
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint8_t hash1[TEE_SHA256_HASH_SIZE] = { };
	uint8_t hash2[TEE_SHA256_HASH_SIZE] = { };
	TEEC_UUID att_uuid = PTA_ATTESTATION_UUID;
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Session session = { };
	uint32_t ret_orig = 0;
	int cmp = 0;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE);
	op.params[0].tmpref.buffer = (void *)&os_test_ta_uuid;
	op.params[0].tmpref.size = sizeof(TEEC_UUID);
	op.params[1].tmpref.buffer = nonce;
	op.params[1].tmpref.size = sizeof(nonce);
	op.params[2].tmpref.buffer = measurement;
	op.params[2].tmpref.size = sizeof(measurement);

	res = xtest_teec_open_session(&session, &att_uuid, NULL, &ret_orig);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		return;

	/* Hash TA and check signature */
	res = TEEC_InvokeCommand(&session, PTA_ATTESTATION_GET_TA_SHDR_DIGEST,
				 &op, &ret_orig);
	ADBG_EXPECT_TEEC_SUCCESS(c, res);
	check_measurement(c, nonce, sizeof(nonce), NULL, measurement);
	/* Save hash */
	memcpy(hash1, measurement, 32);

	/* Hash TA again */
	memset(measurement, 0, sizeof(measurement));
	res = TEEC_InvokeCommand(&session, PTA_ATTESTATION_GET_TA_SHDR_DIGEST,
				 &op, &ret_orig);
	ADBG_EXPECT_TEEC_SUCCESS(c, res);
	/* New hash should be identical */
	check_measurement(c, nonce, sizeof(nonce), hash1, measurement);

	/* Hash another TA */
	op.params[0].tmpref.buffer = (void *)&crypt_user_ta_uuid;
	memset(measurement, 0, sizeof(measurement));
	res = TEEC_InvokeCommand(&session, PTA_ATTESTATION_GET_TA_SHDR_DIGEST,
				 &op, &ret_orig);
	ADBG_EXPECT_TEEC_SUCCESS(c, res);
	check_measurement(c, nonce, sizeof(nonce), NULL, measurement);
	memcpy(hash2, measurement, 32);
	/* Different binaries should have different hashes */
	cmp = memcmp(hash1, hash2, sizeof(hash1));
	ADBG_EXPECT_COMPARE_SIGNED(c, cmp, !=, 0);

	TEEC_CloseSession(&session);
}

/*
 * Invoke os_test TA which will invoke attestation PTA to obtain a hash of
 * itself.
 */
static void attestation_ta_memory(ADBG_Case_t *c)
{
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint8_t nonce[6] = { 0xa0, 0x98, 0x76, 0x54, 0x32, 0x10 };
	uint8_t hash1[TEE_SHA256_HASH_SIZE] = { };
	uint8_t hash2[TEE_SHA256_HASH_SIZE] = { };
	uint8_t measurement[TEE_SHA256_HASH_SIZE + ATT_MAX_KEYSZ / 8] = { };
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Session session = { };
	uint32_t ret_orig = 0;
	int cmp = 0;

	Do_ADBG_BeginSubCase(c, "Consecutive calls");

	/* Open session to os_test TA */
	res = xtest_teec_open_session(&session, &os_test_ta_uuid, NULL,
				      &ret_orig);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		return;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = nonce;
	op.params[0].tmpref.size = sizeof(nonce);
	op.params[1].tmpref.buffer = measurement;
	op.params[1].tmpref.size = sizeof(measurement);

	/* Hash TA */
	res = TEEC_InvokeCommand(&session, TA_OS_TEST_CMD_ATTESTATION, &op,
				&ret_orig);
	ADBG_EXPECT_TEEC_SUCCESS(c, res);

	check_measurement(c, nonce, sizeof(nonce), NULL, measurement);
	memcpy(hash1, measurement, 32);

	/* Hash TA again */
	memset(measurement, 0, sizeof(measurement));
	res = TEEC_InvokeCommand(&session, TA_OS_TEST_CMD_ATTESTATION, &op,
				 &ret_orig);
	ADBG_EXPECT_TEEC_SUCCESS(c, res);

	/* New hash should be identical to hash1 */
	check_measurement(c, nonce, sizeof(nonce), hash1, measurement);

	Do_ADBG_EndSubCase(c, "Consecutive calls");

	/* Close TA session, will cause unload of TA */
	TEEC_CloseSession(&session);

	Do_ADBG_BeginSubCase(c, "TA reload");

	/* Load TA again and open a new session */
	res = xtest_teec_open_session(&session, &os_test_ta_uuid, NULL,
				      &ret_orig);
	ADBG_EXPECT_TEEC_SUCCESS(c, res);
	if (res)
		return;

	/* Hash TA one more time */
	memset(measurement, 0, sizeof(measurement));
	res = TEEC_InvokeCommand(&session, TA_OS_TEST_CMD_ATTESTATION, &op,
				&ret_orig);
	ADBG_EXPECT_TEEC_SUCCESS(c, res);

	/* Hash after reload should still be the same */
	check_measurement(c, nonce, sizeof(nonce), hash1, measurement);

	Do_ADBG_EndSubCase(c, "TA reload");

	Do_ADBG_BeginSubCase(c, "Add shared library");

	/*
	 * Invoke a TA command that causes some additional code to be mapped
	 * (shared library)
	 */
	res = TEEC_InvokeCommand(&session, TA_OS_TEST_CMD_CALL_LIB_DL, NULL,
				 &ret_orig);
	ADBG_EXPECT_TEEC_SUCCESS(c, res);

	/* Hash TA one last time */
	memset(measurement, 0, sizeof(measurement));
	res = TEEC_InvokeCommand(&session, TA_OS_TEST_CMD_ATTESTATION, &op,
				&ret_orig);
	ADBG_EXPECT_TEEC_SUCCESS(c, res);

	check_measurement(c, nonce, sizeof(nonce), NULL, measurement);
	memcpy(hash2, measurement, 32);

	/* Different binaries mapped mean different hashes */
	cmp = memcmp(hash1, hash2, sizeof(hash1));
	ADBG_EXPECT_COMPARE_SIGNED(c, cmp, !=, 0);

	Do_ADBG_EndSubCase(c, "Add shared library");

	TEEC_CloseSession(&session);
}

static void xtest_tee_test_1037(ADBG_Case_t *c)
{
	TEEC_UUID att_uuid = PTA_ATTESTATION_UUID;
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Session session = { };
	uint32_t ret_orig = 0;

	res = xtest_teec_open_session(&session, &att_uuid, NULL, &ret_orig);
	if (res == TEEC_ERROR_ITEM_NOT_FOUND) {
		Do_ADBG_Log("  skip test, pseudo TA not found");
		return;
	}

	TEEC_CloseSession(&session);

	Do_ADBG_BeginSubCase(c, "Get public key");
	get_att_public_key(c);
	Do_ADBG_EndSubCase(c, "Get public key");

	Do_ADBG_BeginSubCase(c, "TEE attestation");
	attestation_tee(c);
	Do_ADBG_EndSubCase(c, "TEE attestation");

	Do_ADBG_BeginSubCase(c, "TA attestation (shdr)");
	attestation_ta_shdr(c);
	Do_ADBG_EndSubCase(c, "TA attestation (shdr)");

	Do_ADBG_BeginSubCase(c, "TA attestation (memory)");
	attestation_ta_memory(c);
	Do_ADBG_EndSubCase(c, "TA attestation (memory)");

	free_att_key();
}
ADBG_CASE_DEFINE(regression, 1037, xtest_tee_test_1037,
		 "Remote attestation");

static void xtest_tee_test_1038(ADBG_Case_t *c)
{
	TEEC_Session session = { };
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig = 0;
	TEEC_Result res = TEEC_SUCCESS;

	Do_ADBG_BeginSubCase(c, "MTE use after free");

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE,
					 TEEC_NONE);

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			xtest_teec_open_session(&session, &os_test_ta_uuid,
						NULL, &ret_orig)))
		return;

	res = TEEC_InvokeCommand(&session, TA_OS_TEST_CMD_MEMTAG_USE_AFTER_FREE,
				 &op, &ret_orig);
	if (res == TEEC_ERROR_NOT_SUPPORTED) {
		Do_ADBG_Log("Binary doesn't support MTE - skip tests");
		goto out;
	}

	ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_TARGET_DEAD, res);
	ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TEE, ret_orig);
	TEEC_CloseSession(&session);

	Do_ADBG_EndSubCase(c, "MTE use after free");

	Do_ADBG_BeginSubCase(c, "MTE invalid tag");

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE,
					 TEEC_NONE);

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			xtest_teec_open_session(&session, &os_test_ta_uuid,
						NULL, &ret_orig)))
		return;

	res = TEEC_InvokeCommand(&session, TA_OS_TEST_CMD_MEMTAG_INVALID_TAG,
				 &op, &ret_orig);
	if (res == TEEC_ERROR_NOT_SUPPORTED) {
		Do_ADBG_Log("Binary doesn't support MTE - skip tests");
		goto out;
	}

	ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_TARGET_DEAD, res);
	ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TEE, ret_orig);

	Do_ADBG_EndSubCase(c, "MTE invalid tag");

	Do_ADBG_BeginSubCase(c, "MTE double free");

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE,
					 TEEC_NONE);

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			xtest_teec_open_session(&session, &os_test_ta_uuid,
						NULL, &ret_orig)))
		return;

	res = TEEC_InvokeCommand(&session, TA_OS_TEST_CMD_MEMTAG_DOUBLE_FREE,
				 &op, &ret_orig);
	if (res == TEEC_ERROR_NOT_SUPPORTED) {
		Do_ADBG_Log("Binary doesn't support MTE - skip tests");
		goto out;
	}

	ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_TARGET_DEAD, res);
	ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TEE, ret_orig);

	Do_ADBG_EndSubCase(c, "MTE double free");

	Do_ADBG_BeginSubCase(c, "MTE buffer overrun");

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE,
					 TEEC_NONE);

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			xtest_teec_open_session(&session, &os_test_ta_uuid,
						NULL, &ret_orig)))
		return;

	res = TEEC_InvokeCommand(&session, TA_OS_TEST_CMD_MEMTAG_BUFFER_OVERRUN,
				 &op, &ret_orig);
	if (res == TEEC_ERROR_NOT_SUPPORTED) {
		Do_ADBG_Log("Binary doesn't support MTE - skip tests");
		goto out;
	}

	ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_TARGET_DEAD, res);
	ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TEE, ret_orig);

	Do_ADBG_EndSubCase(c, "MTE buffer overrun");


out:
	TEEC_CloseSession(&session);
}
ADBG_CASE_DEFINE(regression, 1038, xtest_tee_test_1038,
		 "Test MTE (Memory Tag Extension)");

static void xtest_tee_test_1039(ADBG_Case_t *c)
{
	TEEC_Session session = { };
	uint32_t ret_orig = 0;

	Do_ADBG_BeginSubCase(c, "Load TA with two levels of subkeys");
	if (ADBG_EXPECT_TEEC_SUCCESS(c,
			xtest_teec_open_session(&session, &subkey1_ta_uuid,
						NULL, &ret_orig)))
		TEEC_CloseSession(&session);
	Do_ADBG_EndSubCase(c, "Load TA with two levels of subkeys");

	Do_ADBG_BeginSubCase(c, "Load TA with identity subkey");
	if (ADBG_EXPECT_TEEC_SUCCESS(c,
			xtest_teec_open_session(&session, &subkey2_ta_uuid,
						NULL, &ret_orig)))
		TEEC_CloseSession(&session);
	Do_ADBG_EndSubCase(c, "Load TA with identity subkey");

}
ADBG_CASE_DEFINE(regression, 1039, xtest_tee_test_1039,
		 "Test subkey verification");

struct test_1040_thread_arg {
	TEEC_Result res;
	pthread_t thr;
};

static void *test_1040_thread(void *arg)
{
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	struct test_1040_thread_arg *a = arg;
	TEEC_Result res = TEEC_SUCCESS;
	uint32_t err_orig = 0;
	TEEC_Session session = { };
	size_t loop_count = 100;
	size_t n = 0;

	if (level == 0)
		loop_count /= 2;

	while (n < loop_count) {
		res = xtest_teec_open_session(&session, &sims_test_ta_uuid,
					      NULL, &err_orig);
		if (res) {
			if (res == TEEC_ERROR_TARGET_DEAD)
				continue;
			a->res = res;
			return NULL;
		}

		memset(&op, 0, sizeof(op));
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
						 TEEC_NONE, TEEC_NONE,
						 TEEC_NONE);
		res = TEEC_InvokeCommand(&session, TA_SIMS_CMD_PANIC, &op,
					 &err_orig);
		TEEC_CloseSession(&session);
		if (res != TEEC_ERROR_TARGET_DEAD) {
			if (res)
				a->res = res;
			else
				a->res = TEEC_ERROR_GENERIC;
			return NULL;
		}
		n++;
	}
	a->res = TEEC_SUCCESS;
	return NULL;
}

static void xtest_tee_test_1040(ADBG_Case_t *c)
{
	struct test_1040_thread_arg arg[NUM_THREADS] = { };
	size_t nt = NUM_THREADS;
	size_t n = 0;

	Do_ADBG_BeginSubCase(c, "Concurrent invoke with panic in TA");
	for (n = 0; n < nt; n++) {
		if (!ADBG_EXPECT(c, 0, pthread_create(&arg[n].thr, NULL,
						      test_1040_thread,
						      arg + n)))
			nt = n; /* break loop and start cleanup */
	}
	for (n = 0; n < nt; n++) {
		ADBG_EXPECT(c, 0, pthread_join(arg[n].thr, NULL));
		ADBG_EXPECT_TEEC_SUCCESS(c, arg[n].res);
	}
	Do_ADBG_EndSubCase(c, "Concurrent invoke with panic in TA");
}
ADBG_CASE_DEFINE(regression, 1040, xtest_tee_test_1040,
		 "Test panic in concurrent open/invoke/close session");

static void xtest_tee_test_1041(ADBG_Case_t *c)
{
	const char fname[] = "/dev/tpm0";
	TEE_Result res = TEEC_SUCCESS;
	TEEC_Session sess = { };
	uint32_t ret_orig = 0;
	struct stat sb = { };
	bool found = false;
	int max_wait = 20;
	int i = 0;

	res = xtest_teec_open_session(&sess, &(const TEEC_UUID)TA_FTPM_UUID,
				      NULL, &ret_orig);
	if (res == TEEC_ERROR_ITEM_NOT_FOUND) {
		Do_ADBG_Log("skip test, fTPM TA not present");
		return;
	}
	if (res != TEEC_ERROR_BUSY && ADBG_EXPECT_TEEC_SUCCESS(c, res))
		TEEC_CloseSession(&sess);

	/*
	 * Check for the presence of the TPM device. Give the kernel some time
	 * (5 seconds) otherwise the test may fail if run immediately after
	 * boot.
	 */
	for (i = 0; i < max_wait; i++) {
		if (stat(fname, &sb) == 0) {
			found = true;
			break;
		}
		Do_ADBG_Log("Waiting for TPM device %d / %d", i, max_wait);
		sleep(1);
	}
	if (!ADBG_EXPECT_TRUE(c, found)) {
		Do_ADBG_Log("stat(\"%s\"): %s", fname, strerror(errno));
		if (res != TEEC_ERROR_BUSY)
			Do_ADBG_Log("Perhaps fTPM hasn't finished probing");
		return;
	}

	if (!ADBG_EXPECT_TRUE(c, S_ISCHR(sb.st_mode)))
		Do_ADBG_Log("Expected \"%s\" to be a character device", fname);
}
ADBG_CASE_DEFINE(regression, 1041, xtest_tee_test_1041, "Test fTPM sanity");
