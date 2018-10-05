/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
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

#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "xtest_test.h"
#include "xtest_helpers.h"
#include <signed_hdr.h>
#include <util.h>

#include <pta_invoke_tests.h>
#include <ta_crypt.h>
#include <ta_os_test.h>
#include <ta_create_fail_test.h>
#include <ta_rpc_test.h>
#include <ta_sims_test.h>
#include <ta_concurrent.h>
#include <sdp_basic.h>
#ifdef CFG_SECSTOR_TA_MGMT_PTA
#include <pta_secstor_ta_mgmt.h>
#endif

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

struct xtest_crypto_session {
	ADBG_Case_t *c;
	TEEC_Session *session;
	uint32_t cmd_id_sha256;
	uint32_t cmd_id_aes256ecb_encrypt;
	uint32_t cmd_id_aes256ecb_decrypt;
};

static void xtest_crypto_test(struct xtest_crypto_session *cs)
{
	uint32_t ret_orig;
	uint8_t crypt_out[16];
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
		uint8_t out[16];

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
		uint8_t out[32] = { 0 };

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
		uint8_t out[sizeof(exp_out)];

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
		uint8_t out[sizeof(exp_out)];

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
	TEEC_Result res;
	TEEC_Session session = { 0 };
	uint32_t ret_orig;

	/* Pseudo TA is optional: warn and nicely exit if not found */
	res = xtest_teec_open_session(&session, &pta_invoke_tests_ta_uuid, NULL,
				      &ret_orig);
	if (res == TEEC_ERROR_ITEM_NOT_FOUND) {
		Do_ADBG_Log(" - 1001 -   skip test, pseudo TA not found");
		return;
	}
	ADBG_EXPECT_TEEC_SUCCESS(c, res);

	(void)ADBG_EXPECT_TEEC_SUCCESS(c, TEEC_InvokeCommand(
		&session, PTA_INVOKE_TESTS_CMD_SELF_TESTS, NULL, &ret_orig));
	TEEC_CloseSession(&session);
}
ADBG_CASE_DEFINE(regression, 1001, xtest_tee_test_1001, "Core self tests");

static void xtest_tee_test_1002(ADBG_Case_t *c)
{
	TEEC_Result res;
	TEEC_Session session = { 0 };
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;
	uint8_t buf[16 * 1024];
	uint8_t exp_sum = 0;
	size_t n;

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
	TEEC_Session session = { 0 };
	size_t rounds = 64 * 1024;
	size_t n;

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

static void xtest_tee_test_1003(ADBG_Case_t *c)
{
	size_t num_threads = 3 * 2;
	TEEC_Result res;
	TEEC_Session session = { 0 };
	uint32_t ret_orig;
	size_t repeat = 20;
	pthread_t thr[num_threads];
	struct test_1003_arg arg[num_threads];
	size_t max_read_concurrency = 0;
	size_t max_read_waiters = 0;
	size_t num_concurrent_read_lockers = 0;
	size_t num_concurrent_read_waiters = 0;
	size_t n;
	size_t nt = num_threads;
	double mean_read_concurrency;
	double mean_read_waiters;
	size_t num_writers = 0;
	size_t num_readers = 0;

	/* Pseudo TA is optional: warn and nicely exit if not found */
	res = xtest_teec_open_session(&session, &pta_invoke_tests_ta_uuid, NULL,
				      &ret_orig);
	if (res == TEEC_ERROR_ITEM_NOT_FOUND) {
		Do_ADBG_Log(" - 1003 -   skip test, pseudo TA not found");
		return;
	}
	ADBG_EXPECT_TEEC_SUCCESS(c, res);
	TEEC_CloseSession(&session);

	memset(arg, 0, sizeof(arg));

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

	Do_ADBG_Log("    Number of parallel threads: %zu (%zu writers and %zu readers)",
		    num_threads, num_writers, num_readers);
	Do_ADBG_Log("    Max read concurrency: %zu", max_read_concurrency);
	Do_ADBG_Log("    Max read waiters: %zu", max_read_waiters);
	Do_ADBG_Log("    Mean read concurrency: %g", mean_read_concurrency);
	Do_ADBG_Log("    Mean read waiting: %g", mean_read_waiters);
}
ADBG_CASE_DEFINE(regression, 1003, xtest_tee_test_1003,
		 "Core internal read/write mutex");

static void xtest_tee_test_1004(ADBG_Case_t *c)
{
	TEEC_Session session = { 0 };
	uint32_t ret_orig;
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
	TEEC_Session session = { 0 };
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;

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
	TEEC_Session session = { 0 };
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;
	TEEC_SharedMemory shm;

	memset(&shm, 0, sizeof(shm));
	shm.size = size;
	shm.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		TEEC_AllocateSharedMemory(&xtest_teec_ctx, &shm)))
		return;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		xtest_teec_open_session(&session, &os_test_ta_uuid, NULL,
		                        &ret_orig)))
		return;

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
}

static void xtest_tee_test_1005(ADBG_Case_t *c)
{
	uint32_t ret_orig;
#define MAX_SESSIONS    3
	TEEC_Session sessions[MAX_SESSIONS];
	int i;

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
	TEEC_Session session = { 0 };
	uint32_t ret_orig;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint8_t buf[32];

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
	TEEC_Session session = { 0 };
	uint32_t ret_orig;

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

#ifdef CFG_SECSTOR_TA_MGMT_PTA
#ifndef TA_DIR
# ifdef __ANDROID__
#define TA_DIR "/vendor/lib/optee_armtz"
# else
#define TA_DIR "/lib/optee_armtz"
# endif
#endif

static FILE *open_ta_file(const TEEC_UUID *uuid, const char *mode)
{
	char buf[PATH_MAX];

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
	TEEC_Session session = { 0 };
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	TEEC_UUID uuid = PTA_SECSTOR_TA_MGMT_UUID;
	TEEC_Result res;
	uint32_t ret_orig;
	FILE *f = NULL;
	bool r = false;
	uint8_t *buf = NULL;
	size_t sz;
	size_t fread_res;

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
#endif /*CFG_SECSTOR_TA_MGMT_PTA*/

static void xtest_tee_test_1008(ADBG_Case_t *c)
{
	TEEC_Session session = { 0 };
	TEEC_Session session_crypt = { 0 };
	uint32_t ret_orig;

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
		size_t n;

		(void)ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_GENERIC,
			xtest_teec_open_session(&session_crypt,
						&create_fail_test_ta_uuid, NULL,
						&ret_orig));
		/*
		 * Run this several times to see that there's no memory leakage.
		 */
		for (n = 0; n < 100; n++) {
			Do_ADBG_Log("n = %zu", n);
			(void)ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_GENERIC,
				xtest_teec_open_session(&session_crypt,
					&create_fail_test_ta_uuid,
					NULL, &ret_orig));
		}
	}
	Do_ADBG_EndSubCase(c, "Create session fail");

#ifdef CFG_SECSTOR_TA_MGMT_PTA
	Do_ADBG_BeginSubCase(c, "Load corrupt TA");
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
	ADBG_EXPECT_TRUE(c, load_corrupt_ta(c, 30000, 1)); /* payload */
	Do_ADBG_EndSubCase(c, "Load corrupt TA");
#endif /*CFG_SECSTOR_TA_MGMT_PTA*/
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
	TEEC_Session session = { 0 };
	uint32_t ret_orig;
	pthread_t thr;

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
	unsigned int n;
	unsigned int idx;
	size_t memref_sz[] = { 1024, 65536 };

	for (n = 1; n <= 5; n++) {
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
	TEEC_Session session = { 0 };
	uint32_t ret_orig;
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
	TEEC_Session session1 = { 0 };
	TEEC_Session session2 = { 0 };
	uint32_t ret_orig;
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
		uint8_t out[32] = { 0 };
		int i;

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
	TEEC_Session session = { 0 };
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
	size_t num_threads = NUM_THREADS;
	size_t nt;
	size_t n;
	size_t repeat = 1000;
	pthread_t thr[num_threads];
	TEEC_SharedMemory shm;
	size_t max_concurrency;
	struct test_1013_thread_arg arg[num_threads];
	static const uint8_t sha256_in[] = { 'a', 'b', 'c' };
	static const uint8_t sha256_out[] = {
		0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
		0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
		0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
		0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
	};
	uint8_t out[32] = { 0 };

	Do_ADBG_BeginSubCase(c, "Busy loop repeat %zu", repeat * 10);
	*mean_concurrency = 0;

	memset(&shm, 0, sizeof(shm));
	shm.size = sizeof(struct ta_concurrent_shm);
	shm.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		TEEC_AllocateSharedMemory(&xtest_teec_ctx, &shm)))
		return;

	memset(shm.buffer, 0, shm.size);
	memset(arg, 0, sizeof(arg));
	max_concurrency = 0;
	nt = num_threads;

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
		ADBG_EXPECT_TEEC_SUCCESS(c, arg[n].res);
		if (arg[n].max_concurrency > max_concurrency)
			max_concurrency = arg[n].max_concurrency;
	}

	/*
	 * Concurrency can be limited by several factors, for instance in a
	 * single CPU system it's dependent on the Preemtion Model used by
	 * the kernel (Preemptible Kernel (Low-Latency Desktop) gives the
	 * best result there).
	 */
	(void)ADBG_EXPECT_COMPARE_UNSIGNED(c, max_concurrency, >, 0);
	(void)ADBG_EXPECT_COMPARE_UNSIGNED(c, max_concurrency, <=, num_threads);
	*mean_concurrency += max_concurrency;
	Do_ADBG_EndSubCase(c, "Busy loop repeat %zu", repeat * 10);

	Do_ADBG_BeginSubCase(c, "SHA-256 loop repeat %zu", repeat);
	memset(shm.buffer, 0, shm.size);
	memset(arg, 0, sizeof(arg));
	max_concurrency = 0;
	nt = num_threads;

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
		if (ADBG_EXPECT(c, 0, pthread_join(thr[n], NULL)) &&
		    ADBG_EXPECT_TEEC_SUCCESS(c, arg[n].res))
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
	int i;
	double mean_concurrency;
	double concurrency;
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

#ifndef CFG_PAGED_USER_TA
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
#endif
}
ADBG_CASE_DEFINE(regression, 1013, xtest_tee_test_1013,
		"Test concurency with concurrent TA");

#ifdef CFG_SECURE_DATA_PATH
static void xtest_tee_test_1014(ADBG_Case_t *c)
{
	UNUSED(c);

	int size = 17000;
	int loop = 10;
	int ion_heap = DEFAULT_ION_HEAP_TYPE;
	int rnd_offset = 1;
	int test;
	int ret;

	test = TEST_NS_TO_TA;
	Do_ADBG_BeginSubCase(c, "SDP: NonSecure client invokes a SDP TA");
	ret = sdp_basic_test(test, size, loop, ion_heap, rnd_offset, 0);
	ADBG_EXPECT(c, 0, ret);
	Do_ADBG_EndSubCase(c, "SDP: NonSecure client invokes a SDP TA");

	test = TEST_TA_TO_TA;
	Do_ADBG_BeginSubCase(c, "SDP: SDP TA invokes a SDP TA");
	ret = sdp_basic_test(test, size, loop, ion_heap, rnd_offset, 0);
	ADBG_EXPECT(c, 0, ret);
	Do_ADBG_EndSubCase(c, "SDP: SDP TA invokes a SDP TA");

	test = TEST_TA_TO_PTA;
	Do_ADBG_BeginSubCase(c, "SDP: SDP TA invokes a SDP pTA");
	ret = sdp_basic_test(test, size, loop, ion_heap, rnd_offset, 0);
	ADBG_EXPECT(c, 0, ret);
	Do_ADBG_EndSubCase(c, "SDP: SDP TA invokes a SDP pTA");

	test = TEST_NS_TO_PTA;
	Do_ADBG_BeginSubCase(c, "SDP: NSec CA invokes SDP pTA (should fail)");
	ret = sdp_basic_test(test, size, loop, ion_heap, rnd_offset, 0);
	ADBG_EXPECT(c, 1, ret);
	Do_ADBG_EndSubCase(c, "SDP: NSec CA invokes SDP pTA (should fail)");
}
ADBG_CASE_DEFINE(regression, 1014, xtest_tee_test_1014,
		"Test secure data path against SDP TAs and pTAs");
#endif /*CFG_SECURE_DATA_PATH*/

static void xtest_tee_test_1015(ADBG_Case_t *c)
{
	TEEC_Result res;
	TEEC_Session session = { 0 };
	uint32_t ret_orig;

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

static void xtest_tee_test_1016(ADBG_Case_t *c)
{
	TEEC_Session session = { 0 };
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		xtest_teec_open_session(&session, &os_test_ta_uuid, NULL,
		                        &ret_orig)))
		return;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE,
					 TEEC_NONE);

	(void)ADBG_EXPECT_TEEC_SUCCESS(c,
		TEEC_InvokeCommand(&session, TA_OS_TEST_CMD_TA2TA_MEMREF, &op,
				   &ret_orig));

	TEEC_CloseSession(&session);
}
ADBG_CASE_DEFINE(regression, 1016, xtest_tee_test_1016,
		"Test TA to TA transfers (in/out/inout memrefs on the stack)");

static void xtest_tee_test_1017(ADBG_Case_t *c)
{
	TEEC_Session session = { 0 };
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;
	TEEC_SharedMemory shm;
	size_t page_size = 4096;

	memset(&shm, 0, sizeof(shm));
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

static void xtest_tee_test_1018(ADBG_Case_t *c)
{
	TEEC_Session session = { 0 };
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;
	TEEC_SharedMemory shm;
	size_t page_size = 4096;

	memset(&shm, 0, sizeof(shm));
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
	op.params[3].memref.size = 3 * page_size;
	op.params[3].memref.offset = 6 * page_size;

	/*
	 * Depending on the tee driver we may have different error codes.
	 * What's most important is that secure world doesn't panic and
	 * that someone detects an error.
	 */
	ADBG_EXPECT_NOT(c, TEE_SUCCESS,
			TEEC_InvokeCommand(&session, TA_OS_TEST_CMD_PARAMS, &op,
					   &ret_orig));

	TEEC_CloseSession(&session);
out:
	TEEC_ReleaseSharedMemory(&shm);
}
ADBG_CASE_DEFINE(regression, 1018, xtest_tee_test_1018,
		"Test memref out of bounds");

#if defined(CFG_TA_DYNLINK)
static void xtest_tee_test_1019(ADBG_Case_t *c)
{
	TEEC_Session session = { 0 };
	uint32_t ret_orig;

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
#endif /*CFG_TA_DYNLINK*/

static void xtest_tee_test_1020(ADBG_Case_t *c)
{
	TEEC_Result res;
	TEEC_Session session = { 0 };
	uint32_t ret_orig;

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
