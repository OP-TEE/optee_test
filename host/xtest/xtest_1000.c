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

#include <stdio.h>
#include <string.h>

#ifdef USER_SPACE
#include <pthread.h>
#include <unistd.h>
#endif

#include "xtest_test.h"
#include "xtest_helpers.h"

#include <ta_crypt.h>
#include <ta_os_test.h>
#include <ta_create_fail_test.h>
#include <ta_rpc_test.h>
#include <ta_sims_test.h>

static void xtest_tee_test_1001(ADBG_Case_t *Case_p);
static void xtest_tee_test_1004(ADBG_Case_t *Case_p);
static void xtest_tee_test_1005(ADBG_Case_t *Case_p);
static void xtest_tee_test_1006(ADBG_Case_t *Case_p);
static void xtest_tee_test_1007(ADBG_Case_t *Case_p);
static void xtest_tee_test_1008(ADBG_Case_t *Case_p);
static void xtest_tee_test_1009(ADBG_Case_t *Case_p);
static void xtest_tee_test_1010(ADBG_Case_t *Case_p);
static void xtest_tee_test_1011(ADBG_Case_t *Case_p);
static void xtest_tee_test_1012(ADBG_Case_t *Case_p);

ADBG_CASE_DEFINE(XTEST_TEE_1001, xtest_tee_test_1001,
		/* Title */
		"Registering TAs",
		/* Short description */
		"Short description ...",
		/* Requirement IDs */
		"TEE-??",
		/* How to implement */
		"Description of how to implement ..."
		 );

ADBG_CASE_DEFINE(XTEST_TEE_1004, xtest_tee_test_1004,
		/* Title */
		"Test User Crypt TA",
		/* Short description */
		"Short description ...",
		/* Requirement IDs */
		"TEE-??",
		/* How to implement */
		"Description of how to implement ..."
		 );

ADBG_CASE_DEFINE(XTEST_TEE_1005, xtest_tee_test_1005,
		/* Title */
		"Many sessions",
		/* Short description */
		"Short description ...",
		/* Requirement IDs */
		"TEE-??",
		/* How to implement */
		"Description of how to implement ..."
		 );

ADBG_CASE_DEFINE(XTEST_TEE_1006, xtest_tee_test_1006,
		/* Title */
		"Test Basic OS features",
		/* Short description */
		"Short description ...",
		/* Requirement IDs */
		"TEE-??",
		/* How to implement */
		"Description of how to implement ..."
		 );

ADBG_CASE_DEFINE(XTEST_TEE_1007, xtest_tee_test_1007,
		/* Title */
		"Test Panic",
		/* Short description */
		"Short description ...",
		/* Requirement IDs */
		"TEE-??",
		/* How to implement */
		"Description of how to implement ..."
		 );

ADBG_CASE_DEFINE(XTEST_TEE_1008, xtest_tee_test_1008,
		/* Title */
		"TEE internal client API",
		/* Short description */
		"Short description ...",
		/* Requirement IDs */
		"TEE-??",
		/* How to implement */
		"Description of how to implement ..."
		 );

ADBG_CASE_DEFINE(XTEST_TEE_1009, xtest_tee_test_1009,
		/* Title */
		"TEE Wait",
		/* Short description */
		"Short description ...",
		/* Requirement IDs */
		"TEE-??",
		/* How to implement */
		"Description of how to implement ..."
		 );

ADBG_CASE_DEFINE(XTEST_TEE_1010, xtest_tee_test_1010,
		/* Title */
		"Invalid memory access",
		/* Short description */
		"Short description ...",
		/* Requirement IDs */
		"TEE-??",
		/* How to implement */
		"Description of how to implement ..."
		 );

ADBG_CASE_DEFINE(XTEST_TEE_1011, xtest_tee_test_1011,
		/* Title */
		"Test RPC features with User Crypt TA",
		/* Short description */
		"Short description ...",
		/* Requirement IDs */
		"TEE-??",
		/* How to implement */
		"Description of how to implement ..."
		 );

ADBG_CASE_DEFINE(XTEST_TEE_1012, xtest_tee_test_1012,
		/* Title */
		"Test Single Instance Multi Session features with SIMS TA",
		/* Short description */
		"Short description ...",
		/* Requirement IDs */
		"TEE-??",
		/* How to implement */
		"Description of how to implement ..."
		 );

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

	Do_ADBG_BeginSubCase(cs->c,
			     "AES-256 ECB encrypt test, 32 bytes input, with fixed key");
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
	Do_ADBG_EndSubCase(cs->c,
			   "AES-256 ECB encrypt test, 32 bytes input, with fixed key");

	Do_ADBG_BeginSubCase(cs->c,
			     "AES-256 ECB decrypt test, 32 bytes input, with fixed key");
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
	Do_ADBG_EndSubCase(cs->c,
			   "AES-256 ECB decrypt test, 32 bytes input, with fixed key");
}

static void xtest_tee_test_1001(ADBG_Case_t *c)
{
#ifdef USER_SPACE
	(void)c;
#else
#define REG_TA(name) \
	(void)ADBG_EXPECT_TEEC_SUCCESS(c, \
		TEEC_RegisterTA(name, name ## _size))

	REG_TA(crypt_user_ta);
	REG_TA(os_test_ta);
	REG_TA(create_fail_test_ta);
	REG_TA(rpc_test_ta);
	REG_TA(sims_test_ta);

	TEEC_UnregisterTA(crypt_user_ta);
	TEEC_UnregisterTA(os_test_ta);
	TEEC_UnregisterTA(create_fail_test_ta);
	TEEC_UnregisterTA(rpc_test_ta);
	TEEC_UnregisterTA(sims_test_ta);

	REG_TA(crypt_user_ta);
	REG_TA(os_test_ta);
	REG_TA(create_fail_test_ta);
	REG_TA(rpc_test_ta);
	REG_TA(sims_test_ta);
	REG_TA(storage_ta);

	REG_TA(gp_tta_testing_client_api_ta);
	REG_TA(gp_tta_answer_success_to_open_session_invoke_ta);
	REG_TA(gp_tta_answer_error_to_invoke_ta);
	REG_TA(gp_tta_answer_error_to_open_session_ta);
	REG_TA(gp_tta_check_open_session_with_4_parameters_ta);
	REG_TA(gp_tta_time_ta);
	REG_TA(gp_tta_ds_ta);
	REG_TA(gp_tta_tcf_ta);
	REG_TA(gp_tta_crypto_ta);
	REG_TA(gp_tta_arithm_ta);
	REG_TA(gp_tta_ica_ta);
	REG_TA(gp_tta_ica2_ta);
	REG_TA(gp_tta_tcf_singleinstance_ta);
	REG_TA(gp_tta_tcf_multipleinstance_ta);
#endif  /*!USER_SPACE*/
}

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

#ifndef TEEC_ERROR_TARGET_DEAD
/* To be removed when we have TEEC_ERROR_TARGET_DEAD from tee_client_api.h */
#define TEEC_ERROR_TARGET_DEAD           0xFFFF3024
#endif

static void xtest_tee_test_invalid_mem_access(ADBG_Case_t *c, uint32_t n)
{
	TEEC_Session session = { 0 };
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;

	(void)ADBG_EXPECT_TEEC_SUCCESS(c,
		xtest_teec_open_session(&session, &os_test_ta_uuid, NULL,
					&ret_orig));

	op.params[0].value.a = n;
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE,
					 TEEC_NONE);

	(void)ADBG_EXPECT_TEEC_RESULT(c,
		TEEC_ERROR_TARGET_DEAD,
		TEEC_InvokeCommand(&session, TA_OS_TEST_CMD_BAD_MEM_ACCESS, &op,
				   &ret_orig));

	(void)ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_TARGET_DEAD,
				      TEEC_InvokeCommand(&session,
					TA_OS_TEST_CMD_BAD_MEM_ACCESS,
					&op,
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
			xtest_teec_open_session(&sessions[i], &os_test_ta_uuid,
						NULL, &ret_orig)))
			break;
	}

	for (; --i >= 0; )
		TEEC_CloseSession(&sessions[i]);
}

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

static void xtest_tee_test_1007(ADBG_Case_t *c)
{
	TEEC_Session session = { 0 };
	uint32_t ret_orig;

	(void)ADBG_EXPECT_TEEC_SUCCESS(c,
		xtest_teec_open_session(&session, &os_test_ta_uuid, NULL,
					&ret_orig));

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

static void xtest_tee_test_1008(ADBG_Case_t *c)
{
	TEEC_Session session = { 0 };
	TEEC_Session session_crypt = { 0 };
	uint32_t ret_orig;

	Do_ADBG_BeginSubCase(c, "Invoke command");
	{
		(void)ADBG_EXPECT_TEEC_SUCCESS(c,
			xtest_teec_open_session(&session_crypt,
						&crypt_user_ta_uuid, NULL,
						&ret_orig));

		(void)ADBG_EXPECT_TEEC_SUCCESS(c,
			xtest_teec_open_session(&session, &os_test_ta_uuid,
						NULL, &ret_orig));

		(void)ADBG_EXPECT_TEEC_SUCCESS(c,
			TEEC_InvokeCommand(&session, TA_OS_TEST_CMD_CLIENT,
					   NULL, &ret_orig));

		TEEC_CloseSession(&session);
		TEEC_CloseSession(&session_crypt);
	}
	Do_ADBG_EndSubCase(c, "Invoke command");

	Do_ADBG_BeginSubCase(c, "Invoke command with timeout");
	{
		TEEC_Operation op = TEEC_OPERATION_INITIALIZER;

		op.params[0].value.a = 2000;
		op.paramTypes = TEEC_PARAM_TYPES(
			TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);

		(void)ADBG_EXPECT_TEEC_SUCCESS(c,
			xtest_teec_open_session(&session,
						&os_test_ta_uuid,
						NULL,
						&ret_orig));

		(void)ADBG_EXPECT_TEEC_SUCCESS(c,
			TEEC_InvokeCommand(&session,
					   TA_OS_TEST_CMD_CLIENT_WITH_TIMEOUT,
					   &op, &ret_orig));

		TEEC_CloseSession(&session);
	}
	Do_ADBG_EndSubCase(c, "Invoke command with timeout");

	Do_ADBG_BeginSubCase(c, "Create session fail");
	{
		(void)ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_GENERIC,
			xtest_teec_open_session(&session_crypt,
						&create_fail_test_ta_uuid, NULL,
						&ret_orig));
		size_t n;

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
}

#ifdef USER_SPACE
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
#endif

static void xtest_tee_test_1009(ADBG_Case_t *c)
{
	TEEC_Session session = { 0 };
	uint32_t ret_orig;

	Do_ADBG_BeginSubCase(c, "TEE Wait 0.1s");
	{
		TEEC_Operation op = TEEC_OPERATION_INITIALIZER;

		(void)ADBG_EXPECT_TEEC_SUCCESS(c,
			xtest_teec_open_session(&session, &os_test_ta_uuid,
						NULL, &ret_orig));

		(void)ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TRUSTED_APP,
						    ret_orig);

		op.params[0].value.a = 100;
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
						 TEEC_NONE, TEEC_NONE);

		(void)ADBG_EXPECT_TEEC_SUCCESS(c,
			TEEC_InvokeCommand(&session, TA_OS_TEST_CMD_WAIT, &op,
					   &ret_orig));
		TEEC_CloseSession(&session);
	}
	Do_ADBG_EndSubCase(c, "TEE Wait 0.1s");

	Do_ADBG_BeginSubCase(c, "TEE Wait 0.5s");
	{
		TEEC_Operation op = TEEC_OPERATION_INITIALIZER;

		(void)ADBG_EXPECT_TEEC_SUCCESS(c,
			xtest_teec_open_session(&session, &os_test_ta_uuid,
						NULL, &ret_orig));

		(void)ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TRUSTED_APP,
						    ret_orig);

		op.params[0].value.a = 500;
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
						 TEEC_NONE, TEEC_NONE);

		(void)ADBG_EXPECT_TEEC_SUCCESS(c,
			TEEC_InvokeCommand(&session, TA_OS_TEST_CMD_WAIT, &op,
					   &ret_orig));

		(void)ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TRUSTED_APP,
						    ret_orig);
		TEEC_CloseSession(&session);
	}
	Do_ADBG_EndSubCase(c, "TEE Wait 0.5s");

#ifdef USER_SPACE
	Do_ADBG_BeginSubCase(c, "TEE Wait 2s cancel");
	{
		pthread_t thr;
		TEEC_Operation op = TEEC_OPERATION_INITIALIZER;

		(void)ADBG_EXPECT_TEEC_SUCCESS(c,
			xtest_teec_open_session(&session, &os_test_ta_uuid,
						NULL, &ret_orig));

		(void)ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TRUSTED_APP,
						    ret_orig);

		op.params[0].value.a = 2000;
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
						 TEEC_NONE, TEEC_NONE);

		(void)ADBG_EXPECT(c, 0,
			pthread_create(&thr, NULL, cancellation_thread, &op));

		(void)ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_CANCEL,
			TEEC_InvokeCommand(&session, TA_OS_TEST_CMD_WAIT, &op,
					   &ret_orig));

		(void)ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TRUSTED_APP,
						    ret_orig);
		(void)ADBG_EXPECT(c, 0, pthread_join(thr, NULL));
		TEEC_CloseSession(&session);
	}
	Do_ADBG_EndSubCase(c, "TEE Wait 2s cancel");
#endif

	Do_ADBG_BeginSubCase(c, "TEE Wait 2s");
	{
		TEEC_Operation op = TEEC_OPERATION_INITIALIZER;

		(void)ADBG_EXPECT_TEEC_SUCCESS(c,
			xtest_teec_open_session(&session, &os_test_ta_uuid,
						NULL, &ret_orig));

		op.params[0].value.a = 2000;
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
						 TEEC_NONE, TEEC_NONE);

		(void)ADBG_EXPECT_TEEC_SUCCESS(c,
			TEEC_InvokeCommand(&session, TA_OS_TEST_CMD_WAIT, &op,
					   &ret_orig));

		TEEC_CloseSession(&session);
	}
	Do_ADBG_EndSubCase(c, "TEE Wait 2s");
}

static void xtest_tee_test_1010(ADBG_Case_t *c)
{
	unsigned n;

	for (n = 1; n <= 5; n++) {
		Do_ADBG_BeginSubCase(c, "Invalid memory access %u", n);
		xtest_tee_test_invalid_mem_access(c, n);
		Do_ADBG_EndSubCase(c, "Invalid memory access %u", n);
	}
}

static void xtest_tee_test_1011(ADBG_Case_t *c)
{
	TEEC_Session session = { 0 };
	uint32_t ret_orig;
	struct xtest_crypto_session cs = {
		c, &session, TA_RPC_CMD_CRYPT_SHA256,
		TA_RPC_CMD_CRYPT_AES256ECB_ENC,
		TA_RPC_CMD_CRYPT_AES256ECB_DEC
	};
	TEEC_UUID uuid = rpc_test_ta_uuid;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		xtest_teec_open_session(&session, &uuid, NULL, &ret_orig)))
		return;

	/*
	 * Run the "complete crypto test suite" using RPC
	 */
	xtest_crypto_test(&cs);
	TEEC_CloseSession(&session);
}

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

		(void)ADBG_EXPECT_TEEC_SUCCESS(c,
			xtest_teec_open_session(&session1, &uuid, NULL,
						&ret_orig));

		op.params[0].value.a = 0;
		op.params[1].tmpref.buffer = (void *)in;
		op.params[1].tmpref.size = sizeof(in);
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
						 TEEC_MEMREF_TEMP_INPUT,
						 TEEC_NONE, TEEC_NONE);

		(void)ADBG_EXPECT_TEEC_SUCCESS(c,
			TEEC_InvokeCommand(&session1, TA_SIMS_CMD_WRITE, &op,
					   &ret_orig));

		for (i = 1; i < 1000; i++) {
			(void)ADBG_EXPECT_TEEC_SUCCESS(c,
				xtest_teec_open_session(&session2, &uuid, NULL,
							&ret_orig));

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
