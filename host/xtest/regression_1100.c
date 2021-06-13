// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2020, Microsoft Corporation
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <ta_ocall_data.h>
#include <ta_ocall_test.h>

#include "xtest_helpers.h"
#include "xtest_test.h"

static ADBG_Case_t *local_c;

static bool no_ecall_params_no_ocall_params_reply;
static bool no_ecall_params_ocall_value_params_reply;
static bool no_ecall_params_ocall_memref_params_reply;
static bool null_memref_params_reply;
static bool null_memref_params_mixed_reply;
static bool null_memref_params_invalid_reply;
static bool session_open_ocall_reply;
static bool session_open_ocall_premature_ctx_finalize_reply;

static TEEC_Result
ocall_handler(TEEC_UUID *taUUID, uint32_t commandId, uint32_t paramTypes,
	      TEEC_Parameter params[TEEC_CONFIG_PAYLOAD_REF_COUNT],
	      void *ctx_data, void *session_data)
{
	uint32_t exp_pt;

	ADBG_EXPECT_EQUAL(local_c, &ocall_ta_uuid, taUUID,
			  sizeof(*taUUID));

	switch (commandId) {
	case CA_OCALL_CMD_NO_ECALL_PARAMS_NO_OCALL_PARAMS:
		no_ecall_params_no_ocall_params_reply = true;

		exp_pt = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE,
					  TEEC_NONE);
		ADBG_EXPECT(local_c, exp_pt, paramTypes);
		break;

	case CA_OCALL_CMD_NO_ECALL_PARAMS_OCALL_VALUE_PARAMS:
		no_ecall_params_ocall_value_params_reply = true;

		exp_pt = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_VALUE_INOUT,
					  TEEC_VALUE_OUTPUT, TEEC_VALUE_INPUT);
		ADBG_EXPECT(local_c, exp_pt, paramTypes);

		ADBG_EXPECT_COMPARE_UNSIGNED(local_c,
			params[0].value.a, ==, ocall_test_val1_in_a);
		ADBG_EXPECT_COMPARE_UNSIGNED(local_c,
			params[0].value.b, ==, ocall_test_val1_in_b);
		ADBG_EXPECT_COMPARE_UNSIGNED(local_c,
			params[1].value.a, ==, ocall_test_val2_in_a);
		ADBG_EXPECT_COMPARE_UNSIGNED(local_c,
			params[1].value.b, ==, ocall_test_val2_in_b);
		ADBG_EXPECT_COMPARE_UNSIGNED(local_c,
			params[3].value.a, ==, ocall_test_val4_in_a);
		ADBG_EXPECT_COMPARE_UNSIGNED(local_c,
			params[3].value.b, ==, ocall_test_val4_in_b);

		params[1].value.a = ocall_test_val2_out_a;
		params[1].value.b = ocall_test_val2_out_b;
		params[2].value.a = ocall_test_val3_out_a;
		params[2].value.b = ocall_test_val3_out_b;
		break;

	case CA_OCALL_CMD_NO_ECALL_PARAMS_OCALL_MEMREF_PARAMS:
		no_ecall_params_ocall_memref_params_reply = true;

		exp_pt = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					  TEEC_MEMREF_TEMP_INOUT,
					  TEEC_MEMREF_TEMP_OUTPUT,
					  TEEC_MEMREF_TEMP_INPUT);
		ADBG_EXPECT(local_c, exp_pt, paramTypes);

		ADBG_EXPECT_BUFFER(local_c, ocall_test_buf1_in,
				   sizeof(ocall_test_buf1_in),
				   params[0].tmpref.buffer,
				   params[0].tmpref.size);
		ADBG_EXPECT_BUFFER(local_c, ocall_test_buf2_in,
				   sizeof(ocall_test_buf2_in),
				   params[1].tmpref.buffer,
				   params[1].tmpref.size);
		ADBG_EXPECT_BUFFER(local_c, ocall_test_buf4_in,
				   sizeof(ocall_test_buf4_in),
				   params[3].tmpref.buffer,
				   params[3].tmpref.size);

		if (!ADBG_EXPECT_COMPARE_UNSIGNED(local_c,
			params[1].tmpref.size, ==,
			sizeof(ocall_test_buf2_out)) ||
		    !ADBG_EXPECT_COMPARE_UNSIGNED(local_c,
			params[2].tmpref.size, ==,
			sizeof(ocall_test_buf3_out)))
			return TEE_ERROR_BAD_PARAMETERS;

		memcpy(params[1].tmpref.buffer, ocall_test_buf2_out,
		       sizeof(ocall_test_buf2_out));
		memcpy(params[2].tmpref.buffer, ocall_test_buf3_out,
		       sizeof(ocall_test_buf3_out));
		break;

	case CA_OCALL_CMD_PREMATURE_SESSION_CLOSE:
		exp_pt = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE,
					  TEEC_NONE);
		ADBG_EXPECT(local_c, exp_pt, paramTypes);
		ADBG_EXPECT_NOT_NULL(local_c, session_data);
		TEEC_CloseSession((TEEC_Session *)session_data);
		break;

	case CA_OCALL_CMD_PREMATURE_CONTEXT_FINALIZE:
		exp_pt = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE,
					  TEEC_NONE);
		ADBG_EXPECT(local_c, exp_pt, paramTypes);
		ADBG_EXPECT_NOT_NULL(local_c, ctx_data);
		TEEC_FinalizeContext((TEEC_Context *)ctx_data);
		break;

	case CA_OCALL_CMD_NULL_MEMREF_PARAMS:
		null_memref_params_reply = true;

		exp_pt = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					  TEEC_MEMREF_TEMP_INOUT,
					  TEEC_MEMREF_TEMP_OUTPUT,
					  TEEC_NONE);
		ADBG_EXPECT(local_c, exp_pt, paramTypes);
		ADBG_EXPECT_BUFFER(local_c, NULL, 0, params[0].tmpref.buffer,
			params[0].tmpref.size);
		ADBG_EXPECT_BUFFER(local_c, NULL, 0, params[1].tmpref.buffer,
			params[1].tmpref.size);
		ADBG_EXPECT_BUFFER(local_c, NULL, 0, params[2].tmpref.buffer,
			params[2].tmpref.size);
		break;

	case CA_OCALL_CMD_NULL_MEMREF_PARAMS_MIXED:
		null_memref_params_mixed_reply = true;

		exp_pt = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					  TEEC_MEMREF_TEMP_INOUT,
					  TEEC_MEMREF_TEMP_OUTPUT,
					  TEEC_VALUE_OUTPUT);
		ADBG_EXPECT(local_c, exp_pt, paramTypes);

		ADBG_EXPECT_BUFFER(local_c, NULL, 0, params[0].tmpref.buffer,
				   params[0].tmpref.size);
		ADBG_EXPECT_BUFFER(local_c, ocall_test_buf2_in,
				   sizeof(ocall_test_buf2_in),
				   params[1].tmpref.buffer,
				   params[1].tmpref.size);
		ADBG_EXPECT_BUFFER(local_c, NULL, 0, params[2].tmpref.buffer,
				   params[2].tmpref.size);

		memcpy(params[1].tmpref.buffer, ocall_test_buf2_out,
		       sizeof(ocall_test_buf2_out));
		params[3].value.a = ocall_test_val5_out_a;
		params[3].value.b = ocall_test_val5_out_b;
		break;

	case CA_OCALL_CMD_NULL_MEMREF_PARAMS_INVALID:
		/*
		 * Should not be called; the OCALL should fail to send at the
		 * TA due to invalid parameters.
		 */
		null_memref_params_invalid_reply = true;
		break;

	case CA_OCALL_CMD_OPEN_SESSION_OCALL:
		session_open_ocall_reply = true;

		exp_pt = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE,
					  TEEC_NONE);
		ADBG_EXPECT(local_c, exp_pt, paramTypes);
		break;

	case CA_OCALL_CMD_OPEN_SESSION_OCALL_PREMATURE_CONTEXT_FINALIZE:
		session_open_ocall_premature_ctx_finalize_reply = true;

		exp_pt = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE,
					  TEEC_NONE);
		ADBG_EXPECT(local_c, exp_pt, paramTypes);
		ADBG_EXPECT_NOT_NULL(local_c, ctx_data);
		TEEC_FinalizeContext((TEEC_Context *)ctx_data);
		break;

	default:
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	return TEEC_SUCCESS;
}

static bool test_premature_session_close_prologue(ADBG_Case_t *c)
{
	TEEC_Context ctx = {};
	TEEC_Session sess = {};
	uint32_t ret_orig = 0;
	bool ret = false;

	TEEC_ContextSettingOCall ocall_setting = { ocall_handler, &ctx };
	TEEC_ContextSetting ctx_settings[] = {
		{ .type = TEEC_CONTEXT_SETTING_OCALL,
		  .u.ocall = &ocall_setting }
	};

	TEEC_SessionSettingData data_setting = { &sess };
	TEEC_SessionSetting sess_settings[] = {
		{ .type = TEEC_SESSION_SETTING_DATA,
		  .u.data = &data_setting }
	};

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		TEEC_InitializeContext2(xtest_tee_name, &ctx, ctx_settings, 1)))
		goto no_ctx;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		TEEC_OpenSession2(&ctx, &sess, &ocall_ta_uuid,
				  TEEC_LOGIN_PUBLIC, NULL, NULL, &ret_orig,
				  sess_settings, 1)))
		goto no_sess;

	if (!ADBG_EXPECT_TEEC_RESULT(c,
		TEE_ERROR_GENERIC,
		TEEC_InvokeCommand(&sess,
				   TA_OCALL_CMD_PREMATURE_SESSION_CLOSE,
				   NULL, &ret_orig)))
		goto no_invoke;

	ret = true;

	/* The session will have been closed by the OCALL handler */
	goto no_sess;

no_invoke:
	TEEC_CloseSession(&sess);
no_sess:
	TEEC_FinalizeContext(&ctx);
no_ctx:
	return ret;
}

static bool test_premature_context_finalize_prologue(ADBG_Case_t *c)
{
	TEEC_Context ctx = {};
	TEEC_Session sess = {};
	uint32_t ret_orig = 0;
	bool ret = false;

	TEEC_ContextSettingOCall ocall_setting = { ocall_handler, &ctx };
	TEEC_ContextSetting ctx_settings[] = {
		{ .type = TEEC_CONTEXT_SETTING_OCALL,
		  .u.ocall = &ocall_setting }
	};

	TEEC_SessionSettingData data_setting = { &sess };
	TEEC_SessionSetting sess_settings[] = {
		{ .type = TEEC_SESSION_SETTING_DATA,
		  .u.data = &data_setting }
	};

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		TEEC_InitializeContext2(xtest_tee_name, &ctx, ctx_settings, 1)))
		goto no_ctx;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		TEEC_OpenSession2(&ctx, &sess, &ocall_ta_uuid,
				  TEEC_LOGIN_PUBLIC, NULL, NULL, &ret_orig,
				  sess_settings, 1)))
		goto no_sess;

	if (!ADBG_EXPECT_TEEC_RESULT(c,
		TEE_ERROR_GENERIC,
		TEEC_InvokeCommand(&sess,
				   TA_OCALL_CMD_PREMATURE_CONTEXT_FINALIZE,
				   NULL, &ret_orig)))
		goto no_invoke;

	ret = true;

	/* The context will have been finalized by the OCALL handler */
	goto no_ctx;

no_invoke:
	TEEC_CloseSession(&sess);
no_sess:
	TEEC_FinalizeContext(&ctx);
no_ctx:
	return ret;
}

static bool test_ocall_during_session_open(ADBG_Case_t *c)
{
	TEEC_Context ctx = {};
	TEEC_Session sess = {};
	uint32_t ret_orig = 0;
	TEEC_Operation op = { 0 };
	bool ret = false;

	TEEC_ContextSettingOCall ocall_setting = { ocall_handler, &ctx };
	TEEC_ContextSetting ctx_settings[] = {
		{ .type = TEEC_CONTEXT_SETTING_OCALL,
		  .u.ocall = &ocall_setting }
	};

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		TEEC_InitializeContext2(xtest_tee_name, &ctx, ctx_settings, 1)))
		return false;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].value.a = TA_OCALL_CMD_OPEN_SESSION_OCALL;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		TEEC_OpenSession(&ctx, &sess, &ocall_ta_uuid, TEEC_LOGIN_PUBLIC,
				 NULL, &op, &ret_orig)))
		goto no_sess;

	/* Executes after the OCALL handler */
	ADBG_EXPECT_BOOLEAN(c, true, session_open_ocall_reply);

	TEEC_CloseSession(&sess);
	ret = true;

no_sess:
	TEEC_FinalizeContext(&ctx);
	return ret;
}

static bool text_ctx_finalize_during_session_open_ocall(ADBG_Case_t *c)
{
	TEEC_Context ctx = {};
	TEEC_Session sess = {};
	uint32_t ret_orig = 0;
	TEEC_Operation op = { 0 };
	bool ret = false;

	TEEC_ContextSettingOCall ocall_setting = { ocall_handler, &ctx };
	TEEC_ContextSetting ctx_settings[] = {
		{ .type = TEEC_CONTEXT_SETTING_OCALL,
		  .u.ocall = &ocall_setting }
	};

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		TEEC_InitializeContext2(xtest_tee_name, &ctx, ctx_settings, 1)))
		return false;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].value.a =
		TA_OCALL_CMD_OPEN_SESSION_OCALL_PREMATURE_CONTEXT_FINALIZE;

	if (!ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_GENERIC,
		TEEC_OpenSession(&ctx, &sess, &ocall_ta_uuid, TEEC_LOGIN_PUBLIC,
				 NULL, &op, &ret_orig)))
		goto no_sess;

	/* Executes after the OCALL handler */
	ADBG_EXPECT_BOOLEAN(c, true,
			    session_open_ocall_premature_ctx_finalize_reply);

	/*
	 * The OCALL handler will have closed the session by finalizing the
	 * context.
	 */
	ret = true;

no_sess:
	TEEC_FinalizeContext(&ctx);
	return ret;
}

static void xtest_tee_test_1101(ADBG_Case_t *c)
{
	TEEC_Context ctx = {};
	TEEC_Session sess = {};
	uint32_t ret_orig = 0;

	TEEC_ContextSettingOCall ocall_setting = { ocall_handler, &ctx };
	TEEC_ContextSetting ctx_settings[] = {
		{ .type = TEEC_CONTEXT_SETTING_OCALL,
		  .u.ocall = &ocall_setting }
	};

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		TEEC_InitializeContext2(xtest_tee_name, &ctx, ctx_settings, 1)))
		return;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		TEEC_OpenSession(&ctx, &sess, &ocall_ta_uuid,
				 TEEC_LOGIN_PUBLIC, NULL, NULL, &ret_orig)))
		goto out;

	local_c = c;

	Do_ADBG_BeginSubCase(c, "OCALL without parameters");
	ADBG_EXPECT_TEEC_SUCCESS(c,
		TEEC_InvokeCommand(&sess,
				   TA_OCALL_CMD_NO_ECALL_PARAMS_NO_OCALL_PARAMS,
				   NULL, &ret_orig));
	ADBG_EXPECT_BOOLEAN(c, true, no_ecall_params_no_ocall_params_reply);
	Do_ADBG_EndSubCase(c, "OCALL without parameters");

	Do_ADBG_BeginSubCase(c, "OCALL with value parameters (in/inout/out/in)");
	ADBG_EXPECT_TEEC_SUCCESS(c,
		TEEC_InvokeCommand(&sess,
				   TA_OCALL_CMD_NO_ECALL_PARAMS_OCALL_VALUE_PARAMS,
				   NULL, &ret_orig));
	ADBG_EXPECT_BOOLEAN(c, true, no_ecall_params_ocall_value_params_reply);
	Do_ADBG_EndSubCase(c, "OCALL with value parameters (in/inout/out/in)");

	Do_ADBG_BeginSubCase(c, "OCALL with memref parameters (in/inout/out/in)");
	ADBG_EXPECT_TEEC_SUCCESS(c,
		TEEC_InvokeCommand(&sess,
				   TA_OCALL_CMD_NO_ECALL_PARAMS_OCALL_MEMREF_PARAMS,
				   NULL, &ret_orig));
	ADBG_EXPECT_BOOLEAN(c, true, no_ecall_params_ocall_memref_params_reply);
	Do_ADBG_EndSubCase(c, "OCALL with memref parameters (in/inout/out/in)");

	Do_ADBG_BeginSubCase(c, "Close session during OCALL");
	if (test_premature_session_close_prologue(c))
		ADBG_EXPECT_TEEC_SUCCESS(c,
			TEEC_InvokeCommand(&sess,
					   TA_OCALL_CMD_GET_PREMATURE_SESSION_CLOSE_STATUS,
					   NULL, &ret_orig));
	Do_ADBG_EndSubCase(c, "Close session during OCALL");

	Do_ADBG_BeginSubCase(c, "Finalize context during OCALL");
	if (test_premature_context_finalize_prologue(c))
		ADBG_EXPECT_TEEC_SUCCESS(c,
			TEEC_InvokeCommand(&sess,
					   TA_OCALL_CMD_GET_PREMATURE_CONTEXT_FINALIZE_STATUS,
					   NULL, &ret_orig));
	Do_ADBG_EndSubCase(c, "Finalize context during OCALL");

	Do_ADBG_BeginSubCase(c, "NULL memref param");
	ADBG_EXPECT_TEEC_SUCCESS(c,
		TEEC_InvokeCommand(&sess,
				   TA_OCALL_CMD_NULL_MEMREF_PARAMS,
				   NULL, &ret_orig));
	ADBG_EXPECT_BOOLEAN(c, true, null_memref_params_reply);
	Do_ADBG_EndSubCase(c, "NULL memref param");

	Do_ADBG_BeginSubCase(c, "NULL memref param (mixed params)");
	ADBG_EXPECT_TEEC_SUCCESS(c,
		TEEC_InvokeCommand(&sess,
				   TA_OCALL_CMD_NULL_MEMREF_PARAMS_MIXED,
				   NULL, &ret_orig));
	ADBG_EXPECT_BOOLEAN(c, true, null_memref_params_mixed_reply);
	Do_ADBG_EndSubCase(c, "NULL memref param (mixed params)");

	Do_ADBG_BeginSubCase(c, "NULL memref param (invalid params)");
	ADBG_EXPECT_TEEC_SUCCESS(c,
		TEEC_InvokeCommand(&sess,
				   TA_OCALL_CMD_NULL_MEMREF_PARAMS_INVALID,
				   NULL, &ret_orig));
	ADBG_EXPECT_BOOLEAN(c, false, null_memref_params_invalid_reply);
	Do_ADBG_EndSubCase(c, "NULL memref param (invalid params)");

	Do_ADBG_BeginSubCase(c, "OCALL during session open");
	ADBG_EXPECT_BOOLEAN(c, true, test_ocall_during_session_open(c));
	Do_ADBG_EndSubCase(c, "OCALL during session open");

	Do_ADBG_BeginSubCase(c, "Finalize context during session open OCALL");
	ADBG_EXPECT_BOOLEAN(c, true,
			    text_ctx_finalize_during_session_open_ocall(c));
	ADBG_EXPECT_TEEC_SUCCESS(c,
		TEEC_InvokeCommand(&sess,
				   TA_OCALL_CMD_OPEN_SESSION_OCALL_PREMATURE_CONTEXT_FINALIZE_STATUS,
				   NULL, &ret_orig));
	Do_ADBG_EndSubCase(c, "Finalize context during session open OCALL");

	TEEC_CloseSession(&sess);

out:
	TEEC_FinalizeContext(&ctx);
}
ADBG_CASE_DEFINE(regression, 1100, xtest_tee_test_1101,
		 "Test OCALLs");
