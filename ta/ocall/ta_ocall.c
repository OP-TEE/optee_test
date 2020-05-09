// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2020, Microsoft Corporation
 */

#include <stdint.h>
#include <string.h>
#include <ta_ocall.h>
#include <ta_ocall_data.h>
#include <ta_ocall_test.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <trace.h>

bool g_close_session_entry_point_called;
bool g_test_premature_context_finalize_during_session_open_ocall_ok;

TEE_Result test_no_ecall_params_no_ocall_params(uint32_t param_types)
{
	TEE_Result res;
	uint32_t eorig;

	const uint32_t expected_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						     TEE_PARAM_TYPE_NONE,
						     TEE_PARAM_TYPE_NONE,
						     TEE_PARAM_TYPE_NONE);

	if (param_types != expected_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	res = TEE_InvokeCACommand(TEE_TIMEOUT_INFINITE,
				  CA_OCALL_CMD_NO_ECALL_PARAMS_NO_OCALL_PARAMS,
				  0, NULL, &eorig);
	if (res != TEE_SUCCESS)
		EMSG("TEE_InvokeCACommand failed with code 0x%x origin 0x%x",
			res, eorig);

	return res;
}

TEE_Result test_no_ecall_params_ocall_value_params(uint32_t param_types)
{
	TEE_Param ocall_params[TEE_NUM_PARAMS];
	TEE_Result res;
	uint32_t eorig;

	const uint32_t expected_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						     TEE_PARAM_TYPE_NONE,
						     TEE_PARAM_TYPE_NONE,
						     TEE_PARAM_TYPE_NONE);

	const uint32_t ocall_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						  TEE_PARAM_TYPE_VALUE_INOUT,
						  TEE_PARAM_TYPE_VALUE_OUTPUT,
						  TEE_PARAM_TYPE_VALUE_INPUT);

	if (param_types != expected_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	ocall_params[0].value.a = ocall_test_val1_in_a;
	ocall_params[0].value.b = ocall_test_val1_in_b;

	ocall_params[1].value.a = ocall_test_val2_in_a;
	ocall_params[1].value.b = ocall_test_val2_in_b;

	ocall_params[3].value.a = ocall_test_val4_in_a;
	ocall_params[3].value.b = ocall_test_val4_in_b;

	res = TEE_InvokeCACommand(TEE_TIMEOUT_INFINITE,
				  CA_OCALL_CMD_NO_ECALL_PARAMS_OCALL_VALUE_PARAMS,
				  ocall_pt, ocall_params, &eorig);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_InvokeCACommand failed with code 0x%x origin 0x%x",
			res, eorig);
		return res;
	}

	if (ocall_params[1].value.a != ocall_test_val2_out_a ||
	    ocall_params[1].value.b != ocall_test_val2_out_b ||
	    ocall_params[2].value.a != ocall_test_val3_out_a ||
	    ocall_params[2].value.b != ocall_test_val3_out_b)
		return TEE_ERROR_BAD_PARAMETERS;

	return res;
}

TEE_Result test_no_ecall_params_ocall_memref_params(uint32_t param_types)
{
	TEE_Param ocall_params[TEE_NUM_PARAMS];
	TEE_Result res;
	uint32_t eorig;

	char ocall_test_buf2_in_local[8];
	char ocall_test_buf3_in[16] = { 0 };

	const uint32_t expected_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						     TEE_PARAM_TYPE_NONE,
						     TEE_PARAM_TYPE_NONE,
						     TEE_PARAM_TYPE_NONE);

	const uint32_t ocall_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						  TEE_PARAM_TYPE_MEMREF_INOUT,
						  TEE_PARAM_TYPE_MEMREF_OUTPUT,
						  TEE_PARAM_TYPE_MEMREF_INPUT);

	if (param_types != expected_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	memcpy(ocall_test_buf2_in_local, ocall_test_buf2_in,
	       sizeof(ocall_test_buf2_in_local));

	ocall_params[0].memref.buffer = (void *)ocall_test_buf1_in;
	ocall_params[0].memref.size = sizeof(ocall_test_buf1_in);

	ocall_params[1].memref.buffer = (void *)ocall_test_buf2_in_local;
	ocall_params[1].memref.size = sizeof(ocall_test_buf2_in_local);

	ocall_params[2].memref.buffer = (void *)ocall_test_buf3_in;
	ocall_params[2].memref.size = sizeof(ocall_test_buf3_in);

	ocall_params[3].memref.buffer = (void *)ocall_test_buf4_in;
	ocall_params[3].memref.size = sizeof(ocall_test_buf4_in);

	res = TEE_InvokeCACommand(TEE_TIMEOUT_INFINITE,
				  CA_OCALL_CMD_NO_ECALL_PARAMS_OCALL_MEMREF_PARAMS,
				  ocall_pt, ocall_params, &eorig);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_InvokeCACommand failed with code 0x%x origin 0x%x",
			res, eorig);
		return res;
	}

	if (ocall_params[1].memref.size != sizeof(ocall_test_buf2_out) ||
	    ocall_params[2].memref.size != sizeof(ocall_test_buf3_out))
		return TEE_ERROR_BAD_PARAMETERS;

	if (TEE_MemCompare(ocall_params[1].memref.buffer, ocall_test_buf2_out,
			   sizeof(ocall_test_buf2_out)))
		return TEE_ERROR_BAD_PARAMETERS;

	if (TEE_MemCompare(ocall_params[2].memref.buffer, ocall_test_buf3_out,
			   sizeof(ocall_test_buf3_out)))
		return TEE_ERROR_BAD_PARAMETERS;

	return TEE_SUCCESS;
}

static bool g_test_premature_session_close_ok;
TEE_Result test_premature_session_close(uint32_t param_types)
{
	TEE_Result res;
	uint32_t eorig;

	const uint32_t expected_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						     TEE_PARAM_TYPE_NONE,
						     TEE_PARAM_TYPE_NONE,
						     TEE_PARAM_TYPE_NONE);

	if (param_types != expected_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	res = TEE_InvokeCACommand(TEE_TIMEOUT_INFINITE,
				  CA_OCALL_CMD_PREMATURE_SESSION_CLOSE,
				  0, NULL, &eorig);
	if (res != TEE_ERROR_TARGET_DEAD || eorig != TEE_ORIGIN_COMMS) {
		EMSG("TEE_InvokeCACommand failed with wrong code 0x%x and/or origin 0x%x",
			res, eorig);
		return res;
	}

	g_test_premature_session_close_ok = true;

	return TEE_SUCCESS;
}

TEE_Result get_premature_session_close_status(uint32_t param_types)
{
	TEE_Result res;

	const uint32_t expected_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						     TEE_PARAM_TYPE_NONE,
						     TEE_PARAM_TYPE_NONE,
						     TEE_PARAM_TYPE_NONE);

	if (param_types != expected_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	if (g_close_session_entry_point_called &&
	    g_test_premature_session_close_ok)
		res = TEE_SUCCESS;
	else
		res = TEE_ERROR_BAD_STATE;

	g_close_session_entry_point_called = false;
	g_test_premature_session_close_ok = false;

	return res;
}

static bool g_test_premature_context_finalize_ok;
TEE_Result test_premature_context_finalize(uint32_t param_types)
{
	TEE_Result res;
	uint32_t eorig;

	const uint32_t expected_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						     TEE_PARAM_TYPE_NONE,
						     TEE_PARAM_TYPE_NONE,
						     TEE_PARAM_TYPE_NONE);

	if (param_types != expected_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	res = TEE_InvokeCACommand(TEE_TIMEOUT_INFINITE,
				  CA_OCALL_CMD_PREMATURE_CONTEXT_FINALIZE,
				  0, NULL, &eorig);
	if (res != TEE_ERROR_TARGET_DEAD || eorig != TEE_ORIGIN_COMMS) {
		EMSG("TEE_InvokeCACommand failed with wrong code 0x%x and/or origin 0x%x",
			res, eorig);
		return res;
	}

	g_test_premature_context_finalize_ok = true;

	return TEE_SUCCESS;
}

TEE_Result get_premature_context_finalize_status(uint32_t param_types)
{
	TEE_Result res;

	const uint32_t expected_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						     TEE_PARAM_TYPE_NONE,
						     TEE_PARAM_TYPE_NONE,
						     TEE_PARAM_TYPE_NONE);

	if (param_types != expected_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	if (g_close_session_entry_point_called &&
	    g_test_premature_context_finalize_ok)
		res = TEE_SUCCESS;
	else
		res = TEE_ERROR_BAD_STATE;

	g_close_session_entry_point_called = false;
	g_test_premature_context_finalize_ok = false;

	return res;
}

TEE_Result test_null_memref_params(uint32_t param_types)
{
	TEE_Param ocall_params[TEE_NUM_PARAMS];
	TEE_Result res;
	uint32_t eorig;

	const uint32_t expected_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						     TEE_PARAM_TYPE_NONE,
						     TEE_PARAM_TYPE_NONE,
						     TEE_PARAM_TYPE_NONE);

	const uint32_t ocall_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						  TEE_PARAM_TYPE_MEMREF_INOUT,
						  TEE_PARAM_TYPE_MEMREF_OUTPUT,
						  TEE_PARAM_TYPE_NONE);

	if (param_types != expected_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	ocall_params[0].memref.buffer = NULL;
	ocall_params[0].memref.size = 0;

	ocall_params[1].memref.buffer = NULL;
	ocall_params[1].memref.size = 0;

	ocall_params[2].memref.buffer = NULL;
	ocall_params[2].memref.size = 0;

	res = TEE_InvokeCACommand(TEE_TIMEOUT_INFINITE,
				  CA_OCALL_CMD_NULL_MEMREF_PARAMS,
				  ocall_pt, ocall_params, &eorig);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_InvokeCACommand failed with code 0x%x origin 0x%x",
			res, eorig);
		return res;
	}

	return TEE_SUCCESS;
}

TEE_Result test_null_memref_params_mixed(uint32_t param_types)
{
	TEE_Param ocall_params[TEE_NUM_PARAMS];
	TEE_Result res;
	uint32_t eorig;

	char ocall_test_buf2_in_local[8];

	const uint32_t expected_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						     TEE_PARAM_TYPE_NONE,
						     TEE_PARAM_TYPE_NONE,
						     TEE_PARAM_TYPE_NONE);

	const uint32_t ocall_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						  TEE_PARAM_TYPE_MEMREF_INOUT,
						  TEE_PARAM_TYPE_MEMREF_OUTPUT,
						  TEE_PARAM_TYPE_VALUE_OUTPUT);

	if (param_types != expected_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	memcpy(ocall_test_buf2_in_local, ocall_test_buf2_in,
	       sizeof(ocall_test_buf2_in_local));

	ocall_params[0].memref.buffer = NULL;
	ocall_params[0].memref.size = 0;

	ocall_params[1].memref.buffer = (void *)ocall_test_buf2_in_local;
	ocall_params[1].memref.size = sizeof(ocall_test_buf2_in_local);

	ocall_params[2].memref.buffer = NULL;
	ocall_params[2].memref.size = 0;

	res = TEE_InvokeCACommand(TEE_TIMEOUT_INFINITE,
				  CA_OCALL_CMD_NULL_MEMREF_PARAMS_MIXED,
				  ocall_pt, ocall_params, &eorig);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_InvokeCACommand failed with code 0x%x origin 0x%x",
			res, eorig);
		return res;
	}

	if (ocall_params[1].memref.size != sizeof(ocall_test_buf2_out))
		return TEE_ERROR_BAD_PARAMETERS;

	if (TEE_MemCompare(ocall_params[1].memref.buffer, ocall_test_buf2_out,
			   sizeof(ocall_test_buf2_out)))
		return TEE_ERROR_BAD_PARAMETERS;

	if (ocall_params[3].value.a != ocall_test_val5_out_a ||
	    ocall_params[3].value.b != ocall_test_val5_out_b)
		return TEE_ERROR_BAD_PARAMETERS;

	return TEE_SUCCESS;
}

TEE_Result test_null_memref_params_invalid(uint32_t param_types)
{
	TEE_Param ocall_params[TEE_NUM_PARAMS];
	TEE_Result res;
	uint32_t eorig;

	const uint32_t expected_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						     TEE_PARAM_TYPE_NONE,
						     TEE_PARAM_TYPE_NONE,
						     TEE_PARAM_TYPE_NONE);

	const uint32_t ocall_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						  TEE_PARAM_TYPE_MEMREF_INOUT,
						  TEE_PARAM_TYPE_NONE,
						  TEE_PARAM_TYPE_NONE);

	if (param_types != expected_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	ocall_params[0].memref.buffer = NULL;
	ocall_params[0].memref.size = UINT32_MAX;

	ocall_params[1].memref.buffer = (void *)ocall_params;
	ocall_params[1].memref.size = 0;

	res = TEE_InvokeCACommand(TEE_TIMEOUT_INFINITE,
				  CA_OCALL_CMD_NULL_MEMREF_PARAMS_INVALID,
				  ocall_pt, ocall_params, &eorig);
	if (res != TEE_ERROR_BAD_PARAMETERS || eorig != TEE_ORIGIN_API) {
		EMSG("TEE_InvokeCACommand failed with wrong code 0x%x and/or origin 0x%x",
			res, eorig);
		return res;
	}

	return TEE_SUCCESS;
}

TEE_Result
get_premature_context_finalize_during_session_open_ocall_status(uint32_t param_types)
{
	const uint32_t expected_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						     TEE_PARAM_TYPE_NONE,
						     TEE_PARAM_TYPE_NONE,
						     TEE_PARAM_TYPE_NONE);

	if (param_types != expected_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	if (g_test_premature_context_finalize_during_session_open_ocall_ok) {
		g_test_premature_context_finalize_during_session_open_ocall_ok = false;
		return TEE_SUCCESS;
	}

	return TEE_ERROR_BAD_STATE;
}
