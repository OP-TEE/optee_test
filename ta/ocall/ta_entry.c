// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2020, Microsoft Corporation
 */

#include <ta_ocall.h>
#include <ta_ocall_test.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <tee_ta_api.h>
#include <trace.h>

/*
 * Trusted Application Entry Points
 */

/* Called each time a new instance is created */
TEE_Result TA_CreateEntryPoint(void)
{
	DMSG("TA_CreateEntryPoint");
	return TEE_SUCCESS;
}

/* Called each time an instance is destroyed */
void TA_DestroyEntryPoint(void)
{
	DMSG("TA_DestroyEntryPoint");
}

/* Called each time a session is opened */
TEE_Result TA_OpenSessionEntryPoint(uint32_t nParamTypes,
				    TEE_Param pParams[4],
				    void **ppSessionContext __unused)
{
	TEE_Result res;
	uint32_t eorig;

	const uint32_t expected_pt1 = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
	const uint32_t expected_pt2 = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

	DMSG("TA_OpenSessionEntryPoint");

	if (nParamTypes == expected_pt1)
		return TEE_SUCCESS;

	if (nParamTypes != expected_pt2)
		return TEE_ERROR_BAD_PARAMETERS;

	switch (pParams[0].value.a) {
	case TA_OCALL_CMD_OPEN_SESSION_OCALL:
		res = TEE_InvokeCACommand(TEE_TIMEOUT_INFINITE,
					  CA_OCALL_CMD_OPEN_SESSION_OCALL, 0,
					  NULL, &eorig);
		if (res != TEE_SUCCESS)
			EMSG("TEE_InvokeCACommand failed with code 0x%x origin 0x%x",
				res, eorig);
		break;

	case TA_OCALL_CMD_OPEN_SESSION_OCALL_PREMATURE_CONTEXT_FINALIZE:
		res = TEE_InvokeCACommand(TEE_TIMEOUT_INFINITE,
					  CA_OCALL_CMD_OPEN_SESSION_OCALL_PREMATURE_CONTEXT_FINALIZE,
					  0, NULL, &eorig);
		if (res != TEE_ERROR_TARGET_DEAD || eorig != TEE_ORIGIN_COMMS) {
			EMSG("TEE_InvokeCACommand failed with wrong code 0x%x and/or origin 0x%x",
				res, eorig);
			return res;
		}

		g_test_premature_context_finalize_during_session_open_ocall_ok = true;

		break;

	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return res;
}

/* Called each time a session is closed */
void TA_CloseSessionEntryPoint(void *pSessionContext)
{
	(void)pSessionContext;
	g_close_session_entry_point_called = true;
	DMSG("TA_CloseSessionEntryPoint");
}

/* Called when a command is invoked */
TEE_Result TA_InvokeCommandEntryPoint(void *pSessionContext,
				      uint32_t nCommandID, uint32_t nParamTypes,
				      TEE_Param pParams[4])
{
	(void)pSessionContext;
	(void)pParams;

	switch (nCommandID) {
	case TA_OCALL_CMD_NO_ECALL_PARAMS_NO_OCALL_PARAMS:
		return test_no_ecall_params_no_ocall_params(nParamTypes);

	case TA_OCALL_CMD_NO_ECALL_PARAMS_OCALL_VALUE_PARAMS:
		return test_no_ecall_params_ocall_value_params(nParamTypes);

	case TA_OCALL_CMD_NO_ECALL_PARAMS_OCALL_MEMREF_PARAMS:
		return test_no_ecall_params_ocall_memref_params(nParamTypes);

	case TA_OCALL_CMD_PREMATURE_SESSION_CLOSE:
		return test_premature_session_close(nParamTypes);

	case TA_OCALL_CMD_GET_PREMATURE_SESSION_CLOSE_STATUS:
		return get_premature_session_close_status(nParamTypes);

	case TA_OCALL_CMD_PREMATURE_CONTEXT_FINALIZE:
		return test_premature_context_finalize(nParamTypes);

	case TA_OCALL_CMD_GET_PREMATURE_CONTEXT_FINALIZE_STATUS:
		return get_premature_context_finalize_status(nParamTypes);

	case TA_OCALL_CMD_NULL_MEMREF_PARAMS:
		return test_null_memref_params(nParamTypes);

	case TA_OCALL_CMD_NULL_MEMREF_PARAMS_MIXED:
		return test_null_memref_params_mixed(nParamTypes);

	case TA_OCALL_CMD_NULL_MEMREF_PARAMS_INVALID:
		return test_null_memref_params_invalid(nParamTypes);

	case TA_OCALL_CMD_OPEN_SESSION_OCALL_PREMATURE_CONTEXT_FINALIZE_STATUS:
		return get_premature_context_finalize_during_session_open_ocall_status(nParamTypes);

	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
