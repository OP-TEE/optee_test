/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2021, Linaro Limited
 * All rights reserved.
 */

#include <inttypes.h>
#include <pta_system.h>
#include <string.h>
#include <ta_bti.h>
#include <tee_internal_api.h>

/*
 * Trusted Application Entry Points
 */

/* Called each time a new instance is created */
TEE_Result TA_CreateEntryPoint(void)
{
	return TEE_SUCCESS;
}

/* Called each time an instance is destroyed */
void TA_DestroyEntryPoint(void)
{
}

/* Called each time a session is opened */
TEE_Result TA_OpenSessionEntryPoint(uint32_t nParamTypes __unused,
				    TEE_Param pParams[4] __unused,
				    void **ppSessionContext __unused)
{
	return TEE_SUCCESS;
}

/* Called each time a session is closed */
void TA_CloseSessionEntryPoint(void *pSessionContext __unused)
{
}

static TEE_Result get_cpu_features(uint32_t param_types, TEE_Param params[4])
{
	static const TEE_UUID system_uuid = PTA_SYSTEM_UUID;
	TEE_TASessionHandle sess = TEE_HANDLE_NULL;
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t ret_orig = 0;

	if (param_types !=
	    TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
			    TEE_PARAM_TYPE_NONE,
			    TEE_PARAM_TYPE_NONE,
			    TEE_PARAM_TYPE_NONE)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	res = TEE_OpenTASession(&system_uuid, TEE_TIMEOUT_INFINITE, 0, NULL,
				&sess, &ret_orig);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_OpenTASession failed");
		goto cleanup_return;
	}

	res = TEE_InvokeTACommand(sess, TEE_TIMEOUT_INFINITE,
				  PTA_SYSTEM_GET_CPU_FEATURES,
				  param_types, params, &ret_orig);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_InvokeTACommand failed");
		goto cleanup_return;
	}

	if (CPU_FEATURE_BTI & params[0].value.a)
		params[0].value.a = 1;

cleanup_return:
	TEE_CloseTASession(sess);
	return res;
}

void call_using_blr(void (*)(void));
void call_using_br(void (*)(void));
void call_using_br_x16(void (*)(void));
void bti_j(void);
void bti_c(void);
void bti_jc(void);
void bti_none(void);

static TEE_Result test_bti(uint32_t nCommandID, uint32_t nParamTypes, TEE_Param pParams[4])
{
	void (*func)(void) = NULL;

	if (nParamTypes != TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT, 0, 0, 0))
		return TEE_ERROR_GENERIC;

	switch (pParams[0].value.a) {
	case TA_FUNC_BTI_C:
		func = bti_c;
		break;
	case TA_FUNC_BTI_J:
		func = bti_j;
		break;
	case TA_FUNC_BTI_JC:
		func = bti_jc;
		break;
	case TA_FUNC_BTI_NONE:
		func = bti_none;
		break;
	default:
		break;
	}

	switch (nCommandID) {
	case TA_TEST_USING_BLR :
		call_using_blr(func);
		break;
	case TA_TEST_USING_BR :
		call_using_br(func);
		break;
	case TA_TEST_USING_BR_X16 :
		call_using_br_x16(func);
		break;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return TEE_SUCCESS;
}

/* Called when a command is invoked */
TEE_Result TA_InvokeCommandEntryPoint(void *pSessionContext __unused,
				      uint32_t nCommandID,
				      uint32_t nParamTypes,
				      TEE_Param pParams[4] )
{

	TEE_Result res = TEE_SUCCESS;

	switch (nCommandID) {
	case TA_TEST_USING_BLR :
	case TA_TEST_USING_BR :
	case TA_TEST_USING_BR_X16 :
		res = test_bti(nCommandID, nParamTypes, pParams);
		break;
	case TA_BTI_FEATURE :
		res = get_cpu_features(nParamTypes, pParams);
		break;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return res;
}
