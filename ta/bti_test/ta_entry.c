/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2021, Linaro Limited
 * All rights reserved.
 */

#include <inttypes.h>
#include <string.h>
#include <ta_arm_bti.h>
#include <ta_arm_bti_priv.h>
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

static TEE_Result check_bti_implemented(uint32_t param_types,
					TEE_Param params[4])
{
	bool implemented = false;
	TEE_Result res = TEE_ERROR_GENERIC;

	if (param_types !=
	    TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
			    TEE_PARAM_TYPE_NONE,
			    TEE_PARAM_TYPE_NONE,
			    TEE_PARAM_TYPE_NONE)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	res = TEE_GetPropertyAsBool(
			TEE_PROPSET_TEE_IMPLEMENTATION,
			"org.trustedfirmware.optee.cpu.feat_bti_implemented",
			&implemented);
	if (res == TEE_SUCCESS && implemented)
		params[0].value.a = 1;

	if (res == TEE_ERROR_ITEM_NOT_FOUND) {
		params[0].value.a = 0;
		res = TEE_SUCCESS;
	}

	return res;
}

__weak TEE_Result test_bti(uint32_t nCommandID __unused,
			   uint32_t nParamTypes __unused,
			   TEE_Param pParams[4] __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
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
	case TA_FEAT_BTI_IMPLEMENTED :
		res = check_bti_implemented(nParamTypes, pParams);
		break;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return res;
}
