/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2021, Linaro Limited
 * All rights reserved.
 */

#include <inttypes.h>
#include <string.h>
#include <ta_arm_pauth.h>
#include <ta_arm_pauth_priv.h>
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

__weak TEE_Result test_nop(void)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

__weak void corrupt_pac(void) {}

/* Called when a command is invoked */
TEE_Result TA_InvokeCommandEntryPoint(void *pSessionContext __unused,
				      uint32_t nCommandID,
				      uint32_t nParamTypes __unused,
				      TEE_Param pParams[4] __unused)
{
	TEE_Result res = TEE_SUCCESS;

	switch (nCommandID) {
	case TA_TEST_NOP:
		res = test_nop();
		break;
	case TA_TEST_CORRUPT_PAC:
		corrupt_pac();
		break;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return res;
}
