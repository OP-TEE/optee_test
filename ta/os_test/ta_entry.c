/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include <stdint.h>
#include <init.h>
#include <os_test.h>
#include <ta_os_test.h>
#include <tee_internal_api_extensions.h>
#include <tee_ta_api.h>

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
				    void **ppSessionContext)
{
	(void)nParamTypes;
	(void)pParams;
	(void)ppSessionContext;
	DMSG("TA_OpenSessionEntryPoint");
	TEE_UnmaskCancellation();
	return TEE_SUCCESS;
}

/* Called each time a session is closed */
void TA_CloseSessionEntryPoint(void *pSessionContext)
{
	(void)pSessionContext;
	DMSG("TA_CloseSessionEntryPoint");
}

/* Called when a command is invoked */
TEE_Result TA_InvokeCommandEntryPoint(void *pSessionContext,
				      uint32_t nCommandID, uint32_t nParamTypes,
				      TEE_Param pParams[4])
{
	(void)pSessionContext;

	switch (nCommandID) {
	case TA_OS_TEST_CMD_INIT:
		return ta_entry_init(nParamTypes, pParams);

	case TA_OS_TEST_CMD_CLIENT_WITH_TIMEOUT:
		return ta_entry_client_with_timeout(nParamTypes, pParams);

	case TA_OS_TEST_CMD_BASIC:
		return ta_entry_basic(nParamTypes, pParams);

	case TA_OS_TEST_CMD_PANIC:
		return ta_entry_panic(nParamTypes, pParams);

	case TA_OS_TEST_CMD_CLIENT:
		return ta_entry_client(nParamTypes, pParams);

	case TA_OS_TEST_CMD_PARAMS_ACCESS:
		return ta_entry_params_access_rights(nParamTypes, pParams);

	case TA_OS_TEST_CMD_WAIT:
		return ta_entry_wait(nParamTypes, pParams);

	case TA_OS_TEST_CMD_BAD_MEM_ACCESS:
		return ta_entry_bad_mem_access(nParamTypes, pParams);

	case TA_OS_TEST_CMD_TA2TA_MEMREF:
		return ta_entry_ta2ta_memref(nParamTypes, pParams);

	case TA_OS_TEST_CMD_TA2TA_MEMREF_MIX:
		return ta_entry_ta2ta_memref_mix(nParamTypes, pParams);

	case TA_OS_TEST_CMD_PARAMS:
		return ta_entry_params(nParamTypes, pParams);

	case TA_OS_TEST_CMD_CALL_LIB:
		return ta_entry_call_lib(nParamTypes, pParams);

	case TA_OS_TEST_CMD_CALL_LIB_PANIC:
		return ta_entry_call_lib_panic(nParamTypes, pParams);

	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
