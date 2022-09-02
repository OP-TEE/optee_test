// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2022, Linaro Limited
 */

#include <ta_subkey1.h>
#include <tee_internal_api.h>

TEE_Result TA_CreateEntryPoint(void)
{
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types __unused,
				    TEE_Param params[4] __unused,
				    void **session_ctx __unused)
{
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *session_ctx __unused)
{
}

TEE_Result TA_InvokeCommandEntryPoint(void *session_ctx __unused,
				      uint32_t cmd_id __unused,
				      uint32_t param_types __unused,
				      TEE_Param params[4] __unused)
{
	return TEE_SUCCESS;
}
