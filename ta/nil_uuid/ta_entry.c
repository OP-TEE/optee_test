// SPDX-License-Identifier: BSD-2-Clause
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
				    void **session __unused)
{
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *session __unused)
{
}

TEE_Result TA_InvokeCommandEntryPoint(void *session __unused,
				      uint32_t command __unused,
				      uint32_t param_types __unused,
				      TEE_Param params[4] __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}
