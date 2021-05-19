// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021, Linaro Limited
 */

#include <ta_large.h>
#include <tee_internal_api.h>

/*
 * Declare a large buffer likely to span mutiple translation tables.
 *
 * Ideally we'd like to have one that is slightly larger than 2MiB since
 * that would guarantee this. But that would consume yet another static
 * translation table (MAX_XLAT_TABLES) which would typically only be needed
 * when loading this TA but would cause a permanent increase in the OP-TEE
 * memory footprint.
 *
 * So we settle with this size, it should quite often be enough if
 * configured with CFG_TA_ASLR=y. It will be 100% effective with
 * CFG_WITH_LPAE=n.
 */
static const uint8_t large_buffer[1024 * 1024 ] = { 1 };

TEE_Result TA_CreateEntryPoint(void)
{
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
				    TEE_Param params[4],
				    void **session_ctx)
{
	(void)param_types;
	(void)params;

	/* Don't let the linker garbage collect this symbol. */
	*session_ctx = (void *)large_buffer;

	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *session_ctx)
{
	(void)session_ctx;
}

TEE_Result TA_InvokeCommandEntryPoint(void *session_ctx,
				      uint32_t cmd_id, uint32_t param_types,
				      TEE_Param params[4])
{
	(void)session_ctx;
	(void)cmd_id;
	(void)param_types;
	(void)params;

	return TEE_ERROR_GENERIC;
}
