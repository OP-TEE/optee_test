/*
 * Copyright 2020 NXP
 */

#define STR_TRACE_USER_TA "GCOV"

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <gcov.h>
#include <pta_gcov.h>
#include "ta_gcov.h"

TEE_Result TA_CreateEntryPoint(void)
{
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
		TEE_Param  params[4], void **sess_ctx)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);
	if (param_types != exp_param_types) {
		EMSG("Wrong param_types, exp %x, got %x", exp_param_types,
		     param_types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	(void)&params;
	(void)&sess_ctx;

	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx)
{
	(void)&sess_ctx;
}

static TEE_Result get_version(uint32_t param_types, TEE_Param params[4])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types) {
		EMSG("Wrong param_types, exp %x, got %x", exp_param_types,
		     param_types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return gcov_get_version(&params[0].value.a);
}

static TEE_Result dump_core(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result res;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);
	uint32_t cRT = TEE_TIMEOUT_INFINITE;
	TEE_UUID uuid = (TEE_UUID)PTA_GCOV_UUID;
	TEE_TASessionHandle sess;
	uint32_t err_origin;
	uint32_t int_ptypes = 0;
	TEE_Param int_params[TEE_NUM_PARAMS] = {0};

	if (param_types != exp_param_types) {
		EMSG("Wrong param_types, exp %x, got %x", exp_param_types,
		     param_types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Call gcov pta to dump the data */
	res = TEE_OpenTASession(&uuid, cRT, 0, NULL, &sess, &err_origin);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_OpenTASession failed with code 0x%x origin 0x%x",
		     res, err_origin);
		goto exit;
	}

	int_ptypes = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE);

	/* new_filepath */
	int_params[0].memref.buffer = params[0].memref.buffer;
	int_params[0].memref.size = params[0].memref.size;

	res = TEE_InvokeTACommand(sess, cRT, PTA_CMD_GCOV_CORE_DUMP_ALL,
				  int_ptypes, int_params, &err_origin);
	if (res != TEE_SUCCESS)
		EMSG("TEE_InvokeTACommand failed with code 0x%x origin 0x%x",
		     res, err_origin);

exit:
	TEE_CloseTASession(sess);

	return res;
}

static TEE_Result dump_ta(uint32_t param_types, TEE_Param params[4])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types) {
		EMSG("Wrong param_types, exp %x, got %x", exp_param_types,
		     param_types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return gcov_dump_all_coverage_data(params[0].memref.buffer);
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd_id,
			uint32_t param_types, TEE_Param params[4])
{
	(void)&sess_ctx;

	switch (cmd_id) {
	case TA_GCOV_CMD_GET_VERSION:
		return get_version(param_types, params);
	case TA_GCOV_CMD_DUMP_CORE:
		return dump_core(param_types, params);
	case TA_GCOV_CMD_DUMP_TA:
		return dump_ta(param_types, params);
	default:
		EMSG("Command %d not supported", cmd_id);
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
