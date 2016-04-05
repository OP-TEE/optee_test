/*
 * Copyright (c) 2015-2016, Linaro Limited
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

#include <atomic.h>
#include <tee_ta_api.h>
#include <tee_api.h>
#include <ta_concurrent_large.h>
#include <trace.h>
#include <utee_defines.h>

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
	(void)session_ctx;
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *session_ctx)
{
	(void)session_ctx;
}

static uint32_t inc_active_count(struct ta_concurrent_shm *shm)
{
	return atomic_inc32(&shm->active_count);
}

static uint32_t dec_active_count(struct ta_concurrent_shm *shm)
{
	return atomic_dec32(&shm->active_count);
}


static TEE_Result ta_entry_busy_loop(uint32_t param_types, TEE_Param params[4])
{
	size_t num_rounds;
	uint32_t req_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
				TEE_PARAM_TYPE_VALUE_INOUT,
				TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

	if (param_types != req_param_types) {
		EMSG("got param_types 0x%x, expected 0x%x",
			param_types, req_param_types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (params[0].memref.size < sizeof(struct ta_concurrent_shm))
		return TEE_ERROR_BAD_PARAMETERS;

	params[1].value.b = inc_active_count(params[0].memref.buffer);

	num_rounds = params[1].value.a;
	while (num_rounds) {
		volatile size_t n = 1000;

		while (n)
			n--;

		num_rounds--;
	}

	dec_active_count(params[0].memref.buffer);
	return TEE_SUCCESS;
}

static TEE_Result ta_entry_sha256(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result res;
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	void *out;
	uint32_t out_len;
	size_t num_rounds;
	uint32_t req_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
				TEE_PARAM_TYPE_VALUE_INOUT,
				TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_MEMREF_OUTPUT);

	if (param_types != req_param_types) {
		EMSG("got param_types 0x%x, expected 0x%x",
			param_types, req_param_types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (params[0].memref.size < sizeof(struct ta_concurrent_shm))
		return TEE_ERROR_BAD_PARAMETERS;
	if (params[3].memref.size < TEE_SHA256_HASH_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	params[1].value.b = inc_active_count(params[0].memref.buffer);

	out_len = params[3].memref.size;
	out = TEE_Malloc(out_len, 0);
	if (!out) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	res = TEE_AllocateOperation(&op, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
	if (res != TEE_SUCCESS)
		goto out;


	num_rounds = params[1].value.a;
	while (num_rounds) {
		TEE_ResetOperation(op);
		res = TEE_DigestDoFinal(op, params[2].memref.buffer,
					params[2].memref.size, out, &out_len);
		num_rounds--;
	}

	TEE_MemMove(params[3].memref.buffer, out, out_len);
	params[3].memref.size = out_len;

out:
	if (out)
		TEE_Free(out);
	if (op)
		TEE_FreeOperation(op);
	dec_active_count(params[0].memref.buffer);
	return res;
}

TEE_Result TA_InvokeCommandEntryPoint(void *session_ctx,
				      uint32_t cmd_id, uint32_t param_types,
				      TEE_Param params[4])
{
	(void)session_ctx;

	switch (cmd_id) {
	case TA_CONCURRENT_CMD_BUSY_LOOP:
		return ta_entry_busy_loop(param_types, params);
	case TA_CONCURRENT_CMD_SHA256:
		return ta_entry_sha256(param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
