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

#include <ta_sims.h>
#include <tee_api.h>

#define TA_SIMS_MAX_STORAGE 4

struct sims_bucket {
	uint32_t size;
	void *data;
};

struct sims_session {
	uint32_t counter;
	uint32_t array[2048];
};

static struct sims_bucket storage[TA_SIMS_MAX_STORAGE] = { {0} };

static uint32_t counter;

TEE_Result sims_open_session(void **ctx)
{
	struct sims_session *context =
	    TEE_Malloc(sizeof(struct sims_session), 0);
	if (context == NULL)
		return TEE_ERROR_OUT_OF_MEMORY;

	context->counter = counter;
	*ctx = context;

	counter++;

	return TEE_SUCCESS;
}

void sims_close_session(void *ctx)
{
	TEE_Free(ctx);
}

TEE_Result sims_read(uint32_t param_types, TEE_Param params[4])
{
	uint32_t index;
	void *p;

	if (param_types !=
	    TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
			    TEE_PARAM_TYPE_MEMREF_OUTPUT, 0, 0))
		return TEE_ERROR_BAD_PARAMETERS;

	index = params[0].value.a;
	if (index >= TA_SIMS_MAX_STORAGE)
		return TEE_ERROR_BAD_PARAMETERS;

	if (storage[index].size > params[1].memref.size)
		return TEE_ERROR_OVERFLOW;

	p = TEE_Malloc(16000, 0);
	if (p == NULL)
		return TEE_ERROR_OUT_OF_MEMORY;

	TEE_MemMove(params[1].memref.buffer, storage[index].data,
		    params[1].memref.size);

	TEE_Free(p);

	return TEE_SUCCESS;
}

TEE_Result sims_write(uint32_t param_types, TEE_Param params[4])
{
	uint32_t index;

	if (param_types !=
	    TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
			    TEE_PARAM_TYPE_MEMREF_INPUT, 0, 0))
		return TEE_ERROR_BAD_PARAMETERS;

	index = params[0].value.a;
	if (index >= TA_SIMS_MAX_STORAGE)
		return TEE_ERROR_BAD_PARAMETERS;

	if (storage[index].data != NULL)
		TEE_Free(storage[index].data);

	storage[index].data = TEE_Malloc(params[1].memref.size, 0);
	if (storage[index].data == NULL) {
		storage[index].size = 0;
		return TEE_ERROR_OUT_OF_MEMORY;
	}
	storage[index].size = params[1].memref.size;

	TEE_MemMove(storage[index].data, params[1].memref.buffer,
		    params[1].memref.size);

	return TEE_SUCCESS;
}

TEE_Result sims_get_counter(void *session_context, uint32_t param_types,
			    TEE_Param params[4])
{
	struct sims_session *ctx = (struct sims_session *)session_context;

	if (param_types !=
	    TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT, 0, 0, 0))
		return TEE_ERROR_BAD_PARAMETERS;

	params[0].value.a = ctx->counter;

	return TEE_SUCCESS;
}
