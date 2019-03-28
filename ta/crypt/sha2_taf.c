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

#include "sha2_taf.h"
#include "sha2_impl.h"

TEE_Result ta_entry_sha224(uint32_t param_types, TEE_Param params[4])
{
	/*
	 * It is expected that memRef[0] is input buffer and memRef[1] is
	 * output buffer.
	 */
	if (param_types !=
	    TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
			    TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE,
			    TEE_PARAM_TYPE_NONE)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (params[1].memref.size < SHA224_DIGEST_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	sha224((unsigned char *)params[0].memref.buffer,
	       (unsigned int)params[0].memref.size,
	       (unsigned char *)params[1].memref.buffer);

	return TEE_SUCCESS;
}

TEE_Result ta_entry_sha256(uint32_t param_types, TEE_Param params[4])
{
	/*
	 * It is expected that memRef[0] is input buffer and memRef[1] is
	 * output buffer.
	 */
	if (param_types !=
	    TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
			    TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE,
			    TEE_PARAM_TYPE_NONE)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (params[1].memref.size < SHA256_DIGEST_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	sha256((unsigned char *)params[0].memref.buffer,
	       (unsigned int)params[0].memref.size,
	       (unsigned char *)params[1].memref.buffer);

	return TEE_SUCCESS;
}
