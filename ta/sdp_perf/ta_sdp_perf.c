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

#include <tee_internal_api_extensions.h>
#include <tee_internal_api.h>
#include <tee_ta_api.h>
#include <string.h>
#include <trace.h>

#include "ta_sdp_perf.h"
#include "ta_sdp_perf_priv.h"

#define CHECK(res, name, action) do {			\
		if ((res) != TEE_SUCCESS) {		\
			DMSG(name ": 0x%08x", (res));	\
			action				\
		}					\
	} while(0)

/*
 * AES Performance Test Over Secure Data Path buffer
 *
 * - command PROCESS: process AES decryption from input buffer output buffer
 * - command PREPARE: setup AES operation and init with IV
 * - command CLEAN: cleanup AES decryption operation (release resource)
 */
static uint8_t iv[] = { 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
			0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF };
static int use_iv;

static TEE_OperationHandle crypto_op = NULL;

TEE_Result cmd_process(uint32_t param_types,
		       TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res;
	bool secure_in;
	bool secure_out;

	switch (TEE_PARAM_TYPE_GET(param_types, 0)) {
	case TEE_PARAM_TYPE_MEMREF_INPUT:
	case TEE_PARAM_TYPE_MEMREF_INOUT:
		break;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
	switch (TEE_PARAM_TYPE_GET(param_types, 1)) {
	case TEE_PARAM_TYPE_MEMREF_OUTPUT:
	case TEE_PARAM_TYPE_MEMREF_INOUT:
		break;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
	if (TEE_PARAM_TYPE_GET(param_types, 2) != TEE_PARAM_TYPE_VALUE_INPUT)
		return TEE_ERROR_BAD_PARAMETERS;
	if (TEE_PARAM_TYPE_GET(param_types, 3) != TEE_PARAM_TYPE_NONE)
		return TEE_ERROR_BAD_PARAMETERS;

	/*
	 * check input buffer secure attribute
	 * Trust core on validity of the memref size: test only 1st byte
	 * instead of the overall buffer, and if it's not secure, assume
	 * the buffer is nonsecure.
	 */
	res = TEE_CheckMemoryAccessRights(TEE_MEMORY_ACCESS_ANY_OWNER |
					 TEE_MEMORY_ACCESS_READ |
					 TEE_MEMORY_ACCESS_SECURE,
					 params[0].memref.buffer, 1);
	secure_in = (res == TEE_SUCCESS);

#ifdef CFG_CACHE_API
	if (secure_in) {
		/*
		 * we should invalidate cache (here we assume buffer were not
		 * filled through cpu core caches. We flush buffers so that
		 * cache is not corrupted in cache target buffer not aligned
		 * on cache line size.
		 */
		res = TEE_CacheFlush(params[0].memref.buffer,
				     params[0].memref.size);
		CHECK(res, "TEE_CacheFlush(in)", return res;);
	}
#endif /* CFG_CACHE_API */

	/* check output buffer secure attribute (first byte only) */
	res = TEE_CheckMemoryAccessRights(TEE_MEMORY_ACCESS_ANY_OWNER |
					 TEE_MEMORY_ACCESS_WRITE |
					 TEE_MEMORY_ACCESS_SECURE,
					 params[1].memref.buffer, 1);
	secure_out = (res == TEE_SUCCESS);

#ifdef CFG_CACHE_API
	if (secure_out) {
		/*
		 * we should invalidate cache (here we assume buffer were not
		 * filled through cpu core caches. We flush buffers so that
		 * cache is not corrupted in cache target buffer not aligned
		 * on cache line size.
		 */
		res = TEE_CacheFlush(params[1].memref.buffer,
				     params[1].memref.size);
		CHECK(res, "TEE_CacheFlush(out)", return res;);
	}
#endif /* CFG_CACHE_API */

	while (params[2].value.a--) {
		res = TEE_CipherUpdate(crypto_op,
					params[0].memref.buffer,
					params[0].memref.size,
					params[1].memref.buffer,
					&params[1].memref.size);
		CHECK(res, "TEE_CipherUpdate", return res;);
	}

#ifdef CFG_CACHE_API
	if (secure_out) {
		/*
		 * we should invalidate cache (here we assume buffer were not
		 * filled through cpu core caches. We flush buffers so that
		 * cache is not corrupted in cache target buffer not aligned
		 * on cache line size.
		 */
		res = TEE_CacheFlush(params[1].memref.buffer,
				     params[1].memref.size);
		CHECK(res, "TEE_CacheFlush(out)", return res;);
	}
#endif /* CFG_CACHE_API */

	(void)secure_in;
	(void)secure_out;
	return TEE_SUCCESS;
}

TEE_Result cmd_prepare_key(uint32_t param_types,
			   TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res;
	TEE_ObjectHandle hkey;
	TEE_ObjectHandle hkey2;
	TEE_Attribute attr;
	uint32_t mode;
	uint32_t op_keysize;
	uint32_t keysize;
	uint32_t algo;
	static uint8_t aes_key[] = { 0x00, 0x01, 0x02, 0x03,
				     0x04, 0x05, 0x06, 0x07,
				     0x08, 0x09, 0x0A, 0x0B,
				     0x0C, 0x0D, 0x0E, 0x0F,
				     0x10, 0x11, 0x12, 0x13,
				     0x14, 0x15, 0x16, 0x17,
				     0x18, 0x19, 0x1A, 0x1B,
				     0x1C, 0x1D, 0x1E, 0x1F };
	static uint8_t aes_key2[] = { 0x20, 0x21, 0x22, 0x23,
				      0x24, 0x25, 0x26, 0x27,
				      0x28, 0x29, 0x2A, 0x2B,
				      0x2C, 0x2D, 0x2E, 0x2F,
				      0x30, 0x31, 0x32, 0x33,
				      0x34, 0x35, 0x36, 0x37,
				      0x38, 0x39, 0x3A, 0x3B,
				      0x3C, 0x3D, 0x3E, 0x3F };

	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	mode = params[0].value.a ? TEE_MODE_DECRYPT : TEE_MODE_ENCRYPT;
	keysize = params[0].value.b;
	op_keysize = keysize;

	switch (params[1].value.a) {
	case TA_SDP_ECB:
		algo = TEE_ALG_AES_ECB_NOPAD;
		use_iv = 0;
		break;
	case TA_SDP_CBC:
		algo = TEE_ALG_AES_CBC_NOPAD;
		use_iv = 1;
		break;
	case TA_SDP_CTR:
		algo = TEE_ALG_AES_CTR;
		use_iv = 1;
		break;
	case TA_SDP_XTS:
		algo = TEE_ALG_AES_XTS;
		use_iv = 1;
		op_keysize *= 2;
		break;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	cmd_clean_res();

	res = TEE_AllocateOperation(&crypto_op, algo, mode, op_keysize);
	CHECK(res, "TEE_AllocateOperation", return res;);

	res = TEE_AllocateTransientObject(TEE_TYPE_AES, keysize, &hkey);
	CHECK(res, "TEE_AllocateTransientObject", return res;);

	attr.attributeID = TEE_ATTR_SECRET_VALUE;
	attr.content.ref.buffer = aes_key;
	attr.content.ref.length = keysize / 8;

	res = TEE_PopulateTransientObject(hkey, &attr, 1);
	CHECK(res, "TEE_PopulateTransientObject", return res;);

	if (algo == TEE_ALG_AES_XTS) {
		res = TEE_AllocateTransientObject(TEE_TYPE_AES, keysize,
						  &hkey2);
		CHECK(res, "TEE_AllocateTransientObject", return res;);

		attr.content.ref.buffer = aes_key2;

		res = TEE_PopulateTransientObject(hkey2, &attr, 1);
		CHECK(res, "TEE_PopulateTransientObject", return res;);

		res = TEE_SetOperationKey2(crypto_op, hkey, hkey2);
		CHECK(res, "TEE_SetOperationKey2", return res;);

		TEE_FreeTransientObject(hkey2);
	} else {
		res = TEE_SetOperationKey(crypto_op, hkey);
		CHECK(res, "TEE_SetOperationKey", return res;);
	}

	TEE_FreeTransientObject(hkey);

	if (use_iv)
		TEE_CipherInit(crypto_op, iv, sizeof(iv));
	else
		TEE_CipherInit(crypto_op, NULL, 0);

	return TEE_SUCCESS;
}

void cmd_clean_res(void)
{
	if (crypto_op)
		TEE_FreeOperation(crypto_op);
}

