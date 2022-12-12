// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 */

#include <tee_internal_api.h>
#include <tee_ta_api.h>
#include <string.h>
#include <trace.h>

#include "ta_hash_perf.h"
#include "ta_hash_perf_priv.h"

#define CHECK(res, name, action) do {			 \
		if ((res) != TEE_SUCCESS) {		 \
			DMSG(name ": %#08"PRIx32, (res));\
			action				 \
		}					 \
	} while(0)

static TEE_OperationHandle digest_op;

static bool is_mac(uint32_t algo)
{
	switch (algo) {
	case TEE_ALG_HMAC_SHA1:
	case TEE_ALG_HMAC_SHA224:
	case TEE_ALG_HMAC_SHA256:
	case TEE_ALG_HMAC_SHA384:
	case TEE_ALG_HMAC_SHA512:
	case TEE_ALG_HMAC_SM3:
		return true;
	default:
		return false;
	}
}

TEE_Result cmd_process(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result res = TEE_ERROR_GENERIC;
	TEE_OperationInfo info = { };
	int n = 0;
	void *in = NULL;
	void *out = NULL;
	size_t insz = 0;
	size_t outsz = 0;
	uint32_t offset = 0;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_OUTPUT,
						   TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	offset = params[2].value.b;
	in = (uint8_t *)params[0].memref.buffer + offset;
	insz = params[0].memref.size - offset;
	out = params[1].memref.buffer;
	outsz = params[1].memref.size;
	n = params[2].value.a;

	TEE_GetOperationInfo(digest_op, &info);

	if (is_mac(info.algorithm)) {
		while (n--) {
			TEE_MACInit(digest_op, NULL, 0);
			res = TEE_MACComputeFinal(digest_op, in, insz, out, &outsz);
			CHECK(res, "TEE_MACComputeFinal", return res;);
		}
	} else {
		while (n--) {
			res = TEE_DigestDoFinal(digest_op, in, insz, out, &outsz);
			CHECK(res, "TEE_DigestDoFinal", return res;);
		}
	}

	return TEE_SUCCESS;
}

TEE_Result cmd_prepare_op(uint32_t param_types, TEE_Param params[4])
{
	TEE_ObjectHandle hkey = TEE_HANDLE_NULL;
	TEE_Result res = TEE_ERROR_GENERIC;
	TEE_Attribute attr = { };
	uint32_t key_type = TEE_TYPE_HMAC_SHA1;
	uint32_t mac_key_size = 512;
	uint32_t max_key_size = 0;
	uint32_t algo = 0;
	static uint8_t mac_key[] = {
		0x00, 0x01, 0x02, 0x03,
		0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B,
		0x0C, 0x0D, 0x0E, 0x0F,
		0x10, 0x11, 0x12, 0x13,
		0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1A, 0x1B,
		0x1C, 0x1D, 0x1E, 0x1F,
		0x20, 0x21, 0x22, 0x23,
		0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2A, 0x2B,
		0x2C, 0x2D, 0x2E, 0x2F,
		0x30, 0x31, 0x32, 0x33,
		0x34, 0x35, 0x36, 0x37,
		0x38, 0x39, 0x3A, 0x3B,
		0x3C, 0x3D, 0x3E, 0x3F
	};
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	switch (params[0].value.a) {
	case TA_SHA_SHA1:
		algo = TEE_ALG_SHA1;
		break;
	case TA_SHA_SHA224:
		algo = TEE_ALG_SHA224;
		break;
	case TA_SHA_SHA256:
		algo = TEE_ALG_SHA256;
		break;
	case TA_SHA_SHA384:
		algo = TEE_ALG_SHA384;
		break;
	case TA_SHA_SHA512:
		algo = TEE_ALG_SHA512;
		break;
	case TA_SM3:
		algo = TEE_ALG_SM3;
		break;
	case TA_HMAC_SHA1:
		key_type = TEE_TYPE_HMAC_SHA1;
		algo = TEE_ALG_HMAC_SHA1;
		max_key_size = 512;
		break;
	case TA_HMAC_SHA224:
		key_type = TEE_TYPE_HMAC_SHA224;
		algo = TEE_ALG_HMAC_SHA224;
		max_key_size = 512;
		break;
	case TA_HMAC_SHA256:
		key_type = TEE_TYPE_HMAC_SHA256;
		algo = TEE_ALG_HMAC_SHA256;
		max_key_size = 512;
		break;
	case TA_HMAC_SHA384:
		key_type = TEE_TYPE_HMAC_SHA384;
		algo = TEE_ALG_HMAC_SHA384;
		max_key_size = 1024;
		break;
	case TA_HMAC_SHA512:
		key_type = TEE_TYPE_HMAC_SHA512;
		algo = TEE_ALG_HMAC_SHA512;
		max_key_size = 1024;
		break;
	case TA_HMAC_SM3:
		key_type = TEE_TYPE_HMAC_SM3;
		algo = TEE_ALG_HMAC_SM3;
		max_key_size = 512;
		break;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (digest_op)
		TEE_FreeOperation(digest_op);

	if (is_mac(algo)) {
		res = TEE_AllocateOperation(&digest_op, algo, TEE_MODE_MAC, max_key_size);
		CHECK(res, "TEE_AllocateOperation", return res;);

		res = TEE_AllocateTransientObject(key_type, max_key_size, &hkey);
		CHECK(res, "TEE_AllocateTransientObject", return res;);

		attr.attributeID = TEE_ATTR_SECRET_VALUE;
		attr.content.ref.buffer = mac_key;
		attr.content.ref.length = mac_key_size / 8;

		res = TEE_PopulateTransientObject(hkey, &attr, 1);
		CHECK(res, "TEE_PopulateTransientObject", return res;);

		res = TEE_SetOperationKey(digest_op, hkey);
		CHECK(res, "TEE_SetOperationKey", return res;);

		TEE_FreeTransientObject(hkey);
	} else {
		res = TEE_AllocateOperation(&digest_op, algo, TEE_MODE_DIGEST, 0);
		CHECK(res, "TEE_AllocateOperation", return res;);
	}
	return TEE_SUCCESS;
}

void cmd_clean_res(void)
{
	if (digest_op)
		TEE_FreeOperation(digest_op);
}
