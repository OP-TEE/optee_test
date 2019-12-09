// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2019 Huawei Technologies Co., Ltd
 */

#include <sm4.h>
#include <stdint.h>
#include <string.h>
#include <tee_api.h>
#include <trace.h>

#include "sm4_taf.h"

uint8_t plain1[] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		     0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 };
uint8_t key1[] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		   0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 };
uint8_t cipher1[] = { 0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e,
		      0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46 };

uint8_t plain2[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
uint8_t key2[] = { 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
		   0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };
uint8_t cipher2[] = { 0xf7, 0x66, 0x67, 0x8f, 0x13, 0xf0, 0x1a, 0xde,
		   0xac, 0x1b, 0x3e, 0xa9, 0x55, 0xad, 0xb5, 0x94 };

#define COMPARE_BUFFERS(got, exp) \
	if (memcmp(got, exp, sizeof(exp))) { \
		DMSG("SM4 error\nExpected:"); \
		DHEXDUMP(exp, sizeof(exp)); \
		DMSG("Got:"); \
		DHEXDUMP(got, sizeof(got)); \
		return TEE_ERROR_GENERIC; \
	}

TEE_Result ta_entry_sm4(uint32_t param_types, TEE_Param params[4])
{
	struct sm4_context ctx = { };
	uint8_t out[16];

	(void)params;

	if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
					   TEE_PARAM_TYPE_NONE,
					   TEE_PARAM_TYPE_NONE,
					   TEE_PARAM_TYPE_NONE)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	sm4_setkey_enc(&ctx, key1);
	sm4_crypt_ecb(&ctx, sizeof(plain1), plain1, out);
	COMPARE_BUFFERS(out, cipher1);

	sm4_setkey_dec(&ctx, key1);
	sm4_crypt_ecb(&ctx, sizeof(cipher1), cipher1, out);
	COMPARE_BUFFERS(out, plain1);

	sm4_setkey_enc(&ctx, key2);
	sm4_crypt_ecb(&ctx, sizeof(plain2), plain2, out);
	COMPARE_BUFFERS(out, cipher2);

	sm4_setkey_dec(&ctx, key2);
	sm4_crypt_ecb(&ctx, sizeof(cipher2), cipher2, out);
	COMPARE_BUFFERS(out, plain2);

	return TEE_SUCCESS;
}
