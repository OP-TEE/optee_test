// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2019 Huawei Technologies Co., Ltd
 */

#include <sm3.h>
#include <stdint.h>
#include <string.h>
#include <tee_api.h>
#include <trace.h>

#include "sm3_taf.h"

#define COMPARE_BUFFERS(got, exp) \
	if (memcmp(got, exp, sizeof(exp))) { \
		DMSG("SM3 error\nExpected:"); \
		DHEXDUMP(exp, sizeof(exp)); \
		DMSG("Got:"); \
		DHEXDUMP(got, sizeof(got)); \
		return TEE_ERROR_GENERIC; \
	}

uint8_t in1[] = "abc";
uint8_t out1[] = { 0x66, 0xc7, 0xf0, 0xf4, 0x62, 0xee, 0xed, 0xd9,
		   0xd1, 0xf2, 0xd4, 0x6b, 0xdc, 0x10, 0xe4, 0xe2,
		   0x41, 0x67, 0xc4, 0x87, 0x5c, 0xf2, 0xf7, 0xa2,
		   0x29, 0x7d, 0xa0, 0x2b, 0x8f, 0x4b, 0xa8, 0xe0 };

uint8_t in2[] = "abcdabcdabcdabcdabcdabcdabcdabcd"
		"abcdabcdabcdabcdabcdabcdabcdabcd";
uint8_t out2[] = { 0xde, 0xbe, 0x9f, 0xf9, 0x22, 0x75, 0xb8, 0xa1,
		   0x38, 0x60, 0x48, 0x89, 0xc1, 0x8e, 0x5a, 0x4d,
		   0x6f, 0xdb, 0x70, 0xe5, 0x38, 0x7e, 0x57, 0x65,
		   0x29, 0x3d, 0xcb, 0xa3, 0x9c, 0x0c, 0x57, 0x32 };

TEE_Result ta_entry_sm3(uint32_t param_types, TEE_Param params[4])
{
	struct sm3_context ctx = { };
	uint8_t out[32];

	(void)params;

	if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
					   TEE_PARAM_TYPE_NONE,
					   TEE_PARAM_TYPE_NONE,
					   TEE_PARAM_TYPE_NONE)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	memset(out, 0, sizeof(out));
	sm3(in1, sizeof(in1) - 1, out);
	COMPARE_BUFFERS(out, out1);

	memset(out, 0, sizeof(out));
	sm3_init(&ctx);
	sm3_update(&ctx, in1, sizeof(in1) - 1);
	sm3_final(&ctx, out);
	COMPARE_BUFFERS(out, out1);

	memset(out, 0, sizeof(out));
	sm3(in2, sizeof(in2) - 1, out);
	COMPARE_BUFFERS(out, out2);

	memset(out, 0, sizeof(out));
	sm3_init(&ctx);
	sm3_update(&ctx, in2, sizeof(in2) - 1);
	sm3_final(&ctx, out);
	COMPARE_BUFFERS(out, out2);

	return TEE_SUCCESS;
}
