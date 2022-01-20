/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2022, Linaro Limited
 * All rights reserved.
 */

#include <inttypes.h>
#include <string.h>
#include <ta_arm_pauth.h>
#include <ta_arm_pauth_priv.h>
#include <tee_internal_api.h>

/* Assuming VA_MASK considering maximum 48 bit of VA */
#define VA_MASK		0xfffff0000000000

TEE_Result test_nop(void)
{
	uint64_t pac = 0;
	uint64_t ptr = 0;
	bool implemented = false;
	TEE_Result res = TEE_ERROR_GENERIC;

	res = TEE_GetPropertyAsBool(
			TEE_PROPSET_TEE_IMPLEMENTATION,
			"org.trustedfirmware.optee.cpu.feat_pauth_implemented",
			&implemented);
	if (res != TEE_SUCCESS)
		return res;

	if (!implemented)
		return TEE_ERROR_NOT_IMPLEMENTED;

	for (int i = 0; i < 10; i++) {
		asm volatile("paciza %0 " : "+r" (ptr));
		pac |= ptr & VA_MASK;
		ptr = i;
	}

	if (implemented && pac)
		return TEE_SUCCESS;

	return TEE_ERROR_GENERIC;
}
