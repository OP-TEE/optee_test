/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2022, Linaro Limited
 */

#include <inttypes.h>
#include <os_test.h>
#include <string.h>
#include <ta_os_test.h>
#include <tee_internal_api.h>

void corrupt_pac(void);

/* Assuming VA_MASK considering maximum 48 bit of VA */
#define VA_MASK		0xfffff0000000000

static uint64_t sign_using_keyia(uint64_t ptr)
{
	asm volatile("paciza %0 " : "+r" (ptr));
	return ptr;
}

TEE_Result ta_entry_pauth_test_nop(void)
{
	uint64_t pac = 0;
	bool implemented = false;
	TEE_Result res = TEE_ERROR_GENERIC;

	res = TEE_GetPropertyAsBool(
			TEE_PROPSET_TEE_IMPLEMENTATION,
			"org.trustedfirmware.optee.cpu.feat_pauth_implemented",
			&implemented);
	if (res != TEE_SUCCESS)
		return res;

	if (!implemented)
		return TEE_ERROR_NOT_SUPPORTED;

	/* Check if PAC instruction generates the authentication code */
	for (int i = 0; i < 10; i++)
		pac |= sign_using_keyia(i) & VA_MASK;

	if (implemented && pac)
		return TEE_SUCCESS;

	return TEE_ERROR_GENERIC;
}

TEE_Result ta_entry_pauth_corrupt_pac(void)
{
	corrupt_pac();

	return TEE_SUCCESS;
}
