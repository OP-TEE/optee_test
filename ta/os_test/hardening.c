// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, RiscStar
 */

#include <compiler.h>
#include <config.h>
#include <stdint.h>
#include <string.h>
#include <ta_os_test.h>
#include <tee_internal_api.h>
#include <util.h>

#include "os_test.h"

#define SCAN_WORDS	64

static uint8_t aslr_data[16];

static void __noinline touch(char *buf, size_t len)
{
	memset(buf, 0x5a, len);
}

TEE_Result ta_entry_aslr(uint32_t param_types, TEE_Param params[4])
{
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
					  TEE_PARAM_TYPE_VALUE_OUTPUT,
					  TEE_PARAM_TYPE_VALUE_OUTPUT,
					  TEE_PARAM_TYPE_NONE);
	uintptr_t code = (uintptr_t)ta_entry_aslr;
	uintptr_t data = (uintptr_t)aslr_data;
	uint32_t flags = 0;

	if (param_types != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	if (IS_ENABLED(CFG_TA_ASLR))
		flags |= TA_OS_TEST_ASLR_ENABLED;

	params[0].value.a = flags;
	params[0].value.b = 0;
	reg_pair_from_64(code, &params[1].value.b, &params[1].value.a);
	reg_pair_from_64(data, &params[2].value.b, &params[2].value.a);

	return TEE_SUCCESS;
}

/* Find this frame's canary slot: first word above @buf holding the guard */
static uintptr_t *__noinline find_canary(char *buf)
{
	uintptr_t *p = (void *)ROUNDUP((uintptr_t)buf, sizeof(uintptr_t));
	size_t n = 0;

	for (n = 0; n < SCAN_WORDS; n++)
		if (p[n] == (uintptr_t)__stack_chk_guard)
			return (uintptr_t *)(p + n);

	return NULL;
}

static bool __noinline frame_has_canary(void)
{
	char buf[16] = { };

	touch(buf, sizeof(buf));

	return !!find_canary(buf);
}

TEE_Result ta_entry_stack_protector(uint32_t param_types, TEE_Param params[4])
{
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE);
	uintptr_t guard = (uintptr_t)__stack_chk_guard;
	uint32_t flags = 0;

	if (param_types != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	if (IS_ENABLED2(_CFG_TA_STACK_PROTECTOR))
		flags |= TA_OS_TEST_STACK_PROTECTOR_ENABLED;
	/*
	 * A guard supplied by the RNG has its least significant byte
	 * cleared, which the build time default value has not.
	 */
	if (guard && !(guard & 0xff))
		flags |= TA_OS_TEST_STACK_PROTECTOR_RANDOMIZED;
	if ((flags & TA_OS_TEST_STACK_PROTECTOR_ENABLED) && frame_has_canary())
		flags |= TA_OS_TEST_STACK_PROTECTOR_CANARY;

	params[0].value.a = flags;
	params[0].value.b = 0;

	return TEE_SUCCESS;
}

static void __noinline overflow(size_t len)
{
	char buf[16] = { };

	touch(buf, len);
}

TEE_Result ta_entry_stack_smash(uint32_t param_types, TEE_Param params[4])
{
	uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE);

	if (param_types != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!IS_ENABLED2(_CFG_TA_STACK_PROTECTOR))
		return TEE_ERROR_NOT_SUPPORTED;

	overflow(params[0].value.a);

	return TEE_ERROR_GENERIC;
}
