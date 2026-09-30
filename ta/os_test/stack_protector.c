// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, RISCStar Solutions Corporation
 */

#include <compiler.h>
#include <config.h>
#include <stdint.h>
#include <ta_os_test.h>
#include <tee_internal_api.h>
#include <util.h>

#include "os_test.h"

#define SCAN_WORDS	64

/*
 * Keep the buffer alive and the frame instrumented.
 *
 * A canary is only emitted for a frame the compiler believes holds a
 * vulnerable object, and the compiler may delete a local array whose
 * contents it can prove are never observed. Either would remove the
 * canary this test looks for, leaving a test that passes against an
 * uninstrumented frame and proves nothing.
 *
 * __noinline alone is not enough to rely on: inter-procedural analysis
 * is free to notice that a memset() of a dead buffer has no observable
 * effect and drop it. Fill the buffer from the RNG instead, so the
 * contents cannot be predicted or constant folded, and store one byte
 * of the result to a volatile sink so the write has an observable side
 * effect that must be kept. The core test does the same with io_write8(),
 * which the TA dev kit does not export.
 */
static volatile uint8_t stack_sink;

static void __noinline touch(void *buf, size_t len)
{
	TEE_GenerateRandom(buf, len);

	stack_sink = ((uint8_t *)buf)[len - 1];
}

/* Find this frame's canary slot: first word above @buf holding the guard */
static uintptr_t *__noinline find_canary(void *buf)
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
	uint8_t buf[16] = { };

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
	uint8_t buf[16] = { };

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
