// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, RiscStar
 */

#include <config.h>
#include <stdint.h>
#include <ta_os_test.h>
#include <tee_internal_api.h>
#include <util.h>

#include "os_test.h"

static uint8_t aslr_data[16];

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
