/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2021, Linaro Limited
 * All rights reserved.
 */

#include <inttypes.h>
#include <string.h>
#include <ta_arm_bti.h>
#include <ta_arm_bti_priv.h>
#include <tee_internal_api.h>

void call_using_blr(void (*)(void));
void call_using_br(void (*)(void));
void call_using_br_x16(void (*)(void));
void bti_j(void);
void bti_c(void);
void bti_jc(void);
void bti_none(void);

TEE_Result test_bti(uint32_t nCommandID, uint32_t nParamTypes, TEE_Param pParams[4])
{
	void (*func)(void) = NULL;

	if (nParamTypes != TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT, 0, 0, 0))
		return TEE_ERROR_GENERIC;

	switch (pParams[0].value.a) {
	case TA_FUNC_BTI_C:
		func = bti_c;
		break;
	case TA_FUNC_BTI_J:
		func = bti_j;
		break;
	case TA_FUNC_BTI_JC:
		func = bti_jc;
		break;
	case TA_FUNC_BTI_NONE:
		func = bti_none;
		break;
	default:
		break;
	}

	switch (nCommandID) {
	case TA_TEST_USING_BLR :
		call_using_blr(func);
		break;
	case TA_TEST_USING_BR :
		call_using_br(func);
		break;
	case TA_TEST_USING_BR_X16 :
		call_using_br_x16(func);
		break;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return TEE_SUCCESS;
}
