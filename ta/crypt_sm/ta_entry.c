// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2019 Huawei Technologies Co., Ltd
 */

#include <sm2_taf.h>
#include <sm3_taf.h>
#include <sm4_taf.h>
#include <ta_crypt_sm.h>
#include <tee_ta_api.h>
#include <trace.h>

TEE_Result TA_CreateEntryPoint(void)
{
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t nParamTypes,
				    TEE_Param pParams[4],
				    void **ppSessionContext)
{
	(void)nParamTypes;
	(void)pParams;
	(void)ppSessionContext;
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *pSessionContext)
{
	(void)pSessionContext;
}

TEE_Result TA_InvokeCommandEntryPoint(void *pSessionContext,
				      uint32_t nCommandID, uint32_t nParamTypes,
				      TEE_Param pParams[4])
{
	(void)pSessionContext;

	switch (nCommandID) {
	case TA_CRYPT_SM_CMD_SM2:
		return ta_entry_sm2(nParamTypes, pParams);
	case TA_CRYPT_SM_CMD_SM3:
		return ta_entry_sm3(nParamTypes, pParams);
	case TA_CRYPT_SM_CMD_SM4:
		return ta_entry_sm4(nParamTypes, pParams);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
