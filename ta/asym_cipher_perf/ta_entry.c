// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2023, Huawei Technologies Co., Ltd
 * All rights reserved.
 */

#include <tee_ta_api.h>
#include <trace.h>

#include "ta_asym_cipher_perf.h"
#include "ta_asym_cipher_perf_priv.h"

/*
 * Trusted Application Entry Points
 */

/* Called each time a new instance is created */
TEE_Result TA_CreateEntryPoint(void)
{
 return TEE_SUCCESS;
}

/* Called each time an instance is destroyed */
void TA_DestroyEntryPoint(void)
{
}

/* Called each time a session is opened */
TEE_Result TA_OpenSessionEntryPoint(uint32_t nParamTypes,
     TEE_Param pParams[4],
     void **ppSessionContext)
{
 (void)nParamTypes;
 (void)pParams;
 (void)ppSessionContext;
 return TEE_SUCCESS;
}

/* Called each time a session is closed */
void TA_CloseSessionEntryPoint(void *pSessionContext)
{
 (void)pSessionContext;

 cmd_clean_op();
 cmd_clean_obj();
}

/* Called when a command is invoked */
TEE_Result TA_InvokeCommandEntryPoint(void *pSessionContext,
       uint32_t nCommandID, uint32_t nParamTypes,
       TEE_Param pParams[4])
{
 (void)pSessionContext;

 switch (nCommandID) {
 case TA_ASYM_CIPHER_PERF_CMD_PROCESS_GEN_KEYPAIR:
 return cmd_process_keypair(nParamTypes, pParams);
 case TA_ASYM_CIPHER_PERF_CMD_PROCESS:
 return cmd_process_rsa_ecc(nParamTypes, pParams);
 case TA_ASYM_CIPHER_PERF_CMD_PREPARE_KEYPAIR:
 return cmd_prepare_keypair(nParamTypes, pParams);
 case TA_ASYM_CIPHER_PERF_CMD_PREPARE_HASH:
 return cmd_prepare_hash(nParamTypes, pParams);
 case TA_ASYM_CIPHER_PERF_CMD_PREPARE_OBJ:
 return cmd_prepare_obj(nParamTypes, pParams);
 case TA_ASYM_CIPHER_PERF_CMD_PREPARE_ENC_SIGN:
 return cmd_prepare_enc_sign(nParamTypes, pParams);
 default:
 return TEE_ERROR_BAD_PARAMETERS;
 }
}
