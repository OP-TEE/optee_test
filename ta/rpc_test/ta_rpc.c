/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include <stdint.h>

#include <ta_rpc.h>
#include <tee_api.h>
#include <trace.h>
#include <ta_crypt.h>
#include <ta_sims_test.h>

static TEE_UUID cryp_uuid = TA_CRYPT_UUID;

static TEE_Result rpc_call_cryp(uint32_t nParamTypes, TEE_Param pParams[4],
				uint32_t cmd)
{
	TEE_TASessionHandle cryp_session;
	TEE_Result res;
	uint32_t origin;
	TEE_Param params[4];

	uint32_t types =
	    TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
			    TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

	TEE_MemFill(params, 0, sizeof(TEE_Param) * 4);

	res = TEE_OpenTASession(&cryp_uuid, 0, types, params, &cryp_session,
				&origin);

	if (res != TEE_SUCCESS) {
		EMSG("rpc_sha256 - TEE_OpenTASession returned 0x%x\n",
		     (unsigned int)res);
		return res;
	}

	res = TEE_InvokeTACommand(cryp_session, 0, cmd, nParamTypes,
				  pParams, &origin);

	if (res != TEE_SUCCESS) {
		EMSG("rpc_sha256 - TEE_InvokeTACommand returned 0x%x\n",
		     (unsigned int)res);
	}

	TEE_CloseTASession(cryp_session);

	return res;
}

TEE_Result rpc_sha224(uint32_t nParamTypes, TEE_Param pParams[4])
{
	return rpc_call_cryp(nParamTypes, pParams, TA_CRYPT_CMD_SHA224);
}

TEE_Result rpc_sha256(uint32_t nParamTypes, TEE_Param pParams[4])
{
	return rpc_call_cryp(nParamTypes, pParams, TA_CRYPT_CMD_SHA256);
}

TEE_Result rpc_aes256ecb_encrypt(uint32_t nParamTypes, TEE_Param pParams[4])
{
	return rpc_call_cryp(nParamTypes, pParams, TA_CRYPT_CMD_AES256ECB_ENC);
}

TEE_Result rpc_aes256ecb_decrypt(uint32_t nParamTypes, TEE_Param pParams[4])
{
	return rpc_call_cryp(nParamTypes, pParams, TA_CRYPT_CMD_AES256ECB_DEC);
}

TEE_Result rpc_open(void *session_context, uint32_t param_types,
		    TEE_Param params[4])
{
	TEE_TASessionHandle session;
	uint32_t orig;
	TEE_Result res;
	TEE_UUID uuid = TA_SIMS_TEST_UUID;
	uint32_t types =
	    TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT, TEE_PARAM_TYPE_NONE,
			    TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
	TEE_Param par[4];

	(void)session_context;
	(void)param_types;

	res = TEE_OpenTASession(&uuid, 0, 0, NULL, &session, &orig);

	if (res != TEE_SUCCESS)
		return res;

	TEE_MemFill(params, 0, sizeof(TEE_Param) * 4);
	res =
	    TEE_InvokeTACommand(session, 0, TA_SIMS_CMD_GET_COUNTER, types, par,
				&orig);

	if (res != TEE_SUCCESS)
		goto exit;

exit:
	TEE_CloseTASession(session);

	return res;
}
