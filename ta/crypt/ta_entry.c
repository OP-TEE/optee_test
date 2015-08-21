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

#include <tee_ta_api.h>
#include <ta_crypt.h>
#include <aes_taf.h>
#include <sha2_taf.h>
#include <cryp_taf.h>
#include <trace.h>

static TEE_Result set_global(uint32_t param_types, TEE_Param params[4]);
static TEE_Result get_global(uint32_t param_types, TEE_Param params[4]);
static int _globalvalue;

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
}

/*
 * To provoke the linker to produce R_ARM_ABS32 relocations we need to
 * pre-initilize a pointer to the function and then also call the function
 * directly.
 */
static TEE_Result (*ta_cmd_entries[])(uint32_t, TEE_Param *) = {
	[TA_CRYPT_CMD_SHA224] = ta_entry_sha224,
	[TA_CRYPT_CMD_SHA256] = ta_entry_sha256,
};

/* Called when a command is invoked */
TEE_Result TA_InvokeCommandEntryPoint(void *pSessionContext,
				      uint32_t nCommandID, uint32_t nParamTypes,
				      TEE_Param pParams[4])
{
	static bool use_fptr = false;

	(void)pSessionContext;


	switch (nCommandID) {
	case TA_CRYPT_CMD_SHA224:
		use_fptr = !use_fptr;
		if (use_fptr)
			return ta_cmd_entries[nCommandID](nParamTypes, pParams);
		else
			return ta_entry_sha224(nParamTypes, pParams);

	case TA_CRYPT_CMD_SHA256:
		use_fptr = !use_fptr;
		if (use_fptr)
			return ta_cmd_entries[nCommandID](nParamTypes, pParams);
		else
			return ta_entry_sha256(nParamTypes, pParams);

	case TA_CRYPT_CMD_AES256ECB_ENC:
		return ta_entry_aes256ecb_encrypt(nParamTypes, pParams);

	case TA_CRYPT_CMD_AES256ECB_DEC:
		return ta_entry_aes256ecb_decrypt(nParamTypes, pParams);

	case TA_CRYPT_CMD_ALLOCATE_OPERATION:
		return ta_entry_allocate_operation(nParamTypes, pParams);

	case TA_CRYPT_CMD_FREE_OPERATION:
		return ta_entry_free_operation(nParamTypes, pParams);

	case TA_CRYPT_CMD_GET_OPERATION_INFO:
		return ta_entry_get_operation_info(nParamTypes, pParams);

	case TA_CRYPT_CMD_RESET_OPERATION:
		return ta_entry_reset_operation(nParamTypes, pParams);

	case TA_CRYPT_CMD_SET_OPERATION_KEY:
		return ta_entry_set_operation_key(nParamTypes, pParams);

	case TA_CRYPT_CMD_SET_OPERATION_KEY2:
		return ta_entry_set_operation_key2(nParamTypes, pParams);

	case TA_CRYPT_CMD_COPY_OPERATION:
		return ta_entry_copy_operation(nParamTypes, pParams);

	case TA_CRYPT_CMD_DIGEST_UPDATE:
		return ta_entry_digest_update(nParamTypes, pParams);

	case TA_CRYPT_CMD_DIGEST_DO_FINAL:
		return ta_entry_digest_do_final(nParamTypes, pParams);

	case TA_CRYPT_CMD_CIPHER_INIT:
		return ta_entry_cipher_init(nParamTypes, pParams);

	case TA_CRYPT_CMD_CIPHER_UPDATE:
		return ta_entry_cipher_update(nParamTypes, pParams);

	case TA_CRYPT_CMD_CIPHER_DO_FINAL:
		return ta_entry_cipher_do_final(nParamTypes, pParams);

	case TA_CRYPT_CMD_MAC_INIT:
		return ta_entry_mac_init(nParamTypes, pParams);

	case TA_CRYPT_CMD_MAC_UPDATE:
		return ta_entry_mac_update(nParamTypes, pParams);

	case TA_CRYPT_CMD_MAC_FINAL_COMPUTE:
		return ta_entry_mac_final_compute(nParamTypes, pParams);

	case TA_CRYPT_CMD_MAC_FINAL_COMPARE:
		return ta_entry_mac_final_compare(nParamTypes, pParams);

	case TA_CRYPT_CMD_ALLOCATE_TRANSIENT_OBJECT:
		return ta_entry_allocate_transient_object(nParamTypes, pParams);

	case TA_CRYPT_CMD_FREE_TRANSIENT_OBJECT:
		return ta_entry_free_transient_object(nParamTypes, pParams);

	case TA_CRYPT_CMD_RESET_TRANSIENT_OBJECT:
		return ta_entry_reset_transient_object(nParamTypes, pParams);

	case TA_CRYPT_CMD_POPULATE_TRANSIENT_OBJECT:
		return ta_entry_populate_transient_object(nParamTypes, pParams);

	case TA_CRYPT_CMD_COPY_OBJECT_ATTRIBUTES:
		return ta_entry_copy_object_attributes(nParamTypes, pParams);

	case TA_CRYPT_CMD_GENERATE_KEY:
		return ta_entry_generate_key(nParamTypes, pParams);

	case TA_CRYPT_CMD_ASYMMETRIC_ENCRYPT:
		return ta_entry_asymmetric_encrypt(nParamTypes, pParams);

	case TA_CRYPT_CMD_ASYMMETRIC_DECRYPT:
		return ta_entry_asymmetric_decrypt(nParamTypes, pParams);

	case TA_CRYPT_CMD_ASYMMETRIC_SIGN_DIGEST:
		return ta_entry_asymmetric_sign_digest(nParamTypes, pParams);

	case TA_CRYPT_CMD_ASYMMETRIC_VERIFY_DIGEST:
		return ta_entry_asymmetric_verify_digest(nParamTypes, pParams);

	case TA_CRYPT_CMD_DERIVE_KEY:
		return ta_entry_derive_key(nParamTypes, pParams);

	case TA_CRYPT_CMD_RANDOM_NUMBER_GENEREATE:
		return ta_entry_random_number_generate(nParamTypes, pParams);

	case TA_CRYPT_CMD_AE_INIT:
		return ta_entry_ae_init(nParamTypes, pParams);

	case TA_CRYPT_CMD_AE_UPDATE_AAD:
		return ta_entry_ae_update_aad(nParamTypes, pParams);

	case TA_CRYPT_CMD_AE_UPDATE:
		return ta_entry_ae_update(nParamTypes, pParams);

	case TA_CRYPT_CMD_AE_ENCRYPT_FINAL:
		return ta_entry_ae_encrypt_final(nParamTypes, pParams);

	case TA_CRYPT_CMD_AE_DECRYPT_FINAL:
		return ta_entry_ae_decrypt_final(nParamTypes, pParams);

	case TA_CRYPT_CMD_GET_OBJECT_BUFFER_ATTRIBUTE:
		return ta_entry_get_object_buffer_attribute(nParamTypes,
							    pParams);
	case TA_CRYPT_CMD_GET_OBJECT_VALUE_ATTRIBUTE:
		return ta_entry_get_object_value_attribute(nParamTypes,
							   pParams);
	case TA_CRYPT_CMD_SETGLOBAL:
		return set_global(nParamTypes, pParams);

	case TA_CRYPT_CMD_GETGLOBAL:
		return get_global(nParamTypes, pParams);

	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}

static TEE_Result set_global(uint32_t param_types, TEE_Param params[4])
{
	int i;

	/* Param 0 is a memref, input/output */
	if (TEE_PARAM_TYPE_VALUE_INPUT != TEE_PARAM_TYPE_GET(param_types, 0))
		return TEE_ERROR_BAD_PARAMETERS;

	/* Other parameters must be of type TEE_PARAM_TYPE_NONE */
	for (i = 1; i < 4; i++) {
		if (TEE_PARAM_TYPE_NONE != TEE_PARAM_TYPE_GET(param_types, i))
			return TEE_ERROR_BAD_PARAMETERS;
	}

	_globalvalue = params[0].value.a;
	return TEE_SUCCESS;
}

static TEE_Result get_global(uint32_t param_types, TEE_Param params[4])
{
	int i;

	/* Param 0 is a memref, input/output */
	if (TEE_PARAM_TYPE_VALUE_OUTPUT != TEE_PARAM_TYPE_GET(param_types, 0))
		return TEE_ERROR_BAD_PARAMETERS;

	/* Other parameters must be of type TEE_PARAM_TYPE_NONE */
	for (i = 1; i < 4; i++) {
		if (TEE_PARAM_TYPE_NONE != TEE_PARAM_TYPE_GET(param_types, i))
			return TEE_ERROR_BAD_PARAMETERS;
	}

	params[0].value.a = _globalvalue;
	return TEE_SUCCESS;
}
