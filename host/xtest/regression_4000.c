// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * Copyright (c) 2021, SumUp Services GmbH
 * Copyright 2023 NXP
 */

#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <malloc.h>
#include <time.h>

#include "xtest_test.h"
#include "xtest_helpers.h"

#include <tee_api_types.h>
#include <tee_api_defines_extensions.h>
#include <tee_api_compat.h>
#include <ta_crypt.h>
#include <utee_defines.h>
#include <util.h>

#include <regression_4000_data.h>
#include <nist/186-2ecdsatestvectors.h>

#include <assert.h>

static TEEC_Result ta_crypt_cmd_reset_operation(ADBG_Case_t *c, TEEC_Session *s,
						TEE_OperationHandle oph)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig = 0;

	assert((uintptr_t)oph <= UINT32_MAX);
	op.params[0].value.a = (uint32_t)(uintptr_t)oph;
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE,
					 TEEC_NONE);
	res = TEEC_InvokeCommand(s, TA_CRYPT_CMD_RESET_OPERATION, &op,
				 &ret_orig);
	if (res != TEEC_SUCCESS) {
		(void)ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TRUSTED_APP,
						    ret_orig);
	}
	return res;
}

static TEEC_Result ta_crypt_cmd_copy_operation(ADBG_Case_t *c,
					       TEEC_Session *s,
					       TEE_OperationHandle dst_oph,
					       TEE_OperationHandle src_oph)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig = 0;

	assert((uintptr_t)dst_oph <= UINT32_MAX);
	op.params[0].value.a = (uint32_t)(uintptr_t)dst_oph;

	assert((uintptr_t)src_oph <= UINT32_MAX);
	op.params[0].value.b = (uint32_t)(uintptr_t)src_oph;
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE,
					 TEEC_NONE);

	res = TEEC_InvokeCommand(s, TA_CRYPT_CMD_COPY_OPERATION, &op,
				 &ret_orig);

	if (res != TEEC_SUCCESS) {
		(void)ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TRUSTED_APP,
						    ret_orig);
	}
	return res;
}

static TEEC_Result ta_crypt_cmd_digest_update(ADBG_Case_t *c, TEEC_Session *s,
					      TEE_OperationHandle oph,
					      const void *chunk,
					      size_t chunk_size)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig = 0;

	assert((uintptr_t)oph <= UINT32_MAX);
	op.params[0].value.a = (uint32_t)(uintptr_t)oph;
	op.params[1].tmpref.buffer = (void *)chunk;
	op.params[1].tmpref.size = chunk_size;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_TEMP_INPUT, TEEC_NONE,
					 TEEC_NONE);

	res = TEEC_InvokeCommand(s, TA_CRYPT_CMD_DIGEST_UPDATE, &op, &ret_orig);

	if (res != TEEC_SUCCESS) {
		(void)ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TRUSTED_APP,
			    ret_orig);
	}

	return res;
}

static TEEC_Result ta_crypt_cmd_digest_do_final(ADBG_Case_t *c, TEEC_Session *s,
						TEE_OperationHandle oph,
						const void *chunk,
						size_t chunk_len, void *hash,
						size_t *hash_len)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig = 0;

	assert((uintptr_t)oph <= UINT32_MAX);
	op.params[0].value.a = (uint32_t)(uintptr_t)oph;

	op.params[1].tmpref.buffer = (void *)chunk;
	op.params[1].tmpref.size = chunk_len;

	op.params[2].tmpref.buffer = (void *)hash;
	op.params[2].tmpref.size = *hash_len;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE);

	res = TEEC_InvokeCommand(s, TA_CRYPT_CMD_DIGEST_DO_FINAL, &op,
				 &ret_orig);

	if (res != TEEC_SUCCESS) {
		(void)ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TRUSTED_APP,
						    ret_orig);
	}

	if (res == TEEC_SUCCESS)
		*hash_len = op.params[2].tmpref.size;

	return res;
}

static TEEC_Result ta_crypt_cmd_digest_extract(ADBG_Case_t *c, TEEC_Session *s,
						TEE_OperationHandle oph,
						void *hash, size_t *hash_len)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig = 0;

	assert((uintptr_t)oph <= UINT32_MAX);
	op.params[0].value.a = (uint32_t)(uintptr_t)oph;

	op.params[1].tmpref.buffer = (void *)hash;
	op.params[1].tmpref.size = *hash_len;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(s, TA_CRYPT_CMD_DIGEST_EXTRACT, &op,
				 &ret_orig);

	if (res != TEEC_SUCCESS) {
		(void)ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TRUSTED_APP,
						    ret_orig);
	}

	if (res == TEEC_SUCCESS)
		*hash_len = op.params[1].tmpref.size;

	return res;
}
static TEE_Result ta_crypt_cmd_set_operation_key2(ADBG_Case_t *c,
						  TEEC_Session *s,
						  TEE_OperationHandle oph,
						  TEE_ObjectHandle key1,
						  TEE_ObjectHandle key2)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig = 0;

	assert((uintptr_t)oph <= UINT32_MAX);
	op.params[0].value.a = (uint32_t)(uintptr_t)oph;

	assert((uintptr_t)key1 <= UINT32_MAX);
	op.params[0].value.b = (uint32_t)(uintptr_t)key1;

	assert((uintptr_t)key2 <= UINT32_MAX);
	op.params[1].value.a = (uint32_t)(uintptr_t)key2;
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_VALUE_INPUT,
					 TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(s, TA_CRYPT_CMD_SET_OPERATION_KEY2, &op,
				 &ret_orig);

	if (res != TEEC_SUCCESS) {
		(void)ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TRUSTED_APP,
			    ret_orig);
	}

	return res;
}

static TEEC_Result ta_crypt_cmd_mac_init(ADBG_Case_t *c, TEEC_Session *s,
					 TEE_OperationHandle oph,
					 const void *iv, size_t iv_len)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig = 0;

	assert((uintptr_t)oph <= UINT32_MAX);
	op.params[0].value.a = (uint32_t)(uintptr_t)oph;

	if (iv != NULL) {
		op.params[1].tmpref.buffer = (void *)iv;
		op.params[1].tmpref.size = iv_len;
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
						 TEEC_MEMREF_TEMP_INPUT,
						 TEEC_NONE, TEEC_NONE);
	} else {
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
						 TEEC_NONE, TEEC_NONE);
	}

	res = TEEC_InvokeCommand(s, TA_CRYPT_CMD_MAC_INIT, &op, &ret_orig);

	if (res != TEEC_SUCCESS) {
		(void)ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TRUSTED_APP,
						    ret_orig);
	}

	return res;
}

static TEEC_Result ta_crypt_cmd_mac_update(ADBG_Case_t *c, TEEC_Session *s,
					   TEE_OperationHandle oph,
					   const void *chunk, size_t chunk_size)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig = 0;

	assert((uintptr_t)oph <= UINT32_MAX);
	op.params[0].value.a = (uint32_t)(uintptr_t)oph;

	op.params[1].tmpref.buffer = (void *)chunk;
	op.params[1].tmpref.size = chunk_size;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_TEMP_INPUT, TEEC_NONE,
					 TEEC_NONE);

	res = TEEC_InvokeCommand(s, TA_CRYPT_CMD_MAC_UPDATE, &op, &ret_orig);

	if (res != TEEC_SUCCESS) {
		(void)ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TRUSTED_APP,
						    ret_orig);
	}

	return res;
}

static TEEC_Result ta_crypt_cmd_mac_final_compute(ADBG_Case_t *c,
						  TEEC_Session *s,
						  TEE_OperationHandle oph,
						  const void *chunk,
						  size_t chunk_len,
						  void *hash,
						  size_t *hash_len)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig = 0;

	assert((uintptr_t)oph <= UINT32_MAX);
	op.params[0].value.a = (uint32_t)(uintptr_t)oph;

	op.params[1].tmpref.buffer = (void *)chunk;
	op.params[1].tmpref.size = chunk_len;

	op.params[2].tmpref.buffer = (void *)hash;
	op.params[2].tmpref.size = *hash_len;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE);

	res = TEEC_InvokeCommand(s, TA_CRYPT_CMD_MAC_FINAL_COMPUTE, &op,
				 &ret_orig);

	if (res != TEEC_SUCCESS) {
		(void)ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TRUSTED_APP,
						    ret_orig);
	}

	if (res == TEEC_SUCCESS)
		*hash_len = op.params[2].tmpref.size;

	return res;
}

static TEEC_Result ta_crypt_cmd_mac_final_compare(ADBG_Case_t *c,
						  TEEC_Session *s,
						  TEE_OperationHandle oph,
						  const void *chunk,
						  size_t chunk_len,
						  const uint8_t *hash,
						  size_t hash_len)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig = 0;

	assert((uintptr_t)oph <= UINT32_MAX);
	op.params[0].value.a = (uint32_t)(uintptr_t)oph;

	op.params[1].tmpref.buffer = (void *)chunk;
	op.params[1].tmpref.size = chunk_len;

	op.params[2].tmpref.buffer = (void *)hash;
	op.params[2].tmpref.size = hash_len;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_INPUT, TEEC_NONE);

	res = TEEC_InvokeCommand(s, TA_CRYPT_CMD_MAC_FINAL_COMPARE, &op,
				 &ret_orig);

	if (res != TEEC_SUCCESS) {
		(void)ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TRUSTED_APP,
						    ret_orig);
	}

	return res;
}

static TEEC_Result ta_crypt_cmd_cipher_init(ADBG_Case_t *c, TEEC_Session *s,
					    TEE_OperationHandle oph,
					    const void *iv, size_t iv_len)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig = 0;

	assert((uintptr_t)oph <= UINT32_MAX);
	op.params[0].value.a = (uint32_t)(uintptr_t)oph;

	if (iv != NULL) {
		op.params[1].tmpref.buffer = (void *)iv;
		op.params[1].tmpref.size = iv_len;

		op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
						 TEEC_MEMREF_TEMP_INPUT,
						 TEEC_NONE, TEEC_NONE);
	} else {
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
						 TEEC_NONE, TEEC_NONE);
	}

	res = TEEC_InvokeCommand(s, TA_CRYPT_CMD_CIPHER_INIT, &op, &ret_orig);

	if (res != TEEC_SUCCESS) {
		(void)ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TRUSTED_APP,
						    ret_orig);
	}

	return res;
}

static TEEC_Result ta_crypt_cmd_cipher_update(ADBG_Case_t *c, TEEC_Session *s,
					      TEE_OperationHandle oph,
					      const void *src, size_t src_len,
					      void *dst, size_t *dst_len)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig = 0;

	assert((uintptr_t)oph <= UINT32_MAX);
	op.params[0].value.a = (uint32_t)(uintptr_t)oph;

	op.params[1].tmpref.buffer = (void *)src;
	op.params[1].tmpref.size = src_len;

	op.params[2].tmpref.buffer = dst;
	op.params[2].tmpref.size = *dst_len;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE);

	res = TEEC_InvokeCommand(s, TA_CRYPT_CMD_CIPHER_UPDATE, &op, &ret_orig);

	if (res != TEEC_SUCCESS) {
		(void)ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TRUSTED_APP,
						    ret_orig);
	}

	*dst_len = op.params[2].tmpref.size;

	return res;
}

static TEEC_Result ta_crypt_cmd_cipher_do_final(ADBG_Case_t *c,
						TEEC_Session *s,
						TEE_OperationHandle oph,
						const void *src,
						size_t src_len,
						void *dst,
						size_t *dst_len)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig = 0;

	assert((uintptr_t)oph <= UINT32_MAX);
	op.params[0].value.a = (uint32_t)(uintptr_t)oph;

	op.params[1].tmpref.buffer = (void *)src;
	op.params[1].tmpref.size = src_len;

	op.params[2].tmpref.buffer = (void *)dst;
	op.params[2].tmpref.size = *dst_len;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE);

	res = TEEC_InvokeCommand(s, TA_CRYPT_CMD_CIPHER_DO_FINAL, &op,
				 &ret_orig);

	if (res != TEEC_SUCCESS) {
		(void)ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TRUSTED_APP,
			    ret_orig);
	}

	*dst_len = op.params[2].tmpref.size;

	return res;
}

static TEEC_Result ta_crypt_cmd_random_number_generate(ADBG_Case_t *c,
						       TEEC_Session *s,
						       void *buf,
						       size_t blen)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig = 0;

	op.params[0].tmpref.buffer = buf;
	op.params[0].tmpref.size = blen;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(s, TA_CRYPT_CMD_RANDOM_NUMBER_GENERATE, &op,
				 &ret_orig);

	if (res != TEEC_SUCCESS) {
		(void)ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TRUSTED_APP,
						    ret_orig);
	}

	(void)ADBG_EXPECT_COMPARE_UNSIGNED(c, blen, ==,
					   op.params[0].tmpref.size);
	return res;
}

static TEEC_Result ta_crypt_cmd_ae_init(ADBG_Case_t *c, TEEC_Session *s,
					TEE_OperationHandle oph,
					const void *nonce, size_t nonce_len,
					size_t tag_len, size_t aad_len,
					size_t payload_len)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig = 0;

	assert((uintptr_t)oph <= UINT32_MAX);
	op.params[0].value.a = (uint32_t)(uintptr_t)oph;
	op.params[0].value.b = tag_len;

	op.params[1].tmpref.buffer = (void *)nonce;
	op.params[1].tmpref.size = nonce_len;

	op.params[2].value.a = aad_len;
	op.params[2].value.b = payload_len;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_VALUE_INPUT, TEEC_NONE);

	res = TEEC_InvokeCommand(s, TA_CRYPT_CMD_AE_INIT, &op, &ret_orig);

	if (res != TEEC_SUCCESS) {
		(void)ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TRUSTED_APP,
						    ret_orig);
	}
	return res;
}

static TEEC_Result ta_crypt_cmd_ae_update_aad(ADBG_Case_t *c, TEEC_Session *s,
					      TEE_OperationHandle oph,
					      const void *aad, size_t aad_len)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig = 0;

	assert((uintptr_t)oph <= UINT32_MAX);
	op.params[0].value.a = (uint32_t)(uintptr_t)oph;

	op.params[1].tmpref.buffer = (void *)aad;
	op.params[1].tmpref.size = aad_len;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_TEMP_INPUT, TEEC_NONE,
					 TEEC_NONE);

	res = TEEC_InvokeCommand(s, TA_CRYPT_CMD_AE_UPDATE_AAD, &op, &ret_orig);

	if (res != TEEC_SUCCESS) {
		(void)ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TRUSTED_APP,
						    ret_orig);
	}

	return res;
}

static TEEC_Result ta_crypt_cmd_ae_update(ADBG_Case_t *c,
					  TEEC_Session *s,
					  TEE_OperationHandle oph,
					  const void *src,
					  size_t src_len,
					  void *dst,
					  size_t *dst_len)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig = 0;

	assert((uintptr_t)oph <= UINT32_MAX);
	op.params[0].value.a = (uint32_t)(uintptr_t)oph;

	op.params[1].tmpref.buffer = (void *)src;
	op.params[1].tmpref.size = src_len;

	op.params[2].tmpref.buffer = (void *)dst;
	op.params[2].tmpref.size = *dst_len;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE);

	res = TEEC_InvokeCommand(s, TA_CRYPT_CMD_AE_UPDATE, &op, &ret_orig);

	if (res != TEEC_SUCCESS) {
		(void)ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TRUSTED_APP,
						    ret_orig);
	}

	*dst_len = op.params[2].tmpref.size;

	return res;
}

static TEEC_Result ta_crypt_cmd_ae_encrypt_final(ADBG_Case_t *c,
						 TEEC_Session *s,
						 TEE_OperationHandle oph,
						 const void *src,
						 size_t src_len, void *dst,
						 size_t *dst_len, void *tag,
						 size_t *tag_len)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig = 0;

	assert((uintptr_t)oph <= UINT32_MAX);
	op.params[0].value.a = (uint32_t)(uintptr_t)oph;

	op.params[1].tmpref.buffer = (void *)src;
	op.params[1].tmpref.size = src_len;

	op.params[2].tmpref.buffer = (void *)dst;
	op.params[2].tmpref.size = *dst_len;

	op.params[3].tmpref.buffer = (void *)tag;
	op.params[3].tmpref.size = *tag_len;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_MEMREF_TEMP_OUTPUT);

	res = TEEC_InvokeCommand(s, TA_CRYPT_CMD_AE_ENCRYPT_FINAL, &op,
				 &ret_orig);

	if (res != TEEC_SUCCESS) {
		(void)ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TRUSTED_APP,
						    ret_orig);
	}

	*dst_len = op.params[2].tmpref.size;
	*tag_len = op.params[3].tmpref.size;

	return res;
}

static TEEC_Result ta_crypt_cmd_ae_decrypt_final(ADBG_Case_t *c,
						 TEEC_Session *s,
						 TEE_OperationHandle oph,
						 const void *src, size_t src_len,
						 void *dst, size_t *dst_len,
						 const void *tag, size_t tag_len)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig = 0;

	assert((uintptr_t)oph <= UINT32_MAX);
	op.params[0].value.a = (uint32_t)(uintptr_t)oph;

	op.params[1].tmpref.buffer = (void *)src;
	op.params[1].tmpref.size = src_len;

	op.params[2].tmpref.buffer = dst;
	op.params[2].tmpref.size = *dst_len;

	op.params[3].tmpref.buffer = (void *)tag;
	op.params[3].tmpref.size = tag_len;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_MEMREF_TEMP_INPUT);

	res = TEEC_InvokeCommand(s, TA_CRYPT_CMD_AE_DECRYPT_FINAL, &op,
				 &ret_orig);

	if (res != TEEC_SUCCESS) {
		(void)ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TRUSTED_APP,
						    ret_orig);
	}

	*dst_len = op.params[2].tmpref.size;

	return res;
}

static TEEC_Result ta_crypt_cmd_asymmetric_operate(ADBG_Case_t *c,
						   TEEC_Session *s,
						   TEE_OperationHandle oph,
						   uint32_t cmd,
						   const TEE_Attribute *params,
						   uint32_t paramCount,
						   const void *src,
						   size_t src_len,
						   void *dst,
						   size_t *dst_len)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig = 0;
	uint8_t *buf = NULL;
	size_t blen = 0;

	res = pack_attrs(params, paramCount, &buf, &blen);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		return res;

	assert((uintptr_t)oph <= UINT32_MAX);
	op.params[0].value.a = (uint32_t)(uintptr_t)oph;

	op.params[1].tmpref.buffer = buf;
	op.params[1].tmpref.size = blen;

	op.params[2].tmpref.buffer = (void *)src;
	op.params[2].tmpref.size = src_len;

	op.params[3].tmpref.buffer = dst;
	op.params[3].tmpref.size = *dst_len;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT);

	res = TEEC_InvokeCommand(s, cmd, &op, &ret_orig);

	if (res != TEEC_SUCCESS) {
		(void)ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TRUSTED_APP,
						    ret_orig);
	}

	if (res == TEEC_SUCCESS)
		*dst_len = op.params[3].tmpref.size;

	free(buf);
	return res;
}

static TEEC_Result ta_crypt_cmd_asymmetric_encrypt(ADBG_Case_t *c,
						   TEEC_Session *s,
						   TEE_OperationHandle oph,
						   const TEE_Attribute *params,
						   uint32_t paramCount,
						   const void *src,
						   size_t src_len,
						   void *dst,
						   size_t *dst_len)
{
	return ta_crypt_cmd_asymmetric_operate(c, s, oph,
					       TA_CRYPT_CMD_ASYMMETRIC_ENCRYPT,
					       params, paramCount,
					       src, src_len, dst, dst_len);
}

static TEEC_Result ta_crypt_cmd_asymmetric_decrypt(ADBG_Case_t *c,
						   TEEC_Session *s,
						   TEE_OperationHandle oph,
						   const TEE_Attribute *params,
						   uint32_t paramCount,
						   const void *src,
						   size_t src_len,
						   void *dst,
						   size_t *dst_len)
{
	return ta_crypt_cmd_asymmetric_operate(c, s, oph,
					       TA_CRYPT_CMD_ASYMMETRIC_DECRYPT,
					       params, paramCount,
					       src, src_len, dst, dst_len);
}

static TEEC_Result ta_crypt_cmd_asymmetric_sign(ADBG_Case_t *c,
						TEEC_Session *s,
						TEE_OperationHandle oph,
						const TEE_Attribute *params,
						uint32_t paramCount,
						const void *digest,
						size_t digest_len,
						void *signature,
						size_t *signature_len)
{
	return ta_crypt_cmd_asymmetric_operate(c, s, oph,
			TA_CRYPT_CMD_ASYMMETRIC_SIGN_DIGEST, params, paramCount,
			digest, digest_len, signature, signature_len);
}

static TEEC_Result ta_crypt_cmd_asymmetric_verify(ADBG_Case_t *c,
						  TEEC_Session *s,
						  TEE_OperationHandle oph,
						  const TEE_Attribute *params,
						  uint32_t paramCount,
						  const void *digest,
						  size_t digest_len,
						  const void *signature,
						  size_t signature_len)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig = 0;
	uint8_t *buf = NULL;
	size_t blen = 0;

	res = pack_attrs(params, paramCount, &buf, &blen);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		return res;

	assert((uintptr_t)oph <= UINT32_MAX);
	op.params[0].value.a = (uint32_t)(uintptr_t)oph;

	op.params[1].tmpref.buffer = buf;
	op.params[1].tmpref.size = blen;

	op.params[2].tmpref.buffer = (void *)digest;
	op.params[2].tmpref.size = digest_len;

	op.params[3].tmpref.buffer = (void *)signature;
	op.params[3].tmpref.size = signature_len;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_INPUT);

	res = TEEC_InvokeCommand(s, TA_CRYPT_CMD_ASYMMETRIC_VERIFY_DIGEST,
				 &op, &ret_orig);

	if (res != TEEC_SUCCESS) {
		(void)ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TRUSTED_APP,
						    ret_orig);
	}

	free(buf);
	return res;
}

static TEEC_Result ta_crypt_cmd_get_object_value_attribute(ADBG_Case_t *c,
							   TEEC_Session *s,
							   TEE_ObjectHandle o,
							   uint32_t attr_id,
							   uint32_t *valuea,
							   uint32_t *valueb)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig = 0;

	assert((uintptr_t)o <= UINT32_MAX);
	op.params[0].value.a = (uint32_t)(uintptr_t)o;
	op.params[0].value.b = attr_id;
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_VALUE_OUTPUT,
					 TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(s, TA_CRYPT_CMD_GET_OBJECT_VALUE_ATTRIBUTE,
				 &op, &ret_orig);

	if (res != TEEC_SUCCESS) {
		(void)ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TRUSTED_APP,
						    ret_orig);
	}

	if (res == TEEC_SUCCESS) {
		*valuea = op.params[1].value.a;
		*valueb = op.params[1].value.b;
	}

	return res;
}

static TEEC_Result ta_crypt_cmd_generate_key(ADBG_Case_t *c,
					     TEEC_Session *s,
					     TEE_ObjectHandle o,
					     uint32_t key_size,
					     const TEE_Attribute *params,
					     uint32_t paramCount)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig = 0;
	uint8_t *buf = NULL;
	size_t blen = 0;

	res = pack_attrs(params, paramCount, &buf, &blen);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		return res;

	assert((uintptr_t)o <= UINT32_MAX);
	op.params[0].value.a = (uint32_t)(uintptr_t)o;
	op.params[0].value.b = key_size;

	op.params[1].tmpref.buffer = buf;
	op.params[1].tmpref.size = blen;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_TEMP_INPUT, TEEC_NONE,
					 TEEC_NONE);

	res = TEEC_InvokeCommand(s, TA_CRYPT_CMD_GENERATE_KEY, &op, &ret_orig);

	if (res != TEEC_SUCCESS) {
		(void)ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TRUSTED_APP,
						    ret_orig);
	}

	free(buf);
	return res;
}

static const uint8_t hash_data_md5_in1[] = {
	'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm'
};

static const uint8_t hash_data_md5_out1[] = {
	0x61, 0x12, 0x71, 0x83, 0x70, 0x8d, 0x3a, 0xc7,
	0xf1, 0x9b, 0x66, 0x06, 0xfc, 0xae, 0x7d, 0xf6
};

static const uint8_t hash_data_sha1_in1[] = {
	'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm'
};

static const uint8_t hash_data_sha1_out1[] = {
	0x4b, 0x98, 0x92, 0xb6, 0x52, 0x72, 0x14, 0xaf,
	0xc6, 0x55, 0xb8, 0xaa, 0x52, 0xf4, 0xd2, 0x03,
	0xc1, 0x5e, 0x7c, 0x9c
};

static const uint8_t hash_data_sha224_in1[] = {
	'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm'
};

static const uint8_t hash_data_sha224_out1[] = {
	0x08, 0x21, 0x69, 0xf9, 0x77, 0x1b, 0x80, 0x15,
	0xf3, 0x97, 0xae, 0xde, 0x5b, 0xba, 0xa2, 0x72,
	0x2d, 0x8f, 0x5c, 0x19, 0xfe, 0xd2, 0xe2, 0x68,
	0x92, 0x49, 0xd8, 0x44
};

static const uint8_t hash_data_sha256_in1[] = { 'a', 'b', 'c' };

static const uint8_t hash_data_sha256_out1[] = {
	0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
	0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
	0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
	0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
};

static const uint8_t hash_data_sha256_in2[] = { 'e', 'f', 'g' };

static const uint8_t hash_data_sha256_out2[] = {
	0xd4, 0xff, 0xe8, 0xe9, 0xee, 0x0b, 0x48, 0xeb,
	0xa7, 0x16, 0x70, 0x61, 0x23, 0xa7, 0x18, 0x7f,
	0x32, 0xea, 0xe3, 0xbd, 0xcb, 0x0e, 0x77, 0x63,
	0xe4, 0x1e, 0x53, 0x32, 0x67, 0xbd, 0x8a, 0x53
};


static const uint8_t hash_data_sha384_in1[] = {
	'a', 'b', 'c', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm'
};

static const uint8_t hash_data_sha384_out1[] = {
	0x4c, 0xab, 0x80, 0x9d, 0x96, 0x84, 0x01, 0x47,
	0x67, 0x0a, 0xc1, 0x7a, 0xb6, 0xb9, 0xf7, 0x6e,
	0x35, 0xa6, 0xb0, 0x8c, 0xf5, 0x2a, 0x3d, 0x64,
	0x9a, 0x8c, 0x7e, 0x0c, 0x55, 0x45, 0xd3, 0x7d,
	0x1f, 0x7f, 0x28, 0x34, 0x96, 0x14, 0x44, 0x2a,
	0xf5, 0x98, 0xa2, 0x95, 0x24, 0x76, 0x53, 0x97
};

static const uint8_t hash_data_sha512_in1[] = {
	'a', 'b', 'c', 'd', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm'
};

static const uint8_t hash_data_sha512_out1[] = {
	0x20, 0xd8, 0x64, 0x4f, 0x54, 0xa2, 0x5f, 0x6f,
	0x0a, 0xf9, 0xd5, 0x27, 0x7d, 0x17, 0xa8, 0x99,
	0x4c, 0x64, 0x3f, 0xd0, 0xf3, 0x83, 0x36, 0xee,
	0x93, 0x12, 0x55, 0xcd, 0x2e, 0x12, 0x34, 0xa0,
	0xc2, 0xaa, 0xf9, 0xbb, 0x15, 0xc5, 0xe9, 0xfa,
	0xf7, 0xa7, 0xda, 0xb8, 0x2f, 0x72, 0xa0, 0x47,
	0xe3, 0x02, 0x04, 0xe8, 0xa0, 0x35, 0x0c, 0x96,
	0x26, 0xd1, 0xcb, 0x8b, 0x47, 0x45, 0x25, 0xd0
};

/* SHA-3 vectors from https://www.di-mgt.com.au/sha_testvectors.html */
#define hash_data_sha3_in1 hash_data_sha256_in1

static const uint8_t hash_data_sha3_224_out1[] = {
	0xe6, 0x42, 0x82, 0x4c, 0x3f, 0x8c, 0xf2, 0x4a,
	0xd0, 0x92, 0x34, 0xee, 0x7d, 0x3c, 0x76, 0x6f,
	0xc9, 0xa3, 0xa5, 0x16, 0x8d, 0x0c, 0x94, 0xad,
	0x73, 0xb4, 0x6f, 0xdf
};

static const uint8_t hash_data_sha3_256_out1[] = {
	0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xb2,
	0x04, 0x5c, 0x17, 0x2d, 0x6b, 0xd3, 0x90, 0xbd,
	0x85, 0x5f, 0x08, 0x6e, 0x3e, 0x9d, 0x52, 0x5b,
	0x46, 0xbf, 0xe2, 0x45, 0x11, 0x43, 0x15, 0x32
};

static const uint8_t hash_data_sha3_384_out1[] = {
	0xec, 0x01, 0x49, 0x82, 0x88, 0x51, 0x6f, 0xc9,
	0x26, 0x45, 0x9f, 0x58, 0xe2, 0xc6, 0xad, 0x8d,
	0xf9, 0xb4, 0x73, 0xcb, 0x0f, 0xc0, 0x8c, 0x25,
	0x96, 0xda, 0x7c, 0xf0, 0xe4, 0x9b, 0xe4, 0xb2,
	0x98, 0xd8, 0x8c, 0xea, 0x92, 0x7a, 0xc7, 0xf5,
	0x39, 0xf1, 0xed, 0xf2, 0x28, 0x37, 0x6d, 0x25
};

static const uint8_t hash_data_sha3_512_out1[] = {
	0xb7, 0x51, 0x85, 0x0b, 0x1a, 0x57, 0x16, 0x8a,
	0x56, 0x93, 0xcd, 0x92, 0x4b, 0x6b, 0x09, 0x6e,
	0x08, 0xf6, 0x21, 0x82, 0x74, 0x44, 0xf7, 0x0d,
	0x88, 0x4f, 0x5d, 0x02, 0x40, 0xd2, 0x71, 0x2e,
	0x10, 0xe1, 0x16, 0xe9, 0x19, 0x2a, 0xf3, 0xc9,
	0x1a, 0x7e, 0xc5, 0x76, 0x47, 0xe3, 0x93, 0x40,
	0x57, 0x34, 0x0b, 0x4c, 0xf4, 0x08, 0xd5, 0xa5,
	0x65, 0x92, 0xf8, 0x27, 0x4e, 0xec, 0x53, 0xf0
};

/*
 * SHAKE output generated with:
 * https://asecuritysite.com/hash/shake?m=abc&l=54
 */
static const uint8_t hash_data_shake128_out1[] = {
	0x58, 0x81, 0x09, 0x2d, 0xd8, 0x18, 0xbf, 0x5c,
	0xf8, 0xa3, 0xdd, 0xb7, 0x93, 0xfb, 0xcb, 0xa7,
	0x40, 0x97, 0xd5, 0xc5, 0x26, 0xa6, 0xd3, 0x5f,
	0x97, 0xb8, 0x33, 0x51, 0x94, 0x0f, 0x2c, 0xc8,
	0x44, 0xc5, 0x0a, 0xf3, 0x2a, 0xcd, 0x3f, 0x2c,
	0xdd, 0x06, 0x65, 0x68, 0x70, 0x6f, 0x50, 0x9b,
	0xc1, 0xbd, 0xde, 0x58, 0x29, 0x5d
};

static const uint8_t hash_data_shake256_out1[] = {
	0x48, 0x33, 0x66, 0x60, 0x13, 0x60, 0xa8, 0x77,
	0x1c, 0x68, 0x63, 0x08, 0x0c, 0xc4, 0x11, 0x4d,
	0x8d, 0xb4, 0x45, 0x30, 0xf8, 0xf1, 0xe1, 0xee,
	0x4f, 0x94, 0xea, 0x37, 0xe7, 0x8b, 0x57, 0x39,
	0xd5, 0xa1, 0x5b, 0xef, 0x18, 0x6a, 0x53, 0x86,
	0xc7, 0x57, 0x44, 0xc0, 0x52, 0x7e, 0x1f, 0xaa,
	0x9f, 0x87, 0x26, 0xe4, 0x62, 0xa1
};

/*
 * More SHA-3 test cases from
 * https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing
 * https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/sha-3bytetestvectors.zip
 */

/* Excerpt from SHA3_224LongMsg.rsp */
static const uint8_t hash_data_sha3_224_in2[] = {
	0x31, 0xc8, 0x2d, 0x71, 0x78, 0x5b, 0x7c, 0xa6,
	0xb6, 0x51, 0xcb, 0x6c, 0x8c, 0x9a, 0xd5, 0xe2,
	0xac, 0xeb, 0x0b, 0x06, 0x33, 0xc0, 0x88, 0xd3,
	0x3a, 0xa2, 0x47, 0xad, 0xa7, 0xa5, 0x94, 0xff,
	0x49, 0x36, 0xc0, 0x23, 0x25, 0x13, 0x19, 0x82,
	0x0a, 0x9b, 0x19, 0xfc, 0x6c, 0x48, 0xde, 0x8a,
	0x6f, 0x7a, 0xda, 0x21, 0x41, 0x76, 0xcc, 0xda,
	0xad, 0xae, 0xef, 0x51, 0xed, 0x43, 0x71, 0x4a,
	0xc0, 0xc8, 0x26, 0x9b, 0xbd, 0x49, 0x7e, 0x46,
	0xe7, 0x8b, 0xb5, 0xe5, 0x81, 0x96, 0x49, 0x4b,
	0x24, 0x71, 0xb1, 0x68, 0x0e, 0x2d, 0x4c, 0x6d,
	0xbd, 0x24, 0x98, 0x31, 0xbd, 0x83, 0xa4, 0xd3,
	0xbe, 0x06, 0xc8, 0xa2, 0xe9, 0x03, 0x93, 0x39,
	0x74, 0xaa, 0x05, 0xee, 0x74, 0x8b, 0xfe, 0x6e,
	0xf3, 0x59, 0xf7, 0xa1, 0x43, 0xed, 0xf0, 0xd4,
	0x91, 0x8d, 0xa9, 0x16, 0xbd, 0x6f, 0x15, 0xe2,
	0x6a, 0x79, 0x0c, 0xff, 0x51, 0x4b, 0x40, 0xa5,
	0xda, 0x7f, 0x72, 0xe1, 0xed, 0x2f, 0xe6, 0x3a,
	0x05, 0xb8, 0x14, 0x95, 0x87, 0xbe, 0xa0, 0x56,
	0x53, 0x71, 0x8c, 0xc8, 0x98, 0x0e, 0xad, 0xbf,
	0xec, 0xa8, 0x5b, 0x7c, 0x9c, 0x28, 0x6d, 0xd0,
	0x40, 0x93, 0x65, 0x85, 0x93, 0x8b, 0xe7, 0xf9,
	0x82, 0x19, 0x70, 0x0c, 0x83, 0xa9, 0x44, 0x3c,
	0x28, 0x56, 0xa8, 0x0f, 0xf4, 0x68, 0x52, 0xb2,
	0x6d, 0x1b, 0x1e, 0xdf, 0x72, 0xa3, 0x02, 0x03,
	0xcf, 0x6c, 0x44, 0xa1, 0x0f, 0xa6, 0xea, 0xf1,
	0x92, 0x01, 0x73, 0xce, 0xdf, 0xb5, 0xc4, 0xcf,
	0x3a, 0xc6, 0x65, 0xb3, 0x7a, 0x86, 0xed, 0x02,
	0x15, 0x5b, 0xbb, 0xf1, 0x7d, 0xc2, 0xe7, 0x86,
	0xaf, 0x94, 0x78, 0xfe, 0x08, 0x89, 0xd8, 0x6c,
	0x5b, 0xfa, 0x85, 0xa2, 0x42, 0xeb, 0x08, 0x54,
	0xb1, 0x48, 0x2b, 0x7b, 0xd1, 0x6f, 0x67, 0xf8,
	0x0b, 0xef, 0x9c, 0x7a, 0x62, 0x8f, 0x05, 0xa1,
	0x07, 0x93, 0x6a, 0x64, 0x27, 0x3a, 0x97, 0xb0,
	0x08, 0x8b, 0x0e, 0x51, 0x54, 0x51, 0xf9, 0x16,
	0xb5, 0x65, 0x62, 0x30, 0xa1, 0x2b, 0xa6, 0xdc,
	0x78
};

static const uint8_t hash_data_sha3_224_out2[] = {
	0xaa, 0xb2, 0x3c, 0x9e, 0x7f, 0xb9, 0xd7, 0xda,
	0xce, 0xfd, 0xfd, 0x0b, 0x1a, 0xe8, 0x5a, 0xb1,
	0x37, 0x4a, 0xbf, 0xf7, 0xc4, 0xe3, 0xf7, 0x55,
	0x6e, 0xca, 0xe4, 0x12
};

/* Excerpt from SHA3_256LongMsg.rsp */
static const uint8_t hash_data_sha3_256_in2[] = {
	0xb1, 0xca, 0xa3, 0x96, 0x77, 0x1a, 0x09, 0xa1,
	0xdb, 0x9b, 0xc2, 0x05, 0x43, 0xe9, 0x88, 0xe3,
	0x59, 0xd4, 0x7c, 0x2a, 0x61, 0x64, 0x17, 0xbb,
	0xca, 0x1b, 0x62, 0xcb, 0x02, 0x79, 0x6a, 0x88,
	0x8f, 0xc6, 0xee, 0xff, 0x5c, 0x0b, 0x5c, 0x3d,
	0x50, 0x62, 0xfc, 0xb4, 0x25, 0x6f, 0x6a, 0xe1,
	0x78, 0x2f, 0x49, 0x2c, 0x1c, 0xf0, 0x36, 0x10,
	0xb4, 0xa1, 0xfb, 0x7b, 0x81, 0x4c, 0x05, 0x78,
	0x78, 0xe1, 0x19, 0x0b, 0x98, 0x35, 0x42, 0x5c,
	0x7a, 0x4a, 0x0e, 0x18, 0x2a, 0xd1, 0xf9, 0x15,
	0x35, 0xed, 0x2a, 0x35, 0x03, 0x3a, 0x5d, 0x8c,
	0x67, 0x0e, 0x21, 0xc5, 0x75, 0xff, 0x43, 0xc1,
	0x94, 0xa5, 0x8a, 0x82, 0xd4, 0xa1, 0xa4, 0x48,
	0x81, 0xdd, 0x61, 0xf9, 0xf8, 0x16, 0x1f, 0xc6,
	0xb9, 0x98, 0x86, 0x0c, 0xbe, 0x49, 0x75, 0x78,
	0x0b, 0xe9, 0x3b, 0x6f, 0x87, 0x98, 0x0b, 0xad,
	0x0a, 0x99, 0xaa, 0x2c, 0xb7, 0x55, 0x6b, 0x47,
	0x8c, 0xa3, 0x5d, 0x1f, 0x37, 0x46, 0xc3, 0x3e,
	0x2b, 0xb7, 0xc4, 0x7a, 0xf4, 0x26, 0x64, 0x1c,
	0xc7, 0xbb, 0xb3, 0x42, 0x5e, 0x21, 0x44, 0x82,
	0x03, 0x45, 0xe1, 0xd0, 0xea, 0x5b, 0x7d, 0xa2,
	0xc3, 0x23, 0x6a, 0x52, 0x90, 0x6a, 0xcd, 0xc3,
	0xb4, 0xd3, 0x4e, 0x47, 0x4d, 0xd7, 0x14, 0xc0,
	0xc4, 0x0b, 0xf0, 0x06, 0xa3, 0xa1, 0xd8, 0x89,
	0xa6, 0x32, 0x98, 0x38, 0x14, 0xbb, 0xc4, 0xa1,
	0x4f, 0xe5, 0xf1, 0x59, 0xaa, 0x89, 0x24, 0x9e,
	0x7c, 0x73, 0x8b, 0x3b, 0x73, 0x66, 0x6b, 0xac,
	0x2a, 0x61, 0x5a, 0x83, 0xfd, 0x21, 0xae, 0x0a,
	0x1c, 0xe7, 0x35, 0x2a, 0xde, 0x7b, 0x27, 0x8b,
	0x58, 0x71, 0x58, 0xfd, 0x2f, 0xab, 0xb2, 0x17,
	0xaa, 0x1f, 0xe3, 0x1d, 0x0b, 0xda, 0x53, 0x27,
	0x20, 0x45, 0x59, 0x80, 0x15, 0xa8, 0xae, 0x4d,
	0x8c, 0xec, 0x22, 0x6f, 0xef, 0xa5, 0x8d, 0xaa,
	0x05, 0x50, 0x09, 0x06, 0xc4, 0xd8, 0x5e, 0x75,
	0x67
};

static const uint8_t hash_data_sha3_256_out2[] = {
	0xcb, 0x56, 0x48, 0xa1, 0xd6, 0x1c, 0x6c, 0x5b,
	0xda, 0xcd, 0x96, 0xf8, 0x1c, 0x95, 0x91, 0xde,
	0xbc, 0x39, 0x50, 0xdc, 0xf6, 0x58, 0x14, 0x5b,
	0x8d, 0x99, 0x65, 0x70, 0xba, 0x88, 0x1a, 0x05
};

/* Excerpt from SHA3_384LongMsg.rsp */
static const uint8_t hash_data_sha3_384_in2[] = {
	0x5f, 0xe3, 0x59, 0x23, 0xb4, 0xe0, 0xaf, 0x7d,
	0xd2, 0x49, 0x71, 0x81, 0x2a, 0x58, 0x42, 0x55,
	0x19, 0x85, 0x0a, 0x50, 0x6d, 0xfa, 0x9b, 0x0d,
	0x25, 0x47, 0x95, 0xbe, 0x78, 0x57, 0x86, 0xc3,
	0x19, 0xa2, 0x56, 0x7c, 0xba, 0xa5, 0xe3, 0x5b,
	0xcf, 0x8f, 0xe8, 0x3d, 0x94, 0x3e, 0x23, 0xfa,
	0x51, 0x69, 0xb7, 0x3a, 0xdc, 0x1f, 0xcf, 0x8b,
	0x60, 0x70, 0x84, 0xb1, 0x5e, 0x6a, 0x01, 0x3d,
	0xf1, 0x47, 0xe4, 0x62, 0x56, 0xe4, 0xe8, 0x03,
	0xab, 0x75, 0xc1, 0x10, 0xf7, 0x78, 0x48, 0x13,
	0x6b, 0xe7, 0xd8, 0x06, 0xe8, 0xb2, 0xf8, 0x68,
	0xc1, 0x6c, 0x3a, 0x90, 0xc1, 0x44, 0x63, 0x40,
	0x70, 0x38, 0xcb, 0x7d, 0x92, 0x85, 0x07, 0x9e,
	0xf1, 0x62, 0xc6, 0xa4, 0x5c, 0xed, 0xf9, 0xc9,
	0xf0, 0x66, 0x37, 0x5c, 0x96, 0x9b, 0x5f, 0xcb,
	0xcd, 0xa3, 0x7f, 0x02, 0xaa, 0xcf, 0xf4, 0xf3,
	0x1c, 0xde, 0xd3, 0x76, 0x75, 0x70, 0x88, 0x54,
	0x26, 0xbe, 0xbd, 0x9e, 0xca, 0x87, 0x7e, 0x44,
	0x67, 0x4e, 0x9a, 0xe2, 0xf0, 0xc2, 0x4c, 0xdd,
	0x0e, 0x7e, 0x1a, 0xaf, 0x1f, 0xf2, 0xfe, 0x7f,
	0x80, 0xa1, 0xc4, 0xf5, 0x07, 0x8e, 0xb3, 0x4c,
	0xd4, 0xf0, 0x6f, 0xa9, 0x4a, 0x2d, 0x1e, 0xab,
	0x58, 0x06, 0xca, 0x43, 0xfd, 0x0f, 0x06, 0xc6,
	0x0b, 0x63, 0xd5, 0x40, 0x2b, 0x95, 0xc7, 0x0c,
	0x21, 0xea, 0x65, 0xa1, 0x51, 0xc5, 0xcf, 0xaf,
	0x82, 0x62, 0xa4, 0x6b, 0xe3, 0xc7, 0x22, 0x26,
	0x4b
};

static const uint8_t hash_data_sha3_384_out2[] = {
	0x30, 0x54, 0xd2, 0x49, 0xf9, 0x16, 0xa6, 0x03,
	0x9b, 0x2a, 0x9c, 0x3e, 0xbe, 0xc1, 0x41, 0x87,
	0x91, 0xa0, 0x60, 0x8a, 0x17, 0x0e, 0x6d, 0x36,
	0x48, 0x60, 0x35, 0xe5, 0xf9, 0x26, 0x35, 0xea,
	0xba, 0x98, 0x07, 0x2a, 0x85, 0x37, 0x3c, 0xb5,
	0x4e, 0x2a, 0xe3, 0xf9, 0x82, 0xce, 0x13, 0x2b
};

/* Excerpt from SHA3_512LongMsg.rsp */
static const uint8_t hash_data_sha3_512_in2[] = {
	0x66, 0x4e, 0xf2, 0xe3, 0xa7, 0x05, 0x9d, 0xaf,
	0x1c, 0x58, 0xca, 0xf5, 0x20, 0x08, 0xc5, 0x22,
	0x7e, 0x85, 0xcd, 0xcb, 0x83, 0xb4, 0xc5, 0x94,
	0x57, 0xf0, 0x2c, 0x50, 0x8d, 0x4f, 0x4f, 0x69,
	0xf8, 0x26, 0xbd, 0x82, 0xc0, 0xcf, 0xfc, 0x5c,
	0xb6, 0xa9, 0x7a, 0xf6, 0xe5, 0x61, 0xc6, 0xf9,
	0x69, 0x70, 0x00, 0x52, 0x85, 0xe5, 0x8f, 0x21,
	0xef, 0x65, 0x11, 0xd2, 0x6e, 0x70, 0x98, 0x89,
	0xa7, 0xe5, 0x13, 0xc4, 0x34, 0xc9, 0x0a, 0x3c,
	0xf7, 0x44, 0x8f, 0x0c, 0xae, 0xec, 0x71, 0x14,
	0xc7, 0x47, 0xb2, 0xa0, 0x75, 0x8a, 0x3b, 0x45,
	0x03, 0xa7, 0xcf, 0x0c, 0x69, 0x87, 0x3e, 0xd3,
	0x1d, 0x94, 0xdb, 0xef, 0x2b, 0x7b, 0x2f, 0x16,
	0x88, 0x30, 0xef, 0x7d, 0xa3, 0x32, 0x2c, 0x3d,
	0x3e, 0x10, 0xca, 0xfb, 0x7c, 0x2c, 0x33, 0xc8,
	0x3b, 0xbf, 0x4c, 0x46, 0xa3, 0x1d, 0xa9, 0x0c,
	0xff, 0x3b, 0xfd, 0x4c, 0xcc, 0x6e, 0xd4, 0xb3,
	0x10, 0x75, 0x84, 0x91, 0xee, 0xba, 0x60, 0x3a,
	0x76
};

static const uint8_t hash_data_sha3_512_out2[] = {
	0xe5, 0x82, 0x5f, 0xf1, 0xa3, 0xc0, 0x70, 0xd5,
	0xa5, 0x2f, 0xbb, 0xe7, 0x11, 0x85, 0x4a, 0x44,
	0x05, 0x54, 0x29, 0x5f, 0xfb, 0x7a, 0x79, 0x69,
	0xa1, 0x79, 0x08, 0xd1, 0x01, 0x63, 0xbf, 0xbe,
	0x8f, 0x1d, 0x52, 0xa6, 0x76, 0xe8, 0xa0, 0x13,
	0x7b, 0x56, 0xa1, 0x1c, 0xdf, 0x0f, 0xfb, 0xb4,
	0x56, 0xbc, 0x89, 0x9f, 0xc7, 0x27, 0xd1, 0x4b,
	0xd8, 0x88, 0x22, 0x32, 0x54, 0x9d, 0x91, 0x4e,
};

/*
 * More SHAKE test cases from
 * https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing
 * https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/shakebytetestvectors.zip
 */

/* Excerpt from SHAKE128LongMsg.rsp */
static const uint8_t hash_data_shake128_in2[] = {
	0xa6, 0xfe, 0x00, 0x06, 0x42, 0x57, 0xaa, 0x31,
	0x8b, 0x62, 0x1c, 0x5e, 0xb3, 0x11, 0xd3, 0x2b,
	0xb8, 0x00, 0x4c, 0x2f, 0xa1, 0xa9, 0x69, 0xd2,
	0x05, 0xd7, 0x17, 0x62, 0xcc, 0x5d, 0x2e, 0x63,
	0x39, 0x07, 0x99, 0x26, 0x29, 0xd1, 0xb6, 0x9d,
	0x95, 0x57, 0xff, 0x6d, 0x5e, 0x8d, 0xeb, 0x45,
	0x4a, 0xb0, 0x0f, 0x6e, 0x49, 0x7c, 0x89, 0xa4,
	0xfe, 0xa0, 0x9e, 0x25, 0x7a, 0x6f, 0xa2, 0x07,
	0x4b, 0xd8, 0x18, 0xce, 0xb5, 0x98, 0x1b, 0x3e,
	0x3f, 0xae, 0xfd, 0x6e, 0x72, 0x0f, 0x2d, 0x1e,
	0xdd, 0x9c, 0x5e, 0x4a, 0x5c, 0x51, 0xe5, 0x00,
	0x9a, 0xbf, 0x63, 0x6e, 0xd5, 0xbc, 0xa5, 0x3f,
	0xe1, 0x59, 0xc8, 0x28, 0x70, 0x14, 0xa1, 0xbd,
	0x90, 0x4f, 0x5c, 0x8a, 0x75, 0x01, 0x62, 0x5f,
	0x79, 0xac, 0x81, 0xeb, 0x61, 0x8f, 0x47, 0x8c,
	0xe2, 0x1c, 0xae, 0x66, 0x64, 0xac, 0xff, 0xb3,
	0x05, 0x72, 0xf0, 0x59, 0xe1, 0xad, 0x0f, 0xc2,
	0x91, 0x22, 0x64, 0xe8, 0xf1, 0xca, 0x52, 0xaf,
	0x26, 0xc8, 0xbf, 0x78, 0xe0, 0x9d, 0x75, 0xf3,
	0xdd, 0x9f, 0xc7, 0x34, 0xaf, 0xa8, 0x77, 0x0a,
	0xbe, 0x0b, 0xd7, 0x8c, 0x90, 0xcc, 0x2f, 0xf4,
	0x48, 0x10, 0x5f, 0xb1, 0x6d, 0xd2, 0xc5, 0xb7,
	0xed, 0xd8, 0x61, 0x1a, 0x62, 0xe5, 0x37, 0xdb,
	0x93, 0x31, 0xf5, 0x02, 0x3e, 0x16, 0xd6, 0xec,
	0x15, 0x0c, 0xc6, 0xe7, 0x06, 0xd7, 0xc7, 0xfc,
	0xbf, 0xff, 0x93, 0x0c, 0x72, 0x81, 0x83, 0x1f,
	0xd5, 0xc4, 0xaf, 0xf8, 0x6e, 0xce, 0x57, 0xed,
	0x0d, 0xb8, 0x82, 0xf5, 0x9a, 0x5f, 0xe4, 0x03,
	0x10, 0x5d, 0x05, 0x92, 0xca, 0x38, 0xa0, 0x81,
	0xfe, 0xd8, 0x49, 0x22, 0x87, 0x3f, 0x53, 0x8e,
	0xe7, 0x74, 0xf1, 0x3b, 0x8c, 0xc0, 0x9b, 0xd0,
	0x52, 0x1d, 0xb4, 0x37, 0x4a, 0xec, 0x69, 0xf4,
	0xba, 0xe6, 0xdc, 0xb6, 0x64, 0x55, 0x82, 0x2c,
	0x0b, 0x84, 0xc9, 0x1a, 0x34, 0x74, 0xff, 0xac,
	0x2a, 0xd0, 0x6f, 0x0a, 0x44, 0x23, 0xcd, 0x2c,
	0x6a, 0x49, 0xd4, 0xf0, 0xd6, 0x24, 0x2d, 0x6a,
	0x18, 0x90, 0x93, 0x7b, 0x5d, 0x98, 0x35, 0xa5,
	0xf0, 0xea, 0x5b, 0x1d, 0x01, 0x88, 0x4d, 0x22,
	0xa6, 0xc1, 0x71, 0x8e, 0x1f, 0x60, 0xb3, 0xab,
	0x5e, 0x23, 0x29, 0x47, 0xc7, 0x6e, 0xf7, 0x0b,
	0x34, 0x41, 0x71, 0x08, 0x3c, 0x68, 0x80, 0x93,
	0xb5, 0xf1, 0x47, 0x53, 0x77, 0xe3, 0x06, 0x98,
	0x63
};

static const uint8_t hash_data_shake128_out2[] = {
	0x31, 0x09, 0xd9, 0x47, 0x2c, 0xa4, 0x36, 0xe8,
	0x05, 0xc6, 0xb3, 0xdb, 0x22, 0x51, 0xa9, 0xbc
};

/* Excerpt from SHAKE256LongMsg.rsp */
static const uint8_t hash_data_shake256_in2[] = {
	0xdc, 0x5a, 0x10, 0x0f, 0xa1, 0x6d, 0xf1, 0x58,
	0x3c, 0x79, 0x72, 0x2a, 0x0d, 0x72, 0x83, 0x3d,
	0x3b, 0xf2, 0x2c, 0x10, 0x9b, 0x88, 0x89, 0xdb,
	0xd3, 0x52, 0x13, 0xc6, 0xbf, 0xce, 0x20, 0x58,
	0x13, 0xed, 0xae, 0x32, 0x42, 0x69, 0x5c, 0xfd,
	0x9f, 0x59, 0xb9, 0xa1, 0xc2, 0x03, 0xc1, 0xb7,
	0x2e, 0xf1, 0xa5, 0x42, 0x31, 0x47, 0xcb, 0x99,
	0x0b, 0x53, 0x16, 0xa8, 0x52, 0x66, 0x67, 0x58,
	0x94, 0xe2, 0x64, 0x4c, 0x3f, 0x95, 0x78, 0xce,
	0xbe, 0x45, 0x1a, 0x09, 0xe5, 0x8c, 0x53, 0x78,
	0x8f, 0xe7, 0x7a, 0x9e, 0x85, 0x09, 0x43, 0xf8,
	0xa2, 0x75, 0xf8, 0x30, 0x35, 0x4b, 0x05, 0x93,
	0xa7, 0x62, 0xba, 0xc5, 0x5e, 0x98, 0x4d, 0xb3,
	0xe0, 0x66, 0x1e, 0xca, 0x3c, 0xb8, 0x3f, 0x67,
	0xa6, 0xfb, 0x34, 0x8e, 0x61, 0x77, 0xf7, 0xde,
	0xe2, 0xdf, 0x40, 0xc4, 0x32, 0x26, 0x02, 0xf0,
	0x94, 0x95, 0x39, 0x05, 0x68, 0x1b, 0xe3, 0x95,
	0x4f, 0xe4, 0x4c, 0x4c, 0x90, 0x2c, 0x8f, 0x6b,
	0xba, 0x56, 0x5a, 0x78, 0x8b, 0x38, 0xf1, 0x34,
	0x11, 0xba, 0x76, 0xce, 0x0f, 0x9f, 0x67, 0x56,
	0xa2, 0xa2, 0x68, 0x74, 0x24, 0xc5, 0x43, 0x5a,
	0x51, 0xe6, 0x2d, 0xf7, 0xa8, 0x93, 0x4b, 0x6e,
	0x14, 0x1f, 0x74, 0xc6, 0xcc, 0xf5, 0x39, 0xe3,
	0x78, 0x2d, 0x22, 0xb5, 0x95, 0x5d, 0x3b, 0xaf,
	0x1a, 0xb2, 0xcf, 0x7b, 0x5c, 0x3f, 0x74, 0xec,
	0x2f, 0x94, 0x47, 0x34, 0x4e, 0x93, 0x79, 0x57,
	0xfd, 0x7f, 0x0b, 0xdf, 0xec, 0x56, 0xd5, 0xd2,
	0x5f, 0x61, 0xcd, 0xe1, 0x8c, 0x09, 0x86, 0xe2,
	0x44, 0xec, 0xf7, 0x80, 0xd6, 0x30, 0x7e, 0x31,
	0x31, 0x17, 0x25, 0x69, 0x48, 0xd4, 0x23, 0x0e,
	0xbb, 0x9e, 0xa6, 0x2b, 0xb3, 0x02, 0xcf, 0xe8,
	0x0d, 0x7d, 0xfe, 0xba, 0xbc, 0x4a, 0x51, 0xd7,
	0x68, 0x79, 0x67, 0xed, 0x5b, 0x41, 0x6a, 0x13,
	0x9e, 0x97, 0x4c, 0x00, 0x5f, 0xff, 0x50, 0x7a,
	0x96
};

static const uint8_t hash_data_shake256_out2[] = {
	0x2b, 0xac, 0x57, 0x16, 0x80, 0x3a, 0x9c, 0xda,
	0x8f, 0x9e, 0x84, 0x36, 0x5a, 0xb0, 0xa6, 0x81,
	0x32, 0x7b, 0x5b, 0xa3, 0x4f, 0xde, 0xdf, 0xb1,
	0xc1, 0x2e, 0x6e, 0x80, 0x7f, 0x45, 0x28, 0x4b,
};

/*
 * SM3
 * https://tools.ietf.org/html/draft-sca-cfrg-sm3-02
 * Appendix A.1
 */
#if __has_attribute(nonstring)
__attribute__((nonstring))
#endif
static const uint8_t hash_data_sm3_a1_in[3] = "abc";

static const uint8_t hash_data_sm3_a1_out[] = {
	0x66, 0xc7, 0xf0, 0xf4, 0x62, 0xee, 0xed, 0xd9,
	0xd1, 0xf2, 0xd4, 0x6b, 0xdc, 0x10, 0xe4, 0xe2,
	0x41, 0x67, 0xc4, 0x87, 0x5c, 0xf2, 0xf7, 0xa2,
	0x29, 0x7d, 0xa0, 0x2b, 0x8f, 0x4b, 0xa8, 0xe0
};

/*
 * SM3
 * https://tools.ietf.org/html/draft-sca-cfrg-sm3-02
 * Appendix A.2
 */
static const uint8_t hash_data_sm3_a2_in[] = {
	0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
	0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
	0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
	0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
	0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
	0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
	0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
	0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64
};

static const uint8_t hash_data_sm3_a2_out[] = {
	0xde, 0xbe, 0x9f, 0xf9, 0x22, 0x75, 0xb8, 0xa1,
	0x38, 0x60, 0x48, 0x89, 0xc1, 0x8e, 0x5a, 0x4d,
	0x6f, 0xdb, 0x70, 0xe5, 0x38, 0x7e, 0x57, 0x65,
	0x29, 0x3d, 0xcb, 0xa3, 0x9c, 0x0c, 0x57, 0x32
};

struct xtest_hash_case {
	uint32_t algo;
	size_t in_incr;
	const uint8_t *in;
	size_t in_len;
	const uint8_t *out;
	size_t out_len;
};

#define XTEST_HASH_CASE(algo, in_incr, in, out) \
	{ (algo), (in_incr), (in), ARRAY_SIZE(in), (out), ARRAY_SIZE(out) }

static const struct xtest_hash_case hash_cases[] = {
	XTEST_HASH_CASE(TEE_ALG_MD5, 6, hash_data_md5_in1,
			hash_data_md5_out1),
	XTEST_HASH_CASE(TEE_ALG_SHA1, 3, hash_data_sha1_in1,
			hash_data_sha1_out1),
	XTEST_HASH_CASE(TEE_ALG_SHA224, 7, hash_data_sha224_in1,
			hash_data_sha224_out1),
	XTEST_HASH_CASE(TEE_ALG_SHA256, 1, hash_data_sha256_in1,
			hash_data_sha256_out1),
	XTEST_HASH_CASE(TEE_ALG_SHA256, 1, hash_data_sha256_in2,
			hash_data_sha256_out2),
	XTEST_HASH_CASE(TEE_ALG_SHA384, 1, hash_data_sha384_in1,
			hash_data_sha384_out1),
	XTEST_HASH_CASE(TEE_ALG_SHA512, 1, hash_data_sha512_in1,
			hash_data_sha512_out1),
	XTEST_HASH_CASE(TEE_ALG_SHA3_224, 1, hash_data_sha3_in1,
			hash_data_sha3_224_out1),
	XTEST_HASH_CASE(TEE_ALG_SHA3_224, 4, hash_data_sha3_224_in2,
			hash_data_sha3_224_out2),
	XTEST_HASH_CASE(TEE_ALG_SHA3_256, 1, hash_data_sha3_in1,
			hash_data_sha3_256_out1),
	XTEST_HASH_CASE(TEE_ALG_SHA3_256, 4, hash_data_sha3_256_in2,
			hash_data_sha3_256_out2),
	XTEST_HASH_CASE(TEE_ALG_SHA3_384, 1, hash_data_sha3_in1,
			hash_data_sha3_384_out1),
	XTEST_HASH_CASE(TEE_ALG_SHA3_384, 4, hash_data_sha3_384_in2,
			hash_data_sha3_384_out2),
	XTEST_HASH_CASE(TEE_ALG_SHA3_512, 1, hash_data_sha3_in1,
			hash_data_sha3_512_out1),
	XTEST_HASH_CASE(TEE_ALG_SHA3_512, 4, hash_data_sha3_512_in2,
			hash_data_sha3_512_out2),
	XTEST_HASH_CASE(TEE_ALG_SHAKE128, 1, hash_data_sha3_in1,
			hash_data_shake128_out1),
	XTEST_HASH_CASE(TEE_ALG_SHAKE128, 4, hash_data_shake128_in2,
			hash_data_shake128_out2),
	XTEST_HASH_CASE(TEE_ALG_SHAKE256, 1, hash_data_sha3_in1,
			hash_data_shake256_out1),
	XTEST_HASH_CASE(TEE_ALG_SHAKE256, 4, hash_data_shake256_in2,
			hash_data_shake256_out2),
	XTEST_HASH_CASE(TEE_ALG_SM3, 2, hash_data_sm3_a1_in,
			hash_data_sm3_a1_out),
	XTEST_HASH_CASE(TEE_ALG_SM3, 19, hash_data_sm3_a2_in,
			hash_data_sm3_a2_out),
};

static void xtest_tee_test_4001(ADBG_Case_t *c)
{
	TEEC_Session session = { };
	uint32_t ret_orig = 0;
	size_t n = 0;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		xtest_teec_open_session(&session, &crypt_user_ta_uuid, NULL,
					&ret_orig)))
		return;


	for (n = 0; n < ARRAY_SIZE(hash_cases); n++) {
		TEE_OperationHandle op1 = TEE_HANDLE_NULL;
		TEE_OperationHandle op2 = TEE_HANDLE_NULL;
		uint8_t out[64] = { };
		size_t out_size = 0;

		if (hash_cases[n].algo == TEE_ALG_SM3 &&
		    !ta_crypt_cmd_is_algo_supported(c, &session, TEE_ALG_SM3,
						    TEE_CRYPTO_ELEMENT_NONE)) {
		    Do_ADBG_Log("SM3 not supported: skip subcase");
		    continue;
		}

		Do_ADBG_BeginSubCase(c, "Hash case %d algo 0x%x",
				     (int)n, (unsigned int)hash_cases[n].algo);

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_allocate_operation(c, &session, &op1,
							hash_cases[n].algo,
							TEE_MODE_DIGEST, 0)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_allocate_operation(c, &session, &op2,
							hash_cases[n].algo,
							TEE_MODE_DIGEST, 0)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_digest_update(c, &session, op1,
						   hash_cases[n].in,
						   hash_cases[n].in_incr)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_copy_operation(c, &session, op2, op1)))
			goto out;

		out_size = hash_cases[n].out_len;
		memset(out, 0, sizeof(out));
		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_digest_do_final(c, &session, op2,
				hash_cases[n].in + hash_cases[n].in_incr,
				hash_cases[n].in_len - hash_cases[n].in_incr,
				out, &out_size)))
			goto out;

		(void)ADBG_EXPECT_BUFFER(c, hash_cases[n].out,
					 hash_cases[n].out_len, out, out_size);

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_reset_operation(c, &session, op1)))
			goto out;

		out_size = hash_cases[n].out_len;
		memset(out, 0, sizeof(out));
		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_digest_do_final(c, &session, op1,
						     hash_cases[n].in,
						     hash_cases[n].in_len, out,
						     &out_size)))
			goto out;

		(void)ADBG_EXPECT_BUFFER(c, hash_cases[n].out,
					 hash_cases[n].out_len, out, out_size);

		/*
		 * Invoke TEE_DigestDoFinal() a second time to check that state
		 * was properly reset
		 */
		out_size = hash_cases[n].out_len;
		memset(out, 0, sizeof(out));
		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_digest_do_final(c, &session, op1,
						     hash_cases[n].in,
						     hash_cases[n].in_len, out,
						     &out_size)))
			goto out;

		(void)ADBG_EXPECT_BUFFER(c, hash_cases[n].out,
					 hash_cases[n].out_len, out, out_size);

		/*
		 * Test that TEE_DigestExtract() and TEE_DigestDoFinal()
		 * work together.
		 */

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_digest_update(c, &session, op1,
						   hash_cases[n].in,
						   hash_cases[n].in_len)))
			goto out;

		out_size = hash_cases[n].in_incr;
		memset(out, 0, sizeof(out));
		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_digest_extract(c, &session, op1,
						    out, &out_size)))
			goto out;
		ADBG_EXPECT_BUFFER(c, hash_cases[n].out,
				   hash_cases[n].in_incr, out, out_size);

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_copy_operation(c, &session, op2, op1)))
			goto out;

		out_size = hash_cases[n].out_len - hash_cases[n].in_incr;
		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_digest_do_final(c, &session, op1,
						     NULL, 0, out, &out_size)))
			goto out;
		ADBG_EXPECT_BUFFER(c, hash_cases[n].out + hash_cases[n].in_incr,
				   hash_cases[n].out_len -
					hash_cases[n].in_incr, out, out_size);

		out_size = hash_cases[n].out_len - hash_cases[n].in_incr;
		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_digest_extract(c, &session, op2,
						    out, &out_size)))
			goto out;
		ADBG_EXPECT_BUFFER(c, hash_cases[n].out + hash_cases[n].in_incr,
				   hash_cases[n].out_len -
					hash_cases[n].in_incr, out, out_size);

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_free_operation(c, &session, op1)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_free_operation(c, &session, op2)))
			goto out;

		Do_ADBG_EndSubCase(c, NULL);
	}

out:
	TEEC_CloseSession(&session);
}
ADBG_CASE_DEFINE(regression, 4001, xtest_tee_test_4001,
		"Test TEE Internal API hash operations");

struct xtest_mac_case {
	uint32_t algo;
	uint32_t key_type;
	const uint8_t *key;
	size_t key_len;
	size_t in_incr;
	const uint8_t *in;
	size_t in_len;
	const uint8_t *out;
	size_t out_len;
	bool multiple_incr;
};

#define XTEST_MAC_CASE_1(algo, key_type, key, in_incr, in, out) \
	{ (algo), (key_type), (key), ARRAY_SIZE(key), \
	  (in_incr), (in), ARRAY_SIZE(in), (out), ARRAY_SIZE(out), false }

#define XTEST_MAC_CASE_MULT(algo, key_type, key, in_incr, in, out) \
	{ (algo), (key_type), (key), ARRAY_SIZE(key), \
	  (in_incr), (in), ARRAY_SIZE(in), (out), ARRAY_SIZE(out), true }

#define XTEST_MAC_CASE(algo, key_type, key, in_incr, in, out) \
	XTEST_MAC_CASE_1((algo), (key_type), (key), (in_incr), (in), (out)), \
	XTEST_MAC_CASE_MULT((algo), (key_type), (key), (in_incr), (in), (out))

#define XTEST_MAC_CBC_CASE(algo, key_type, vect, in_incr) \
	XTEST_MAC_CASE((algo), (key_type), \
		       mac_cbc_ ## vect ## _key, (in_incr), \
		       mac_cbc_ ## vect ## _data, mac_cbc_ ## vect ## _out)

#define XTEST_MAC_CMAC_CASE(vect, in_incr) \
	XTEST_MAC_CASE(TEE_ALG_AES_CMAC, TEE_TYPE_AES, \
		       mac_cmac_ ## vect ## _key, (in_incr), \
		       mac_cmac_ ## vect ## _data, mac_cmac_ ## vect ## _out)

#define XTEST_MAC_DES3_CMAC_CASE(vect, in_incr) \
	XTEST_MAC_CASE(TEE_ALG_DES3_CMAC, TEE_TYPE_DES3, \
			mac_des3_cmac_ ## vect ## _key, (in_incr), \
			mac_des3_cmac_ ## vect ## _data, mac_des3_cmac_ ## vect ## _out)

static const struct xtest_mac_case mac_cases[] = {
	XTEST_MAC_CASE(TEE_ALG_HMAC_MD5, TEE_TYPE_HMAC_MD5,
		       mac_data_md5_key1,
		       4, mac_data_md5_in1, mac_data_md5_out1),
	XTEST_MAC_CASE(TEE_ALG_HMAC_SHA1, TEE_TYPE_HMAC_SHA1,
		       mac_data_sha1_key1,
		       5, mac_data_sha1_in1, mac_data_sha1_out1),
	XTEST_MAC_CASE(TEE_ALG_HMAC_SHA224, TEE_TYPE_HMAC_SHA224,
		       mac_data_sha224_key1,
		       8, mac_data_sha224_in1, mac_data_sha224_out1),
	XTEST_MAC_CASE(TEE_ALG_HMAC_SHA256, TEE_TYPE_HMAC_SHA256,
		       mac_data_sha256_key1,
		       1, mac_data_sha256_in1, mac_data_sha256_out1),
	XTEST_MAC_CASE(TEE_ALG_HMAC_SHA256, TEE_TYPE_HMAC_SHA256,
		       mac_data_sha256_key2,
		       7, mac_data_sha256_in2, mac_data_sha256_out2),
	XTEST_MAC_CASE(TEE_ALG_HMAC_SHA384, TEE_TYPE_HMAC_SHA384,
		       mac_data_sha384_key1,
		       11, mac_data_sha384_in1, mac_data_sha384_out1),
	XTEST_MAC_CASE(TEE_ALG_HMAC_SHA512, TEE_TYPE_HMAC_SHA512,
		       mac_data_sha512_key1,
		       13, mac_data_sha512_in1, mac_data_sha512_out1),
	XTEST_MAC_CASE(TEE_ALG_HMAC_SHA3_224, TEE_TYPE_HMAC_SHA3_224,
		       mac_data_sha3_224_key1,
		       13, mac_data_sha3_224_in1, mac_data_sha3_224_out1),
	XTEST_MAC_CASE(TEE_ALG_HMAC_SHA3_256, TEE_TYPE_HMAC_SHA3_256,
		       mac_data_sha3_256_key1,
		       13, mac_data_sha3_256_in1, mac_data_sha3_256_out1),
	XTEST_MAC_CASE(TEE_ALG_HMAC_SHA3_384, TEE_TYPE_HMAC_SHA3_384,
		       mac_data_sha3_384_key1,
		       13, mac_data_sha3_384_in1, mac_data_sha3_384_out1),
	XTEST_MAC_CASE(TEE_ALG_HMAC_SHA3_512, TEE_TYPE_HMAC_SHA3_512,
		       mac_data_sha3_512_key1,
		       13, mac_data_sha3_512_in1, mac_data_sha3_512_out1),

	XTEST_MAC_CBC_CASE(TEE_ALG_AES_CBC_MAC_NOPAD, TEE_TYPE_AES, vect1, 14),
	XTEST_MAC_CBC_CASE(TEE_ALG_DES_CBC_MAC_NOPAD, TEE_TYPE_DES, vect2, 16),
	XTEST_MAC_CBC_CASE(TEE_ALG_DES3_CBC_MAC_NOPAD, TEE_TYPE_DES3, vect3,
			   17),
	XTEST_MAC_CBC_CASE(TEE_ALG_AES_CBC_MAC_PKCS5, TEE_TYPE_AES, vect4, 11),
	XTEST_MAC_CBC_CASE(TEE_ALG_DES_CBC_MAC_PKCS5, TEE_TYPE_DES, vect5, 9),
	XTEST_MAC_CBC_CASE(TEE_ALG_DES3_CBC_MAC_PKCS5, TEE_TYPE_DES3, vect6, 4),
	XTEST_MAC_CBC_CASE(TEE_ALG_AES_CBC_MAC_PKCS5, TEE_TYPE_AES, vect7, 3),
	XTEST_MAC_CBC_CASE(TEE_ALG_DES_CBC_MAC_PKCS5, TEE_TYPE_DES, vect8, 23),
	XTEST_MAC_CBC_CASE(TEE_ALG_DES3_CBC_MAC_PKCS5, TEE_TYPE_DES3, vect9,
			   34),
	XTEST_MAC_CBC_CASE(TEE_ALG_DES3_CBC_MAC_PKCS5, TEE_TYPE_DES3, vect10, 4),

	{ TEE_ALG_AES_CMAC, TEE_TYPE_AES, mac_cmac_vect1_key,
	  ARRAY_SIZE(mac_cmac_vect1_key), 0, NULL, 0, mac_cmac_vect1_out,
	  ARRAY_SIZE(mac_cmac_vect1_out) },
	XTEST_MAC_CMAC_CASE(vect2, 9),
	XTEST_MAC_CMAC_CASE(vect3, 9),
	XTEST_MAC_CMAC_CASE(vect4, 9),
	{ TEE_ALG_AES_CMAC, TEE_TYPE_AES, mac_cmac_vect5_key,
	  ARRAY_SIZE(mac_cmac_vect5_key), 0, NULL, 0, mac_cmac_vect5_out,
	  ARRAY_SIZE(mac_cmac_vect5_out) },
	XTEST_MAC_CMAC_CASE(vect6, 9),
	XTEST_MAC_CMAC_CASE(vect7, 9),
	XTEST_MAC_CMAC_CASE(vect8, 9),
	{ TEE_ALG_AES_CMAC, TEE_TYPE_AES, mac_cmac_vect9_key,
	  ARRAY_SIZE(mac_cmac_vect9_key), 0, NULL, 0, mac_cmac_vect9_out,
	  ARRAY_SIZE(mac_cmac_vect9_out) },
	XTEST_MAC_CMAC_CASE(vect10, 9),
	XTEST_MAC_CMAC_CASE(vect11, 9),
	XTEST_MAC_CMAC_CASE(vect12, 9),
	XTEST_MAC_CMAC_CASE(vect12, 16),
	XTEST_MAC_CMAC_CASE(vect13, 1),

	{ TEE_ALG_DES3_CMAC, TEE_TYPE_DES3, mac_des3_cmac_vect1_key,
	  ARRAY_SIZE(mac_des3_cmac_vect1_key), 0, NULL, 0, mac_des3_cmac_vect1_out,
	  ARRAY_SIZE(mac_des3_cmac_vect1_out) },
	XTEST_MAC_DES3_CMAC_CASE(vect2, 3),
	XTEST_MAC_DES3_CMAC_CASE(vect3, 9),
	XTEST_MAC_DES3_CMAC_CASE(vect4, 9),
	{ TEE_ALG_DES3_CMAC, TEE_TYPE_DES3, mac_des3_cmac_vect5_key,
	  ARRAY_SIZE(mac_des3_cmac_vect5_key), 0, NULL, 0, mac_des3_cmac_vect5_out,
	  ARRAY_SIZE(mac_des3_cmac_vect5_out) },
	XTEST_MAC_DES3_CMAC_CASE(vect6, 3),
	XTEST_MAC_DES3_CMAC_CASE(vect7, 5),
	XTEST_MAC_DES3_CMAC_CASE(vect8, 9),

	XTEST_MAC_CASE(TEE_ALG_HMAC_SM3, TEE_TYPE_HMAC_SM3,
		       mac_data_sm3_d31_key,
		       13, mac_data_sm3_d31_in, mac_data_sm3_d31_out),
	XTEST_MAC_CASE(TEE_ALG_HMAC_SM3, TEE_TYPE_HMAC_SM3,
		       mac_data_sm3_d32_key,
		       13, mac_data_sm3_d32_in, mac_data_sm3_d32_out),
};

static void xtest_tee_test_4002(ADBG_Case_t *c)
{
	TEEC_Session session = { };
	TEE_OperationHandle op1 = TEE_HANDLE_NULL;
	TEE_OperationHandle op2 = TEE_HANDLE_NULL;
	TEE_OperationHandle op3 = TEE_HANDLE_NULL;
	TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
	uint8_t out[64] = { };
	size_t out_size = 0;
	uint32_t ret_orig = 0;
	size_t n = 0;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		xtest_teec_open_session(&session, &crypt_user_ta_uuid, NULL,
					&ret_orig)))
		return;

	for (n = 0; n < ARRAY_SIZE(mac_cases); n++) {
		TEE_Attribute key_attr = { };
		size_t key_size = 0;
		size_t offs = 0;

		if (mac_cases[n].algo == TEE_ALG_HMAC_SM3 &&
		    !ta_crypt_cmd_is_algo_supported(c, &session,
						    TEE_ALG_HMAC_SM3,
						    TEE_CRYPTO_ELEMENT_NONE)) {
			Do_ADBG_Log("SM3 not supported: skip subcase");
			continue;
		}

		Do_ADBG_BeginSubCase(c, "MAC case %d algo 0x%x",
				     (int)n, (unsigned int)mac_cases[n].algo);

		key_attr.attributeID = TEE_ATTR_SECRET_VALUE;
		key_attr.content.ref.buffer = (void *)mac_cases[n].key;
		key_attr.content.ref.length = mac_cases[n].key_len;

		key_size = key_attr.content.ref.length * 8;
		if (mac_cases[n].key_type == TEE_TYPE_DES ||
		    mac_cases[n].key_type == TEE_TYPE_DES3)
			/* Exclude parity in bit size of key */
			key_size -= key_size / 8;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_allocate_operation(c, &session, &op1,
				mac_cases[n].algo, TEE_MODE_MAC, key_size)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_allocate_operation(c, &session, &op2,
				mac_cases[n].algo, TEE_MODE_MAC, key_size)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_allocate_operation(c, &session, &op3,
				mac_cases[n].algo, TEE_MODE_MAC, key_size)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_allocate_transient_object(c, &session,
				mac_cases[n].key_type, key_size, &key_handle)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_populate_transient_object(c, &session,
				key_handle, &key_attr, 1)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_set_operation_key(c, &session, op1,
				key_handle)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_free_transient_object(c, &session,
				key_handle)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_mac_init(c, &session, op1, NULL, 0)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_copy_operation(c, &session, op3, op1)))
			goto out;

		offs = 0;
		if (mac_cases[n].in != NULL) {
			while (offs + mac_cases[n].in_incr <
					mac_cases[n].in_len) {
				if (!ADBG_EXPECT_TEEC_SUCCESS(c,
					ta_crypt_cmd_mac_update(c, &session,
						op1, mac_cases[n].in + offs,
						mac_cases[n].in_incr)))
					goto out;
				offs += mac_cases[n].in_incr;
				if (!mac_cases[n].multiple_incr)
					break;
			}
		}

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_copy_operation(c, &session, op2, op1)))
			goto out;

		out_size = sizeof(out);
		memset(out, 0, sizeof(out));
		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_mac_final_compute(c, &session, op2,
				mac_cases[n].in + offs,
				mac_cases [n].in_len - offs,
				out, &out_size)))
			goto out;

		(void)ADBG_EXPECT_BUFFER(c, mac_cases[n].out,
					 mac_cases[n].out_len, out, out_size);

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_mac_init(c, &session, op1, NULL, 0)))
			goto out;

		out_size = sizeof(out);
		memset(out, 0, sizeof(out));
		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_mac_final_compute(c, &session, op1,
				mac_cases[n].in, mac_cases[n].in_len, out,
				&out_size)))
			goto out;

		(void)ADBG_EXPECT_BUFFER(c, mac_cases[n].out,
					 mac_cases[n].out_len, out, out_size);

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_mac_final_compare(c, &session, op3,
				mac_cases[n].in, mac_cases[n].in_len,
				mac_cases[n].out, mac_cases[n].out_len)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_free_operation(c, &session, op1)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_free_operation(c, &session, op2)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_free_operation(c, &session, op3)))
			goto out;

		Do_ADBG_EndSubCase(c, NULL);
	}
out:
	TEEC_CloseSession(&session);
}
ADBG_CASE_DEFINE(regression, 4002, xtest_tee_test_4002,
		"Test TEE Internal API MAC operations");

static const uint8_t ciph_data_aes_key1[] = {
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, /* 01234567 */
	0x38, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, /* 89ABCDEF */
};

static const uint8_t ciph_data_aes_key2[] = {
	0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
	0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
};

static const uint8_t ciph_data_des_key1[] = {
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37 /* 01234567 */
};

static const uint8_t ciph_data_des_key2[] = {
	0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1
};


static const uint8_t ciph_data_des3_key1[] = {
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, /* 01234567 */
	0x38, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, /* 89ABCDEF */
	0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, /* 12345678 */
};

static const uint8_t ciph_data_des3_key2[] = {
	0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1,
	0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1,
	0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1
};

static const uint8_t ciph_data_des2_key1[] = {
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, /* 01234567 */
	0x38, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, /* 89ABCDEF */
};

static const uint8_t ciph_data_in1[] = {
	0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, /* 23456789 */
	0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x30, 0x31, /* ABCDEF01 */
	0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x41, /* 3456789A */
	0x42, 0x43, 0x44, 0x45, 0x46, 0x30, 0x31, 0x32, /* BCDEF012 */
	0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x41, 0x42, /* 456789AB */
	0x43, 0x44, 0x45, 0x46, 0x30, 0x31, 0x32, 0x33, /* CDEF0123 */
};

static const uint8_t ciph_data_in3[] = {
	0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, /* 23456789 */
	0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x30, 0x31, /* ABCDEF01 */
	0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x41, /* 3456789A */
	0x42, 0x43, 0x44, 0x45, 0x46, 0x30, 0x31, 0x32, /* BCDEF012 */
	0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x41, 0x42, /* 456789AB */
	0x43, 0x44, 0x45, 0x46, 0x30,                   /* CDEF0    */
};

static const uint8_t ciph_data_in4[] = {
	0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, /* 23456789 */
	0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x30, 0x31, /* ABCDEF01 */
	0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x41, /* 3456789A */
	0x42, 0x43, 0x44, 0x45, 0x46, 0x30, 0x31, 0x32, /* BCDEF012 */
	0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x41, 0x42, /* 456789AB */
	0x43, 0x44, 0x45, 0x46, 0x30, 0x31, 0x32, 0x33, /* CDEF0123 */
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, /* 01234567 */
	0x38, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, /* 89ABCDEF */
};

static const uint8_t ciph_data_in5[] = {
	0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	0x01, 0x01, 0x01
};

static const uint8_t ciph_data_128_iv1[] = {
	0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, /* 12345678 */
	0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x30, /* 9ABCDEF0 */
};

static const uint8_t ciph_data_128_iv2[] = {
	0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
	0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
};

static const uint8_t ciph_data_64_iv1[] = {
	0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, /* 12345678 */
};

static const uint8_t ciph_data_in2[] = {
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
};

static const uint8_t ciph_data_aes_ecb_nopad_out1[] = {
	0xA5, 0xBE, 0x14, 0xD5, 0x01, 0x05, 0x24, 0x48, /* ......$H */
	0x58, 0x1A, 0x6B, 0x82, 0xD4, 0x41, 0xD2, 0xB3, /* X.k..A.. */
	0xBB, 0xF9, 0xAE, 0x37, 0x94, 0xAC, 0x18, 0x50, /* ...7...P */
	0x87, 0x09, 0xCC, 0x3F, 0x43, 0xD2, 0xC2, 0xB7, /* ...?C... */
	0xD7, 0x6F, 0x84, 0x07, 0xB4, 0x78, 0xCE, 0x34, /* .o...x.4 */
	0x48, 0xC9, 0x16, 0x86, 0x42, 0xB8, 0xFF, 0xCF, /* H...B... */
};

static const uint8_t ciph_data_aes_cbc_nopad_out1[] = {
	0x8D, 0x9F, 0x88, 0xD8, 0xAF, 0x9F, 0xC1, 0x3B, /* .......; */
	0x02, 0x15, 0x43, 0x6A, 0x8C, 0x1E, 0x34, 0x5C, /* ..Cj..4\ */
	0x83, 0xF4, 0x85, 0x3E, 0x43, 0x0F, 0xE5, 0x5F, /* ...>C.._ */
	0x81, 0x4C, 0xC0, 0x28, 0x3F, 0xD9, 0x98, 0x53, /* .L.(?..S */
	0xB1, 0x44, 0x51, 0x38, 0x21, 0xAB, 0x10, 0xCE, /* .DQ8!... */
	0xC2, 0xEC, 0x65, 0x54, 0xDD, 0x5C, 0xEA, 0xDC, /* ..eT.\.. */
};

static const uint8_t ciph_data_aes_ctr_out1[] = {
	0xD2, 0xDD, 0x11, 0xA8, 0xF7, 0xB0, 0xAE, 0x55, /* .......U */
	0xBE, 0x61, 0x7A, 0xE6, 0xA1, 0x6C, 0x79, 0xF4, /* .az..ly. */
	0x62, 0x51, 0x7B, 0xE9, 0x7C, 0xA0, 0x31, 0x0C, /* bQ{.|.1. */
	0x24, 0x15, 0x70, 0x7F, 0x47, 0x37, 0x69, 0xE0, /* $.p.G7i. */
	0x24, 0xC3, 0x29, 0xCD, 0xF2, 0x26, 0x69, 0xFF, /* $.)..&i. */
	0x72, 0x0E, 0x3C, 0xD1, 0xA1, 0x2F, 0x5D, 0x33, /* r.<../]3 */
};

static const uint8_t ciph_data_aes_ctr_out2[] = {
	0xD2, 0xDD, 0x11, 0xA8, 0xF7, 0xB0, 0xAE, 0x55, /* .......U */
	0xBE, 0x61, 0x7A, 0xE6, 0xA1, 0x6C, 0x79, 0xF4, /* .az..ly. */
	0x62, 0x51, 0x7B, 0xE9, 0x7C, 0xA0, 0x31, 0x0C, /* bQ{.|.1. */
	0x24, 0x15, 0x70, 0x7F, 0x47, 0x37, 0x69, 0xE0, /* $.p.G7i. */
	0x24, 0xC3, 0x29, 0xCD, 0xF2, 0x26, 0x69, 0xFF, /* $.)..&i. */
	0x72, 0x0E, 0x3C, 0xD1, 0xA1,                   /* r.<..    */
};

static const uint8_t ciph_data_aes_ctr_out4[] = {
	0xD2, 0xDD, 0x11, 0xA8, 0xF7, 0xB0, 0xAE, 0x55, /* .......U */
	0xBE, 0x61, 0x7A, 0xE6, 0xA1, 0x6C, 0x79, 0xF4, /* .az..ly. */
	0x62, 0x51, 0x7B, 0xE9, 0x7C, 0xA0, 0x31, 0x0C, /* bQ{.|.1. */
	0x24, 0x15, 0x70, 0x7F, 0x47, 0x37, 0x69, 0xE0, /* $.p.G7i. */
	0x24, 0xC3, 0x29, 0xCD, 0xF2, 0x26, 0x69, 0xFF, /* $.)..&i. */
	0x72, 0x0E, 0x3C, 0xD1, 0xA1, 0x2F, 0x5D, 0x33, /* r.<../]3 */
	0x9F, 0xD7, 0x0C, 0x92, 0xD4, 0xA5, 0x9D, 0x06, /* ........ */
	0x01, 0x80, 0x38, 0xCD, 0xC2, 0x71, 0x5D, 0x4A, /* ..8..q]J */
};

static const uint8_t ciph_data_aes_ctr_out5[] = {
	0xbb, 0xfe, 0x07, 0x04, 0x1c, 0x8e, 0x09, 0x61,
	0xfb, 0xb1, 0x7c, 0xa5, 0x4d, 0x2b, 0x30, 0xf6,
	0x26, 0x9e, 0xff, 0x61, 0x18, 0x47, 0xc6, 0x06,
	0x81, 0x02, 0x84, 0xcd, 0x9c, 0x4b, 0x6d, 0x21,
	0xe2, 0x64, 0xa6, 0x50, 0x7f, 0x28, 0x81, 0x6f,
	0x29, 0xda, 0xd5, 0x56, 0x3f, 0x46, 0xac, 0xca,
	0x37, 0xe7, 0x77, 0x36, 0xbc, 0x76, 0x39, 0x57,
	0xaa, 0x67, 0x1b, 0x2a, 0xe6, 0x36, 0x57, 0x6d,
	0x2a, 0xb8, 0x77, 0x41, 0xc2, 0x4e, 0x4f, 0x27,
	0x4c, 0x34, 0x7a, 0x01, 0x6a, 0xda, 0x75, 0x75,
	0x3e, 0x68, 0xb2
};

static const uint8_t ciph_data_aes_cbc_vect1_key[] = {
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, /* 01234567 */
	0x38, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, /* 89ABCDEF */
};

static const uint8_t ciph_data_aes_cbc_vect1_iv[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
};

static const uint8_t ciph_data_aes_cbc_vect1_ptx[] = {
	0x43, 0x69, 0x70, 0x68, 0x65, 0x72, 0x20, 0x62, /* Cipher b */
	0x6C, 0x6F, 0x63, 0x6B, 0x20, 0x63, 0x68, 0x61, /* lock cha */
	0x69, 0x6E, 0x69, 0x6E, 0x67, 0x20, 0x28, 0x43, /* ining (C */
	0x42, 0x43, 0x29, 0x20, 0x69, 0x73, 0x20, 0x61, /* BC) is a */
	0x20, 0x63, 0x6F, 0x6D, 0x6D, 0x6F, 0x6E, 0x20, /*  common  */
	0x63, 0x68, 0x61, 0x69, 0x6E, 0x69, 0x6E, 0x67, /* chaining */
	0x20, 0x6D, 0x6F, 0x64, 0x65, 0x20, 0x69, 0x6E, /*  mode in */
	0x20, 0x77, 0x68, 0x69, 0x63, 0x68, 0x20, 0x74, /*  which t */
	0x68, 0x65, 0x20, 0x70, 0x72, 0x65, 0x76, 0x69, /* he previ */
	0x6F, 0x75, 0x73, 0x20, 0x62, 0x6C, 0x6F, 0x63, /* ous bloc */
	0x6B, 0x27, 0x73, 0x20, 0x63, 0x69, 0x70, 0x68, /* k's ciph */
	0x65, 0x72, 0x74, 0x65, 0x78, 0x74, 0x20, 0x69, /* ertext i */
	0x73, 0x20, 0x78, 0x6F, 0x72, 0x65, 0x64, 0x20, /* s xored  */
	0x77, 0x69, 0x74, 0x68, 0x20, 0x74, 0x68, 0x65, /* with the */
	0x20, 0x63, 0x75, 0x72, 0x72, 0x65, 0x6E, 0x74, /*  current */
	0x20, 0x62, 0x6C, 0x6F, 0x63, 0x6B, 0x27, 0x73, /*  block's */
	0x20, 0x70, 0x6C, 0x61, 0x69, 0x6E, 0x74, 0x65, /*  plainte */
	0x78, 0x74, 0x20, 0x62, 0x65, 0x66, 0x6F, 0x72, /* xt befor */
	0x65, 0x20, 0x65, 0x6E, 0x63, 0x72, 0x79, 0x70, /* e encryp */
	0x74, 0x69, 0x6F, 0x6E, 0x2E, 0x2E, 0x2E, 0x2E, /* tion.... */
};

static const uint8_t ciph_data_aes_cbc_vect1_ctx[] = {
	0xDD, 0x16, 0xC3, 0x47, 0x69, 0xEC, 0xF5, 0x86, /* ...Gi... */
	0x20, 0xB4, 0xF7, 0xE3, 0xB9, 0x36, 0xE8, 0xAC, /*  ....6.. */
	0xC9, 0xA2, 0x11, 0x71, 0x3B, 0x10, 0x9D, 0x45, /* ...q;..E */
	0xCA, 0xE2, 0x49, 0xA6, 0x4E, 0x56, 0x07, 0xC5, /* ..I.NV.. */
	0xCE, 0xA3, 0x14, 0xB5, 0x30, 0x1B, 0x63, 0xBB, /* ....0.c. */
	0x2D, 0x6F, 0xE9, 0xCA, 0x0B, 0x00, 0x31, 0x3F, /* -o....1? */
	0xA4, 0x9A, 0x39, 0xE1, 0xC8, 0xD2, 0x24, 0x95, /* ..9...$. */
	0x14, 0xE9, 0xD2, 0x43, 0xE8, 0xA8, 0x1E, 0x0A, /* ...C.... */
	0xFE, 0x9D, 0x4F, 0xF5, 0xBB, 0x16, 0xB9, 0x54, /* ..O....T */
	0x78, 0x07, 0x94, 0x05, 0x8E, 0x47, 0xC3, 0xCB, /* x....G.. */
	0x7C, 0xEC, 0xF4, 0xF8, 0xF2, 0xA4, 0x59, 0x6E, /* |.....Yn */
	0xED, 0xAD, 0x7F, 0x62, 0xAF, 0x89, 0xA8, 0x5B, /* ...b...[ */
	0x75, 0xD4, 0x73, 0xE3, 0xBA, 0x9F, 0x9A, 0xD2, /* u.s..... */
	0x0F, 0xFD, 0x3C, 0xE6, 0xC6, 0xA4, 0xD6, 0x6C, /* ..<....l */
	0x6A, 0x09, 0xE2, 0x16, 0xB0, 0x8C, 0x69, 0x3C, /* j.....i< */
	0xC8, 0x1C, 0xE4, 0x3E, 0x86, 0x4D, 0xB0, 0x2B, /* ...>.M.+ */
	0x29, 0xA0, 0x5A, 0xA3, 0x67, 0xBA, 0xDC, 0x11, /* ).Z.g... */
	0x08, 0x5E, 0x69, 0xB4, 0x6F, 0xA5, 0xE2, 0xB8, /* .^i.o... */
	0xC9, 0x6E, 0x83, 0x7E, 0x35, 0xC8, 0xA7, 0xA0, /* .n.~5... */
	0x33, 0xA3, 0xB1, 0x4B, 0x5A, 0x92, 0x51, 0x2E, /* 3..KZ.Q. */
};

/* AES-CTS test vectors from http://tools.ietf.org/html/rfc3962
 * and http://tools.ietf.org/html/draft-raeburn-krb-rijndael-krb-02 */
static const uint8_t ciph_data_aes_cts_vect1_key[] = {
	0x63, 0x68, 0x69, 0x63, 0x6b, 0x65, 0x6e, 0x20,
	0x74, 0x65, 0x72, 0x69, 0x79, 0x61, 0x6b, 0x69
};

static const uint8_t ciph_data_aes_cts_vect1_iv[16] = {
	0x00
};

static const uint8_t ciph_data_aes_cts_vect1_ptx[] = {
	0x49, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20,
	0x6c, 0x69, 0x6b, 0x65, 0x20, 0x74, 0x68, 0x65,
	0x20
};

static const uint8_t ciph_data_aes_cts_vect1_ctx[] = {
	0xc6, 0x35, 0x35, 0x68, 0xf2, 0xbf, 0x8c, 0xb4,
	0xd8, 0xa5, 0x80, 0x36, 0x2d, 0xa7, 0xff, 0x7f,
	0x97
};

#define ciph_data_aes_cts_vect2_key ciph_data_aes_cts_vect1_key
#define ciph_data_aes_cts_vect2_iv ciph_data_aes_cts_vect1_iv
static const uint8_t ciph_data_aes_cts_vect2_ptx[] = {
	0x49, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20,
	0x6c, 0x69, 0x6b, 0x65, 0x20, 0x74, 0x68, 0x65,
	0x20, 0x47, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x6c,
	0x20, 0x47, 0x61, 0x75, 0x27, 0x73, 0x20
};

static const uint8_t ciph_data_aes_cts_vect2_ctx[] = {
	0xfc, 0x00, 0x78, 0x3e, 0x0e, 0xfd, 0xb2, 0xc1,
	0xd4, 0x45, 0xd4, 0xc8, 0xef, 0xf7, 0xed, 0x22,
	0x97, 0x68, 0x72, 0x68, 0xd6, 0xec, 0xcc, 0xc0,
	0xc0, 0x7b, 0x25, 0xe2, 0x5e, 0xcf, 0xe5
};

#define ciph_data_aes_cts_vect3_key ciph_data_aes_cts_vect1_key
#define ciph_data_aes_cts_vect3_iv ciph_data_aes_cts_vect1_iv
static const uint8_t ciph_data_aes_cts_vect3_ptx[] = {
	0x49, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20,
	0x6c, 0x69, 0x6b, 0x65, 0x20, 0x74, 0x68, 0x65,
	0x20, 0x47, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x6c,
	0x20, 0x47, 0x61, 0x75, 0x27, 0x73, 0x20, 0x43,
};

static const uint8_t ciph_data_aes_cts_vect3_ctx[] = {
	0x39, 0x31, 0x25, 0x23, 0xa7, 0x86, 0x62, 0xd5,
	0xbe, 0x7f, 0xcb, 0xcc, 0x98, 0xeb, 0xf5, 0xa8,
	0x97, 0x68, 0x72, 0x68, 0xd6, 0xec, 0xcc, 0xc0,
	0xc0, 0x7b, 0x25, 0xe2, 0x5e, 0xcf, 0xe5, 0x84,
};

#define ciph_data_aes_cts_vect4_key ciph_data_aes_cts_vect1_key
#define ciph_data_aes_cts_vect4_iv ciph_data_aes_cts_vect1_iv
static const uint8_t ciph_data_aes_cts_vect4_ptx[] = {
	0x49, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20,
	0x6c, 0x69, 0x6b, 0x65, 0x20, 0x74, 0x68, 0x65,
	0x20, 0x47, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x6c,
	0x20, 0x47, 0x61, 0x75, 0x27, 0x73, 0x20, 0x43,
	0x68, 0x69, 0x63, 0x6b, 0x65, 0x6e, 0x2c, 0x20,
	0x70, 0x6c, 0x65, 0x61, 0x73, 0x65, 0x2c,
};

static const uint8_t ciph_data_aes_cts_vect4_ctx[] = {
	0x97, 0x68, 0x72, 0x68, 0xd6, 0xec, 0xcc, 0xc0,
	0xc0, 0x7b, 0x25, 0xe2, 0x5e, 0xcf, 0xe5, 0x84,
	0xb3, 0xff, 0xfd, 0x94, 0x0c, 0x16, 0xa1, 0x8c,
	0x1b, 0x55, 0x49, 0xd2, 0xf8, 0x38, 0x02, 0x9e,
	0x39, 0x31, 0x25, 0x23, 0xa7, 0x86, 0x62, 0xd5,
	0xbe, 0x7f, 0xcb, 0xcc, 0x98, 0xeb, 0xf5,
};

#define ciph_data_aes_cts_vect5_key ciph_data_aes_cts_vect1_key
#define ciph_data_aes_cts_vect5_iv ciph_data_aes_cts_vect1_iv
static const uint8_t ciph_data_aes_cts_vect5_ptx[] = {
	0x49, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20,
	0x6c, 0x69, 0x6b, 0x65, 0x20, 0x74, 0x68, 0x65,
	0x20, 0x47, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x6c,
	0x20, 0x47, 0x61, 0x75, 0x27, 0x73, 0x20, 0x43,
	0x68, 0x69, 0x63, 0x6b, 0x65, 0x6e, 0x2c, 0x20,
	0x70, 0x6c, 0x65, 0x61, 0x73, 0x65, 0x2c, 0x20,
};

static const uint8_t ciph_data_aes_cts_vect5_ctx[] = {
	0x97, 0x68, 0x72, 0x68, 0xd6, 0xec, 0xcc, 0xc0,
	0xc0, 0x7b, 0x25, 0xe2, 0x5e, 0xcf, 0xe5, 0x84,
	0x9d, 0xad, 0x8b, 0xbb, 0x96, 0xc4, 0xcd, 0xc0,
	0x3b, 0xc1, 0x03, 0xe1, 0xa1, 0x94, 0xbb, 0xd8,
	0x39, 0x31, 0x25, 0x23, 0xa7, 0x86, 0x62, 0xd5,
	0xbe, 0x7f, 0xcb, 0xcc, 0x98, 0xeb, 0xf5, 0xa8,
};

#define ciph_data_aes_cts_vect6_key ciph_data_aes_cts_vect1_key
#define ciph_data_aes_cts_vect6_iv ciph_data_aes_cts_vect1_iv
static const uint8_t ciph_data_aes_cts_vect6_ptx[] = {
	0x49, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20,
	0x6c, 0x69, 0x6b, 0x65, 0x20, 0x74, 0x68, 0x65,
	0x20, 0x47, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x6c,
	0x20, 0x47, 0x61, 0x75, 0x27, 0x73, 0x20, 0x43,
	0x68, 0x69, 0x63, 0x6b, 0x65, 0x6e, 0x2c, 0x20,
	0x70, 0x6c, 0x65, 0x61, 0x73, 0x65, 0x2c, 0x20,
	0x61, 0x6e, 0x64, 0x20, 0x77, 0x6f, 0x6e, 0x74,
	0x6f, 0x6e, 0x20, 0x73, 0x6f, 0x75, 0x70, 0x2e,
};

static const uint8_t ciph_data_aes_cts_vect6_ctx[] = {
	0x97, 0x68, 0x72, 0x68, 0xd6, 0xec, 0xcc, 0xc0,
	0xc0, 0x7b, 0x25, 0xe2, 0x5e, 0xcf, 0xe5, 0x84,
	0x39, 0x31, 0x25, 0x23, 0xa7, 0x86, 0x62, 0xd5,
	0xbe, 0x7f, 0xcb, 0xcc, 0x98, 0xeb, 0xf5, 0xa8,
	0x48, 0x07, 0xef, 0xe8, 0x36, 0xee, 0x89, 0xa5,
	0x26, 0x73, 0x0d, 0xbc, 0x2f, 0x7b, 0xc8, 0x40,
	0x9d, 0xad, 0x8b, 0xbb, 0x96, 0xc4, 0xcd, 0xc0,
	0x3b, 0xc1, 0x03, 0xe1, 0xa1, 0x94, 0xbb, 0xd8,
};

/*
 * Test case for https://github.com/OP-TEE/optee_os/issues/1203
 * 80 bytes of data, processed in two steps (32 + 48).
 */

#define ciph_data_aes_cts_issue1203_key ciph_data_aes_cts_vect1_key

static const uint8_t ciph_data_aes_cts_issue1203_iv[] = {
	0x5b, 0x11, 0x7b, 0xf9, 0x83, 0x6a, 0x01, 0x27,
	0x1d, 0x2a, 0xae, 0x0a, 0xd3, 0x27, 0x35, 0x81,
};

static const uint8_t ciph_data_aes_cts_issue1203_ptx[] = {
	0x33, 0x2a, 0xf4, 0x8c, 0x18, 0xa1, 0x30, 0x7c,
	0xa7, 0x52, 0x76, 0xca, 0xa6, 0x68, 0xad, 0xf6,
	0x1e, 0xba, 0xc9, 0x66, 0x66, 0x52, 0x1a, 0xe7,
	0x3e, 0xbc, 0xba, 0x60, 0x95, 0x71, 0x04, 0x5e,
	0xb4, 0xb7, 0x10, 0xd7, 0x93, 0x6d, 0x5f, 0x9a,
	0xb8, 0xbb, 0x6b, 0xb0, 0x6d, 0x47, 0x93, 0x41,
	0x29, 0x21, 0xf2, 0x84, 0xf5, 0xb2, 0xf2, 0x6d,
	0xbe, 0xe5, 0x8a, 0x2b, 0x58, 0x8d, 0x1b, 0x5e,
	0x41, 0x04, 0xba, 0x9e, 0x92, 0xe9, 0x52, 0xb6,
	0x8b, 0x1e, 0x36, 0x72, 0x91, 0xe4, 0x56, 0x66,
};

/*
 * Ciphertext was generated by an online tool for AES CBC.
 * Since the input size is a multiple of the block size, and the ciphertext
 * format is CS3, the output is the same as plain AES CBC with the last
 * two blocks swapped.
 */
static const uint8_t ciph_data_aes_cts_issue1203_ctx[] = {
	0x6c, 0xfe, 0xef, 0x6a, 0x1c, 0x8f, 0xd3, 0xc3,
	0x66, 0xc4, 0xd9, 0x0e, 0xbe, 0x24, 0x17, 0x3f,
	0xcd, 0x19, 0xc9, 0xd2, 0x10, 0x3f, 0xcf, 0xdc,
	0xe9, 0x05, 0xab, 0xd5, 0x1a, 0x31, 0x41, 0x77,
	0x3b, 0xd7, 0x6a, 0x26, 0xae, 0x0d, 0xc9, 0x47,
	0x77, 0xd4, 0xa7, 0xd5, 0x73, 0x88, 0x9e, 0xde,
	0x72, 0x66, 0xe0, 0xe2, 0x3d, 0x62, 0x91, 0x22,
	0xae, 0x11, 0x01, 0x97, 0x22, 0x6a, 0x45, 0xa9,
	0xba, 0x56, 0xd2, 0xbc, 0x55, 0x2d, 0x99, 0x4d,
	0x3d, 0x22, 0x27, 0x9a, 0xac, 0x66, 0x2f, 0xf5,
};

static const uint8_t ciph_data_des_ecb_nopad_out1[] = {
	0x46, 0x2B, 0x91, 0xA8, 0x55, 0xE6, 0x7E, 0x75, /* F+..U.~u */
	0x5E, 0x53, 0xF4, 0x8F, 0x29, 0x41, 0x4E, 0xEF, /* ^S..)AN. */
	0x32, 0x1B, 0x58, 0x42, 0x9B, 0xB4, 0x3A, 0x1F, /* 2.XB..:. */
	0x9A, 0xEA, 0xA4, 0xB4, 0xCD, 0xE9, 0x87, 0x7C, /* .......| */
	0xC0, 0x05, 0x34, 0xED, 0x86, 0x3C, 0x2A, 0x81, /* ..4..<.. */
	0x5E, 0x93, 0x0E, 0x86, 0xA9, 0xBB, 0x80, 0xFF, /* ^....... */
};

static const uint8_t ciph_data_des_ecb_nopad_out2[] = {
	0x85, 0xE8, 0x13, 0x54, 0x0F, 0x0A, 0xB4, 0x05
};

static const uint8_t ciph_data_des_cbc_nopad_out1[] = {
	0xAD, 0xD6, 0xD6, 0x3E, 0x88, 0xD0, 0xDD, 0xD4, /* ...>.... */
	0x9A, 0x93, 0x95, 0xA0, 0x86, 0x22, 0x5B, 0x9E, /* ....."[. */
	0x84, 0x0C, 0x6F, 0x12, 0x04, 0x11, 0x6F, 0xD4, /* ..o...o. */
	0x12, 0x29, 0xC6, 0x78, 0x0C, 0xFB, 0x58, 0x5B, /* .).x..X[ */
	0x66, 0x82, 0x0E, 0x52, 0xDC, 0x25, 0x16, 0x51, /* f..R.%.Q */
	0x69, 0xDF, 0xFE, 0x4E, 0x11, 0x1D, 0x9D, 0x08, /* i..N.... */
};

static const uint8_t ciph_data_des3_ecb_nopad_out1[] = {
	0xA7, 0x46, 0xEC, 0xA8, 0x6A, 0x7F, 0x4A, 0xF1, /* .F..j.J. */
	0x44, 0x60, 0x37, 0x3B, 0x7F, 0x76, 0xE5, 0xFF, /* D`7;.v.. */
	0xC1, 0xE7, 0xA5, 0x04, 0x9C, 0x29, 0x5C, 0xA5, /* .....)\. */
	0xDD, 0xC8, 0xEE, 0x36, 0x1F, 0x48, 0xE0, 0xA9, /* ...6.H.. */
	0x82, 0x2D, 0x53, 0x84, 0x49, 0x69, 0x78, 0xFA, /* .-S.Iix. */
	0x23, 0x69, 0x1D, 0xF7, 0x08, 0x38, 0x44, 0x05, /* #i...8D. */
};

static const uint8_t ciph_data_des3_cbc_nopad_out1[] = {
	0x18, 0x09, 0xEB, 0x98, 0xE4, 0x58, 0x72, 0x11, /* .....Xr. */
	0x30, 0x58, 0xAB, 0x38, 0xB0, 0xC9, 0x2B, 0xED, /* 0X.8..+. */
	0xDA, 0xC5, 0xE8, 0xA9, 0xF6, 0x8A, 0xA7, 0x80, /* ........ */
	0xBE, 0x54, 0x1F, 0x63, 0xF6, 0xEE, 0xA2, 0x4C, /* .T.c...L */
	0x7C, 0xEB, 0x84, 0x7D, 0xDA, 0xCA, 0x1E, 0xB2, /* |..}.... */
	0xED, 0x5E, 0x96, 0xB8, 0x01, 0x4B, 0x77, 0x02, /* .^...Kw. */
};

static const uint8_t ciph_data_des2_ecb_nopad_out1[] = {
	0xAB, 0x12, 0xB6, 0xE2, 0x4A, 0x3A, 0x26, 0x14, /* ....J:&. */
	0xF0, 0x7D, 0x23, 0xD0, 0x55, 0xDF, 0x5C, 0x16, /* .}#.U.\. */
	0x43, 0x59, 0x1E, 0x44, 0x01, 0x76, 0xD7, 0x50, /* CY.D.v.P */
	0x44, 0xC0, 0x15, 0xDF, 0x2E, 0x7F, 0x8B, 0xC5, /* D....... */
	0xFF, 0x8B, 0x87, 0xFE, 0x33, 0xD7, 0xCB, 0x2C, /* ....3.., */
	0xDA, 0x79, 0x6F, 0xA4, 0x05, 0x2B, 0x30, 0xCE, /* .yo..+0. */
};

static const uint8_t ciph_data_des2_cbc_nopad_out1[] = {
	0x47, 0x2F, 0xB1, 0x83, 0xC4, 0xBB, 0x93, 0x16, /* G/...... */
	0x73, 0xF9, 0xAD, 0x6F, 0x00, 0xF9, 0xCB, 0x4A, /* s..o...J */
	0x0F, 0x4F, 0x75, 0x75, 0xFB, 0x39, 0x0B, 0xFC, /* .Ouu.9.. */
	0x9F, 0x48, 0x52, 0xAD, 0xA2, 0x75, 0x2C, 0xF1, /* .HR..u, . */
	0x7D, 0xC3, 0x8F, 0x16, 0xCF, 0xC9, 0x76, 0x29, /* }.....v) */
	0x1A, 0xBF, 0xB3, 0xD9, 0x10, 0x7E, 0xAA, 0x49, /* .....~.I */
};

/* SM4 ECB */

static const uint8_t ciph_data_sm4_key1[] = {
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
	0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
};

static const uint8_t ciph_data_sm4_in1[] = {
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
	0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
};

static const uint8_t ciph_data_sm4_ecb_nopad_out1[] = {
	0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e,
	0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46,
};

/*
 * SM4 CBC
 * https://tools.ietf.org/html/draft-ribose-cfrg-sm4-10#appendix-A.2.2.1
 */
static const uint8_t ciph_data_sm4_cbc_a221_key[] = {
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
	0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
};

static const uint8_t ciph_data_sm4_cbc_a221_iv[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};

static const uint8_t ciph_data_sm4_cbc_a221_in[] = {
	0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xbb, 0xbb,
	0xcc, 0xcc, 0xcc, 0xcc, 0xdd, 0xdd, 0xdd, 0xdd,
	0xee, 0xee, 0xee, 0xee, 0xff, 0xff, 0xff, 0xff,
	0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xbb, 0xbb,
};

static const uint8_t ciph_data_sm4_cbc_a221_out[] = {
	0x78, 0xeb, 0xb1, 0x1c, 0xc4, 0x0b, 0x0a, 0x48,
	0x31, 0x2a, 0xae, 0xb2, 0x04, 0x02, 0x44, 0xcb,
	0x4c, 0xb7, 0x01, 0x69, 0x51, 0x90, 0x92, 0x26,
	0x97, 0x9b, 0x0d, 0x15, 0xdc, 0x6a, 0x8f, 0x6d,
};

/*
 * SM4 CBC
 * https://tools.ietf.org/html/draft-ribose-cfrg-sm4-10#appendix-A.2.2.2
 */
static const uint8_t ciph_data_sm4_cbc_a222_key[] = {
	0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
};

static const uint8_t ciph_data_sm4_cbc_a222_iv[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};

static const uint8_t ciph_data_sm4_cbc_a222_in[] = {
	0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xbb, 0xbb,
	0xcc, 0xcc, 0xcc, 0xcc, 0xdd, 0xdd, 0xdd, 0xdd,
	0xee, 0xee, 0xee, 0xee, 0xff, 0xff, 0xff, 0xff,
	0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xbb, 0xbb,
};

static const uint8_t ciph_data_sm4_cbc_a222_out[] = {
	0x0d, 0x3a, 0x6d, 0xdc, 0x2d, 0x21, 0xc6, 0x98,
	0x85, 0x72, 0x15, 0x58, 0x7b, 0x7b, 0xb5, 0x9a,
	0x91, 0xf2, 0xc1, 0x47, 0x91, 0x1a, 0x41, 0x44,
	0x66, 0x5e, 0x1f, 0xa1, 0xd4, 0x0b, 0xae, 0x38,
};

/*
 * SM4 CTR
 * https://tools.ietf.org/html/draft-ribose-cfrg-sm4-10#appendix-A.2.5.1
 */
static const uint8_t ciph_data_sm4_ctr_a251_key[] = {
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
	0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
};

static const uint8_t ciph_data_sm4_ctr_a251_iv[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};

static const uint8_t ciph_data_sm4_ctr_a251_in[] = {
	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
	0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
	0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
	0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
};

static const uint8_t ciph_data_sm4_ctr_a251_out[] = {
	0xac, 0x32, 0x36, 0xcb, 0x97, 0x0c, 0xc2, 0x07,
	0x91, 0x36, 0x4c, 0x39, 0x5a, 0x13, 0x42, 0xd1,
	0xa3, 0xcb, 0xc1, 0x87, 0x8c, 0x6f, 0x30, 0xcd,
	0x07, 0x4c, 0xce, 0x38, 0x5c, 0xdd, 0x70, 0xc7,
	0xf2, 0x34, 0xbc, 0x0e, 0x24, 0xc1, 0x19, 0x80,
	0xfd, 0x12, 0x86, 0x31, 0x0c, 0xe3, 0x7b, 0x92,
	0x6e, 0x02, 0xfc, 0xd0, 0xfa, 0xa0, 0xba, 0xf3,
	0x8b, 0x29, 0x33, 0x85, 0x1d, 0x82, 0x45, 0x14,
};

/*
 * SM4 CTR
 * https://tools.ietf.org/html/draft-ribose-cfrg-sm4-10#appendix-A.2.5.2
 */
static const uint8_t ciph_data_sm4_ctr_a252_key[] = {
	0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
};

static const uint8_t ciph_data_sm4_ctr_a252_iv[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};

static const uint8_t ciph_data_sm4_ctr_a252_in[] = {
	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
	0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
	0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
	0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
};

static const uint8_t ciph_data_sm4_ctr_a252_out[] = {
	0x5d, 0xcc, 0xcd, 0x25, 0xb9, 0x5a, 0xb0, 0x74,
	0x17, 0xa0, 0x85, 0x12, 0xee, 0x16, 0x0e, 0x2f,
	0x8f, 0x66, 0x15, 0x21, 0xcb, 0xba, 0xb4, 0x4c,
	0xc8, 0x71, 0x38, 0x44, 0x5b, 0xc2, 0x9e, 0x5c,
	0x0a, 0xe0, 0x29, 0x72, 0x05, 0xd6, 0x27, 0x04,
	0x17, 0x3b, 0x21, 0x23, 0x9b, 0x88, 0x7f, 0x6c,
	0x8c, 0xb5, 0xb8, 0x00, 0x91, 0x7a, 0x24, 0x88,
	0x28, 0x4b, 0xde, 0x9e, 0x16, 0xea, 0x29, 0x06,
};

struct xtest_ciph_case {
	uint32_t algo;
	uint32_t mode;
	uint32_t key_type;
	const uint8_t *key1;
	size_t key1_len;
	const uint8_t *key2;
	size_t key2_len;
	const uint8_t *iv;
	size_t iv_len;
	size_t in_incr;
	const uint8_t *in;
	size_t in_len;
	const uint8_t *out;
	size_t out_len;
	size_t line;
};

#define XTEST_CIPH_CASE_NO_IV(algo, key_type, key, in_incr, ptx, ctx) \
	{ (algo), TEE_MODE_ENCRYPT, (key_type), (key), ARRAY_SIZE(key), \
	  NULL, 0, NULL, 0, \
	  (in_incr), (ptx), ARRAY_SIZE(ptx), (ctx), ARRAY_SIZE(ctx), \
	  __LINE__ }, \
	{ (algo), TEE_MODE_DECRYPT, (key_type), (key), ARRAY_SIZE(key), \
	  NULL, 0, NULL, 0, \
	  (in_incr), (ctx), ARRAY_SIZE(ctx), (ptx), ARRAY_SIZE(ptx), __LINE__ }

#define XTEST_CIPH_CASE(algo, key_type, key, iv, in_incr, ptx, ctx) \
	{ (algo), TEE_MODE_ENCRYPT, (key_type), (key), ARRAY_SIZE(key), \
	  NULL, 0, iv, ARRAY_SIZE(iv), (in_incr), (ptx), ARRAY_SIZE(ptx), \
	  (ctx), ARRAY_SIZE(ctx), __LINE__ }, \
	{ (algo), TEE_MODE_DECRYPT, (key_type), (key), ARRAY_SIZE(key), \
	  NULL, 0, iv, ARRAY_SIZE(iv), (in_incr), (ctx), ARRAY_SIZE(ctx),  \
	  (ptx), ARRAY_SIZE(ptx), __LINE__ }

#define XTEST_CIPH_CASE_AES_XTS(vect, in_incr) \
	{ TEE_ALG_AES_XTS, TEE_MODE_ENCRYPT, TEE_TYPE_AES, \
	  ciph_data_aes_xts_ ## vect ## _key1, \
	  ARRAY_SIZE(ciph_data_aes_xts_ ## vect ## _key1), \
	  ciph_data_aes_xts_ ## vect ## _key2, \
	  ARRAY_SIZE(ciph_data_aes_xts_ ## vect ## _key2), \
	  ciph_data_aes_xts_ ## vect ## _iv, \
	  ARRAY_SIZE(ciph_data_aes_xts_ ## vect ## _iv), \
	  (in_incr), \
	  ciph_data_aes_xts_ ## vect ## _ptx, \
	  ARRAY_SIZE(ciph_data_aes_xts_ ## vect ## _ptx), \
	  ciph_data_aes_xts_ ## vect ## _ctx, \
	  ARRAY_SIZE(ciph_data_aes_xts_ ## vect ## _ctx), __LINE__ }, \
	{ TEE_ALG_AES_XTS, TEE_MODE_DECRYPT, TEE_TYPE_AES, \
	  ciph_data_aes_xts_ ## vect ## _key1, \
	  ARRAY_SIZE(ciph_data_aes_xts_ ## vect ## _key1), \
	  ciph_data_aes_xts_ ## vect ## _key2, \
	  ARRAY_SIZE(ciph_data_aes_xts_ ## vect ## _key2), \
	  ciph_data_aes_xts_ ## vect ## _iv, \
	  ARRAY_SIZE(ciph_data_aes_xts_ ## vect ## _iv), \
	  (in_incr), \
	  ciph_data_aes_xts_ ## vect ## _ctx, \
	  ARRAY_SIZE(ciph_data_aes_xts_ ## vect ## _ctx), \
	  ciph_data_aes_xts_ ## vect ## _ptx, \
	  ARRAY_SIZE(ciph_data_aes_xts_ ## vect ## _ptx), __LINE__ }

#define XTEST_CIPH_CASE_AES_CBC(vect, in_incr) \
	XTEST_CIPH_CASE(TEE_ALG_AES_CBC_NOPAD, TEE_TYPE_AES, \
			ciph_data_aes_cbc_ ## vect ## _key, \
			ciph_data_aes_cbc_ ## vect ## _iv, \
			(in_incr), ciph_data_aes_cbc_ ## vect ## _ptx, \
			ciph_data_aes_cbc_ ## vect ## _ctx)

#define XTEST_CIPH_CASE_AES_CTS(vect, in_incr) \
	XTEST_CIPH_CASE(TEE_ALG_AES_CTS, TEE_TYPE_AES, \
			ciph_data_aes_cts_ ## vect ## _key, \
			ciph_data_aes_cts_ ## vect ## _iv, \
			(in_incr), ciph_data_aes_cts_ ## vect ## _ptx, \
			ciph_data_aes_cts_ ## vect ## _ctx)

static const struct xtest_ciph_case ciph_cases[] = {
	/* AES */
	XTEST_CIPH_CASE_NO_IV(TEE_ALG_AES_ECB_NOPAD, TEE_TYPE_AES,
			      ciph_data_aes_key1, 11, ciph_data_in1,
			      ciph_data_aes_ecb_nopad_out1),
	XTEST_CIPH_CASE(TEE_ALG_AES_CBC_NOPAD, TEE_TYPE_AES,
			ciph_data_aes_key1, ciph_data_128_iv1, 11,
			ciph_data_in1,
			ciph_data_aes_cbc_nopad_out1),
	XTEST_CIPH_CASE(TEE_ALG_AES_CTR, TEE_TYPE_AES,
			ciph_data_aes_key1, ciph_data_128_iv1, 13,
			ciph_data_in1,
			ciph_data_aes_ctr_out1),
	XTEST_CIPH_CASE(TEE_ALG_AES_CTR, TEE_TYPE_AES,
			ciph_data_aes_key1, ciph_data_128_iv1, 13,
			ciph_data_in3,
			ciph_data_aes_ctr_out2),
	XTEST_CIPH_CASE(TEE_ALG_AES_CTR, TEE_TYPE_AES,
			ciph_data_aes_key1, ciph_data_128_iv1, 16,
			ciph_data_in3,
			ciph_data_aes_ctr_out2),
	XTEST_CIPH_CASE(TEE_ALG_AES_CTR, TEE_TYPE_AES,
			ciph_data_aes_key1, ciph_data_128_iv1, 16,
			ciph_data_in4,
			ciph_data_aes_ctr_out4),
	XTEST_CIPH_CASE(TEE_ALG_AES_CTR, TEE_TYPE_AES,
			ciph_data_aes_key2, ciph_data_128_iv2, 11,
			ciph_data_in5,
			ciph_data_aes_ctr_out5),

	XTEST_CIPH_CASE_AES_CBC(vect1, 11),
	XTEST_CIPH_CASE_AES_CBC(vect1, 64),

	/* AES-CTS */
	XTEST_CIPH_CASE_AES_CTS(vect1, 13),
	XTEST_CIPH_CASE_AES_CTS(vect2, 14),
	XTEST_CIPH_CASE_AES_CTS(vect3, 11),
	XTEST_CIPH_CASE_AES_CTS(vect4, 9),
	XTEST_CIPH_CASE_AES_CTS(vect5, 7),
	XTEST_CIPH_CASE_AES_CTS(vect6, 17),
	XTEST_CIPH_CASE_AES_CTS(vect6, 0x20),
	XTEST_CIPH_CASE_AES_CTS(issue1203, 32),

	/* DES */
	XTEST_CIPH_CASE_NO_IV(TEE_ALG_DES_ECB_NOPAD, TEE_TYPE_DES,
			      ciph_data_des_key1, 14, ciph_data_in1,
			      ciph_data_des_ecb_nopad_out1),
	XTEST_CIPH_CASE_NO_IV(TEE_ALG_DES_ECB_NOPAD, TEE_TYPE_DES,
			      ciph_data_des_key2, 3, ciph_data_in2,
			      ciph_data_des_ecb_nopad_out2),
	XTEST_CIPH_CASE(TEE_ALG_DES_CBC_NOPAD, TEE_TYPE_DES,
			ciph_data_des_key1, ciph_data_64_iv1, 15, ciph_data_in1,
			ciph_data_des_cbc_nopad_out1),

	/* DES3 */
	XTEST_CIPH_CASE_NO_IV(TEE_ALG_DES3_ECB_NOPAD, TEE_TYPE_DES3,
			      ciph_data_des3_key1, 11, ciph_data_in1,
			      ciph_data_des3_ecb_nopad_out1),
	XTEST_CIPH_CASE_NO_IV(TEE_ALG_DES3_ECB_NOPAD, TEE_TYPE_DES3,
			      ciph_data_des3_key2, 3, ciph_data_in2,
			      ciph_data_des_ecb_nopad_out2),
	XTEST_CIPH_CASE(TEE_ALG_DES3_CBC_NOPAD, TEE_TYPE_DES3,
			ciph_data_des3_key1, ciph_data_64_iv1, 11,
			ciph_data_in1,
			ciph_data_des3_cbc_nopad_out1),

	/* DES2 */
	XTEST_CIPH_CASE_NO_IV(TEE_ALG_DES3_ECB_NOPAD, TEE_TYPE_DES3,
			      ciph_data_des2_key1, 11, ciph_data_in1,
			      ciph_data_des2_ecb_nopad_out1),
	XTEST_CIPH_CASE(TEE_ALG_DES3_CBC_NOPAD, TEE_TYPE_DES3,
			ciph_data_des2_key1, ciph_data_64_iv1, 11,
			ciph_data_in1,
			ciph_data_des2_cbc_nopad_out1),

	/* AES-XTS */
	XTEST_CIPH_CASE_AES_XTS(vect1, 3),
	XTEST_CIPH_CASE_AES_XTS(vect2, 6),
	XTEST_CIPH_CASE_AES_XTS(vect3, 7),
	XTEST_CIPH_CASE_AES_XTS(vect4, 8),
	XTEST_CIPH_CASE_AES_XTS(vect5, 9),
	XTEST_CIPH_CASE_AES_XTS(vect6, 13),
	XTEST_CIPH_CASE_AES_XTS(vect7, 1),
	XTEST_CIPH_CASE_AES_XTS(vect8, 3),
	XTEST_CIPH_CASE_AES_XTS(vect9, 2),
	XTEST_CIPH_CASE_AES_XTS(vect10, 5),
	XTEST_CIPH_CASE_AES_XTS(vect11, 6),
	XTEST_CIPH_CASE_AES_XTS(vect12, 7),
	XTEST_CIPH_CASE_AES_XTS(vect13, 3),
	XTEST_CIPH_CASE_AES_XTS(vect14, 2),
	XTEST_CIPH_CASE_AES_XTS(vect15, 0),
	XTEST_CIPH_CASE_AES_XTS(vect16, 9),
	XTEST_CIPH_CASE_AES_XTS(vect17, 6),
	XTEST_CIPH_CASE_AES_XTS(vect18, 8),
	XTEST_CIPH_CASE_AES_XTS(vect19, 23),

	/* SM4 */
	XTEST_CIPH_CASE_NO_IV(TEE_ALG_SM4_ECB_NOPAD, TEE_TYPE_SM4,
			      ciph_data_sm4_key1, 11, ciph_data_sm4_in1,
			      ciph_data_sm4_ecb_nopad_out1),
	XTEST_CIPH_CASE(TEE_ALG_SM4_CBC_NOPAD, TEE_TYPE_SM4,
			ciph_data_sm4_cbc_a221_key, ciph_data_sm4_cbc_a221_iv,
			11, ciph_data_sm4_cbc_a221_in,
			ciph_data_sm4_cbc_a221_out),
	XTEST_CIPH_CASE(TEE_ALG_SM4_CBC_NOPAD, TEE_TYPE_SM4,
			ciph_data_sm4_cbc_a222_key, ciph_data_sm4_cbc_a222_iv,
			11, ciph_data_sm4_cbc_a222_in,
			ciph_data_sm4_cbc_a222_out),
	XTEST_CIPH_CASE(TEE_ALG_SM4_CTR, TEE_TYPE_SM4,
			ciph_data_sm4_ctr_a251_key, ciph_data_sm4_ctr_a251_iv,
			11, ciph_data_sm4_ctr_a251_in,
			ciph_data_sm4_ctr_a251_out),
	XTEST_CIPH_CASE(TEE_ALG_SM4_CTR, TEE_TYPE_SM4,
			ciph_data_sm4_ctr_a252_key, ciph_data_sm4_ctr_a252_iv,
			11, ciph_data_sm4_ctr_a252_in,
			ciph_data_sm4_ctr_a252_out),
};

static void xtest_tee_test_4003(ADBG_Case_t *c)
{
	TEEC_Session session = { };
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	TEE_OperationHandle op2 = TEE_HANDLE_NULL;
	TEE_ObjectHandle key1_handle = TEE_HANDLE_NULL;
	TEE_ObjectHandle key2_handle = TEE_HANDLE_NULL;
	uint8_t out[2048] = { };
	size_t out_size = 0;
	size_t out_offs = 0;
	size_t out_offs2 = 0;
	uint32_t ret_orig = 0;
	size_t n = 0;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		xtest_teec_open_session(&session, &crypt_user_ta_uuid, NULL,
					&ret_orig)))
		return;

	for (n = 0; n < ARRAY_SIZE(ciph_cases); n++) {
		TEE_Attribute key_attr = { };
		size_t key_size = 0;
		size_t op_key_size = 0;

		switch (ciph_cases[n].algo) {
		case TEE_ALG_SM4_CTR:
		case TEE_ALG_SM4_CBC_NOPAD:
		case TEE_ALG_SM4_ECB_NOPAD:
			if (!ta_crypt_cmd_is_algo_supported(c, &session,
				ciph_cases[n].algo, TEE_CRYPTO_ELEMENT_NONE)) {
				Do_ADBG_Log("SM4 not supported: skip subcase");
				continue;
			}
			break;
		default:
			break;
		}

		Do_ADBG_BeginSubCase(c, "Cipher case %d algo 0x%x line %d",
				     (int)n, (unsigned int)ciph_cases[n].algo,
				     (int)ciph_cases[n].line);

		key_attr.attributeID = TEE_ATTR_SECRET_VALUE;
		key_attr.content.ref.buffer = (void *)ciph_cases[n].key1;
		key_attr.content.ref.length = ciph_cases[n].key1_len;

		key_size = key_attr.content.ref.length * 8;
		if (ciph_cases[n].key_type == TEE_TYPE_DES ||
		    ciph_cases[n].key_type == TEE_TYPE_DES3)
			/* Exclude parity in bit size of key */
			key_size -= key_size / 8;

		op_key_size = key_size;
		if (ciph_cases[n].key2 != NULL)
			op_key_size *= 2;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_allocate_operation(c, &session, &op,
				ciph_cases[n].algo, ciph_cases[n].mode,
				op_key_size)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_allocate_operation(c, &session, &op2,
				ciph_cases[n].algo, ciph_cases[n].mode,
				op_key_size)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_allocate_transient_object(c, &session,
				ciph_cases[n].key_type, key_size,
				&key1_handle)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_populate_transient_object(c, &session,
				key1_handle, &key_attr, 1)))
			goto out;

		if (ciph_cases[n].key2 != NULL) {
			key_attr.content.ref.buffer =
				(void *)ciph_cases[n].key2;
			key_attr.content.ref.length = ciph_cases[n].key2_len;

			if (!ADBG_EXPECT_TEEC_SUCCESS(c,
				ta_crypt_cmd_allocate_transient_object(c,
					&session, ciph_cases[n].key_type,
					key_attr.content.ref.length * 8,
					&key2_handle)))
				goto out;

			if (!ADBG_EXPECT_TEEC_SUCCESS(c,
				ta_crypt_cmd_populate_transient_object(c,
					&session, key2_handle, &key_attr, 1)))
				goto out;

			if (!ADBG_EXPECT_TEEC_SUCCESS(c,
				ta_crypt_cmd_set_operation_key2(c, &session, op,
					key1_handle, key2_handle)))
				goto out;
		} else {
			if (!ADBG_EXPECT_TEEC_SUCCESS(c,
				ta_crypt_cmd_set_operation_key(c, &session, op,
					key1_handle)))
				goto out;
		}

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_free_transient_object(c, &session,
				key1_handle)))
			goto out;
		key1_handle = TEE_HANDLE_NULL;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_free_transient_object(c, &session,
				key2_handle)))
			goto out;
		key2_handle = TEE_HANDLE_NULL;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_cipher_init(c, &session, op,
				ciph_cases[n].iv, ciph_cases[n].iv_len)))
			goto out;

		out_offs = 0;
		out_size = sizeof(out);
		memset(out, 0, sizeof(out));
		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_cipher_update(c, &session, op,
				ciph_cases[n].in, ciph_cases[n].in_incr, out,
				&out_size)))
			goto out;

		if (ciph_cases[n].algo == TEE_ALG_AES_CTR)
			ADBG_EXPECT_COMPARE_UNSIGNED(c, out_size, ==,
				ciph_cases[n].in_incr);

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_copy_operation(c, &session, op2, op)))
			goto out;

		out_offs += out_size;
		out_size = sizeof(out) - out_offs;
		out_offs2 = out_offs;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_cipher_do_final(c, &session, op,
				ciph_cases[n].in + ciph_cases[n].in_incr,
				ciph_cases[n].in_len - ciph_cases[n].in_incr,
				out + out_offs,
				&out_size)))
			goto out;

		out_offs += out_size;

		(void)ADBG_EXPECT_BUFFER(c, ciph_cases[n].out,
					 ciph_cases[n].out_len, out, out_offs);

		/* test on the copied op2 */
		out_size = sizeof(out) - out_offs2;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_cipher_do_final(c, &session, op2,
				ciph_cases[n].in + ciph_cases[n].in_incr,
				ciph_cases[n].in_len - ciph_cases[n].in_incr,
				out + out_offs2,
				&out_size)))
			goto out;

		out_offs2 += out_size;

		ADBG_EXPECT_BUFFER(c, ciph_cases[n].out, ciph_cases[n].out_len,
				   out, out_offs2);

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_free_operation(c, &session, op)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_free_operation(c, &session, op2)))
			goto out;

		Do_ADBG_EndSubCase(c, NULL);
	}
out:
	TEEC_CloseSession(&session);
}
ADBG_CASE_DEFINE(regression, 4003, xtest_tee_test_4003,
		"Test TEE Internal API cipher operations");

static void xtest_tee_test_4004(ADBG_Case_t *c)
{
	TEEC_Session session = { };
	uint32_t ret_orig = 0;
	uint8_t buf1[45] = { };
	uint8_t buf2[45] = { };
	static const uint8_t zeros[45];

	Do_ADBG_BeginSubCase(c, "TEE get random");
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		xtest_teec_open_session(&session, &crypt_user_ta_uuid, NULL,
			&ret_orig)))
		return;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		ta_crypt_cmd_random_number_generate(c, &session, buf1,
			sizeof(buf1))))
		goto out;

	(void)ADBG_EXPECT_COMPARE_SIGNED(c,
		0, !=, memcmp(buf1, zeros, sizeof(buf1)));

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		ta_crypt_cmd_random_number_generate(c, &session, buf2,
			sizeof(buf2))))
		goto out;

	(void)ADBG_EXPECT_COMPARE_SIGNED(c,
		0, !=, memcmp(buf2, zeros, sizeof(buf2)));

	(void)ADBG_EXPECT_COMPARE_SIGNED(c,
		0, !=, memcmp(buf2, buf1, sizeof(buf1)));
out:
	TEEC_CloseSession(&session);
	Do_ADBG_EndSubCase(c, "TEE get random");
}
ADBG_CASE_DEFINE(regression, 4004, xtest_tee_test_4004,
		"Test TEE Internal API get random");

struct xtest_ae_case {
	uint32_t algo;
	uint32_t mode;
	uint32_t key_type;
	const uint8_t *key;
	size_t key_len;
	const uint8_t *nonce;
	size_t nonce_len;
	size_t aad_incr;
	const uint8_t *aad;
	size_t aad_len;
	size_t in_incr;
	const uint8_t *ptx;
	size_t ptx_len;
	const uint8_t *ctx;
	size_t ctx_len;
	const uint8_t *tag;
	size_t tag_len;
	size_t line;
	uint32_t id;
};


#define ARRAY(a)            a, ARRAY_SIZE(a)
#define NULL_ARRAY(a)       NULL, 0

#define XTEST_AE_CASE(algo, vect, aad_incr, in_incr, \
		      aad_array, ptx_array, ctx_array) \
	{ (algo), TEE_MODE_ENCRYPT, TEE_TYPE_AES, ARRAY(vect ## _key), \
	  ARRAY(vect ## _nonce), (aad_incr), \
		aad_array(vect ## _aad), (in_incr), \
	  ptx_array(vect ## _ptx), ctx_array(vect ## _ctx), \
		ARRAY(vect ## _tag), \
	  __LINE__, 0 }, \
	{ (algo), TEE_MODE_DECRYPT, TEE_TYPE_AES, ARRAY(vect ## _key), \
	  ARRAY(vect ## _nonce), (aad_incr), \
		aad_array(vect ## _aad), (in_incr), \
	  ptx_array(vect ## _ptx), ctx_array(vect ## _ctx), \
		ARRAY(vect ## _tag), \
	  __LINE__, 0 }

#define XTEST_AE_CASE_AES_CCM(vect, aad_incr, in_incr) \
	XTEST_AE_CASE(TEE_ALG_AES_CCM, ae_data_aes_ccm_ ## vect, aad_incr, \
		      in_incr, ARRAY, ARRAY, ARRAY)

#define XTEST_AE_CASE_AES_GCM(vect, aad_incr, in_incr, \
			      aad_array, ptx_array, ctx_array) \
	XTEST_AE_CASE(TEE_ALG_AES_GCM, ae_data_aes_gcm_ ## vect, aad_incr, \
		      in_incr, aad_array, ptx_array, ctx_array)



static const struct xtest_ae_case ae_cases[] = {
	XTEST_AE_CASE_AES_CCM(vect1, 3, 2),
	XTEST_AE_CASE_AES_CCM(vect2, 7, 13),
	XTEST_AE_CASE_AES_CCM(vect3, 5, 21),

	XTEST_AE_CASE_AES_GCM(vect1, 0, 0, NULL_ARRAY, NULL_ARRAY, NULL_ARRAY),
	XTEST_AE_CASE_AES_GCM(vect2, 0, 9, NULL_ARRAY, ARRAY, ARRAY),
	XTEST_AE_CASE_AES_GCM(vect3, 0, 9, NULL_ARRAY, ARRAY, ARRAY),
	XTEST_AE_CASE_AES_GCM(vect3, 0, 0x1F, NULL_ARRAY, ARRAY, ARRAY),
	XTEST_AE_CASE_AES_GCM(vect4, 5, 0x20, ARRAY, ARRAY, ARRAY),
	XTEST_AE_CASE_AES_GCM(vect5, 5, 9, ARRAY, ARRAY, ARRAY),
	XTEST_AE_CASE_AES_GCM(vect6, 5, 9, ARRAY, ARRAY, ARRAY),
	XTEST_AE_CASE_AES_GCM(vect7, 0, 0, NULL_ARRAY, NULL_ARRAY, NULL_ARRAY),
	XTEST_AE_CASE_AES_GCM(vect8, 0, 9, NULL_ARRAY, ARRAY, ARRAY),
	XTEST_AE_CASE_AES_GCM(vect9, 0, 9, NULL_ARRAY, ARRAY, ARRAY),
	XTEST_AE_CASE_AES_GCM(vect10, 5, 9, ARRAY, ARRAY, ARRAY),
	XTEST_AE_CASE_AES_GCM(vect11, 5, 9, ARRAY, ARRAY, ARRAY),
	XTEST_AE_CASE_AES_GCM(vect12, 5, 9, ARRAY, ARRAY, ARRAY),
	XTEST_AE_CASE_AES_GCM(vect13, 0, 0, NULL_ARRAY, NULL_ARRAY, NULL_ARRAY),
	XTEST_AE_CASE_AES_GCM(vect14, 0, 9, NULL_ARRAY, ARRAY, ARRAY),
	XTEST_AE_CASE_AES_GCM(vect15, 0, 9, NULL_ARRAY, ARRAY, ARRAY),
	XTEST_AE_CASE_AES_GCM(vect16, 5, 9, ARRAY, ARRAY, ARRAY),
	XTEST_AE_CASE_AES_GCM(vect17, 5, 9, ARRAY, ARRAY, ARRAY),
	XTEST_AE_CASE_AES_GCM(vect18, 5, 9, ARRAY, ARRAY, ARRAY),
#ifdef CFG_GCM_NIST_VECTORS
#include "gcmDecrypt128.h"
#include "gcmDecrypt192.h"
#include "gcmDecrypt256.h"
#include "gcmEncryptExtIV128.h"
#include "gcmEncryptExtIV192.h"
#include "gcmEncryptExtIV256.h"
#endif
#include "aes_gcm_counter_overflow_test_encrypt.h"
#include "aes_gcm_counter_overflow_test_decrypt.h"
};

static void xtest_tee_test_4005(ADBG_Case_t *c)
{
	TEEC_Session session = { };
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	TEE_OperationHandle op2 = TEE_HANDLE_NULL;
	TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
	TEE_Attribute key_attr = { };
	uint8_t out[512] = { };
	size_t out_size = 0;
	size_t out_offs = 0;
	size_t out_offs2 = 0;
	uint32_t ret_orig = 0;
	size_t n = 0;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		xtest_teec_open_session(&session, &crypt_user_ta_uuid, NULL,
			&ret_orig)))
		return;

	for (n = 0; n < ARRAY_SIZE(ae_cases); n++) {
		if (ae_cases[n].id)
			Do_ADBG_BeginSubCase(c, "AE case %d algo 0x%x line %d id %d",
					     (int)n, (unsigned int)ae_cases[n].algo,
					     (int)ae_cases[n].line,
					     (unsigned int)ae_cases[n].id);
		else
			Do_ADBG_BeginSubCase(c, "AE case %d algo 0x%x line %d",
					     (int)n, (unsigned int)ae_cases[n].algo,
					     (int)ae_cases[n].line);

		key_attr.attributeID = TEE_ATTR_SECRET_VALUE;
		key_attr.content.ref.buffer = (void *)ae_cases[n].key;
		key_attr.content.ref.length = ae_cases[n].key_len;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_allocate_operation(c, &session, &op,
				ae_cases[n].algo, ae_cases[n].mode,
				key_attr.content.ref.length * 8)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_allocate_operation(c, &session, &op2,
				ae_cases[n].algo, ae_cases[n].mode,
				key_attr.content.ref.length * 8)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_allocate_transient_object(c, &session,
				ae_cases[n].key_type,
				key_attr.content.ref.length * 8,
				&key_handle)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_populate_transient_object(c, &session,
				key_handle, &key_attr, 1)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_set_operation_key(c, &session, op,
				key_handle)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_free_transient_object(c, &session,
				key_handle)))
			goto out;
		key_handle = TEE_HANDLE_NULL;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_ae_init(c, &session, op, ae_cases[n].nonce,
			ae_cases[n].nonce_len, ae_cases[n].tag_len,
			ae_cases[n].aad_len, ae_cases[n].ptx_len)))
			goto out;

		if (ae_cases[n].aad != NULL) {
			if (!ADBG_EXPECT_TEEC_SUCCESS(c,
				ta_crypt_cmd_ae_update_aad(c, &session, op,
					ae_cases[n].aad, ae_cases[n].aad_incr)))
				goto out;

			if (!ADBG_EXPECT_TEEC_SUCCESS(c,
				ta_crypt_cmd_ae_update_aad(c, &session, op,
					ae_cases[n].aad + ae_cases[n].aad_incr,
					ae_cases [n].aad_len -
						ae_cases[n].aad_incr)))
				goto out;
		}

		out_offs = 0;
		out_size = sizeof(out);
		memset(out, 0, sizeof(out));
		if (ae_cases[n].mode == TEE_MODE_ENCRYPT) {
			if (ae_cases[n].ptx != NULL) {
				if (!ADBG_EXPECT_TEEC_SUCCESS(c,
					ta_crypt_cmd_ae_update(c, &session, op,
						ae_cases[n].ptx,
						ae_cases[n].in_incr, out,
						&out_size)))
					goto out;
				out_offs += out_size;
				if (ae_cases[n].algo == TEE_ALG_AES_GCM)
					ADBG_EXPECT_COMPARE_UNSIGNED(c,
					  out_size, ==, ae_cases[n].in_incr);
			}
		} else {
			if (ae_cases[n].ctx != NULL) {
				if (!ADBG_EXPECT_TEEC_SUCCESS(c,
					ta_crypt_cmd_ae_update(c, &session, op,
						ae_cases[n].ctx,
						ae_cases[n].in_incr, out,
						&out_size)))
					goto out;
				out_offs += out_size;
				if (ae_cases[n].algo == TEE_ALG_AES_GCM)
					ADBG_EXPECT_COMPARE_UNSIGNED(c,
					  out_size, ==, ae_cases[n].in_incr);
			}
		}

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_copy_operation(c, &session, op2, op)))
			goto out;

		out_size = sizeof(out) - out_offs;
		out_offs2 = out_offs;
		if (ae_cases[n].mode == TEE_MODE_ENCRYPT) {
			uint8_t out_tag[64];
			size_t out_tag_len = MIN(sizeof(out_tag),
						 ae_cases[n].tag_len);

			if (!ADBG_EXPECT_TEEC_SUCCESS(c,
				ta_crypt_cmd_ae_encrypt_final(c, &session, op,
					ae_cases[n].ptx + ae_cases[n].in_incr,
					ae_cases[n].ptx_len -
						ae_cases[n].in_incr,
					out + out_offs,
					&out_size, out_tag, &out_tag_len)))
				goto out;

			(void)ADBG_EXPECT_BUFFER(c,
				ae_cases[n].tag, ae_cases[n].tag_len, out_tag,
				out_tag_len);

			out_offs += out_size;

			(void)ADBG_EXPECT_BUFFER(c, ae_cases[n].ctx,
				ae_cases[n].ctx_len, out, out_offs);
		} else {
			if (!ADBG_EXPECT_TEEC_SUCCESS(c,
				ta_crypt_cmd_ae_decrypt_final(c, &session, op,
					ae_cases[n].ctx + ae_cases[n].in_incr,
					ae_cases[n].ctx_len -
						ae_cases[n].in_incr,
					out + out_offs,
					&out_size, ae_cases[n].tag,
					ae_cases[n].tag_len)))
				goto out;

			out_offs += out_size;

			(void)ADBG_EXPECT_BUFFER(c, ae_cases[n].ptx,
				ae_cases[n].ptx_len, out, out_offs);
		}

		/* test on the copied op2 */
		out_size = sizeof(out) - out_offs2;
		memset(out + out_offs2, 0, out_size);
		if (ae_cases[n].mode == TEE_MODE_ENCRYPT) {
			uint8_t out_tag[64] = { 0 };
			size_t out_tag_len = MIN(sizeof(out_tag),
						 ae_cases[n].tag_len);

			if (!ADBG_EXPECT_TEEC_SUCCESS(c,
				ta_crypt_cmd_ae_encrypt_final(c, &session, op2,
					ae_cases[n].ptx + ae_cases[n].in_incr,
					ae_cases[n].ptx_len -
						ae_cases[n].in_incr,
					out + out_offs2,
					&out_size, out_tag, &out_tag_len)))
				goto out;

			ADBG_EXPECT_BUFFER(c, ae_cases[n].tag,
					   ae_cases[n].tag_len, out_tag,
					   out_tag_len);

			out_offs2 += out_size;

			(void)ADBG_EXPECT_BUFFER(c, ae_cases[n].ctx,
				ae_cases[n].ctx_len, out, out_offs2);
		} else {
			if (!ADBG_EXPECT_TEEC_SUCCESS(c,
				ta_crypt_cmd_ae_decrypt_final(c, &session, op2,
					ae_cases[n].ctx + ae_cases[n].in_incr,
					ae_cases[n].ctx_len -
						ae_cases[n].in_incr,
					out + out_offs2,
					&out_size, ae_cases[n].tag,
					ae_cases[n].tag_len)))
				goto out;

			out_offs2 += out_size;

			(void)ADBG_EXPECT_BUFFER(c, ae_cases[n].ptx,
				ae_cases[n].ptx_len, out, out_offs2);
		}

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_free_operation(c, &session, op)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_free_operation(c, &session, op2)))
			goto out;

		Do_ADBG_EndSubCase(c, NULL);
	}
out:
	TEEC_CloseSession(&session);
}
ADBG_CASE_DEFINE(regression, 4005, xtest_tee_test_4005,
		"Test TEE Internal API Authenticated Encryption operations");

struct xtest_ac_case {
	unsigned int level;
	uint32_t algo;
	TEE_OperationMode mode;

	union {
		struct {
			const uint8_t *modulus;
			size_t modulus_len;

			const uint8_t *pub_exp;
			size_t pub_exp_len;

			const uint8_t *priv_exp;
			size_t priv_exp_len;

			const uint8_t *prime1;  /* q */
			size_t prime1_len;
			const uint8_t *prime2;  /* p */
			size_t prime2_len;
			const uint8_t *exp1;    /* dp */
			size_t exp1_len;
			const uint8_t *exp2;    /* dq */
			size_t exp2_len;
			const uint8_t *coeff;   /* iq */
			size_t coeff_len;

			int salt_len;
		} rsa;
		struct {
			const uint8_t *prime;
			size_t prime_len;
			const uint8_t *sub_prime;
			size_t sub_prime_len;
			const uint8_t *base;
			size_t base_len;
			const uint8_t *pub_val;
			size_t pub_val_len;
			const uint8_t *priv_val;
			size_t priv_val_len;
		} dsa;
		struct {
			const uint8_t *private;
			size_t private_len;
			const uint8_t *public_x;
			size_t public_x_len;
			const uint8_t *public_y;
			size_t public_y_len;
		} ecc;
		struct {
			const uint8_t *private;
			size_t private_len;
			const uint8_t *public;
			size_t public_len;
			const uint8_t flag;
			const uint8_t *context;
			size_t context_len;
		} eddsa;
	} params;

	const uint8_t *ptx;
	size_t ptx_len;
	const uint8_t *ctx;
	size_t ctx_len;
	size_t line;
};

#define WITHOUT_SALT(x) -1
#define WITH_SALT(x)    x

#define XTEST_AC_CASE(level, algo, mode, vect, union_params) \
	{ level, (algo), (mode), .params = union_params, \
	  ARRAY(vect ## _ptx), \
	  ARRAY(vect ## _out), \
	  __LINE__ }

#define XTEST_AC_RSA_UNION(vect, opt_crt_array, opt_salt) \
	{ .rsa = { \
		  ARRAY(vect ## _modulus), \
		  ARRAY(vect ## _pub_exp), \
		  ARRAY(vect ## _priv_exp), \
		  opt_crt_array(vect ## _prime1), \
		  opt_crt_array(vect ## _prime2), \
		  opt_crt_array(vect ## _exp1), \
		  opt_crt_array(vect ## _exp2), \
		  opt_crt_array(vect ## _coeff), \
		  opt_salt(vect ## _salt_len) \
	  } }

#define XTEST_AC_RSA_CASE(level, algo, mode, vect, opt_crt_array, opt_salt) \
	XTEST_AC_CASE(level, algo, mode, vect, \
		      XTEST_AC_RSA_UNION(vect, opt_crt_array, opt_salt))

#define XTEST_AC_DSA_UNION(vect) \
	{ .dsa = { \
		  ARRAY(vect ## _prime), \
		  ARRAY(vect ## _sub_prime), \
		  ARRAY(vect ## _base), \
		  ARRAY(vect ## _pub_val), \
		  ARRAY(vect ## _priv_val), \
	  } }

#define XTEST_AC_DSA_CASE(level, algo, mode, vect) \
	XTEST_AC_CASE(level, algo, mode, vect, XTEST_AC_DSA_UNION(vect))

#define XTEST_AC_ECDSA_UNION(vect) \
	{ .ecc = { \
		  ARRAY(vect ## _private), \
		  ARRAY(vect ## _public_x), \
		  ARRAY(vect ## _public_y), \
	  } }

#define XTEST_AC_ECC_CASE(level, algo, mode, vect) \
	XTEST_AC_CASE(level, algo, mode, vect, XTEST_AC_ECDSA_UNION(vect))

#define XTEST_AC_EDDSA_UNION(vect, flag) \
	{ .eddsa = { \
		  ARRAY(vect ## _private), \
		  ARRAY(vect ## _public), \
		  flag, \
	  } }

#define XTEST_AC_EDDSA_CTX_UNION(vect, flag) \
	{ .eddsa = { \
		  ARRAY(vect ## _private), \
		  ARRAY(vect ## _public), \
		  flag, \
		  ARRAY(vect ## _context), \
	  } }

#define XTEST_AC_EDDSA_CASE(level, algo, mode, vect, flag) \
	XTEST_AC_CASE(level, algo, mode, vect, XTEST_AC_EDDSA_UNION(vect, flag))

#define XTEST_AC_EDDSA_CTX_CASE(level, algo, mode, vect, flag) \
	XTEST_AC_CASE(level, algo, mode, vect, XTEST_AC_EDDSA_CTX_UNION(vect, flag))

static const struct xtest_ac_case xtest_ac_cases_rsa[] = {
	/* RSA test without crt parameters */
	XTEST_AC_RSA_CASE(0, TEE_ALG_RSA_NOPAD, TEE_MODE_ENCRYPT,
			  ac_rsassa_vect1, NULL_ARRAY, WITHOUT_SALT),
	XTEST_AC_RSA_CASE(0, TEE_ALG_RSA_NOPAD, TEE_MODE_DECRYPT,
			  ac_rsassa_vect1, NULL_ARRAY, WITHOUT_SALT),
	XTEST_AC_RSA_CASE(0, TEE_ALG_RSA_NOPAD, TEE_MODE_ENCRYPT,
			  ac_rsassa_vect2, NULL_ARRAY, WITHOUT_SALT),
	XTEST_AC_RSA_CASE(0, TEE_ALG_RSA_NOPAD, TEE_MODE_DECRYPT,
			  ac_rsassa_vect2, NULL_ARRAY, WITHOUT_SALT),
	XTEST_AC_RSA_CASE(0, TEE_ALG_RSA_NOPAD, TEE_MODE_ENCRYPT,
			  ac_rsassa_vect18, NULL_ARRAY, WITHOUT_SALT),
	XTEST_AC_RSA_CASE(0, TEE_ALG_RSA_NOPAD, TEE_MODE_DECRYPT,
			  ac_rsassa_vect18, NULL_ARRAY, WITHOUT_SALT),
	XTEST_AC_RSA_CASE(0, TEE_ALG_RSA_NOPAD, TEE_MODE_ENCRYPT,
			  ac_rsassa_vect19, NULL_ARRAY, WITHOUT_SALT),
	XTEST_AC_RSA_CASE(0, TEE_ALG_RSA_NOPAD, TEE_MODE_DECRYPT,
			  ac_rsassa_vect19, NULL_ARRAY, WITHOUT_SALT),
	XTEST_AC_RSA_CASE(0, TEE_ALG_RSASSA_PKCS1_V1_5_SHA1, TEE_MODE_SIGN,
			  ac_rsassa_vect3, NULL_ARRAY, WITHOUT_SALT),
	XTEST_AC_RSA_CASE(0, TEE_ALG_RSASSA_PKCS1_V1_5_SHA1, TEE_MODE_VERIFY,
			  ac_rsassa_vect3, NULL_ARRAY, WITHOUT_SALT),
	XTEST_AC_RSA_CASE(1, TEE_ALG_RSASSA_PKCS1_V1_5_SHA1, TEE_MODE_SIGN,
			  ac_rsassa_vect4, NULL_ARRAY, WITHOUT_SALT),
	XTEST_AC_RSA_CASE(1, TEE_ALG_RSASSA_PKCS1_V1_5_SHA1, TEE_MODE_VERIFY,
			  ac_rsassa_vect4, NULL_ARRAY, WITHOUT_SALT),
	XTEST_AC_RSA_CASE(1, TEE_ALG_RSASSA_PKCS1_V1_5_SHA1, TEE_MODE_SIGN,
			  ac_rsassa_vect5, NULL_ARRAY, WITHOUT_SALT),
	XTEST_AC_RSA_CASE(1, TEE_ALG_RSASSA_PKCS1_V1_5_SHA1, TEE_MODE_VERIFY,
			  ac_rsassa_vect5, NULL_ARRAY, WITHOUT_SALT),
	XTEST_AC_RSA_CASE(1, TEE_ALG_RSASSA_PKCS1_V1_5_SHA1, TEE_MODE_SIGN,
			  ac_rsassa_vect6, NULL_ARRAY, WITHOUT_SALT),
	XTEST_AC_RSA_CASE(1, TEE_ALG_RSASSA_PKCS1_V1_5_SHA1, TEE_MODE_VERIFY,
			  ac_rsassa_vect6, NULL_ARRAY, WITHOUT_SALT),
	XTEST_AC_RSA_CASE(1, TEE_ALG_RSASSA_PKCS1_V1_5_SHA1, TEE_MODE_SIGN,
			  ac_rsassa_vect7, NULL_ARRAY, WITHOUT_SALT),
	XTEST_AC_RSA_CASE(1, TEE_ALG_RSASSA_PKCS1_V1_5_SHA1, TEE_MODE_VERIFY,
			  ac_rsassa_vect7, NULL_ARRAY, WITHOUT_SALT),
	XTEST_AC_RSA_CASE(1, TEE_ALG_RSASSA_PKCS1_V1_5_SHA1, TEE_MODE_SIGN,
			  ac_rsassa_vect8, NULL_ARRAY, WITHOUT_SALT),
	XTEST_AC_RSA_CASE(1, TEE_ALG_RSASSA_PKCS1_V1_5_SHA1, TEE_MODE_VERIFY,
			  ac_rsassa_vect8, NULL_ARRAY, WITHOUT_SALT),

	XTEST_AC_RSA_CASE(0, TEE_ALG_RSASSA_PKCS1_V1_5_SHA224, TEE_MODE_SIGN,
			  ac_rsassa_vect16, NULL_ARRAY, WITHOUT_SALT),
	XTEST_AC_RSA_CASE(0, TEE_ALG_RSASSA_PKCS1_V1_5_SHA224, TEE_MODE_VERIFY,
			  ac_rsassa_vect16, NULL_ARRAY, WITHOUT_SALT),

	/* These 2 tests depend on CFG_CRYPTO_RSASSA_NA1=y OP-TEE OS */
	XTEST_AC_RSA_CASE(0, TEE_ALG_RSASSA_PKCS1_V1_5, TEE_MODE_SIGN,
			  ac_rsassa_vect20, NULL_ARRAY, WITHOUT_SALT),
	XTEST_AC_RSA_CASE(0, TEE_ALG_RSASSA_PKCS1_V1_5, TEE_MODE_VERIFY,
			  ac_rsassa_vect20, NULL_ARRAY, WITHOUT_SALT),

	XTEST_AC_RSA_CASE(0, TEE_ALG_RSASSA_PKCS1_V1_5_SHA256, TEE_MODE_SIGN,
			  ac_rsassa_vect9, NULL_ARRAY, WITHOUT_SALT),
	XTEST_AC_RSA_CASE(0, TEE_ALG_RSASSA_PKCS1_V1_5_SHA256, TEE_MODE_VERIFY,
			  ac_rsassa_vect9, NULL_ARRAY, WITHOUT_SALT),

	XTEST_AC_RSA_CASE(0, TEE_ALG_RSASSA_PKCS1_V1_5_SHA384, TEE_MODE_SIGN,
			  ac_rsassa_vect10, NULL_ARRAY, WITHOUT_SALT),
	XTEST_AC_RSA_CASE(0, TEE_ALG_RSASSA_PKCS1_V1_5_SHA384, TEE_MODE_VERIFY,
			  ac_rsassa_vect10, NULL_ARRAY, WITHOUT_SALT),

	XTEST_AC_RSA_CASE(0, TEE_ALG_RSASSA_PKCS1_V1_5_SHA512, TEE_MODE_SIGN,
			  ac_rsassa_vect11, NULL_ARRAY, WITHOUT_SALT),
	XTEST_AC_RSA_CASE(0, TEE_ALG_RSASSA_PKCS1_V1_5_SHA512, TEE_MODE_VERIFY,
			  ac_rsassa_vect11, NULL_ARRAY, WITHOUT_SALT),

	XTEST_AC_RSA_CASE(1, TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1,
			  TEE_MODE_VERIFY,
			  ac_rsassa_vect12, NULL_ARRAY, WITH_SALT),
	XTEST_AC_RSA_CASE(1, TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1, TEE_MODE_SIGN,
			  ac_rsassa_vect12, NULL_ARRAY, WITH_SALT),

	XTEST_AC_RSA_CASE(1, TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224,
			  TEE_MODE_VERIFY,
			  ac_rsassa_vect17, NULL_ARRAY, WITH_SALT),
	XTEST_AC_RSA_CASE(1, TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224,
			  TEE_MODE_SIGN,
			  ac_rsassa_vect17, NULL_ARRAY, WITH_SALT),

	XTEST_AC_RSA_CASE(0, TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256,
			  TEE_MODE_VERIFY,
			  ac_rsassa_vect13, NULL_ARRAY, WITH_SALT),
	XTEST_AC_RSA_CASE(0, TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256,
			  TEE_MODE_SIGN,
			  ac_rsassa_vect13, NULL_ARRAY, WITH_SALT),

	XTEST_AC_RSA_CASE(1, TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384,
			  TEE_MODE_VERIFY,
			  ac_rsassa_vect14, NULL_ARRAY, WITH_SALT),
	XTEST_AC_RSA_CASE(1, TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384,
			  TEE_MODE_SIGN,
			  ac_rsassa_vect14, NULL_ARRAY, WITH_SALT),

	XTEST_AC_RSA_CASE(1, TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512,
			  TEE_MODE_VERIFY,
			  ac_rsassa_vect15, NULL_ARRAY, WITH_SALT),
	XTEST_AC_RSA_CASE(1, TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512,
			  TEE_MODE_SIGN,
			  ac_rsassa_vect15, NULL_ARRAY, WITH_SALT),

	XTEST_AC_RSA_CASE(0, TEE_ALG_RSAES_PKCS1_V1_5, TEE_MODE_DECRYPT,
			  ac_rsaes_pkcs1_v1_5_vect1, NULL_ARRAY, WITHOUT_SALT),
	XTEST_AC_RSA_CASE(0, TEE_ALG_RSAES_PKCS1_V1_5, TEE_MODE_ENCRYPT,
			  ac_rsaes_pkcs1_v1_5_vect1, NULL_ARRAY, WITHOUT_SALT),
	XTEST_AC_RSA_CASE(1, TEE_ALG_RSAES_PKCS1_V1_5, TEE_MODE_DECRYPT,
			  ac_rsaes_pkcs1_v1_5_vect2, NULL_ARRAY, WITHOUT_SALT),
	XTEST_AC_RSA_CASE(1, TEE_ALG_RSAES_PKCS1_V1_5, TEE_MODE_ENCRYPT,
			  ac_rsaes_pkcs1_v1_5_vect2, NULL_ARRAY, WITHOUT_SALT),
	XTEST_AC_RSA_CASE(1, TEE_ALG_RSAES_PKCS1_V1_5, TEE_MODE_DECRYPT,
			  ac_rsaes_pkcs1_v1_5_vect15, NULL_ARRAY, WITHOUT_SALT),
	XTEST_AC_RSA_CASE(1, TEE_ALG_RSAES_PKCS1_V1_5, TEE_MODE_ENCRYPT,
			  ac_rsaes_pkcs1_v1_5_vect15, NULL_ARRAY, WITHOUT_SALT),

	XTEST_AC_RSA_CASE(0, TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1,
			  TEE_MODE_DECRYPT,
			  ac_rsaes_oaep_vect1, NULL_ARRAY, WITHOUT_SALT),
	XTEST_AC_RSA_CASE(0, TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1,
			  TEE_MODE_ENCRYPT,
			  ac_rsaes_oaep_vect1, NULL_ARRAY, WITHOUT_SALT),
	XTEST_AC_RSA_CASE(1, TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1,
			  TEE_MODE_DECRYPT,
			  ac_rsaes_oaep_vect2, NULL_ARRAY, WITHOUT_SALT),
	XTEST_AC_RSA_CASE(1, TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1,
			  TEE_MODE_ENCRYPT,
			  ac_rsaes_oaep_vect2, NULL_ARRAY, WITHOUT_SALT),
	XTEST_AC_RSA_CASE(1, TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1,
			  TEE_MODE_DECRYPT,
			  ac_rsaes_oaep_vect10, NULL_ARRAY, WITHOUT_SALT),
	XTEST_AC_RSA_CASE(1, TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1,
			  TEE_MODE_ENCRYPT,
			  ac_rsaes_oaep_vect10, NULL_ARRAY, WITHOUT_SALT),
	XTEST_AC_RSA_CASE(0, TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256,
			  TEE_MODE_DECRYPT,
			  ac_rsaes_oaep_vect3, NULL_ARRAY, WITHOUT_SALT),
	XTEST_AC_RSA_CASE(0, TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256,
			  TEE_MODE_ENCRYPT,
			  ac_rsaes_oaep_vect3, NULL_ARRAY, WITHOUT_SALT),

	/* RSA test with crt parameters */
	XTEST_AC_RSA_CASE(0, TEE_ALG_RSA_NOPAD, TEE_MODE_ENCRYPT,
			  ac_rsassa_vect1, ARRAY, WITHOUT_SALT),
	XTEST_AC_RSA_CASE(0, TEE_ALG_RSA_NOPAD, TEE_MODE_DECRYPT,
			  ac_rsassa_vect1, ARRAY, WITHOUT_SALT),
	XTEST_AC_RSA_CASE(1, TEE_ALG_RSA_NOPAD, TEE_MODE_ENCRYPT,
			  ac_rsassa_vect2, ARRAY, WITHOUT_SALT),
	XTEST_AC_RSA_CASE(1, TEE_ALG_RSA_NOPAD, TEE_MODE_DECRYPT,
			  ac_rsassa_vect2, ARRAY, WITHOUT_SALT),
	XTEST_AC_RSA_CASE(0, TEE_ALG_RSASSA_PKCS1_V1_5_SHA1, TEE_MODE_SIGN,
			  ac_rsassa_vect3, ARRAY, WITHOUT_SALT),
	XTEST_AC_RSA_CASE(0, TEE_ALG_RSASSA_PKCS1_V1_5_SHA1, TEE_MODE_VERIFY,
			  ac_rsassa_vect3, ARRAY, WITHOUT_SALT),
	XTEST_AC_RSA_CASE(1, TEE_ALG_RSASSA_PKCS1_V1_5_SHA1, TEE_MODE_SIGN,
			  ac_rsassa_vect4, ARRAY, WITHOUT_SALT),
	XTEST_AC_RSA_CASE(1, TEE_ALG_RSASSA_PKCS1_V1_5_SHA1, TEE_MODE_VERIFY,
			  ac_rsassa_vect4, ARRAY, WITHOUT_SALT),
	XTEST_AC_RSA_CASE(1, TEE_ALG_RSASSA_PKCS1_V1_5_SHA1, TEE_MODE_SIGN,
			  ac_rsassa_vect5, ARRAY, WITHOUT_SALT),
	XTEST_AC_RSA_CASE(1, TEE_ALG_RSASSA_PKCS1_V1_5_SHA1, TEE_MODE_VERIFY,
			  ac_rsassa_vect5, ARRAY, WITHOUT_SALT),
	XTEST_AC_RSA_CASE(1, TEE_ALG_RSASSA_PKCS1_V1_5_SHA1, TEE_MODE_SIGN,
			  ac_rsassa_vect6, ARRAY, WITHOUT_SALT),
	XTEST_AC_RSA_CASE(1, TEE_ALG_RSASSA_PKCS1_V1_5_SHA1, TEE_MODE_VERIFY,
			  ac_rsassa_vect6, ARRAY, WITHOUT_SALT),
	XTEST_AC_RSA_CASE(1, TEE_ALG_RSASSA_PKCS1_V1_5_SHA1, TEE_MODE_SIGN,
			  ac_rsassa_vect7, ARRAY, WITHOUT_SALT),
	XTEST_AC_RSA_CASE(1, TEE_ALG_RSASSA_PKCS1_V1_5_SHA1, TEE_MODE_VERIFY,
			  ac_rsassa_vect7, ARRAY, WITHOUT_SALT),
	XTEST_AC_RSA_CASE(1, TEE_ALG_RSASSA_PKCS1_V1_5_SHA1, TEE_MODE_SIGN,
			  ac_rsassa_vect8, ARRAY, WITHOUT_SALT),
	XTEST_AC_RSA_CASE(1, TEE_ALG_RSASSA_PKCS1_V1_5_SHA1, TEE_MODE_VERIFY,
			  ac_rsassa_vect8, ARRAY, WITHOUT_SALT),
	XTEST_AC_RSA_CASE(0, TEE_ALG_RSASSA_PKCS1_V1_5_SHA256, TEE_MODE_SIGN,
			  ac_rsassa_vect9, ARRAY, WITHOUT_SALT),
	XTEST_AC_RSA_CASE(0, TEE_ALG_RSASSA_PKCS1_V1_5_SHA256, TEE_MODE_VERIFY,
			  ac_rsassa_vect9, ARRAY, WITHOUT_SALT),
	XTEST_AC_RSA_CASE(1, TEE_ALG_RSASSA_PKCS1_V1_5_SHA384, TEE_MODE_SIGN,
			  ac_rsassa_vect10, ARRAY, WITHOUT_SALT),
	XTEST_AC_RSA_CASE(1, TEE_ALG_RSASSA_PKCS1_V1_5_SHA384, TEE_MODE_VERIFY,
			  ac_rsassa_vect10, ARRAY, WITHOUT_SALT),
	XTEST_AC_RSA_CASE(1, TEE_ALG_RSASSA_PKCS1_V1_5_SHA512, TEE_MODE_SIGN,
			  ac_rsassa_vect11, ARRAY, WITHOUT_SALT),
	XTEST_AC_RSA_CASE(1, TEE_ALG_RSASSA_PKCS1_V1_5_SHA512, TEE_MODE_VERIFY,
			  ac_rsassa_vect11, ARRAY, WITHOUT_SALT),

	XTEST_AC_RSA_CASE(1, TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1,
			  TEE_MODE_VERIFY,
			  ac_rsassa_vect12, ARRAY, WITH_SALT),
	XTEST_AC_RSA_CASE(1,TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1, TEE_MODE_SIGN,
			  ac_rsassa_vect12, ARRAY, WITH_SALT),
	XTEST_AC_RSA_CASE(1, TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224,
			  TEE_MODE_VERIFY,
			  ac_rsassa_vect17, ARRAY, WITH_SALT),
	XTEST_AC_RSA_CASE(1, TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224,
			  TEE_MODE_SIGN,
			  ac_rsassa_vect17, ARRAY, WITH_SALT),
	XTEST_AC_RSA_CASE(0, TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256,
			  TEE_MODE_VERIFY,
			  ac_rsassa_vect13, ARRAY, WITH_SALT),
	XTEST_AC_RSA_CASE(0, TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256,
			  TEE_MODE_SIGN,
			  ac_rsassa_vect13, ARRAY, WITH_SALT),
	XTEST_AC_RSA_CASE(1, TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384,
			  TEE_MODE_VERIFY,
			  ac_rsassa_vect14, ARRAY, WITH_SALT),
	XTEST_AC_RSA_CASE(1, TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384,
			  TEE_MODE_SIGN,
			  ac_rsassa_vect14, ARRAY, WITH_SALT),
	XTEST_AC_RSA_CASE(1, TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512,
			  TEE_MODE_VERIFY,
			  ac_rsassa_vect15, ARRAY, WITH_SALT),
	XTEST_AC_RSA_CASE(1, TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512,
			  TEE_MODE_SIGN,
			  ac_rsassa_vect15, ARRAY, WITH_SALT),

	XTEST_AC_RSA_CASE(0, TEE_ALG_RSAES_PKCS1_V1_5, TEE_MODE_DECRYPT,
			  ac_rsaes_pkcs1_v1_5_vect1, ARRAY, WITHOUT_SALT),
	XTEST_AC_RSA_CASE(0, TEE_ALG_RSAES_PKCS1_V1_5, TEE_MODE_ENCRYPT,
			  ac_rsaes_pkcs1_v1_5_vect1, ARRAY, WITHOUT_SALT),
	XTEST_AC_RSA_CASE(1, TEE_ALG_RSAES_PKCS1_V1_5, TEE_MODE_DECRYPT,
			  ac_rsaes_pkcs1_v1_5_vect2, ARRAY, WITHOUT_SALT),
	XTEST_AC_RSA_CASE(1, TEE_ALG_RSAES_PKCS1_V1_5, TEE_MODE_ENCRYPT,
			  ac_rsaes_pkcs1_v1_5_vect2, ARRAY, WITHOUT_SALT),
	XTEST_AC_RSA_CASE(1, TEE_ALG_RSAES_PKCS1_V1_5, TEE_MODE_DECRYPT,
			  ac_rsaes_pkcs1_v1_5_vect15, ARRAY, WITHOUT_SALT),
	XTEST_AC_RSA_CASE(1, TEE_ALG_RSAES_PKCS1_V1_5, TEE_MODE_ENCRYPT,
			  ac_rsaes_pkcs1_v1_5_vect15, ARRAY, WITHOUT_SALT),

	XTEST_AC_RSA_CASE(0, TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1,
			  TEE_MODE_DECRYPT,
			  ac_rsaes_oaep_vect1, ARRAY, WITHOUT_SALT),
	XTEST_AC_RSA_CASE(0, TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1,
			  TEE_MODE_ENCRYPT,
			  ac_rsaes_oaep_vect1, ARRAY, WITHOUT_SALT),
	XTEST_AC_RSA_CASE(1, TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1,
			  TEE_MODE_DECRYPT,
			  ac_rsaes_oaep_vect2, ARRAY, WITHOUT_SALT),
	XTEST_AC_RSA_CASE(1, TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1,
			  TEE_MODE_ENCRYPT,
			  ac_rsaes_oaep_vect2, ARRAY, WITHOUT_SALT),
	XTEST_AC_RSA_CASE(1, TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1,
			  TEE_MODE_DECRYPT,
			  ac_rsaes_oaep_vect10, ARRAY, WITHOUT_SALT),
	XTEST_AC_RSA_CASE(1, TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1,
			  TEE_MODE_ENCRYPT,
			  ac_rsaes_oaep_vect10, ARRAY, WITHOUT_SALT),
	XTEST_AC_RSA_CASE(0, TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256,
			  TEE_MODE_DECRYPT,
			  ac_rsaes_oaep_vect3, ARRAY, WITHOUT_SALT),
	XTEST_AC_RSA_CASE(0, TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256,
			  TEE_MODE_ENCRYPT,
			  ac_rsaes_oaep_vect3, ARRAY, WITHOUT_SALT),
};

static const struct xtest_ac_case xtest_ac_cases_dsa[] = {
	/* DSA tests */
	/* [mod = L=1024, N=160, SHA-1] */
	XTEST_AC_DSA_CASE(1, TEE_ALG_DSA_SHA1, TEE_MODE_VERIFY, ac_dsa_vect1),
	XTEST_AC_DSA_CASE(1, TEE_ALG_DSA_SHA1, TEE_MODE_SIGN, ac_dsa_vect1),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA1, TEE_MODE_VERIFY, ac_dsa_vect2),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA1, TEE_MODE_SIGN, ac_dsa_vect2),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA1, TEE_MODE_VERIFY, ac_dsa_vect3),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA1, TEE_MODE_SIGN, ac_dsa_vect3),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA1, TEE_MODE_VERIFY, ac_dsa_vect4),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA1, TEE_MODE_SIGN, ac_dsa_vect4),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA1, TEE_MODE_VERIFY, ac_dsa_vect5),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA1, TEE_MODE_SIGN, ac_dsa_vect5),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA1, TEE_MODE_VERIFY, ac_dsa_vect6),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA1, TEE_MODE_SIGN, ac_dsa_vect6),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA1, TEE_MODE_VERIFY, ac_dsa_vect7),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA1, TEE_MODE_SIGN, ac_dsa_vect7),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA1, TEE_MODE_VERIFY, ac_dsa_vect8),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA1, TEE_MODE_SIGN, ac_dsa_vect8),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA1, TEE_MODE_VERIFY, ac_dsa_vect9),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA1, TEE_MODE_SIGN, ac_dsa_vect9),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA1, TEE_MODE_VERIFY, ac_dsa_vect10),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA1, TEE_MODE_SIGN, ac_dsa_vect10),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA1, TEE_MODE_VERIFY, ac_dsa_vect11),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA1, TEE_MODE_SIGN, ac_dsa_vect11),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA1, TEE_MODE_VERIFY, ac_dsa_vect12),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA1, TEE_MODE_SIGN, ac_dsa_vect12),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA1, TEE_MODE_VERIFY, ac_dsa_vect13),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA1, TEE_MODE_SIGN, ac_dsa_vect13),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA1, TEE_MODE_VERIFY, ac_dsa_vect14),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA1, TEE_MODE_SIGN, ac_dsa_vect14),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA1, TEE_MODE_VERIFY, ac_dsa_vect15),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA1, TEE_MODE_SIGN, ac_dsa_vect15),
	/* [mod = L=1024, N=160, SHA-224] - GP NOT SUPPORTED */
	/* [mod = L=1024, N=160, SHA-256] - GP NOT SUPPORTED */
	/* [mod = L=1024, N=160, SHA-384] - GP NOT SUPPORTED */
	/* [mod = L=1024, N=160, SHA-512] - GP NOT SUPPORTED */
	/* [mod = L=2048, N=224, SHA-1] - GP NOT SUPPORTED */
	/* [mod = L=2048, N=224, SHA-224] */
	XTEST_AC_DSA_CASE(1, TEE_ALG_DSA_SHA224, TEE_MODE_VERIFY, ac_dsa_vect91),
	XTEST_AC_DSA_CASE(1, TEE_ALG_DSA_SHA224, TEE_MODE_SIGN, ac_dsa_vect91),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA224, TEE_MODE_VERIFY, ac_dsa_vect92),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA224, TEE_MODE_SIGN, ac_dsa_vect92),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA224, TEE_MODE_VERIFY, ac_dsa_vect93),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA224, TEE_MODE_SIGN, ac_dsa_vect93),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA224, TEE_MODE_VERIFY, ac_dsa_vect94),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA224, TEE_MODE_SIGN, ac_dsa_vect94),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA224, TEE_MODE_VERIFY, ac_dsa_vect95),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA224, TEE_MODE_SIGN, ac_dsa_vect95),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA224, TEE_MODE_VERIFY, ac_dsa_vect96),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA224, TEE_MODE_SIGN, ac_dsa_vect96),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA224, TEE_MODE_VERIFY, ac_dsa_vect97),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA224, TEE_MODE_SIGN, ac_dsa_vect97),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA224, TEE_MODE_VERIFY, ac_dsa_vect98),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA224, TEE_MODE_SIGN, ac_dsa_vect98),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA224, TEE_MODE_VERIFY, ac_dsa_vect99),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA224, TEE_MODE_SIGN, ac_dsa_vect99),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA224, TEE_MODE_VERIFY, ac_dsa_vect100),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA224, TEE_MODE_SIGN, ac_dsa_vect100),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA224, TEE_MODE_VERIFY, ac_dsa_vect101),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA224, TEE_MODE_SIGN, ac_dsa_vect101),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA224, TEE_MODE_VERIFY, ac_dsa_vect102),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA224, TEE_MODE_SIGN, ac_dsa_vect102),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA224, TEE_MODE_VERIFY, ac_dsa_vect103),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA224, TEE_MODE_SIGN, ac_dsa_vect103),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA224, TEE_MODE_VERIFY, ac_dsa_vect104),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA224, TEE_MODE_SIGN, ac_dsa_vect104),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA224, TEE_MODE_VERIFY, ac_dsa_vect105),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA224, TEE_MODE_SIGN, ac_dsa_vect105),
	/* [mod = L=2048, N=224, SHA-256] */
	XTEST_AC_DSA_CASE(0, TEE_ALG_DSA_SHA256, TEE_MODE_VERIFY, ac_dsa_vect106),
	XTEST_AC_DSA_CASE(0, TEE_ALG_DSA_SHA256, TEE_MODE_SIGN, ac_dsa_vect106),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_VERIFY, ac_dsa_vect107),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_SIGN, ac_dsa_vect107),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_VERIFY, ac_dsa_vect108),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_SIGN, ac_dsa_vect108),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_VERIFY, ac_dsa_vect109),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_SIGN, ac_dsa_vect109),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_VERIFY, ac_dsa_vect110),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_SIGN, ac_dsa_vect110),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_VERIFY, ac_dsa_vect111),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_SIGN, ac_dsa_vect111),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_VERIFY, ac_dsa_vect112),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_SIGN, ac_dsa_vect112),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_VERIFY, ac_dsa_vect113),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_SIGN, ac_dsa_vect113),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_VERIFY, ac_dsa_vect114),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_SIGN, ac_dsa_vect114),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_VERIFY, ac_dsa_vect115),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_SIGN, ac_dsa_vect115),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_VERIFY, ac_dsa_vect116),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_SIGN, ac_dsa_vect116),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_VERIFY, ac_dsa_vect117),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_SIGN, ac_dsa_vect117),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_VERIFY, ac_dsa_vect118),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_SIGN, ac_dsa_vect118),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_VERIFY, ac_dsa_vect119),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_SIGN, ac_dsa_vect119),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_VERIFY, ac_dsa_vect120),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_SIGN, ac_dsa_vect120),
	/* [mod = L=2048, N=224, SHA-384] - GP NOT SUPPORTED */
	/* [mod = L=2048, N=224, SHA-512] - GP NOT SUPPORTED */
	/* [mod = L=2048, N=256, SHA-1] - GP NOT SUPPORTED */
	/* [mod = L=2048, N=256, SHA-224] */
	XTEST_AC_DSA_CASE(1, TEE_ALG_DSA_SHA224, TEE_MODE_VERIFY, ac_dsa_vect166),
	XTEST_AC_DSA_CASE(1, TEE_ALG_DSA_SHA224, TEE_MODE_SIGN, ac_dsa_vect166),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA224, TEE_MODE_VERIFY, ac_dsa_vect167),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA224, TEE_MODE_SIGN, ac_dsa_vect167),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA224, TEE_MODE_VERIFY, ac_dsa_vect168),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA224, TEE_MODE_SIGN, ac_dsa_vect168),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA224, TEE_MODE_VERIFY, ac_dsa_vect169),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA224, TEE_MODE_SIGN, ac_dsa_vect169),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA224, TEE_MODE_VERIFY, ac_dsa_vect170),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA224, TEE_MODE_SIGN, ac_dsa_vect170),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA224, TEE_MODE_VERIFY, ac_dsa_vect171),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA224, TEE_MODE_SIGN, ac_dsa_vect171),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA224, TEE_MODE_VERIFY, ac_dsa_vect172),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA224, TEE_MODE_SIGN, ac_dsa_vect172),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA224, TEE_MODE_VERIFY, ac_dsa_vect173),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA224, TEE_MODE_SIGN, ac_dsa_vect173),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA224, TEE_MODE_VERIFY, ac_dsa_vect174),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA224, TEE_MODE_SIGN, ac_dsa_vect174),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA224, TEE_MODE_VERIFY, ac_dsa_vect175),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA224, TEE_MODE_SIGN, ac_dsa_vect175),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA224, TEE_MODE_VERIFY, ac_dsa_vect176),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA224, TEE_MODE_SIGN, ac_dsa_vect176),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA224, TEE_MODE_VERIFY, ac_dsa_vect177),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA224, TEE_MODE_SIGN, ac_dsa_vect177),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA224, TEE_MODE_VERIFY, ac_dsa_vect178),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA224, TEE_MODE_SIGN, ac_dsa_vect178),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA224, TEE_MODE_VERIFY, ac_dsa_vect179),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA224, TEE_MODE_SIGN, ac_dsa_vect179),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA224, TEE_MODE_VERIFY, ac_dsa_vect180),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA224, TEE_MODE_SIGN, ac_dsa_vect180),
	/* [mod = L=2048, N=256, SHA-256] */
	XTEST_AC_DSA_CASE(1, TEE_ALG_DSA_SHA256, TEE_MODE_VERIFY, ac_dsa_vect181),
	XTEST_AC_DSA_CASE(1, TEE_ALG_DSA_SHA256, TEE_MODE_SIGN, ac_dsa_vect181),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_VERIFY, ac_dsa_vect182),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_SIGN, ac_dsa_vect182),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_VERIFY, ac_dsa_vect183),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_SIGN, ac_dsa_vect183),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_VERIFY, ac_dsa_vect184),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_SIGN, ac_dsa_vect184),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_VERIFY, ac_dsa_vect185),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_SIGN, ac_dsa_vect185),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_VERIFY, ac_dsa_vect186),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_SIGN, ac_dsa_vect186),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_VERIFY, ac_dsa_vect187),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_SIGN, ac_dsa_vect187),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_VERIFY, ac_dsa_vect188),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_SIGN, ac_dsa_vect188),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_VERIFY, ac_dsa_vect189),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_SIGN, ac_dsa_vect189),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_VERIFY, ac_dsa_vect190),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_SIGN, ac_dsa_vect190),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_VERIFY, ac_dsa_vect191),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_SIGN, ac_dsa_vect191),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_VERIFY, ac_dsa_vect192),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_SIGN, ac_dsa_vect192),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_VERIFY, ac_dsa_vect193),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_SIGN, ac_dsa_vect193),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_VERIFY, ac_dsa_vect194),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_SIGN, ac_dsa_vect194),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_VERIFY, ac_dsa_vect195),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_SIGN, ac_dsa_vect195),
	/* [mod = L=2048, N=256, SHA-384] - GP NOT SUPPORTED */
	/* [mod = L=2048, N=256, SHA-512] - GP NOT SUPPORTED */
	/* [mod = L=3072, N=256, SHA-1] - GP NOT SUPPORTED */
	/* [mod = L=3072, N=256, SHA-224] - GP NOT SUPPORTED */
	/* [mod = L=3072, N=256, SHA-256] */
	XTEST_AC_DSA_CASE(1, TEE_ALG_DSA_SHA256, TEE_MODE_VERIFY, ac_dsa_vect256),
	XTEST_AC_DSA_CASE(1, TEE_ALG_DSA_SHA256, TEE_MODE_SIGN, ac_dsa_vect256),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_VERIFY, ac_dsa_vect257),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_SIGN, ac_dsa_vect257),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_VERIFY, ac_dsa_vect258),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_SIGN, ac_dsa_vect258),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_VERIFY, ac_dsa_vect259),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_SIGN, ac_dsa_vect259),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_VERIFY, ac_dsa_vect260),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_SIGN, ac_dsa_vect260),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_VERIFY, ac_dsa_vect261),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_SIGN, ac_dsa_vect261),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_VERIFY, ac_dsa_vect262),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_SIGN, ac_dsa_vect262),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_VERIFY, ac_dsa_vect263),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_SIGN, ac_dsa_vect263),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_VERIFY, ac_dsa_vect264),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_SIGN, ac_dsa_vect264),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_VERIFY, ac_dsa_vect265),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_SIGN, ac_dsa_vect265),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_VERIFY, ac_dsa_vect266),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_SIGN, ac_dsa_vect266),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_VERIFY, ac_dsa_vect267),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_SIGN, ac_dsa_vect267),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_VERIFY, ac_dsa_vect268),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_SIGN, ac_dsa_vect268),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_VERIFY, ac_dsa_vect269),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_SIGN, ac_dsa_vect269),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_VERIFY, ac_dsa_vect270),
	XTEST_AC_DSA_CASE(15, TEE_ALG_DSA_SHA256, TEE_MODE_SIGN, ac_dsa_vect270),
	/* [mod = L=3072, N=256, SHA-384] - GP NOT SUPPORTED */
	/* [mod = L=3072, N=256, SHA-512] - GP NOT SUPPORTED */
};

static const struct xtest_ac_case xtest_ac_cases_ecdsa[] = {
	/* ECDSA tests */
	/* [P-192] */
	XTEST_AC_ECC_CASE(0, TEE_ALG_ECDSA_P192, TEE_MODE_VERIFY,
			  nist_186_2_ecdsa_testvector_1),
	XTEST_AC_ECC_CASE(0, TEE_ALG_ECDSA_P192, TEE_MODE_SIGN,
			  nist_186_2_ecdsa_testvector_1),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P192, TEE_MODE_VERIFY,
			  nist_186_2_ecdsa_testvector_2),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P192, TEE_MODE_SIGN,
			  nist_186_2_ecdsa_testvector_2),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P192, TEE_MODE_VERIFY,
			  nist_186_2_ecdsa_testvector_3),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P192, TEE_MODE_SIGN,
			  nist_186_2_ecdsa_testvector_3),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P192, TEE_MODE_VERIFY,
			  nist_186_2_ecdsa_testvector_4),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P192, TEE_MODE_SIGN,
			  nist_186_2_ecdsa_testvector_4),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P192, TEE_MODE_VERIFY,
			  nist_186_2_ecdsa_testvector_5),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P192, TEE_MODE_SIGN,
			  nist_186_2_ecdsa_testvector_5),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P192, TEE_MODE_VERIFY,
			  nist_186_2_ecdsa_testvector_6),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P192, TEE_MODE_SIGN,
			  nist_186_2_ecdsa_testvector_6),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P192, TEE_MODE_VERIFY,
			  nist_186_2_ecdsa_testvector_7),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P192, TEE_MODE_SIGN,
			  nist_186_2_ecdsa_testvector_7),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P192, TEE_MODE_VERIFY,
			  nist_186_2_ecdsa_testvector_8),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P192, TEE_MODE_SIGN,
			  nist_186_2_ecdsa_testvector_8),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P192, TEE_MODE_VERIFY,
			  nist_186_2_ecdsa_testvector_9),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P192, TEE_MODE_SIGN,
			  nist_186_2_ecdsa_testvector_9),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P192, TEE_MODE_VERIFY,
			  nist_186_2_ecdsa_testvector_10),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P192, TEE_MODE_SIGN,
			  nist_186_2_ecdsa_testvector_10),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P192, TEE_MODE_VERIFY,
			  nist_186_2_ecdsa_testvector_11),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P192, TEE_MODE_SIGN,
			  nist_186_2_ecdsa_testvector_11),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P192, TEE_MODE_VERIFY,
			  nist_186_2_ecdsa_testvector_12),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P192, TEE_MODE_SIGN,
			  nist_186_2_ecdsa_testvector_12),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P192, TEE_MODE_VERIFY,
			  nist_186_2_ecdsa_testvector_13),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P192, TEE_MODE_SIGN,
			  nist_186_2_ecdsa_testvector_13),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P192, TEE_MODE_VERIFY,
			  nist_186_2_ecdsa_testvector_14),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P192, TEE_MODE_SIGN,
			  nist_186_2_ecdsa_testvector_14),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P192, TEE_MODE_VERIFY,
			  nist_186_2_ecdsa_testvector_15),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P192, TEE_MODE_SIGN,
			  nist_186_2_ecdsa_testvector_15),
	/* [P-224] */
	XTEST_AC_ECC_CASE(1, TEE_ALG_ECDSA_P224, TEE_MODE_VERIFY,
			  nist_186_2_ecdsa_testvector_16),
	XTEST_AC_ECC_CASE(1, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN,
			  nist_186_2_ecdsa_testvector_16),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_VERIFY,
			  nist_186_2_ecdsa_testvector_17),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN,
			  nist_186_2_ecdsa_testvector_17),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_VERIFY,
			  nist_186_2_ecdsa_testvector_18),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN,
			  nist_186_2_ecdsa_testvector_18),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_VERIFY,
			  nist_186_2_ecdsa_testvector_19),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN,
			  nist_186_2_ecdsa_testvector_19),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_VERIFY,
			  nist_186_2_ecdsa_testvector_20),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN,
			  nist_186_2_ecdsa_testvector_20),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_VERIFY,
			  nist_186_2_ecdsa_testvector_21),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN,
			  nist_186_2_ecdsa_testvector_21),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_VERIFY,
			  nist_186_2_ecdsa_testvector_22),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN,
			  nist_186_2_ecdsa_testvector_22),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_VERIFY,
			  nist_186_2_ecdsa_testvector_23),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN,
			  nist_186_2_ecdsa_testvector_23),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_VERIFY,
			  nist_186_2_ecdsa_testvector_24),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN,
			  nist_186_2_ecdsa_testvector_24),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_VERIFY,
			  nist_186_2_ecdsa_testvector_25),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN,
			  nist_186_2_ecdsa_testvector_25),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_VERIFY,
			  nist_186_2_ecdsa_testvector_26),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN,
			  nist_186_2_ecdsa_testvector_26),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_VERIFY,
			  nist_186_2_ecdsa_testvector_27),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN,
			  nist_186_2_ecdsa_testvector_27),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_VERIFY,
			  nist_186_2_ecdsa_testvector_28),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN,
			  nist_186_2_ecdsa_testvector_28),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_VERIFY,
			  nist_186_2_ecdsa_testvector_29),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN,
			  nist_186_2_ecdsa_testvector_29),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_VERIFY,
			  nist_186_2_ecdsa_testvector_30),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P224, TEE_MODE_SIGN,
			  nist_186_2_ecdsa_testvector_30),
	/* [P-256] */
	XTEST_AC_ECC_CASE(1, TEE_ALG_ECDSA_P256, TEE_MODE_VERIFY,
			  nist_186_2_ecdsa_testvector_31),
	XTEST_AC_ECC_CASE(1, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN,
			  nist_186_2_ecdsa_testvector_31),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_VERIFY,
			  nist_186_2_ecdsa_testvector_32),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN,
			  nist_186_2_ecdsa_testvector_32),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_VERIFY,
			  nist_186_2_ecdsa_testvector_33),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN,
			  nist_186_2_ecdsa_testvector_33),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_VERIFY,
			  nist_186_2_ecdsa_testvector_34),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN,
			  nist_186_2_ecdsa_testvector_34),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_VERIFY,
			  nist_186_2_ecdsa_testvector_35),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN,
			  nist_186_2_ecdsa_testvector_35),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_VERIFY,
			  nist_186_2_ecdsa_testvector_36),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN,
			  nist_186_2_ecdsa_testvector_36),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_VERIFY,
			  nist_186_2_ecdsa_testvector_37),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN,
			  nist_186_2_ecdsa_testvector_37),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_VERIFY,
			  nist_186_2_ecdsa_testvector_38),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN,
			  nist_186_2_ecdsa_testvector_38),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_VERIFY,
			  nist_186_2_ecdsa_testvector_39),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN,
			  nist_186_2_ecdsa_testvector_39),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_VERIFY,
			  nist_186_2_ecdsa_testvector_40),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN,
			  nist_186_2_ecdsa_testvector_40),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_VERIFY,
			  nist_186_2_ecdsa_testvector_41),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN,
			  nist_186_2_ecdsa_testvector_41),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_VERIFY,
			  nist_186_2_ecdsa_testvector_42),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN,
			  nist_186_2_ecdsa_testvector_42),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_VERIFY,
			  nist_186_2_ecdsa_testvector_43),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN,
			  nist_186_2_ecdsa_testvector_43),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_VERIFY,
			  nist_186_2_ecdsa_testvector_44),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN,
			  nist_186_2_ecdsa_testvector_44),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_VERIFY,
			  nist_186_2_ecdsa_testvector_45),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN,
			  nist_186_2_ecdsa_testvector_45),
	/* [P-384] */
	XTEST_AC_ECC_CASE(1, TEE_ALG_ECDSA_P384, TEE_MODE_VERIFY,
			  nist_186_2_ecdsa_testvector_46),
	XTEST_AC_ECC_CASE(1, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN,
			  nist_186_2_ecdsa_testvector_46),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_VERIFY,
			  nist_186_2_ecdsa_testvector_47),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN,
			  nist_186_2_ecdsa_testvector_47),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_VERIFY,
			  nist_186_2_ecdsa_testvector_48),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN,
			  nist_186_2_ecdsa_testvector_48),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_VERIFY,
			  nist_186_2_ecdsa_testvector_49),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN,
			  nist_186_2_ecdsa_testvector_49),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_VERIFY,
			  nist_186_2_ecdsa_testvector_50),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN,
			  nist_186_2_ecdsa_testvector_50),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_VERIFY,
			  nist_186_2_ecdsa_testvector_51),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN,
			  nist_186_2_ecdsa_testvector_51),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_VERIFY,
			  nist_186_2_ecdsa_testvector_52),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN,
			  nist_186_2_ecdsa_testvector_52),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_VERIFY,
			  nist_186_2_ecdsa_testvector_53),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN,
			  nist_186_2_ecdsa_testvector_53),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_VERIFY,
			  nist_186_2_ecdsa_testvector_54),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN,
			  nist_186_2_ecdsa_testvector_54),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_VERIFY,
			  nist_186_2_ecdsa_testvector_55),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN,
			  nist_186_2_ecdsa_testvector_55),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_VERIFY,
			  nist_186_2_ecdsa_testvector_56),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN,
			  nist_186_2_ecdsa_testvector_56),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_VERIFY,
			  nist_186_2_ecdsa_testvector_57),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN,
			  nist_186_2_ecdsa_testvector_57),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_VERIFY,
			  nist_186_2_ecdsa_testvector_58),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN,
			  nist_186_2_ecdsa_testvector_58),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_VERIFY,
			  nist_186_2_ecdsa_testvector_59),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN,
			  nist_186_2_ecdsa_testvector_59),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_VERIFY,
			  nist_186_2_ecdsa_testvector_60),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P384, TEE_MODE_SIGN,
			  nist_186_2_ecdsa_testvector_60),
	/* [P-521] */
	XTEST_AC_ECC_CASE(1, TEE_ALG_ECDSA_P521, TEE_MODE_VERIFY,
			  nist_186_2_ecdsa_testvector_61),
	XTEST_AC_ECC_CASE(1, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN,
			  nist_186_2_ecdsa_testvector_61),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_VERIFY,
			  nist_186_2_ecdsa_testvector_62),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN,
			  nist_186_2_ecdsa_testvector_62),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_VERIFY,
			  nist_186_2_ecdsa_testvector_63),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN,
			  nist_186_2_ecdsa_testvector_63),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_VERIFY,
			  nist_186_2_ecdsa_testvector_64),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN,
			  nist_186_2_ecdsa_testvector_64),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_VERIFY,
			  nist_186_2_ecdsa_testvector_65),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN,
			  nist_186_2_ecdsa_testvector_65),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_VERIFY,
			  nist_186_2_ecdsa_testvector_66),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN,
			  nist_186_2_ecdsa_testvector_66),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_VERIFY,
			  nist_186_2_ecdsa_testvector_67),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN,
			  nist_186_2_ecdsa_testvector_67),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_VERIFY,
			  nist_186_2_ecdsa_testvector_68),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN,
			  nist_186_2_ecdsa_testvector_68),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_VERIFY,
			  nist_186_2_ecdsa_testvector_69),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN,
			  nist_186_2_ecdsa_testvector_69),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_VERIFY,
			  nist_186_2_ecdsa_testvector_70),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN,
			  nist_186_2_ecdsa_testvector_70),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_VERIFY,
			  nist_186_2_ecdsa_testvector_71),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN,
			  nist_186_2_ecdsa_testvector_71),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_VERIFY,
			  nist_186_2_ecdsa_testvector_72),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN,
			  nist_186_2_ecdsa_testvector_72),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_VERIFY,
			  nist_186_2_ecdsa_testvector_73),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN,
			  nist_186_2_ecdsa_testvector_73),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_VERIFY,
			  nist_186_2_ecdsa_testvector_74),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN,
			  nist_186_2_ecdsa_testvector_74),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_VERIFY,
			  nist_186_2_ecdsa_testvector_75),
	XTEST_AC_ECC_CASE(15, TEE_ALG_ECDSA_P521, TEE_MODE_SIGN,
			  nist_186_2_ecdsa_testvector_75),
	/* [K-163] - GP NOT SUPPORTED */
	/* [K-233] - GP NOT SUPPORTED */
	/* [K-283] - GP NOT SUPPORTED */
	/* [K-409] - GP NOT SUPPORTED */
	/* [K-571] - GP NOT SUPPORTED */
	/* [B-163] - GP NOT SUPPORTED */
	/* [B-233] - GP NOT SUPPORTED */
	/* [B-283] - GP NOT SUPPORTED */
	/* [B-409] - GP NOT SUPPORTED */
	/* [B-571] - GP NOT SUPPORTED */
};

static const struct xtest_ac_case xtest_ac_cases_sm2[] = {
	XTEST_AC_ECC_CASE(0, TEE_ALG_SM2_PKE, TEE_MODE_ENCRYPT,
			  gmt_0003_part5_c2_sm2_testvector),
	XTEST_AC_ECC_CASE(0, TEE_ALG_SM2_PKE, TEE_MODE_DECRYPT,
			  gmt_0003_part5_c2_sm2_testvector),
	XTEST_AC_ECC_CASE(0, TEE_ALG_SM2_PKE, TEE_MODE_ENCRYPT,
			  sm2_testvector2),

	XTEST_AC_ECC_CASE(0, TEE_ALG_SM2_DSA_SM3, TEE_MODE_VERIFY,
			  gmt_003_part5_a2),
	XTEST_AC_ECC_CASE(0, TEE_ALG_SM2_DSA_SM3, TEE_MODE_SIGN,
			  gmt_003_part5_a2),
};

static const struct xtest_ac_case xtest_ac_eddsa_cases[] = {

	XTEST_AC_EDDSA_CASE(0, TEE_ALG_ED25519, TEE_MODE_SIGN,
			    ed25519_rfc_8032_7_1, 0),
	XTEST_AC_EDDSA_CASE(0, TEE_ALG_ED25519, TEE_MODE_VERIFY,
			    ed25519_rfc_8032_7_1, 0),

	XTEST_AC_EDDSA_CTX_CASE(0, TEE_ALG_ED25519, TEE_MODE_SIGN,
				ed25519ctx_rfc_8032_7_2, 0),
	XTEST_AC_EDDSA_CTX_CASE(0, TEE_ALG_ED25519, TEE_MODE_VERIFY,
				ed25519ctx_rfc_8032_7_2, 0),

	XTEST_AC_EDDSA_CASE(0, TEE_ALG_ED25519, TEE_MODE_SIGN,
			    ed25519ph_rfc_8032_7_3, 1),
	XTEST_AC_EDDSA_CASE(0, TEE_ALG_ED25519, TEE_MODE_VERIFY,
			    ed25519ph_rfc_8032_7_3, 1),
};

static bool create_key(ADBG_Case_t *c, TEEC_Session *s,
		       uint32_t max_key_size, uint32_t key_type,
		       TEE_Attribute *attrs, size_t num_attrs,
		       TEE_ObjectHandle *handle)
{
	size_t n = 0;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		ta_crypt_cmd_allocate_transient_object(c, s, key_type,
			max_key_size, handle)))
		return false;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		ta_crypt_cmd_populate_transient_object(c, s, *handle, attrs,
			num_attrs)))
		return false;

	for (n = 0; n < num_attrs; n++) {
		uint8_t out[512] = { };
		size_t out_size = sizeof(out);

		if (attrs[n].attributeID == TEE_ATTR_ECC_CURVE)
			continue;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_get_object_buffer_attribute(c, s, *handle,
				attrs[n].attributeID, out, &out_size)))
			return false;

		if (out_size < attrs[n].content.ref.length) {
			memmove(out + (attrs[n].content.ref.length - out_size),
				out,
				attrs[n].content.ref.length);
			memset(out, 0, attrs[n].content.ref.length - out_size);
			out_size = attrs[n].content.ref.length;
		}

		if (!ADBG_EXPECT_BUFFER(c, attrs[n].content.ref.buffer,
			attrs[n].content.ref.length, out, out_size))
			return false;
	}

	return true;
}

#define XTEST_NO_CURVE 0xFFFFFFFF /* implementation-defined as per GP spec */

static void xtest_tee_test_4006(ADBG_Case_t *c,
				const struct xtest_ac_case *ac_cases,
				size_t ac_cases_count)
{
	TEEC_Session session = { };
	TEEC_Result res = TEEC_ERROR_NOT_SUPPORTED;
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	TEE_ObjectHandle priv_key_handle = TEE_HANDLE_NULL;
	TEE_ObjectHandle pub_key_handle = TEE_HANDLE_NULL;
	TEE_Attribute key_attrs[8] = { };
	TEE_Attribute algo_params[2] = { };
	size_t num_algo_params = 0;
	uint8_t out[512] = { };
	size_t out_size = 0;
	uint8_t out_enc[512] = { };
	size_t out_enc_size = 0;
	uint8_t ptx_hash[TEE_MAX_HASH_SIZE] = { };
	size_t ptx_hash_size = 0;
	size_t max_key_size = 0;
	size_t num_key_attrs = 0;
	uint32_t ret_orig = 0;
	size_t n = 0;
	uint32_t curve = 0;
	uint32_t pub_key_type = 0;
	uint32_t priv_key_type = 0;
	uint32_t hash_algo = 0;
	uint32_t sha1_algo_id = TEE_ALG_SHA1;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		xtest_teec_open_session(&session, &crypt_user_ta_uuid, NULL,
			&ret_orig)))
		return;

	for (n = 0; n < ac_cases_count; n++) {
		const struct xtest_ac_case *tv = ac_cases + n;

		if (tv->level > level)
			continue;

		if ((tv->algo == TEE_ALG_SM2_PKE ||
		     tv->algo == TEE_ALG_SM2_DSA_SM3) &&
		    !ta_crypt_cmd_is_algo_supported(c, &session, tv->algo,
						    TEE_ECC_CURVE_SM2)) {
			Do_ADBG_Log("SM2 not supported: skip subcase");
			continue;
		}

		if (tv->algo == TEE_ALG_RSASSA_PKCS1_V1_5 &&
		    !ta_crypt_cmd_is_algo_supported(c, &session, tv->algo,
						    TEE_CRYPTO_ELEMENT_NONE)) {
			Do_ADBG_Log("RSASSA_PKCS1_V1_5 not supported: skip subcase");
			continue;
		}

		Do_ADBG_BeginSubCase(c, "Asym Crypto case %d algo 0x%x line %d",
				     (int)n, (unsigned int)tv->algo,
				     (int)tv->line);

		/*
		 * When signing or verifying we're working with the hash of
		 * the payload.
		 */
		if (tv->mode == TEE_MODE_VERIFY || tv->mode == TEE_MODE_SIGN) {
			if (TEE_ALG_GET_MAIN_ALG(tv->algo) == TEE_MAIN_ALGO_ECDSA)
				hash_algo = TEE_ALG_SHA1;
			else if (tv->algo == TEE_ALG_RSASSA_PKCS1_V1_5)
				hash_algo = TEE_ALG_SHA256;
			else
				hash_algo = TEE_ALG_HASH_ALGO(
					TEE_ALG_GET_DIGEST_HASH(tv->algo));

			if (!ADBG_EXPECT_TEEC_SUCCESS(c,
				ta_crypt_cmd_allocate_operation(c, &session,
					&op, hash_algo, TEE_MODE_DIGEST, 0)))
				goto out;

			ptx_hash_size = sizeof(ptx_hash);
			if (!ADBG_EXPECT_TEEC_SUCCESS(c,
				ta_crypt_cmd_digest_do_final(c, & session, op,
					tv->ptx, tv->ptx_len, ptx_hash,
					&ptx_hash_size)))
				goto out;

			/*
			 * When we use DSA algorithms, the size of the hash we
			 * consider equals the min between the size of the
			 * "subprime" in the key and the size of the hash
			 */
			if (TEE_ALG_GET_MAIN_ALG(tv->algo) ==
			    TEE_MAIN_ALGO_DSA) {
				if (tv->params.dsa.sub_prime_len <=
				    ptx_hash_size)
					ptx_hash_size =
						tv->params.dsa.sub_prime_len;
			}

			if (!ADBG_EXPECT_TEEC_SUCCESS(c,
				ta_crypt_cmd_free_operation(c, &session, op)))
				goto out;
		}

		num_algo_params = 0;
		num_key_attrs = 0;
		switch (TEE_ALG_GET_MAIN_ALG(tv->algo)) {
		case TEE_MAIN_ALGO_RSA:
			if (tv->params.rsa.salt_len > 0) {
				algo_params[0].attributeID =
					TEE_ATTR_RSA_PSS_SALT_LENGTH;
				algo_params[0].content.value.a =
					tv->params.rsa.salt_len;
				algo_params[0].content.value.b = 0;
				num_algo_params = 1;
			}

			max_key_size = tv->params.rsa.modulus_len * 8;

			xtest_add_attr(&num_key_attrs, key_attrs,
				       TEE_ATTR_RSA_MODULUS,
				       tv->params.rsa.modulus,
				       tv->params.rsa.modulus_len);
			xtest_add_attr(&num_key_attrs, key_attrs,
				       TEE_ATTR_RSA_PUBLIC_EXPONENT,
				       tv->params.rsa.pub_exp,
				       tv->params.rsa.pub_exp_len);

			if (!ADBG_EXPECT_TRUE(c,
				create_key(c, &session,
					   max_key_size,
					   TEE_TYPE_RSA_PUBLIC_KEY,
					   key_attrs,
					   num_key_attrs,
					   &pub_key_handle)))
				goto out;

			xtest_add_attr(&num_key_attrs, key_attrs,
				       TEE_ATTR_RSA_PRIVATE_EXPONENT,
				       tv->params.rsa.priv_exp,
				       tv->params.rsa.priv_exp_len);

			if (tv->params.rsa.prime1_len != 0) {
				xtest_add_attr(&num_key_attrs, key_attrs,
					       TEE_ATTR_RSA_PRIME1,
					       tv->params.rsa.prime1,
					       tv->params.rsa.prime1_len);
			}

			if (tv->params.rsa.prime2_len != 0) {
				xtest_add_attr(&num_key_attrs, key_attrs,
			       TEE_ATTR_RSA_PRIME2,
			       tv->params.rsa.prime2,
			       tv->params.rsa.prime2_len);
			}

			if (tv->params.rsa.exp1_len != 0) {
				xtest_add_attr(&num_key_attrs, key_attrs,
			       TEE_ATTR_RSA_EXPONENT1,
			       tv->params.rsa.exp1,
			       tv->params.rsa.exp1_len);
			}

			if (tv->params.rsa.exp2_len != 0) {
				xtest_add_attr(&num_key_attrs, key_attrs,
			       TEE_ATTR_RSA_EXPONENT2,
			       tv->params.rsa.exp2,
			       tv->params.rsa.exp2_len);
			}

			if (tv->params.rsa.coeff_len != 0) {
				xtest_add_attr(&num_key_attrs, key_attrs,
			       TEE_ATTR_RSA_COEFFICIENT,
			       tv->params.rsa.coeff,
			       tv->params.rsa.coeff_len);
			}

			if (!ADBG_EXPECT_TRUE(c,
			      create_key(c, &session,
				 max_key_size,
				 TEE_TYPE_RSA_KEYPAIR,
				 key_attrs,
				 num_key_attrs,
				 &priv_key_handle)))
				goto out;
			break;

		case TEE_MAIN_ALGO_DSA:
			max_key_size = tv->params.dsa.prime_len * 8;

			xtest_add_attr(&num_key_attrs, key_attrs,
				       TEE_ATTR_DSA_PRIME,
				       tv->params.dsa.prime,
				       tv->params.dsa.prime_len);
			xtest_add_attr(&num_key_attrs, key_attrs,
				       TEE_ATTR_DSA_SUBPRIME,
				       tv->params.dsa.sub_prime,
				       tv->params.dsa.sub_prime_len);
			xtest_add_attr(&num_key_attrs, key_attrs,
				       TEE_ATTR_DSA_BASE,
				       tv->params.dsa.base,
				       tv->params.dsa.base_len);
			xtest_add_attr(&num_key_attrs, key_attrs,
				       TEE_ATTR_DSA_PUBLIC_VALUE,
				       tv->params.dsa.pub_val,
				       tv->params.dsa.pub_val_len);

			if (!ADBG_EXPECT_TRUE(c,
				create_key(c, &session, max_key_size,
					   TEE_TYPE_DSA_PUBLIC_KEY, key_attrs,
					   num_key_attrs, &pub_key_handle)))
				goto out;

			xtest_add_attr(&num_key_attrs, key_attrs,
				       TEE_ATTR_DSA_PRIVATE_VALUE,
				       tv->params.dsa.priv_val,
				       tv->params.dsa.priv_val_len);

			if (!ADBG_EXPECT_TRUE(c,
				create_key(c, &session, max_key_size,
					   TEE_TYPE_DSA_KEYPAIR, key_attrs,
					   num_key_attrs, &priv_key_handle)))
				goto out;
			break;

		case TEE_MAIN_ALGO_ECDSA:
		case TEE_MAIN_ALGO_SM2_PKE:
		case TEE_MAIN_ALGO_SM2_DSA_SM3:
			switch (tv->algo) {
			case TEE_ALG_ECDSA_P192:
				curve = TEE_ECC_CURVE_NIST_P192;
				pub_key_type = TEE_TYPE_ECDSA_PUBLIC_KEY;
				priv_key_type = TEE_TYPE_ECDSA_KEYPAIR;
				break;
			case TEE_ALG_ECDSA_P224:
				curve = TEE_ECC_CURVE_NIST_P224;
				pub_key_type = TEE_TYPE_ECDSA_PUBLIC_KEY;
				priv_key_type = TEE_TYPE_ECDSA_KEYPAIR;
				break;
			case TEE_ALG_ECDSA_P256:
				curve = TEE_ECC_CURVE_NIST_P256;
				pub_key_type = TEE_TYPE_ECDSA_PUBLIC_KEY;
				priv_key_type = TEE_TYPE_ECDSA_KEYPAIR;
				break;
			case TEE_ALG_ECDSA_P384:
				curve = TEE_ECC_CURVE_NIST_P384;
				pub_key_type = TEE_TYPE_ECDSA_PUBLIC_KEY;
				priv_key_type = TEE_TYPE_ECDSA_KEYPAIR;
				break;
			case TEE_ALG_ECDSA_P521:
				curve = TEE_ECC_CURVE_NIST_P521;
				pub_key_type = TEE_TYPE_ECDSA_PUBLIC_KEY;
				priv_key_type = TEE_TYPE_ECDSA_KEYPAIR;
				break;
			case TEE_ALG_SM2_PKE:
				curve = XTEST_NO_CURVE;
				pub_key_type = TEE_TYPE_SM2_PKE_PUBLIC_KEY;
				priv_key_type = TEE_TYPE_SM2_PKE_KEYPAIR;
				break;
			case TEE_ALG_SM2_DSA_SM3:
				curve = XTEST_NO_CURVE;
				pub_key_type = TEE_TYPE_SM2_DSA_PUBLIC_KEY;
				priv_key_type = TEE_TYPE_SM2_DSA_KEYPAIR;
				break;
			default:
				curve = 0xFF;
				break;
			}

			if (tv->algo == TEE_ALG_ECDSA_P521)
				max_key_size = 521;
			else
				max_key_size = tv->params.ecc.private_len * 8;

			if (curve != XTEST_NO_CURVE)
				xtest_add_attr_value(&num_key_attrs, key_attrs,
					     TEE_ATTR_ECC_CURVE, curve, 0);
			xtest_add_attr(&num_key_attrs, key_attrs,
				       TEE_ATTR_ECC_PUBLIC_VALUE_X,
				       tv->params.ecc.public_x,
				       tv->params.ecc.public_x_len);
			xtest_add_attr(&num_key_attrs, key_attrs,
				       TEE_ATTR_ECC_PUBLIC_VALUE_Y,
				       tv->params.ecc.public_y,
				       tv->params.ecc.public_y_len);

			if (!ADBG_EXPECT_TRUE(c,
				create_key(c, &session, max_key_size,
					   pub_key_type, key_attrs,
					   num_key_attrs, &pub_key_handle)))
				goto out;

			xtest_add_attr(&num_key_attrs, key_attrs,
				       TEE_ATTR_ECC_PRIVATE_VALUE,
				       tv->params.ecc.private,
				       tv->params.ecc.private_len);

			if (!ADBG_EXPECT_TRUE(c,
				create_key(c, &session, max_key_size,
					   priv_key_type, key_attrs,
					   num_key_attrs, &priv_key_handle)))
				goto out;
			break;

		default:
			ADBG_EXPECT_TRUE(c, false);
			goto out;
		}

		out_size = sizeof(out);
		memset(out, 0, sizeof(out));
		switch (tv->mode) {
		case TEE_MODE_ENCRYPT:
			if (!ADBG_EXPECT_TEEC_SUCCESS(c,
				ta_crypt_cmd_allocate_operation(c, &session,
					&op, tv->algo, TEE_MODE_ENCRYPT,
					max_key_size)))
				goto out;

			if (!ADBG_EXPECT_TEEC_SUCCESS(c,
				ta_crypt_cmd_set_operation_key(c, &session, op,
					pub_key_handle)))
				goto out;

			if (!ADBG_EXPECT_TEEC_SUCCESS(c,
				ta_crypt_cmd_free_transient_object(c, &session,
					pub_key_handle)))
				goto out;
			pub_key_handle = TEE_HANDLE_NULL;

			num_algo_params = 0;
			if (tv->algo == TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1 ||
			    tv->algo == TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256) {
				algo_params[0].attributeID =
					TEE_ATTR_RSA_OAEP_MGF_HASH;
				algo_params[0].content.ref.length =
					sizeof(sha1_algo_id);
				algo_params[0].content.ref.buffer =
					&sha1_algo_id;
				num_algo_params = 1;
			}

			out_enc_size = sizeof(out_enc);
			res = ta_crypt_cmd_asymmetric_encrypt(c, &session, op,
					algo_params, num_algo_params, tv->ptx,
					tv->ptx_len, out_enc, &out_enc_size);

			if (tv->algo == TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256 &&
			    res == TEEC_ERROR_NOT_SUPPORTED) {
				Do_ADBG_Log("RSA-OAEP with a different MGF1 hash not supported: skip subcase");
				break;
			}

			if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
				goto out;

			/*
			 * A PS which is random is added when formatting the
			 * message internally of the algorithm so we can't
			 * verify against precomputed values, instead we use the
			 * decrypt operation to see that output is correct.
			 */

			if (!ADBG_EXPECT_TEEC_SUCCESS(c,
				ta_crypt_cmd_free_operation(c, &session, op)))
				goto out;

			if (!ADBG_EXPECT_TEEC_SUCCESS(c,
				ta_crypt_cmd_allocate_operation(c, &session,
					&op, tv->algo, TEE_MODE_DECRYPT,
					max_key_size)))
				goto out;

			if (!ADBG_EXPECT_TEEC_SUCCESS(c,
				ta_crypt_cmd_set_operation_key(c, &session, op,
					priv_key_handle)))
				goto out;

			if (!ADBG_EXPECT_TEEC_SUCCESS(c,
				ta_crypt_cmd_free_transient_object(c, &session,
					priv_key_handle)))
				goto out;

			priv_key_handle = TEE_HANDLE_NULL;

			if (!ADBG_EXPECT_TEEC_SUCCESS(c,
				ta_crypt_cmd_asymmetric_decrypt(c, &session, op,
					algo_params, num_algo_params, out_enc,
					out_enc_size, out, &out_size)))
				goto out;

			(void)ADBG_EXPECT_BUFFER(c, tv->ptx, tv->ptx_len, out,
						 out_size);
			break;

		case TEE_MODE_DECRYPT:
			if (!ADBG_EXPECT_TEEC_SUCCESS(c,
				ta_crypt_cmd_allocate_operation(c, &session,
					&op, tv->algo, TEE_MODE_DECRYPT,
					max_key_size)))
				goto out;

			if (!ADBG_EXPECT_TEEC_SUCCESS(c,
				ta_crypt_cmd_set_operation_key(c, &session, op,
					priv_key_handle)))
				goto out;

			if (!ADBG_EXPECT_TEEC_SUCCESS(c,
				ta_crypt_cmd_free_transient_object(c, &session,
					priv_key_handle)))
				goto out;

			num_algo_params = 0;
			if (tv->algo == TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1 ||
			    tv->algo == TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256) {
				algo_params[0].attributeID =
					TEE_ATTR_RSA_OAEP_MGF_HASH;
				algo_params[0].content.ref.length =
					sizeof(sha1_algo_id);
				algo_params[0].content.ref.buffer =
					&sha1_algo_id;
				num_algo_params = 1;
			}

			priv_key_handle = TEE_HANDLE_NULL;
			res = ta_crypt_cmd_asymmetric_decrypt(c, &session, op,
					algo_params, num_algo_params, tv->ctx,
					tv->ctx_len, out, &out_size);

			if (tv->algo == TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256 &&
			    res == TEEC_ERROR_NOT_SUPPORTED) {
				Do_ADBG_Log("RSA-OAEP with a different MGF1 hash not supported: skip subcase");
				break;
			}

			if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
				goto out;

			(void)ADBG_EXPECT_BUFFER(c, tv->ptx, tv->ptx_len, out,
						 out_size);
			break;

		case TEE_MODE_VERIFY:
			if (!ADBG_EXPECT_TEEC_SUCCESS(c,
				ta_crypt_cmd_allocate_operation(c, &session,
					&op, tv->algo, TEE_MODE_VERIFY,
					max_key_size)))
				goto out;

			if (!ADBG_EXPECT_TEEC_SUCCESS(c,
				ta_crypt_cmd_set_operation_key(c, &session, op,
					pub_key_handle)))
				goto out;

			if (!ADBG_EXPECT_TEEC_SUCCESS(c,
				ta_crypt_cmd_free_transient_object(c, &session,
					pub_key_handle)))
				goto out;

			pub_key_handle = TEE_HANDLE_NULL;

			if (!ADBG_EXPECT_TEEC_SUCCESS(c,
				ta_crypt_cmd_asymmetric_verify(c, &session, op,
					algo_params, num_algo_params, ptx_hash,
					ptx_hash_size, tv->ctx, tv->ctx_len)))
				goto out;
			break;

		case TEE_MODE_SIGN:
			if (!ADBG_EXPECT_TEEC_SUCCESS(c,
				ta_crypt_cmd_allocate_operation(c, &session,
					&op, tv->algo, TEE_MODE_SIGN,
					max_key_size)))
				goto out;

			if (!ADBG_EXPECT_TEEC_SUCCESS(c,
				ta_crypt_cmd_set_operation_key(c, &session, op,
					priv_key_handle)))
				goto out;

			if (!ADBG_EXPECT_TEEC_SUCCESS(c,
				ta_crypt_cmd_free_transient_object(c, &session,
					priv_key_handle)))
				goto out;

			priv_key_handle = TEE_HANDLE_NULL;

			out_size = 0;
			if (!ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_SHORT_BUFFER,
				ta_crypt_cmd_asymmetric_sign(c, &session, op,
					algo_params, num_algo_params, ptx_hash,
					ptx_hash_size, out, &out_size)))
				goto out;

			out_size = 1;
			if (!ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_SHORT_BUFFER,
				ta_crypt_cmd_asymmetric_sign(c, &session, op,
					algo_params, num_algo_params, ptx_hash,
					ptx_hash_size, out, &out_size)))
				goto out;

			out_size = sizeof(out);
			if (!ADBG_EXPECT_TEEC_SUCCESS(c,
				ta_crypt_cmd_asymmetric_sign(c, &session, op,
					algo_params, num_algo_params, ptx_hash,
					ptx_hash_size, out, &out_size)))
				goto out;

			if (TEE_ALG_GET_CHAIN_MODE(tv->algo) ==
			    TEE_CHAIN_MODE_PKCS1_PSS_MGF1 ||
			    tv->algo == TEE_ALG_DSA_SHA1 ||
			    tv->algo == TEE_ALG_DSA_SHA224 ||
			    tv->algo == TEE_ALG_DSA_SHA256 ||
			    TEE_ALG_GET_MAIN_ALG(tv->algo) ==
					    TEE_MAIN_ALGO_ECDSA ||
			    tv->algo == TEE_ALG_SM2_DSA_SM3) {
				if (!ADBG_EXPECT_TEEC_SUCCESS(c,
					ta_crypt_cmd_free_operation(c, &session,
								    op)))
					goto out;
				/*
				 * The salt or K is random so we can't verify
				 * signing against precomputed values, instead
				 * we use the verify operation to see that
				 * output is correct.
				 */
				if (!ADBG_EXPECT_TEEC_SUCCESS(c,
					ta_crypt_cmd_allocate_operation(c,
						&session, &op, tv->algo,
						TEE_MODE_VERIFY, max_key_size)))
					goto out;

				if (!ADBG_EXPECT_TEEC_SUCCESS(c,
					ta_crypt_cmd_set_operation_key(c,
						&session, op, pub_key_handle)))
					goto out;

				if (!ADBG_EXPECT_TEEC_SUCCESS(c,
					ta_crypt_cmd_free_transient_object(c,
						&session, pub_key_handle)))
					goto out;

				pub_key_handle = TEE_HANDLE_NULL;

				if (!ADBG_EXPECT_TEEC_SUCCESS(c,
					ta_crypt_cmd_asymmetric_verify(c,
						&session, op, algo_params,
						num_algo_params, ptx_hash,
						ptx_hash_size, out, out_size)))
					goto out;
			} else {
				(void)ADBG_EXPECT_BUFFER(c, tv->ctx,
							 tv->ctx_len, out,
							 out_size);
			}
			break;

		default:
			break;
		}

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_free_operation(c, &session, op)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_free_transient_object(c, &session,
				pub_key_handle)))
			goto out;
		pub_key_handle = TEE_HANDLE_NULL;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_free_transient_object(c, &session,
				priv_key_handle)))
			goto out;

		priv_key_handle = TEE_HANDLE_NULL;

		Do_ADBG_EndSubCase(c, NULL);
	}
out:
	TEEC_CloseSession(&session);
}

static void xtest_tee_test_4006_rsa(ADBG_Case_t *c)
{
	xtest_tee_test_4006(c, xtest_ac_cases_rsa,
			    ARRAY_SIZE(xtest_ac_cases_rsa));
}
ADBG_CASE_DEFINE(regression, 4006_rsa, xtest_tee_test_4006_rsa,
		"Test TEE Internal API RSA Cipher/Authentication operations");

static void xtest_tee_test_4006_dsa(ADBG_Case_t *c)
{
	xtest_tee_test_4006(c, xtest_ac_cases_dsa,
			    ARRAY_SIZE(xtest_ac_cases_dsa));
}
ADBG_CASE_DEFINE(regression, 4006_dsa, xtest_tee_test_4006_dsa,
		"Test TEE Internal API DSA Cipher/Authentication operations");

static void xtest_tee_test_4006_ecdsa(ADBG_Case_t *c)
{
	xtest_tee_test_4006(c, xtest_ac_cases_ecdsa,
			    ARRAY_SIZE(xtest_ac_cases_ecdsa));
}
ADBG_CASE_DEFINE(regression, 4006_ecdsa, xtest_tee_test_4006_ecdsa,
		"Test TEE Internal API ECDSA Cipher/Authentication operations");

static void xtest_tee_test_4006_sm2(ADBG_Case_t *c)
{
	xtest_tee_test_4006(c, xtest_ac_cases_sm2,
			    ARRAY_SIZE(xtest_ac_cases_sm2));
}
ADBG_CASE_DEFINE(regression, 4006_sm2, xtest_tee_test_4006_sm2,
		"Test TEE Internal API SM2 Cipher/Authentication operations");

#define KEY_ATTR(x, y) { #x, (x), y }

struct key_attrs {
	const char *name;
	uint32_t attr;
	/*
	 * When keysize_check != 0: size of attribute is checked
	 * Expected value is key_size bits except for DH in which case it is
	 * the value of keysize_check.
	 */
	uint32_t keysize_check;
};

static bool is_caam_black_key(uint8_t *buf, size_t size)
{
	/*
	 * This value is a magic number for the a CAAM Black key. This value
	 * must match the value defined in optee-os
	 * core/drivers/crypto/caam/caam_key.c
	 */
	const uint8_t magic_number[4] = {0xFB, 0xBF, 0xAF, 0xCA};

	if (size < sizeof(magic_number))
		return false;

	return !memcmp(buf, magic_number, sizeof(magic_number));
}

static bool test_keygen_attributes(ADBG_Case_t *c, TEEC_Session *s,
				   TEE_ObjectHandle key, uint32_t key_size,
				   struct key_attrs *attrs, size_t num_attrs)
{
	uint8_t out[2048] = { };
	size_t out_size = 0;
	size_t n = 0;
	size_t m = 0;

	for (m = 0; m < num_attrs; m++) {
		if ((attrs[m].attr & TEE_ATTR_BIT_VALUE) == 0) {
			out_size = sizeof(out);
			memset(out, 0, sizeof(out));
			if (!ADBG_EXPECT_TEEC_SUCCESS(c,
				ta_crypt_cmd_get_object_buffer_attribute(c, s,
					key, attrs[m].attr, out, &out_size)))
				return false;

			/*
			 * Check for CAAM black key header. If the buffer holds
			 * a CAAM black key, do not check the key size as the
			 * buffer size and the key size do not match.
			 */
			if (attrs[m].keysize_check &&
			    !is_caam_black_key(out, out_size))
				ADBG_EXPECT_COMPARE_UNSIGNED(c, out_size, <=,
							     key_size / 8);

			if (out_size > 0) {
				/* Check that buffer isn't all zeroes */
				for (n = 0; n < out_size; n++)
					if (out[n] != 0)
						break;
				if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, n, <,
								  out_size))
					return false;
			}
		} else {
			uint32_t a = 0;
			uint32_t b = 0;

			if (!ADBG_EXPECT_TEEC_SUCCESS(c,
				ta_crypt_cmd_get_object_value_attribute(c, s, key,
					attrs[m].attr, &a, &b)))
				return false;
		}
	}
	return true;
}

static bool test_secret_value(ADBG_Case_t *c, TEEC_Session *s,
			      TEE_ObjectHandle key, uint32_t key_size)
{
	const struct key_attrs attrs[] = {
		KEY_ATTR(TEE_ATTR_SECRET_VALUE, true),
	};

	return test_keygen_attributes(c, s, key, key_size,
				      (struct key_attrs *)&attrs,
				      ARRAY_SIZE(attrs));
}


static bool test_rsa_key_pair(ADBG_Case_t *c, TEEC_Session *s,
			      TEE_ObjectHandle key, uint32_t key_size)
{
	const struct key_attrs attrs[] = {
		KEY_ATTR(TEE_ATTR_RSA_MODULUS, true),
		KEY_ATTR(TEE_ATTR_RSA_PUBLIC_EXPONENT, false),
		KEY_ATTR(TEE_ATTR_RSA_PRIVATE_EXPONENT, false),
		KEY_ATTR(TEE_ATTR_RSA_PRIME1, false),
		KEY_ATTR(TEE_ATTR_RSA_PRIME2, false),
		KEY_ATTR(TEE_ATTR_RSA_EXPONENT1, false),
		KEY_ATTR(TEE_ATTR_RSA_EXPONENT2, false),
		KEY_ATTR(TEE_ATTR_RSA_COEFFICIENT, false),
	};

	return test_keygen_attributes(c, s, key, key_size,
				      (struct key_attrs *)&attrs,
				      ARRAY_SIZE(attrs));
}

static bool test_ecc_key_pair(ADBG_Case_t *c, TEEC_Session *s,
			      TEE_ObjectHandle key, uint32_t key_size)
{
	const struct key_attrs attrs[] = {
		KEY_ATTR(TEE_ATTR_ECC_PRIVATE_VALUE, false),
		KEY_ATTR(TEE_ATTR_ECC_PUBLIC_VALUE_X , false),
		KEY_ATTR(TEE_ATTR_ECC_PUBLIC_VALUE_Y , false),
		/* KEY_ATTR(TEE_ATTR_ECC_CURVE, false), - do not test */
	};

	return test_keygen_attributes(c, s, key, key_size,
				      (struct key_attrs *)&attrs,
				      ARRAY_SIZE(attrs));
}

static bool test_dh_key_pair(ADBG_Case_t *c, TEEC_Session *s,
			     TEE_ObjectHandle key, uint32_t check_keysize)
{
	const struct key_attrs attrs[] = {
		KEY_ATTR(TEE_ATTR_DH_PRIME, false),
		KEY_ATTR(TEE_ATTR_DH_BASE, false),
		KEY_ATTR(TEE_ATTR_DH_PUBLIC_VALUE, false),
		KEY_ATTR(TEE_ATTR_DH_PRIVATE_VALUE, check_keysize),
		KEY_ATTR(TEE_ATTR_DH_X_BITS, false),
	};

	return test_keygen_attributes(c, s, key, check_keysize,
				      (struct key_attrs *)&attrs,
				      ARRAY_SIZE(attrs));
}

static bool test_dsa_key_pair(ADBG_Case_t *c, TEEC_Session *s,
			      TEE_ObjectHandle key, uint32_t key_size)
{
	const struct key_attrs attrs[] = {
		KEY_ATTR(TEE_ATTR_DSA_PRIME, true),
		KEY_ATTR(TEE_ATTR_DSA_SUBPRIME, false),
		KEY_ATTR(TEE_ATTR_DSA_BASE, false),
		KEY_ATTR(TEE_ATTR_DSA_PUBLIC_VALUE, false),
		KEY_ATTR(TEE_ATTR_DSA_PRIVATE_VALUE, false),
	};

	return test_keygen_attributes(c, s, key, key_size,
				      (struct key_attrs *)&attrs,
				      ARRAY_SIZE(attrs));
}

static bool test_x25519_key_pair(ADBG_Case_t *c, TEEC_Session *s,
			      TEE_ObjectHandle key, uint32_t key_size)
{
	const struct key_attrs attrs[] = {
		KEY_ATTR(TEE_ATTR_X25519_PRIVATE_VALUE, false),
		KEY_ATTR(TEE_ATTR_X25519_PUBLIC_VALUE, false),
	};

	return test_keygen_attributes(c, s, key, key_size,
				      (struct key_attrs *)&attrs,
				      ARRAY_SIZE(attrs));
}

static bool test_ed25519_key_pair(ADBG_Case_t *c, TEEC_Session *s,
				  TEE_ObjectHandle key, uint32_t key_size)
{
	const struct key_attrs attrs[] = {
		KEY_ATTR(TEE_ATTR_ED25519_PRIVATE_VALUE, false),
		KEY_ATTR(TEE_ATTR_ED25519_PUBLIC_VALUE, false),
	};

	return test_keygen_attributes(c, s, key, key_size,
				      (struct key_attrs *)&attrs,
				      ARRAY_SIZE(attrs));
}

static bool generate_and_test_key(ADBG_Case_t *c, TEEC_Session *s,
				  uint32_t key_type, uint32_t check_keysize,
				  uint32_t key_size,
				  TEE_Attribute *params, size_t param_count)
{
	TEE_ObjectHandle key = TEE_HANDLE_NULL;
	bool ret_val = true;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		ta_crypt_cmd_allocate_transient_object(c, s, key_type, key_size,
						       &key)))
		return false;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		ta_crypt_cmd_generate_key(c, s, key, key_size, params,
					  param_count)))
		return false;

	switch (key_type) {
	case TEE_TYPE_DES:
	case TEE_TYPE_DES3:
		ret_val = ADBG_EXPECT_TRUE(c,
				test_secret_value(c, s, key,
						  key_size + key_size / 7));
		break;
	case TEE_TYPE_AES:
	case TEE_TYPE_HMAC_MD5:
	case TEE_TYPE_HMAC_SHA1:
	case TEE_TYPE_HMAC_SHA224:
	case TEE_TYPE_HMAC_SHA256:
	case TEE_TYPE_HMAC_SHA384:
	case TEE_TYPE_HMAC_SHA512:
	case TEE_TYPE_GENERIC_SECRET:
		ret_val = ADBG_EXPECT_TRUE(c,
				test_secret_value(c, s, key, key_size));
		break;

	case TEE_TYPE_RSA_KEYPAIR:
		ret_val = ADBG_EXPECT_TRUE(c,
				test_rsa_key_pair(c, s, key, key_size));
		break;

	case TEE_TYPE_ECDSA_KEYPAIR:
	case TEE_TYPE_ECDH_KEYPAIR:
		ret_val = ADBG_EXPECT_TRUE(c,
				test_ecc_key_pair(c, s, key, key_size));
		break;

	case TEE_TYPE_DH_KEYPAIR:
		ret_val = ADBG_EXPECT_TRUE(c,
				test_dh_key_pair(c, s, key, check_keysize));
		break;

	case TEE_TYPE_DSA_KEYPAIR:
		ret_val = ADBG_EXPECT_TRUE(c,
				test_dsa_key_pair(c, s, key, key_size));
		break;

	case TEE_TYPE_X25519_KEYPAIR:
		ret_val = ADBG_EXPECT_TRUE(c,
				test_x25519_key_pair(c, s, key, key_size));
		break;

	case TEE_TYPE_ED25519_KEYPAIR:
		ret_val = ADBG_EXPECT_TRUE(c,
				test_ed25519_key_pair(c, s, key, key_size));
		break;

	default:
		ret_val = false;
		break;
	}

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		ta_crypt_cmd_free_transient_object(c, s, key)))
		return false;

	return ret_val;
}

struct key_types_noparam {
	unsigned level;
	const char *name;
	uint32_t key_type;
	uint32_t quanta;
	uint32_t min_size;
	uint32_t max_size;
};

static void keygen_noparams(ADBG_Case_t *c, TEEC_Session *session,
			    const struct key_types_noparam *key_types,
			    size_t num_key_types)
{
	size_t n = 0;
	uint32_t key_size = 0;

	for (n = 0; n < num_key_types; n++) {
		uint32_t min_size = key_types[n].min_size;
		uint32_t max_size = key_types[n].max_size;
		uint32_t quanta = key_types[n].quanta;

		if (key_types[n].level > level)
			continue;

		Do_ADBG_BeginSubCase(c, "Generate %s key", key_types[n].name);

		for (key_size = min_size; key_size <= max_size;
		     key_size += quanta) {
			if (!ADBG_EXPECT_TRUE(c,
				generate_and_test_key(c, session, key_types
					[n].key_type, 1, key_size, NULL, 0)))
				break;
		}

		Do_ADBG_EndSubCase(c, "Generate %s key", key_types[n].name);
	}
}

static void xtest_tee_test_4007_symmetric(ADBG_Case_t *c)
{
	TEEC_Session session = { };
	uint32_t ret_orig = 0;
	static const struct key_types_noparam key_types[] = {
		{ 0, "AES", TEE_TYPE_AES, 64, 128,
		  256 /* valid sizes 128, 192, 256 */ },
		{ 0, "DES", TEE_TYPE_DES, 56, 56, 56 /* valid size 56 */ },
		{ 0, "DES3", TEE_TYPE_DES3, 56, 112,
		  168 /* valid sizes 112, 168 */ },
		{ 0, "HMAC-MD5", TEE_TYPE_HMAC_MD5, 8, 64, 512 },
		{ 0, "HMAC-SHA1", TEE_TYPE_HMAC_SHA1, 8, 80, 512 },
		{ 0, "HMAC-SHA224", TEE_TYPE_HMAC_SHA224, 8, 112, 512 },
		{ 0, "HMAC-SHA256", TEE_TYPE_HMAC_SHA256, 8, 192, 1024 },
		{ 0, "HMAC-SHA384", TEE_TYPE_HMAC_SHA384, 8, 256, 1024 },
		{ 0, "HMAC-SHA512", TEE_TYPE_HMAC_SHA512, 8, 256, 1024 },
		{ 0, "Generic secret", TEE_TYPE_GENERIC_SECRET, 8, 128, 4096 },
	};

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		xtest_teec_open_session(&session, &crypt_user_ta_uuid, NULL,
					&ret_orig)))
		return;

	keygen_noparams(c, &session, key_types, ARRAY_SIZE(key_types));

	TEEC_CloseSession(&session);
}
ADBG_CASE_DEFINE(regression, 4007_symmetric, xtest_tee_test_4007_symmetric,
		"Test TEE Internal API Generate Symmetric key");

static void xtest_tee_test_4007_rsa(ADBG_Case_t *c)
{
	TEEC_Session session = { };
	uint32_t ret_orig = 0;
	static const struct key_types_noparam key_types[] = {
#ifndef CFG_CRYPTO_SE05X
		{ 0, "RSA-256", TEE_TYPE_RSA_KEYPAIR, 1, 256, 256 },
		{ 1, "RSA-384", TEE_TYPE_RSA_KEYPAIR, 1, 384, 384 },
#endif
		{ 1, "RSA-512", TEE_TYPE_RSA_KEYPAIR, 1, 512, 512 },
#ifndef CFG_CRYPTO_SE05X
		{ 1, "RSA-640", TEE_TYPE_RSA_KEYPAIR, 1, 640, 640 },
		{ 1, "RSA-768", TEE_TYPE_RSA_KEYPAIR, 1, 768, 768 },
		{ 1, "RSA-896", TEE_TYPE_RSA_KEYPAIR, 1, 896, 896 },
#endif
		{ 1, "RSA-1024", TEE_TYPE_RSA_KEYPAIR, 1, 1024, 1024 },
		{ 1, "RSA-2048", TEE_TYPE_RSA_KEYPAIR, 1, 2048, 2048 },
		{ 1, "RSA-3072", TEE_TYPE_RSA_KEYPAIR, 1, 3072, 3072 },
		{ 1, "RSA-4096", TEE_TYPE_RSA_KEYPAIR, 1, 4096, 4096 },
	};

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		xtest_teec_open_session(&session, &crypt_user_ta_uuid, NULL,
					&ret_orig)))
		return;

	keygen_noparams(c, &session, key_types, ARRAY_SIZE(key_types));

	TEEC_CloseSession(&session);
}
ADBG_CASE_DEFINE(regression, 4007_rsa, xtest_tee_test_4007_rsa,
		"Test TEE Internal API Generate RSA key");

static void xtest_tee_test_4007_dh(ADBG_Case_t *c)
{
	TEEC_Session session = { };
	uint32_t ret_orig = 0;
	size_t n = 0;
	size_t param_count = 0;
	/*
	 * Note that the key size parameter is not used when creating the keys
	 * but specifying these sizes make it possible to test the expected size
	 * of the private value. This also means that the keysize must match the
	 * size of p or what is specified in private_bits or the equvivalent
	 * size of the subprime parameter.
	 */
	TEE_Attribute params[4] = { };

#define XTEST_DH_GK_DATA(vect) \
	ARRAY(vect ## _p), \
	ARRAY(vect ## _g), \
	&vect ## _private_bits, \
	0, 0
#define XTEST_DH_GK_DATA_SUBPRIME(vect) \
	ARRAY(vect ## _p), \
	ARRAY(vect ## _g), \
	&vect ## _private_bits, \
	ARRAY(vect ## _subprime)
	static const struct {
		unsigned level;
		uint32_t key_size;
		const uint8_t *p;
		size_t p_len;
		const uint8_t *g;
		size_t g_len;
		const uint32_t *private_bits;
		const uint8_t *subprime;
		size_t subprime_len;
	} key_types[] = {
		{ 0, 256, XTEST_DH_GK_DATA(keygen_dh256) },
		{ 0, 320, XTEST_DH_GK_DATA(keygen_dh320) },
		{ 1, 384, XTEST_DH_GK_DATA(keygen_dh384) },
		{ 1, 448, XTEST_DH_GK_DATA(keygen_dh448) },
		{ 1, 512, XTEST_DH_GK_DATA(keygen_dh512) },
		{ 1, 576, XTEST_DH_GK_DATA(keygen_dh576) },
		{ 1, 640, XTEST_DH_GK_DATA(keygen_dh640) },
		{ 1, 704, XTEST_DH_GK_DATA(keygen_dh704) },
		{ 1, 768, XTEST_DH_GK_DATA(keygen_dh768) },
		{ 1, 832, XTEST_DH_GK_DATA(keygen_dh832) },
		{ 1, 896, XTEST_DH_GK_DATA(keygen_dh896) },
		{ 1, 960, XTEST_DH_GK_DATA(keygen_dh960) },
		{ 1, 1024, XTEST_DH_GK_DATA(keygen_dh1024) },
		{ 1, 1088, XTEST_DH_GK_DATA(keygen_dh1088) },
		{ 1, 1152, XTEST_DH_GK_DATA(keygen_dh1152) },
		{ 1, 1216, XTEST_DH_GK_DATA(keygen_dh1216) },
		{ 1, 1280, XTEST_DH_GK_DATA(keygen_dh1280) },
		{ 1, 1344, XTEST_DH_GK_DATA(keygen_dh1344) },
		{ 1, 1408, XTEST_DH_GK_DATA(keygen_dh1408) },
		{ 1, 1472, XTEST_DH_GK_DATA(keygen_dh1472) },
		{ 1, 1536, XTEST_DH_GK_DATA(keygen_dh1536) },
		{ 1, 1600, XTEST_DH_GK_DATA(keygen_dh1600) },
		{ 1, 1664, XTEST_DH_GK_DATA(keygen_dh1664) },
		{ 1, 1728, XTEST_DH_GK_DATA(keygen_dh1728) },
		{ 1, 1792, XTEST_DH_GK_DATA(keygen_dh1792) },
		{ 1, 1856, XTEST_DH_GK_DATA(keygen_dh1856) },
		{ 1, 1920, XTEST_DH_GK_DATA(keygen_dh1920) },
		{ 1, 1984, XTEST_DH_GK_DATA(keygen_dh1984) },
		{ 1, 2048, XTEST_DH_GK_DATA(keygen_dh2048) },
		{ 1, 2048, XTEST_DH_GK_DATA_SUBPRIME(keygen_dh2048_subprime) }
	};

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		xtest_teec_open_session(&session, &crypt_user_ta_uuid, NULL,
					&ret_orig)))
		return;

	for (n = 0; n < ARRAY_SIZE(key_types); n++) {
		if (key_types[n].level > level)
			continue;

		Do_ADBG_BeginSubCase(c,
				     "Generate DH key %d bits - Private bits = %d",
				     key_types[n].key_size,
				     *key_types[n].private_bits);
		param_count = 0;

		xtest_add_attr(&param_count, params,
			       TEE_ATTR_DH_PRIME,
			       key_types[n].p, key_types[n].p_len);

		xtest_add_attr(&param_count, params, TEE_ATTR_DH_BASE,
			       key_types[n].g, key_types[n].g_len);

		if (key_types[n].private_bits != 0) {
			params[param_count].attributeID = TEE_ATTR_DH_X_BITS;

			params[param_count].content.value.a =
				*key_types[n].private_bits;

			params[param_count].content.value.b = 0;
			param_count++;
		}

		if (key_types[n].subprime != 0) {
			xtest_add_attr(&param_count, params,
				       TEE_ATTR_DH_SUBPRIME,
				       key_types[n].subprime,
				       key_types[n].subprime_len);
		}

		if (!ADBG_EXPECT_TRUE(c,
			generate_and_test_key(c, &session, TEE_TYPE_DH_KEYPAIR,
				*key_types[n].private_bits,
				key_types[n]. key_size, params, param_count)))
			break;

		Do_ADBG_EndSubCase(c,
				   "Generate DH key %d bits - Private bits = %d",
				   key_types[n].key_size,
				   *key_types[n].private_bits);
	}

	TEEC_CloseSession(&session);
}
ADBG_CASE_DEFINE(regression, 4007_dh, xtest_tee_test_4007_dh,
		"Test TEE Internal API Generate DH key");

static void xtest_tee_test_4007_dsa(ADBG_Case_t *c)
{
	TEEC_Session session = { };
	uint32_t ret_orig = 0;
	size_t n = 0;
	size_t param_count = 0;
	TEE_Attribute params[4] = { };

#define XTEST_DSA_GK_DATA(vect) \
	ARRAY(vect ## _p), \
	ARRAY(vect ## _g), \
	ARRAY(vect ## _q)
	static const struct {
		unsigned level;
		uint32_t key_size;
		const uint8_t *prime;
		size_t prime_len;
		const uint8_t *base;
		size_t base_len;
		const uint8_t *sub_prime;
		size_t sub_prime_len;
	} key_types[] = {
		{ 0, 1024, XTEST_DSA_GK_DATA(keygen_dsa_test1) },
		{ 0, 512, XTEST_DSA_GK_DATA(keygen_dsa512) },
		{ 0, 576, XTEST_DSA_GK_DATA(keygen_dsa576) },
		{ 0, 640, XTEST_DSA_GK_DATA(keygen_dsa640) },
		{ 0, 704, XTEST_DSA_GK_DATA(keygen_dsa704) },
		{ 0, 768, XTEST_DSA_GK_DATA(keygen_dsa768) },
		{ 0, 832, XTEST_DSA_GK_DATA(keygen_dsa832) },
		{ 0, 896, XTEST_DSA_GK_DATA(keygen_dsa896) },
		{ 0, 960, XTEST_DSA_GK_DATA(keygen_dsa960) },
		{ 0, 1024, XTEST_DSA_GK_DATA(keygen_dsa1024) },
	};

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		xtest_teec_open_session(&session, &crypt_user_ta_uuid, NULL,
					&ret_orig)))
		return;

	for (n = 0; n < ARRAY_SIZE(key_types); n++) {
		if (key_types[n].level > level)
			continue;

		Do_ADBG_BeginSubCase(c, "Generate DSA key %d bits",
				     key_types[n].key_size);
		param_count = 0;


		xtest_add_attr(&param_count, params, TEE_ATTR_DSA_PRIME,
			       key_types[n].prime, key_types[n].prime_len);

		xtest_add_attr(&param_count, params, TEE_ATTR_DSA_SUBPRIME,
			       key_types[n].sub_prime,
			       key_types[n].sub_prime_len);

		xtest_add_attr(&param_count, params, TEE_ATTR_DSA_BASE,
			       key_types[n].base, key_types[n].base_len);

		if (!ADBG_EXPECT_TRUE(c,
			generate_and_test_key(c, &session, TEE_TYPE_DSA_KEYPAIR,
				1, key_types[n]. key_size, params,
				param_count)))
			break;

		Do_ADBG_EndSubCase(c, "Generate DSA key %d bits",
				   key_types[n].key_size);
	}

	TEEC_CloseSession(&session);
}
ADBG_CASE_DEFINE(regression, 4007_dsa, xtest_tee_test_4007_dsa,
		"Test TEE Internal API Generate DSA key");

static void xtest_tee_test_4007_ecc(ADBG_Case_t *c)
{
	TEEC_Session session = { };
	uint32_t ret_orig = 0;
	size_t n = 0;
	size_t param_count = 0;
	TEE_Attribute params[4] = { };

	static const struct {
		unsigned level;
		const char *name;
		uint32_t algo;
		uint32_t curve;
		uint32_t key_size;
	} key_types[] = {
	/* ECDSA */
	{ 0, "ECDSA-192", TEE_TYPE_ECDSA_KEYPAIR, TEE_ECC_CURVE_NIST_P192,
		192 },
	{ 1, "ECDSA-224", TEE_TYPE_ECDSA_KEYPAIR, TEE_ECC_CURVE_NIST_P224,
		224 },
	{ 1, "ECDSA-256", TEE_TYPE_ECDSA_KEYPAIR, TEE_ECC_CURVE_NIST_P256,
		256 },
	{ 1, "ECDSA-384", TEE_TYPE_ECDSA_KEYPAIR, TEE_ECC_CURVE_NIST_P384,
		384 },
	{ 1, "ECDSA-521", TEE_TYPE_ECDSA_KEYPAIR, TEE_ECC_CURVE_NIST_P521,
		521 },

	/* ECDH */
	{ 0, "ECDH-192", TEE_TYPE_ECDH_KEYPAIR, TEE_ECC_CURVE_NIST_P192,
		192 },
	{ 1, "ECDH-224", TEE_TYPE_ECDH_KEYPAIR, TEE_ECC_CURVE_NIST_P224,
		224 },
	{ 1, "ECDH-256", TEE_TYPE_ECDH_KEYPAIR, TEE_ECC_CURVE_NIST_P256,
		256 },
	{ 1, "ECDH-384", TEE_TYPE_ECDH_KEYPAIR, TEE_ECC_CURVE_NIST_P384,
		384 },
	{ 1, "ECDH-521", TEE_TYPE_ECDH_KEYPAIR, TEE_ECC_CURVE_NIST_P521,
		521 },
	};

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		xtest_teec_open_session(&session, &crypt_user_ta_uuid, NULL,
					&ret_orig)))
		return;

	for (n = 0; n < ARRAY_SIZE(key_types); n++) {
		if (key_types[n].level > level)
			continue;

		Do_ADBG_BeginSubCase(c, "Generate %s", key_types[n].name);
		param_count = 0;

		xtest_add_attr_value(&param_count, params, TEE_ATTR_ECC_CURVE,
			             key_types[n].curve, 0);

		if (!ADBG_EXPECT_TRUE(c,
			generate_and_test_key(c, &session, key_types[n].algo,
				0, key_types[n].key_size, params,
				param_count)))
			break;

		Do_ADBG_EndSubCase(c, "Generate %s", key_types[n].name);
	}

	TEEC_CloseSession(&session);
}
ADBG_CASE_DEFINE(regression, 4007_ecc, xtest_tee_test_4007_ecc,
		"Test TEE Internal API Generate ECC key");

static void xtest_tee_test_4007_x25519(ADBG_Case_t *c)
{
	TEEC_Session session = { };
	uint32_t ret_orig = 0;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			xtest_teec_open_session(&session, &crypt_user_ta_uuid,
						NULL, &ret_orig)))
		return;

	if (!ta_crypt_cmd_is_algo_supported(c, &session, TEE_ALG_X25519,
					    TEE_ECC_CURVE_25519)) {
		Do_ADBG_Log("X25519 not supported: skip subcase");
		goto out;
	}

	Do_ADBG_BeginSubCase(c, "Generate X25519 key");

	if (!ADBG_EXPECT_TRUE(c,
			generate_and_test_key(c, &session,
					      TEE_TYPE_X25519_KEYPAIR, 0, 256,
					      NULL, 0)))
		return;

	Do_ADBG_EndSubCase(c, "Generate X25519 key");
out:
	TEEC_CloseSession(&session);
}
ADBG_CASE_DEFINE(regression, 4007_x25519, xtest_tee_test_4007_x25519,
		"Test TEE Internal API Generate X25519 key");


static void xtest_tee_test_4007_ed25519(ADBG_Case_t *c)
{
	TEEC_Session session = { };
	uint32_t ret_orig = 0;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			xtest_teec_open_session(&session, &crypt_user_ta_uuid,
						NULL, &ret_orig)))
		return;

	if (!ta_crypt_cmd_is_algo_supported(c, &session, TEE_ALG_ED25519,
					    TEE_ECC_CURVE_25519)) {
		Do_ADBG_Log("ED25519 not supported: skip subcase");
		goto out;
	}

	Do_ADBG_BeginSubCase(c, "Generate Ed25519 key");

	ADBG_EXPECT_TRUE(c, generate_and_test_key(c, &session,
						  TEE_TYPE_ED25519_KEYPAIR,
						  0, 256, NULL, 0));

	Do_ADBG_EndSubCase(c, "Generate Ed25519 key");
out:
	TEEC_CloseSession(&session);
}
ADBG_CASE_DEFINE(regression, 4007_ed25519, xtest_tee_test_4007_ed25519,
		"Test TEE Internal API Generate ed25519 key");

static void xtest_tee_test_4008(ADBG_Case_t *c)
{
	TEEC_Session session = { };
	uint32_t ret_orig = 0;
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
	TEE_ObjectHandle sv_handle = TEE_HANDLE_NULL;
	TEE_Attribute params[4] = { };
	size_t param_count = 0;
	uint8_t out[2048] = { };
	size_t out_size = 0;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		xtest_teec_open_session(&session, &crypt_user_ta_uuid, NULL,
					&ret_orig)))
		return;

	Do_ADBG_BeginSubCase(c, "Derive DH key success");

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		ta_crypt_cmd_allocate_operation(c, &session, &op,
			TEE_ALG_DH_DERIVE_SHARED_SECRET, TEE_MODE_DERIVE,
			derive_key_max_keysize)))
		goto out;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		ta_crypt_cmd_allocate_transient_object(c, & session,
			TEE_TYPE_DH_KEYPAIR, derive_key_max_keysize,
			&key_handle)))
		goto out;

	xtest_add_attr(&param_count, params, TEE_ATTR_DH_PRIME,
		       ARRAY(derive_key_dh_prime));

	xtest_add_attr(&param_count, params, TEE_ATTR_DH_BASE,
		       ARRAY(derive_key_dh_base));

	xtest_add_attr(&param_count, params, TEE_ATTR_DH_PUBLIC_VALUE,
		       ARRAY(derive_key_dh_public_value));

	xtest_add_attr(&param_count, params, TEE_ATTR_DH_PRIVATE_VALUE,
		       ARRAY(derive_key_dh_private_value));

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		ta_crypt_cmd_populate_transient_object(c, &session, key_handle,
			params, param_count)))
		goto out;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		ta_crypt_cmd_set_operation_key(c, &session, op, key_handle)))
		goto out;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		ta_crypt_cmd_free_transient_object(c, & session, key_handle)))
		goto out;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		ta_crypt_cmd_allocate_transient_object(c, &session,
			TEE_TYPE_GENERIC_SECRET, derive_key_max_keysize,
			&sv_handle)))
		goto out;

	/* reuse but reset params and param-count */
	param_count = 0;

	xtest_add_attr(&param_count, params, TEE_ATTR_DH_PUBLIC_VALUE,
		       ARRAY(derive_key_dh_public_value_2));

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		ta_crypt_cmd_derive_key(c, &session, op, sv_handle, params,
			param_count)))
		goto out;

	out_size = sizeof(out);
	memset(out, 0, sizeof(out));
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		ta_crypt_cmd_get_object_buffer_attribute(c, &session, sv_handle,
			TEE_ATTR_SECRET_VALUE, out, &out_size)))
		goto out;

	if (!ADBG_EXPECT_BUFFER(c, derive_key_dh_shared_secret,
				sizeof(derive_key_dh_shared_secret), out,
				out_size))
		goto out;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		ta_crypt_cmd_free_operation(c, &session, op)))
		goto out;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		ta_crypt_cmd_free_transient_object(c, &session, sv_handle)))
		goto out;
out:
	Do_ADBG_EndSubCase(c, "Derive DH key success");
	TEEC_CloseSession(&session);
}
ADBG_CASE_DEFINE(regression, 4008, xtest_tee_test_4008,
		"Test TEE Internal API Derive key");

static void xtest_tee_test_4009(ADBG_Case_t *c)
{
	TEEC_Session session = { };
	uint32_t ret_orig = 0;
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
	TEE_ObjectHandle sv_handle = TEE_HANDLE_NULL;
	TEE_Attribute params[4] = { };
	size_t param_count = 0;
	uint8_t out[2048] = { };
	size_t out_size = 0;
	uint32_t size_bytes = 0;
	uint32_t i = 0;
	struct derive_key_ecdh_t const *pt = NULL;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		xtest_teec_open_session(&session, &crypt_user_ta_uuid, NULL,
					&ret_orig)))
		return;

	for (i = 0; i < ARRAY_SIZE(derive_key_ecdh); i++) {
		pt = &derive_key_ecdh[i];

		if (pt->level > level)
			continue;

		Do_ADBG_BeginSubCase(c, "Derive ECDH key - algo = 0x%x",
				     pt->algo);
		size_bytes = (pt->keysize + 7) / 8;
		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_allocate_operation(c, &session, &op,
				pt->algo,
				TEE_MODE_DERIVE, pt->keysize)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_allocate_transient_object(c, & session,
				TEE_TYPE_ECDH_KEYPAIR, pt->keysize,
				&key_handle)))
			goto out;

		param_count = 0;
		xtest_add_attr_value(&param_count, params,
				     TEE_ATTR_ECC_CURVE, pt->curve, 0);
		xtest_add_attr(&param_count, params,
			       TEE_ATTR_ECC_PRIVATE_VALUE,
			       pt->private, size_bytes);
		/*
		 * The public value is not used, but we should provide a valid
		 * one to avoid rejection in case TEE_PopulateTransientObject()
		 * checks for key validity.
		 */
		xtest_add_attr(&param_count, params,
			       TEE_ATTR_ECC_PUBLIC_VALUE_X,
			       pt->public_x, size_bytes);
		xtest_add_attr(&param_count, params,
			       TEE_ATTR_ECC_PUBLIC_VALUE_Y,
			       pt->public_y, size_bytes);

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
				ta_crypt_cmd_populate_transient_object(c,
					&session,
					key_handle, params, param_count)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
				ta_crypt_cmd_set_operation_key(c, &session, op,
					key_handle)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
				ta_crypt_cmd_free_transient_object(c, & session,
					key_handle)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_allocate_transient_object(c, &session,
				TEE_TYPE_GENERIC_SECRET, size_bytes * 8,
				&sv_handle)))
			goto out;

		/* reuse but reset params and param-count */
		param_count = 0;

		xtest_add_attr(&param_count, params,
			       TEE_ATTR_ECC_PUBLIC_VALUE_X,
			       pt->public_x, size_bytes);
		xtest_add_attr(&param_count, params,
			       TEE_ATTR_ECC_PUBLIC_VALUE_Y,
			       pt->public_y, size_bytes);

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_derive_key(c, &session, op, sv_handle,
					        params, param_count)))
			goto out;

		out_size = sizeof(out);
		memset(out, 0, sizeof(out));
		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_get_object_buffer_attribute(c, &session,
				sv_handle,
				TEE_ATTR_SECRET_VALUE, out, &out_size)))
			goto out;

		if (!ADBG_EXPECT_BUFFER(c, pt->out, size_bytes,
					out, out_size))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_free_operation(c, &session, op)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_free_transient_object(c, &session,
							   sv_handle)))
			goto out;

		Do_ADBG_EndSubCase(c, "Derive ECDH key - algo = 0x%x",
				   pt->algo);
	}

	goto noerror;

out:
	Do_ADBG_EndSubCase(c, "Derive ECDH key - algo = 0x%x", pt->algo);

noerror:
	TEEC_CloseSession(&session);
}
ADBG_CASE_DEFINE(regression, 4009, xtest_tee_test_4009,
		"Test TEE Internal API Derive key ECDH");

static void xtest_tee_test_4010(ADBG_Case_t *c)
{
	TEEC_Session session = { };
	uint32_t ret_orig = 0;
	TEE_ObjectHandle o = TEE_HANDLE_NULL;
	static const uint8_t large_key[1024] = { 1, 2, 3, 4, 5, 6 };
	static const TEE_Attribute attr = {
		.attributeID = TEE_ATTR_SECRET_VALUE,
		.content.ref.buffer = (void *)large_key,
		.content.ref.length = sizeof(large_key),
	};

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		xtest_teec_open_session(&session, &crypt_user_ta_uuid, NULL,
					&ret_orig)))
		return;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		ta_crypt_cmd_allocate_transient_object(c, &session,
			TEE_TYPE_HMAC_SHA256, 1024, &o)))
		goto out;

	ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_TARGET_DEAD,
		ta_crypt_cmd_populate_transient_object(c, &session, o,
						       &attr, 1));

out:
	TEEC_CloseSession(&session);
}
ADBG_CASE_DEFINE(regression, 4010, xtest_tee_test_4010,
		"Test TEE Internal API create transient object (negative)");

static void xtest_tee_test_4011(ADBG_Case_t *c)
{
	TEEC_Session s = { };
	size_t key_size = 512;
	TEE_ObjectHandle key = TEE_HANDLE_NULL;
	TEE_OperationHandle ops = TEE_HANDLE_NULL;
	TEE_OperationHandle opv = TEE_HANDLE_NULL;
	TEE_OperationHandle ope = TEE_HANDLE_NULL;
	TEE_OperationHandle opd = TEE_HANDLE_NULL;
	uint32_t ret_orig = 0;
	uint8_t in[TEE_SHA1_HASH_SIZE] = { };
	uint8_t out[1024] = { };
	uint8_t tmp[1024] = { };
	size_t out_size = 0;
	size_t tmp_size = 0;
	size_t n = 0;
	size_t m = 0;
	size_t i = 0;

	/* Setup session, initialize message to sign, create a keypair */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, xtest_teec_open_session(&s,
			&crypt_user_ta_uuid, NULL, &ret_orig)))
		return;
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, ta_crypt_cmd_random_number_generate(c,
			&s, in, sizeof(in))))
		goto out;
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, ta_crypt_cmd_allocate_transient_object(
			c, &s, TEE_TYPE_RSA_KEYPAIR, key_size, &key)))
		goto out;
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, ta_crypt_cmd_generate_key(c, &s,
			key, key_size, NULL, 0)))
		goto out;

	/* Allocate operations for sign, verify, encrypt and decrypt */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, ta_crypt_cmd_allocate_operation(c, &s,
			&ops, TEE_ALG_RSASSA_PKCS1_V1_5_SHA1, TEE_MODE_SIGN,
			key_size)))
		goto out;
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, ta_crypt_cmd_allocate_operation(c, &s,
			&opv, TEE_ALG_RSASSA_PKCS1_V1_5_SHA1, TEE_MODE_VERIFY,
			key_size)))
		goto out;
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, ta_crypt_cmd_allocate_operation(c, &s,
			&ope, TEE_ALG_RSA_NOPAD, TEE_MODE_ENCRYPT, key_size)))
		goto out;
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, ta_crypt_cmd_allocate_operation(c, &s,
			&opd, TEE_ALG_RSA_NOPAD, TEE_MODE_DECRYPT, key_size)))
		goto out;

	/* Assign the keypair to all operations */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		ta_crypt_cmd_set_operation_key(c, &s, ops, key)))
		goto out;
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		ta_crypt_cmd_set_operation_key(c, &s, opv, key)))
		goto out;
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		ta_crypt_cmd_set_operation_key(c, &s, ope, key)))
		goto out;
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		ta_crypt_cmd_set_operation_key(c, &s, opd, key)))
		goto out;

	/*
	 * The core of the test case is inspired by the one in libtomcrypt:
	 * https://github.com/libtom/libtomcrypt/blob/6ad52252688bb34f90b5e79da4830a927e87b81f/testprof/rsa_test.c#L398
	 *
	 * Testcase for Bleichenbacher attack
	 *
	 * (1) Create a valid signature
	 * (2) Check that it can be verified
	 * (3) Transform the package to fetch plain text (using the encrypt
	 *     operation in GP TEE Internal API)
	 * (4) Forge the structure of PKCS#1-EMSA encoded data
	 * (4.1) Search for start and end of the padding string
	 * (4.2) Move the signature to the front of the padding string
	 * (4.3) Zero the message until the end
	 * (5) Transform the package back (using the decrypt operation in
	 *     GP TEE Internal API)
	 * (6) The result should not be valid if the implementation is robust.
	 */


	for (i = 0; i < 9; i++) {
		Do_ADBG_Log("Iteration %zu", i);

		/* 1 */
		out_size = sizeof(out);
		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_asymmetric_sign(c, &s, ops, NULL, 0,
				in, sizeof(in), out, &out_size)))
			goto out;

		/* 2 */
		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_asymmetric_verify(c, &s, opv, NULL, 0,
				in, sizeof(in), out, out_size)))
			goto out;

		/* 3 */
		tmp_size = sizeof(tmp);
		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_asymmetric_encrypt(c, &s, ope, NULL, 0,
				out, out_size, tmp, &tmp_size)))
			goto out;

		if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, tmp_size, <=, sizeof(tmp)))
			goto out;

		/* 4.1 */
		for (n = 0; n < tmp_size - i; n++)
			if (tmp[n] == 0xff)
				break;

		/* Shall find at least a padding start before buffer end */
	        if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, n, <, tmp_size - i - 1))
			goto out;

		for (m = n + 1; m < tmp_size; m++)
			if (tmp[m] != 0xff)
				break;

		/* 4.2 */
		memmove(tmp + n + i, tmp + m, tmp_size - m);

		/* 4.3 */
		n = n + i + tmp_size - m;

		/* Prevent overrun when zeroing buffer end */
		if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, n, <=, tmp_size))
			goto out;

		memset(tmp + n, 0, tmp_size - n);

		/* 5 */
		out_size = sizeof(out);
		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_asymmetric_decrypt(c, &s, opd, NULL, 0,
				tmp, tmp_size, out, &out_size)))
			goto out;

		/* 6 */
		if (!ADBG_EXPECT_TEEC_RESULT(c, TEE_ERROR_SIGNATURE_INVALID,
			ta_crypt_cmd_asymmetric_verify(c, &s, opv, NULL, 0,
				in, sizeof(in), out, out_size)))
			goto out;
	}

out:
	TEEC_CloseSession(&s);
}
ADBG_CASE_DEFINE(regression, 4011, xtest_tee_test_4011,
		"Test TEE Internal API Bleichenbacher attack (negative)");

static void xtest_tee_test_4012(ADBG_Case_t *c)
{
	TEEC_Result res = TEEC_SUCCESS;
	TEEC_Session session = { };
	uint32_t ret_orig = 0;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	/* Fortuna PRNG requires seed <= 32 bytes */
	uint8_t pool_input[32] = { };
	time_t t = 0;
	struct tm tm_local = { };

	t = time(NULL);
	tm_local = *localtime(&t);

	memcpy((void *)pool_input, (void *)&tm_local,
	       sizeof(pool_input) < sizeof(tm_local) ?
	       sizeof(pool_input) : sizeof(tm_local));


	op.params[0].tmpref.buffer = pool_input;
	op.params[0].tmpref.size = sizeof(pool_input);
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_NONE,
					 TEEC_NONE,
					 TEEC_NONE);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		xtest_teec_open_session(&session, &crypt_user_ta_uuid, NULL,
					&ret_orig)))
		return;

       res = TEEC_InvokeCommand(&session, TA_CRYPT_CMD_SEED_RNG_POOL,
				&op, &ret_orig);
	if (res == TEEC_ERROR_ITEM_NOT_FOUND &&
	    ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, ret_orig,
					  TEEC_ORIGIN_TRUSTED_APP))
		Do_ADBG_Log("System PTA not available, skipping test 4012");
	else
		ADBG_EXPECT_TEEC_SUCCESS(c, res);

	TEEC_CloseSession(&session);
}
ADBG_CASE_DEFINE(regression, 4012, xtest_tee_test_4012,
		"Test seeding RNG entropy");

static void xtest_tee_test_4013(ADBG_Case_t *c)
{
	TEEC_Result res = TEEC_SUCCESS;
	TEEC_Session session = { };
	uint32_t ret_orig = 0;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint8_t key[32] = { };
	uint8_t extra_data[32] = { };

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE,
					 TEEC_NONE,
					 TEEC_NONE,
					 TEEC_NONE);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			xtest_teec_open_session(&session, &crypt_user_ta_uuid,
						NULL, &ret_orig)))
		return;

	res = TEEC_InvokeCommand(&session, TA_CRYPT_CMD_DERIVE_TA_UNIQUE_KEY,
				 &op, &ret_orig);
	if (res == TEEC_ERROR_ITEM_NOT_FOUND &&
	    ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, ret_orig,
					  TEEC_ORIGIN_TRUSTED_APP)) {
		Do_ADBG_Log("System PTA not available, skipping test 4013");
		goto out;
	}
	ADBG_EXPECT_TEEC_SUCCESS(c, res);

	/* Negative test using non-secure memory */
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE,
					 TEEC_NONE);

	op.params[0].tmpref.buffer = extra_data;
	op.params[0].tmpref.size = sizeof(extra_data);
	op.params[1].tmpref.buffer = key;
	op.params[1].tmpref.size = sizeof(key);
	(void)ADBG_EXPECT_TEEC_RESULT(c,
			TEEC_ERROR_SECURITY,
			TEEC_InvokeCommand(&session,
					   TA_CRYPT_CMD_DERIVE_TA_UNIQUE_KEY_SHM,
					   &op,
					   &ret_orig));

out:
	TEEC_CloseSession(&session);
}
ADBG_CASE_DEFINE(regression, 4013, xtest_tee_test_4013,
		"Test generation of device unique TA keys");

static void xtest_tee_test_4014(ADBG_Case_t *c)
{
	TEEC_Session session = { };
	uint32_t ret_orig = 0;
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	TEE_ObjectHandle keyA = TEE_HANDLE_NULL;
	TEE_ObjectHandle eph_keyA = TEE_HANDLE_NULL;
	TEE_ObjectHandle keyB = TEE_HANDLE_NULL;
	TEE_ObjectHandle eph_keyB = TEE_HANDLE_NULL;
	TEE_ObjectHandle sv_handle = TEE_HANDLE_NULL;
	TEE_Attribute params[9] = { };
	size_t param_count = 0;
	uint8_t out[128] = { };
	size_t out_size = 0;
	uint8_t conf_A[32] = { };
	uint8_t conf_B[32] = { };

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		xtest_teec_open_session(&session, &crypt_user_ta_uuid, NULL,
					&ret_orig)))
		return;

	if (!ta_crypt_cmd_is_algo_supported(c, &session, TEE_ALG_SM2_KEP,
					    TEE_ECC_CURVE_SM2)) {
		Do_ADBG_Log("SM2 KEP not supported: skip subcase");
		goto out;
	}

	Do_ADBG_BeginSubCase(c, "Initiator side");

	/*
	 * Key exchange protocol running on user A's side. A is initiator.
	 */

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		ta_crypt_cmd_allocate_operation(c, &session, &op,
			TEE_ALG_SM2_KEP, TEE_MODE_DERIVE, 512)))
		goto out;

	/* Allocate and initialize keypair of user A */

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		ta_crypt_cmd_allocate_transient_object(c, &session,
			TEE_TYPE_SM2_KEP_KEYPAIR, 256, &keyA)))
		goto out;

	param_count = 0;

	xtest_add_attr(&param_count, params, TEE_ATTR_ECC_PUBLIC_VALUE_X,
		       ARRAY(gmt_003_part5_b2_public_xA));

	xtest_add_attr(&param_count, params, TEE_ATTR_ECC_PUBLIC_VALUE_Y,
		       ARRAY(gmt_003_part5_b2_public_yA));

	xtest_add_attr(&param_count, params, TEE_ATTR_ECC_PRIVATE_VALUE,
		       ARRAY(gmt_003_part5_b2_private_A));

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		ta_crypt_cmd_populate_transient_object(c, &session, keyA,
			params, param_count)))
		goto out;

	/*
	 * Allocate and set ephemeral key of user A. Note: it is a regular ECC
	 * key -- we don't use the *_EPHEMERAL_* attributes flags which are
	 * reserved for use in TEE_DeriveKey() to pass the ephermeral key of
	 * user B.
	 */

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		ta_crypt_cmd_allocate_transient_object(c, &session,
			TEE_TYPE_SM2_KEP_KEYPAIR, 256, &eph_keyA)))
		goto out;

	param_count = 0;

	xtest_add_attr(&param_count, params, TEE_ATTR_ECC_PUBLIC_VALUE_X,
		       ARRAY(gmt_003_part5_b2_eph_public_xA));

	xtest_add_attr(&param_count, params, TEE_ATTR_ECC_PUBLIC_VALUE_Y,
		       ARRAY(gmt_003_part5_b2_eph_public_yA));

	xtest_add_attr(&param_count, params, TEE_ATTR_ECC_PRIVATE_VALUE,
		       ARRAY(gmt_003_part5_b2_eph_private_A));

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		ta_crypt_cmd_populate_transient_object(c, &session, eph_keyA,
			params, param_count)))
		goto out;

	/* Associate user A keys with operation */

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		ta_crypt_cmd_set_operation_key2(c, &session, op, keyA,
						eph_keyA)))
		goto out;

	/* Keys have been set, free key objects */

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		ta_crypt_cmd_free_transient_object(c, &session, keyA)))
		goto out;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		ta_crypt_cmd_free_transient_object(c, &session, eph_keyA)))
		goto out;

	/* Allocate output object */

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		ta_crypt_cmd_allocate_transient_object(c, &session,
			TEE_TYPE_GENERIC_SECRET,
			sizeof(gmt_003_part5_b2_shared_secret),
			&sv_handle)))
		goto out;

	/* Set key derivation parameters: user A role, user B information */

	params[0].attributeID = TEE_ATTR_SM2_KEP_USER;
	params[0].content.value.a = 0; /* Initiator role */
	params[0].content.value.b = 0; /* Not used */
	param_count = 1;

	xtest_add_attr(&param_count, params, TEE_ATTR_ECC_PUBLIC_VALUE_X,
		       ARRAY(gmt_003_part5_b2_public_xB));

	xtest_add_attr(&param_count, params, TEE_ATTR_ECC_PUBLIC_VALUE_Y,
		       ARRAY(gmt_003_part5_b2_public_yB));

	xtest_add_attr(&param_count, params,
		       TEE_ATTR_ECC_EPHEMERAL_PUBLIC_VALUE_X,
		       ARRAY(gmt_003_part5_b2_eph_public_xB));

	xtest_add_attr(&param_count, params,
		       TEE_ATTR_ECC_EPHEMERAL_PUBLIC_VALUE_Y,
		       ARRAY(gmt_003_part5_b2_eph_public_yB));

	xtest_add_attr(&param_count, params, TEE_ATTR_SM2_ID_INITIATOR,
		       ARRAY(gmt_003_part5_b2_id_A));

	xtest_add_attr(&param_count, params, TEE_ATTR_SM2_ID_RESPONDER,
		       ARRAY(gmt_003_part5_b2_id_B));

	xtest_add_attr(&param_count, params, TEE_ATTR_SM2_KEP_CONFIRMATION_IN,
		       ARRAY(gmt_003_part5_b2_conf_B));

	xtest_add_attr(&param_count, params, TEE_ATTR_SM2_KEP_CONFIRMATION_OUT,
		       ARRAY(conf_A));

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		ta_crypt_cmd_derive_key(c, &session, op, sv_handle, params,
			param_count)))
		goto out;

	out_size = sizeof(out);
	memset(out, 0, sizeof(out));
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		ta_crypt_cmd_get_object_buffer_attribute(c, &session, sv_handle,
			TEE_ATTR_SECRET_VALUE, out, &out_size)))
		goto out;

	/* Check derived key */
	if (!ADBG_EXPECT_BUFFER(c, gmt_003_part5_b2_shared_secret,
				sizeof(gmt_003_part5_b2_shared_secret), out,
				out_size))
		goto out;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		ta_crypt_cmd_free_operation(c, &session, op)))
		goto out;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		ta_crypt_cmd_free_transient_object(c, &session, sv_handle)))
		goto out;

	Do_ADBG_EndSubCase(c, "Initiator side");

	Do_ADBG_BeginSubCase(c, "Responder side");

	/*
	 * Key derivation on user B's side
	 */

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		ta_crypt_cmd_allocate_operation(c, &session, &op,
			TEE_ALG_SM2_KEP, TEE_MODE_DERIVE, 512)))
		goto out;

	/* Allocate and initialize keypair of user B */

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		ta_crypt_cmd_allocate_transient_object(c, &session,
			TEE_TYPE_SM2_KEP_KEYPAIR, 256, &keyB)))
		goto out;

	param_count = 0;

	xtest_add_attr(&param_count, params, TEE_ATTR_ECC_PUBLIC_VALUE_X,
		       ARRAY(gmt_003_part5_b2_public_xB));

	xtest_add_attr(&param_count, params, TEE_ATTR_ECC_PUBLIC_VALUE_Y,
		       ARRAY(gmt_003_part5_b2_public_yB));

	xtest_add_attr(&param_count, params, TEE_ATTR_ECC_PRIVATE_VALUE,
		       ARRAY(gmt_003_part5_b2_private_B));

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		ta_crypt_cmd_populate_transient_object(c, &session, keyB,
			params, param_count)))
		goto out;

	/* Allocate and set ephemeral key of user B */

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		ta_crypt_cmd_allocate_transient_object(c, &session,
			TEE_TYPE_SM2_KEP_KEYPAIR, 256, &eph_keyB)))
		goto out;

	param_count = 0;

	xtest_add_attr(&param_count, params, TEE_ATTR_ECC_PUBLIC_VALUE_X,
		       ARRAY(gmt_003_part5_b2_eph_public_xB));

	xtest_add_attr(&param_count, params, TEE_ATTR_ECC_PUBLIC_VALUE_Y,
		       ARRAY(gmt_003_part5_b2_eph_public_yB));

	xtest_add_attr(&param_count, params, TEE_ATTR_ECC_PRIVATE_VALUE,
		       ARRAY(gmt_003_part5_b2_eph_private_B));

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		ta_crypt_cmd_populate_transient_object(c, &session, eph_keyB,
			params, param_count)))
		goto out;

	/* Associate user B keys with operation */

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		ta_crypt_cmd_set_operation_key2(c, &session, op, keyB,
						eph_keyB)))
		goto out;

	/* Keys have been set, free key objects */

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		ta_crypt_cmd_free_transient_object(c, &session, keyB)))
		goto out;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		ta_crypt_cmd_free_transient_object(c, &session, eph_keyB)))
		goto out;

	/* Allocate output object */

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		ta_crypt_cmd_allocate_transient_object(c, &session,
			TEE_TYPE_GENERIC_SECRET,
			sizeof(gmt_003_part5_b2_shared_secret),
			&sv_handle)))
		goto out;

	/* Set key derivation parameters: user B role, user A information */

	params[0].attributeID = TEE_ATTR_SM2_KEP_USER;
	params[0].content.value.a = 1; /* Responder role */
	params[0].content.value.b = 0; /* Not used */
	param_count = 1;

	xtest_add_attr(&param_count, params, TEE_ATTR_ECC_PUBLIC_VALUE_X,
		       ARRAY(gmt_003_part5_b2_public_xA));

	xtest_add_attr(&param_count, params, TEE_ATTR_ECC_PUBLIC_VALUE_Y,
		       ARRAY(gmt_003_part5_b2_public_yA));

	xtest_add_attr(&param_count, params,
		       TEE_ATTR_ECC_EPHEMERAL_PUBLIC_VALUE_X,
		       ARRAY(gmt_003_part5_b2_eph_public_xA));

	xtest_add_attr(&param_count, params,
		       TEE_ATTR_ECC_EPHEMERAL_PUBLIC_VALUE_Y,
		       ARRAY(gmt_003_part5_b2_eph_public_yA));

	xtest_add_attr(&param_count, params, TEE_ATTR_SM2_ID_INITIATOR,
		       ARRAY(gmt_003_part5_b2_id_A));

	xtest_add_attr(&param_count, params, TEE_ATTR_SM2_ID_RESPONDER,
		       ARRAY(gmt_003_part5_b2_id_B));

	xtest_add_attr(&param_count, params, TEE_ATTR_SM2_KEP_CONFIRMATION_IN,
		       ARRAY(gmt_003_part5_b2_conf_A));

	xtest_add_attr(&param_count, params, TEE_ATTR_SM2_KEP_CONFIRMATION_OUT,
		       ARRAY(conf_B));

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		ta_crypt_cmd_derive_key(c, &session, op, sv_handle, params,
			param_count)))
		goto out;

	out_size = sizeof(out);
	memset(out, 0, sizeof(out));
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		ta_crypt_cmd_get_object_buffer_attribute(c, &session, sv_handle,
			TEE_ATTR_SECRET_VALUE, out, &out_size)))
		goto out;

	/* Check derived key */
	if (!ADBG_EXPECT_BUFFER(c, gmt_003_part5_b2_shared_secret,
				sizeof(gmt_003_part5_b2_shared_secret), out,
				out_size))
		goto out;

	Do_ADBG_EndSubCase(c, "Responder side");

out:
	TEEC_CloseSession(&session);
}
ADBG_CASE_DEFINE(regression, 4014, xtest_tee_test_4014,
		"Test SM2 KEP (key derivation)");

static void xtest_tee_test_4015(ADBG_Case_t *c)
{
	TEEC_Session session = { };
	uint32_t ret_orig = 0;
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	TEE_ObjectHandle key_alice = TEE_HANDLE_NULL;
	TEE_ObjectHandle key_bob = TEE_HANDLE_NULL;
	TEE_ObjectHandle sv_handle = TEE_HANDLE_NULL;
	TEE_Attribute params[2] = { };
	size_t param_count = 0;
	uint8_t out[32] = { };
	size_t out_size = 0;
	char case_str[40] = "Alice side computes shared secret";

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		xtest_teec_open_session(&session, &crypt_user_ta_uuid, NULL,
					&ret_orig)))
		return;

	Do_ADBG_BeginSubCase(c, "%s", case_str);

	if (!ta_crypt_cmd_is_algo_supported(c, &session, TEE_ALG_X25519,
					    TEE_ECC_CURVE_25519)) {
		Do_ADBG_Log("X25519 not supported: skip subcase");
		goto out;
	}

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_allocate_operation(c, &session, &op,
				TEE_ALG_X25519, TEE_MODE_DERIVE, 256)))
		goto out;

	/* Allocate and initialize keypair of Alice */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_allocate_transient_object(c, &session,
				TEE_TYPE_X25519_KEYPAIR, 256, &key_alice)))
		goto out;

	param_count = 0;

	xtest_add_attr(&param_count, params, TEE_ATTR_X25519_PUBLIC_VALUE,
		       ARRAY(x25519_alice_public));

	xtest_add_attr(&param_count, params, TEE_ATTR_X25519_PRIVATE_VALUE,
		       ARRAY(x25519_alice_private));

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_populate_transient_object(c, &session,
				key_alice, params, param_count)))
		goto out;

	/* Associate Alices's keys with operation */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_set_operation_key(c, &session, op,
						       key_alice)))
		goto out;

	/* Keys have been set, free key objects */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_free_transient_object(c, &session,
							   key_alice)))
		goto out;

	/* Allocate shared secret output object */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_allocate_transient_object(c, &session,
				TEE_TYPE_GENERIC_SECRET,
				sizeof(x25519_shared_secret), &sv_handle)))
		goto out;

	/* Reset params */
	param_count = 0;

	/* Set Bob's public key for Alice side */
	xtest_add_attr(&param_count, params, TEE_ATTR_X25519_PUBLIC_VALUE,
		       ARRAY(x25519_bob_public));

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_derive_key(c, &session, op, sv_handle,
						params, param_count)))
		goto out;

	out_size = sizeof(out);
	memset(out, 0, sizeof(out));
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_get_object_buffer_attribute(c, &session,
				sv_handle, TEE_ATTR_SECRET_VALUE, out,
				&out_size)))
		goto out;

	/* Check derived key */
	if (!ADBG_EXPECT_BUFFER(c, x25519_shared_secret,
				sizeof(x25519_shared_secret), out,
				out_size))
		goto out;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_free_operation(c, &session, op)))
		goto out;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_free_transient_object(c, &session,
							   sv_handle)))
		goto out;

	Do_ADBG_EndSubCase(c, "%s", case_str);

	strncpy(case_str, "Bob side computes shared secret",
		sizeof(case_str) - 1);

	Do_ADBG_BeginSubCase(c, "%s", case_str);

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_allocate_operation(c, &session, &op,
				TEE_ALG_X25519, TEE_MODE_DERIVE, 256)))
		goto out;

	/* Allocate and initialize keypair of Bob */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_allocate_transient_object(c, &session,
				TEE_TYPE_X25519_KEYPAIR, 256, &key_bob)))
		goto out;

	/* Reset params */
	param_count = 0;

	xtest_add_attr(&param_count, params, TEE_ATTR_X25519_PUBLIC_VALUE,
		       ARRAY(x25519_bob_public));

	xtest_add_attr(&param_count, params, TEE_ATTR_X25519_PRIVATE_VALUE,
		       ARRAY(x25519_bob_private));

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_populate_transient_object(c, &session,
				key_bob, params, param_count)))
		goto out;

	/* Associate Bob's keys with operation */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_set_operation_key(c, &session, op,
						       key_bob)))
		goto out;

	/* Keys have been set, free key objects */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_free_transient_object(c, &session,
							   key_bob)))
		goto out;

	/* Allocate shared secret output object */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_allocate_transient_object(c, &session,
				TEE_TYPE_GENERIC_SECRET,
				sizeof(x25519_shared_secret), &sv_handle)))
		goto out;

	/* Reset params */
	param_count = 0;

	/* Set Alice's public key for Bob side */
	xtest_add_attr(&param_count, params, TEE_ATTR_X25519_PUBLIC_VALUE,
		       ARRAY(x25519_alice_public));

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_derive_key(c, &session, op, sv_handle,
						params, param_count)))
		goto out;

	out_size = sizeof(out);
	memset(out, 0, sizeof(out));
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_get_object_buffer_attribute(c, &session,
				sv_handle, TEE_ATTR_SECRET_VALUE, out,
				&out_size)))
		goto out;

	/* Check derived key */
	if (!ADBG_EXPECT_BUFFER(c, x25519_shared_secret,
				sizeof(x25519_shared_secret), out,
				out_size))
		goto out;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_free_operation(c, &session, op)))
		goto out;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_free_transient_object(c, &session,
							   sv_handle)))
		goto out;

out:
	Do_ADBG_EndSubCase(c, "%s", case_str);
	TEEC_CloseSession(&session);
}
ADBG_CASE_DEFINE(regression, 4015, xtest_tee_test_4015,
		"Test TEE Internal API Derive key X25519");

static void xtest_tee_test_4016_ed25519(ADBG_Case_t *c)
{
	TEEC_Session session = { };
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
	TEE_Attribute key_attrs[2] = { };
	size_t num_key_attrs = 0;
	TEE_Attribute attrs[2] = { };
	size_t num_attrs = 0;
	uint8_t out[128] = { };
	size_t out_size = sizeof(out);
	size_t n = 0;
	uint32_t ret_orig = 0;
	size_t max_key_size = 0;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			xtest_teec_open_session(&session, &crypt_user_ta_uuid,
						NULL, &ret_orig)))
		return;

	if (!ta_crypt_cmd_is_algo_supported(c, &session, TEE_ALG_ED25519,
					    TEE_ECC_CURVE_25519)) {
		Do_ADBG_Log("ED25519 not supported: skip subcase");
		goto out;
	}

	for (n = 0; n < ARRAY_SIZE(xtest_ac_eddsa_cases); n++) {
		const struct xtest_ac_case *tv = xtest_ac_eddsa_cases + n;

		if (tv->algo != TEE_ALG_ED25519)
			continue;

		num_attrs = 0;
		num_key_attrs = 0;
		max_key_size = tv->params.eddsa.private_len * 8;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
				ta_crypt_cmd_allocate_operation(c, &session, &op,
					TEE_ALG_ED25519, tv->mode, max_key_size)))
			goto out;

		xtest_add_attr(&num_key_attrs, key_attrs,
			       TEE_ATTR_ED25519_PUBLIC_VALUE,
			       tv->params.eddsa.public,
			       tv->params.eddsa.public_len);

		if (tv->params.eddsa.flag == 1)
			xtest_add_attr_value(&num_attrs, attrs,
					     TEE_ATTR_EDDSA_PREHASH, 1, 0);

		if (tv->params.eddsa.context_len > 0)
			xtest_add_attr(&num_attrs, attrs, TEE_ATTR_EDDSA_CTX,
				       tv->params.eddsa.context,
				       tv->params.eddsa.context_len);

		switch (tv->mode) {
		case TEE_MODE_SIGN:
			xtest_add_attr(&num_key_attrs, key_attrs,
				       TEE_ATTR_ED25519_PRIVATE_VALUE,
				       tv->params.eddsa.private,
				       tv->params.eddsa.private_len);

			if (!ADBG_EXPECT_TRUE(c,
					create_key(c, &session, max_key_size,
						   TEE_TYPE_ED25519_KEYPAIR,
						   key_attrs, num_key_attrs,
						   &key_handle)))
				goto out;

			if (!ADBG_EXPECT_TEEC_SUCCESS(c,
					ta_crypt_cmd_set_operation_key(c,
						 &session, op, key_handle)))
				goto out;

			out_size = 0;
			if (!ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_SHORT_BUFFER,
					ta_crypt_cmd_asymmetric_sign(c,
						&session, op,
						attrs, num_attrs, tv->ptx,
						tv->ptx_len, out, &out_size)))
				goto out;

			out_size = 63;
			if (!ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_SHORT_BUFFER,
					ta_crypt_cmd_asymmetric_sign(c,
						&session, op,
						attrs, num_attrs, tv->ptx,
						tv->ptx_len, out, &out_size)))
				goto out;

			out_size = sizeof(out);
			if (!ADBG_EXPECT_TEEC_SUCCESS(c,
					ta_crypt_cmd_asymmetric_sign(c,
						&session, op,
						attrs, num_attrs, tv->ptx,
						tv->ptx_len, out, &out_size)))
				goto out;

			ADBG_EXPECT_BUFFER(c, tv->ctx, tv->ctx_len, out, out_size);

			break;

		case TEE_MODE_VERIFY:
			if (!ADBG_EXPECT_TRUE(c,
					create_key(c, &session, max_key_size,
						   TEE_TYPE_ED25519_PUBLIC_KEY,
						   key_attrs, num_key_attrs,
						   &key_handle)))
				goto out;

			if (!ADBG_EXPECT_TEEC_SUCCESS(c,
					ta_crypt_cmd_set_operation_key(c,
						   &session, op, key_handle)))
				goto out;

			if (!ADBG_EXPECT_TEEC_SUCCESS(c,
				ta_crypt_cmd_asymmetric_verify(c, &session, op,
							       attrs, num_attrs,
							       tv->ptx,
							       tv->ptx_len,
							       tv->ctx,
							       tv->ctx_len)))
				goto out;
			break;

		default:
			break;
		}

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
				ta_crypt_cmd_free_operation(c, &session, op)))
			goto out;
	}
out:
	TEEC_CloseSession(&session);
}
ADBG_CASE_DEFINE(regression, 4016, xtest_tee_test_4016_ed25519,
		 "Test TEE Internal API ED25519 sign/verify");

struct buf_state {
	bool buffer_two_blocks;
	bool auth_enc;
	bool decrypt;
	uint8_t *plain_text;
	uint8_t *ciph_text;
	uint8_t *tmp_text;
	size_t text_size;
	size_t block_size;
	uint8_t *iv;
	size_t iv_len;
	uint8_t tag[96 / 8];
	uint8_t tmp_tag[96 / 8];
	TEE_OperationHandle oph;
	TEEC_Session *s;

	size_t in_count;
	size_t out_count;
	size_t buf_count;
};

static bool process_bytes_4017(ADBG_Case_t *c, struct buf_state *bs,
			       size_t count)
{
	TEE_Result res = TEEC_SUCCESS;
	size_t new_buf_count = 0;
	void *reference = NULL;
	void *src = NULL;
	size_t out = 0;
	size_t dlen = 0;

	if (bs->decrypt) {
		src = bs->ciph_text + bs->in_count;
		reference = bs->plain_text + bs->out_count;
	} else {
		src = bs->plain_text + bs->in_count;
		reference = bs->ciph_text + bs->out_count;
	}

	bs->in_count += count;
	if (bs->buffer_two_blocks) {
		if (bs->in_count > bs->block_size)
			new_buf_count = ((bs->in_count - 1) % bs->block_size) +
					bs->block_size + 1;
		else
			new_buf_count = bs->in_count;
	} else {
		new_buf_count = bs->in_count % bs->block_size;
	}

	out = bs->buf_count + count - new_buf_count;
	bs->out_count += out;
	bs->buf_count = new_buf_count;

	if (bs->auth_enc) {
		res = ta_crypt_cmd_ae_update(c, bs->s, bs->oph, src, count,
					     NULL, &dlen);
		if (!res)
			return ADBG_EXPECT_COMPARE_UNSIGNED(c, dlen, ==, 0) &&
			       ADBG_EXPECT_COMPARE_UNSIGNED(c, dlen, ==, out);
		if (!ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_SHORT_BUFFER, res) ||
		    !ADBG_EXPECT_COMPARE_UNSIGNED(c, dlen, ==, out))
			return false;
		res = ta_crypt_cmd_ae_update(c, bs->s, bs->oph, src, count,
					     bs->tmp_text, &dlen);
		if (!ADBG_EXPECT_TEEC_SUCCESS(c, res) ||
		    !ADBG_EXPECT_BUFFER(c, reference, out,
					bs->tmp_text, dlen))
			return false;
	} else {
		res = ta_crypt_cmd_cipher_update(c, bs->s, bs->oph, src, count,
						 NULL, &dlen);
		if (!res)
			return ADBG_EXPECT_COMPARE_UNSIGNED(c, dlen, ==, out);
		if (!ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_SHORT_BUFFER, res) ||
		    !ADBG_EXPECT_COMPARE_UNSIGNED(c, dlen, ==, out))
			return false;
		res = ta_crypt_cmd_cipher_update(c, bs->s, bs->oph, src, count,
						 bs->tmp_text, &dlen);
		if (!ADBG_EXPECT_TEEC_SUCCESS(c, res) ||
		    !ADBG_EXPECT_BUFFER(c, reference, out,
					bs->tmp_text, dlen))
			return false;
	}

	return true;
}

static bool process_bytes_final_4017(ADBG_Case_t *c, struct buf_state *bs)
{
	TEEC_Result res = TEEC_SUCCESS;
	void *reference = NULL;
	size_t src_len = 0;
	void *src = NULL;
	size_t dlen = 0;
	size_t tlen = 0;

	if (bs->decrypt) {
		src = bs->ciph_text + bs->in_count;
		reference = bs->plain_text + bs->out_count;
	} else {
		src = bs->plain_text + bs->in_count;
		reference = bs->ciph_text + bs->out_count;
	}
	src_len = bs->text_size - bs->in_count;

	if (bs->auth_enc) {
		if (bs->decrypt)
			res = ta_crypt_cmd_ae_decrypt_final(c, bs->s, bs->oph,
							    src, src_len,
							    NULL, &dlen,
							    bs->tag,
							    sizeof(bs->tag));
		else
			res = ta_crypt_cmd_ae_encrypt_final(c, bs->s, bs->oph,
							    src, src_len,
							    NULL, &dlen, NULL,
							    &tlen);
		if (!res && bs->decrypt)
			return ADBG_EXPECT_COMPARE_UNSIGNED(c, dlen, ==,
							   src_len);
		if (!ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_SHORT_BUFFER, res) ||
		    !ADBG_EXPECT_COMPARE_UNSIGNED(c, bs->text_size -
                                                  bs->out_count, ==, dlen))
			return false;
		if (!bs->decrypt &&
		    !ADBG_EXPECT_COMPARE_UNSIGNED(c, sizeof(bs->tag), ==, tlen))
			return false;
		if (bs->decrypt)
			res = ta_crypt_cmd_ae_decrypt_final(c, bs->s, bs->oph,
							    src, src_len,
							    bs->tmp_text, &dlen,
							    bs->tag,
							    sizeof(bs->tag));
		else
			res = ta_crypt_cmd_ae_encrypt_final(c, bs->s, bs->oph,
							    src, src_len,
							    bs->tmp_text, &dlen,
							    bs->tmp_tag, &tlen);
		if (!ADBG_EXPECT_TEEC_SUCCESS(c, res) ||
		    !ADBG_EXPECT_BUFFER(c, reference,
					bs->text_size - bs->out_count,
					bs->tmp_text, dlen))
			return false;
		if (!bs->decrypt &&
		    !ADBG_EXPECT_BUFFER(c, bs->tag, sizeof(bs->tag),
					bs->tmp_tag, tlen))
			return false;
	} else {
		res = ta_crypt_cmd_cipher_do_final(c, bs->s, bs->oph,
						   src, src_len, NULL, &dlen);
		if (!res)
			return ADBG_EXPECT_COMPARE_UNSIGNED(c, dlen, ==,
							    src_len);
		if (!ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_SHORT_BUFFER, res) ||
		    !ADBG_EXPECT_COMPARE_UNSIGNED(c,
						  bs->text_size -
						  bs->out_count, ==, dlen))
			return false;

		res = ta_crypt_cmd_cipher_do_final(c, bs->s, bs->oph,
						   src, src_len,
						   bs->tmp_text, &dlen);
		if (!ADBG_EXPECT_TEEC_SUCCESS(c, res) ||
		    !ADBG_EXPECT_BUFFER(c, reference,
					bs->text_size - bs->out_count,
					bs->tmp_text, dlen))
			return false;
	}

	return true;
}

static bool process_text_4017(ADBG_Case_t *c, struct buf_state *bs,
			      size_t initial_count, size_t middle_count)
{
	TEEC_Result res = TEEC_SUCCESS;
	size_t n = 0;

	bs->in_count = 0;
	bs->out_count = 0;
	bs->buf_count = 0;

	if (bs->auth_enc)
		res = ta_crypt_cmd_ae_init(c, bs->s, bs->oph, bs->iv,
					   bs->iv_len, sizeof(bs->tag), 0,
					   bs->text_size);
	else
		res = ta_crypt_cmd_cipher_init(c, bs->s, bs->oph, bs->iv,
					       bs->iv_len);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		return false;

	if (initial_count &&
	    !ADBG_EXPECT_TRUE(c, process_bytes_4017(c, bs, initial_count)))
		return false;

	for (n = 0; n < middle_count && n + initial_count < bs->text_size; n++)
		if (!ADBG_EXPECT_TRUE(c, process_bytes_4017(c, bs, 1)))
			return false;

	return process_bytes_final_4017(c, bs);
}

static bool alloc_oph_4017(ADBG_Case_t *c, TEEC_Session *s, uint32_t algo,
			   uint32_t mode, void *key, size_t key_size,
			   TEE_OperationHandle *oph)
{
	TEEC_Result res = TEEC_SUCCESS;
	TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
	TEE_ObjectHandle key2_handle = TEE_HANDLE_NULL;
	TEE_Attribute key_attr = {
		.attributeID = TEE_ATTR_SECRET_VALUE,
		.content.ref.buffer = key,
		.content.ref.length = key_size,
	};
	bool ret = false;

	res = ta_crypt_cmd_allocate_transient_object(c, s, TEE_TYPE_AES,
						     key_size * 8, &key_handle);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		goto out;
	res = ta_crypt_cmd_populate_transient_object(c, s, key_handle,
						     &key_attr, 1);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		goto out;

	if (algo == TEE_ALG_AES_XTS) {
		res = ta_crypt_cmd_allocate_transient_object(c, s, TEE_TYPE_AES,
							     key_size * 8,
							     &key2_handle);
		if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
			goto out;
		res = ta_crypt_cmd_populate_transient_object(c, s, key2_handle,
							     &key_attr, 1);
		if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
			goto out;

		res = ta_crypt_cmd_allocate_operation(c, s, oph, algo, mode,
						      key_size * 8 * 2);
		if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
			goto out;
		res = ta_crypt_cmd_set_operation_key2(c, s, *oph, key_handle,
						      key2_handle);
		if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
			goto out;
	} else {
		res = ta_crypt_cmd_allocate_operation(c, s, oph, algo, mode,
						      key_size * 8);
		if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
			goto out;
		res = ta_crypt_cmd_set_operation_key(c, s, *oph, key_handle);
		if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
			goto out;
	}

	ret = true;
out:
	if (key2_handle)
		ta_crypt_cmd_free_transient_object(c, s, key2_handle);
	if (key_handle)
		ta_crypt_cmd_free_transient_object(c, s, key_handle);
	return ret;
}

static bool do_algo_4017(ADBG_Case_t *c, TEEC_Session *s, uint32_t algo,
			 size_t extra_size)
{
	TEEC_Result res = TEEC_SUCCESS;
	struct buf_state bs = { .s = s, };
	size_t middle_count = 0;
	uint8_t iv[16] = { };
	uint8_t key[16] = { };
	size_t prev_n = 0;
	bool ret = false;
	size_t dlen = 0;
	size_t tlen = 0;
	size_t n = 0;

	if (level >= 12)
		middle_count = 2 * TEE_AES_BLOCK_SIZE;
	else
		middle_count = 2;

	bs.block_size = 16;
	bs.text_size = bs.block_size * 6 + extra_size;
	bs.plain_text = calloc(3, bs.text_size);
	if (!ADBG_EXPECT_NOT_NULL(c, bs.plain_text))
		return false;
	bs.ciph_text = bs.plain_text + bs.text_size;
	bs.tmp_text = bs.ciph_text + bs.text_size;

	for (n = 0; n < bs.text_size; n++)
		bs.plain_text[n] = n + 1;
	for (n = 0; n < ARRAY_SIZE(iv); n++)
		iv[n] = n + 1;
	for (n = 0; n < ARRAY_SIZE(key); n++)
		key[n] = n + 1;

	if (!ADBG_EXPECT_TRUE(c, alloc_oph_4017(c, s, algo, TEE_MODE_ENCRYPT,
						key, sizeof(key), &bs.oph)))
		return false;

	if (algo != TEE_ALG_AES_ECB_NOPAD) {
		bs.iv = iv;
		bs.iv_len = sizeof(iv);
	}
	if (algo == TEE_ALG_AES_CCM)
		bs.iv_len = 13;
	if (algo == TEE_ALG_AES_CTR || algo == TEE_ALG_AES_GCM)
		bs.block_size = 1;
	else
		bs.block_size = TEE_AES_BLOCK_SIZE;
	if (algo == TEE_ALG_AES_CTS || algo == TEE_ALG_AES_XTS)
		bs.buffer_two_blocks = true;
	if (algo == TEE_ALG_AES_CCM || algo == TEE_ALG_AES_GCM)
		bs.auth_enc = true;

	if (bs.auth_enc) {
		res = ta_crypt_cmd_ae_init(c, bs.s, bs.oph, bs.iv, bs.iv_len,
					   sizeof(bs.tag), 0, bs.text_size);
		if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
			goto out;
		res = ta_crypt_cmd_ae_encrypt_final(c, bs.s, bs.oph,
						    bs.plain_text, bs.text_size,
						    NULL, &dlen, NULL, &tlen);
		if (!ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_SHORT_BUFFER, res) ||
		    !ADBG_EXPECT_COMPARE_UNSIGNED(c, bs.text_size, ==, dlen))
			goto out;
		res = ta_crypt_cmd_ae_encrypt_final(c, bs.s, bs.oph,
						    bs.plain_text, bs.text_size,
						    bs.ciph_text, &dlen, bs.tag,
						    &tlen);
		if (!ADBG_EXPECT_TEEC_SUCCESS(c, res) ||
		    !ADBG_EXPECT_COMPARE_UNSIGNED(c, bs.text_size, ==, dlen))
			goto out;
	} else {
		res = ta_crypt_cmd_cipher_init(c, bs.s, bs.oph, bs.iv,
					       bs.iv_len);
		if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
			goto out;
		res = ta_crypt_cmd_cipher_do_final(c, bs.s, bs.oph,
						   bs.plain_text, bs.text_size,
						   NULL, &dlen);
		if (!ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_SHORT_BUFFER, res) ||
		    !ADBG_EXPECT_COMPARE_UNSIGNED(c, bs.text_size, ==, dlen))
			goto out;
		res = ta_crypt_cmd_cipher_do_final(c, bs.s, bs.oph,
						   bs.plain_text, bs.text_size,
						   bs.ciph_text, &dlen);
		if (!ADBG_EXPECT_TEEC_SUCCESS(c, res) ||
		    !ADBG_EXPECT_COMPARE_UNSIGNED(c, bs.text_size, ==, dlen))
			goto out;
	}

	for (n = 0; n < bs.text_size; n++) {
		/*
		 * If level < 12 test with initial count of:
		 * 0, 1, 15 for each AES block, that is,
		 * 0, 1, 15, 16, 17, 31, 32, 33, 47, 48, 49, 63, 64, 65,
		 * 79, 80, 81, and 95
		 * If level >= 12 test with initial count of each n, an
		 * exhaustive of every possible initial count.
		 *
		 * If level >= 12 test with middle_count of 32 else 2.
		 * (middle_count - n) bytes are processed one by one.
		 *
		 * The idea is to try to match all corner cases when
		 * buffering AES blocks. With special focus on what happens
		 * when a complete block has been buffered.
		 */
		if (level < 12 && (n % TEE_AES_BLOCK_SIZE) > 1 &&
		    (n % TEE_AES_BLOCK_SIZE) < (TEE_AES_BLOCK_SIZE - 1))
			continue;
		ret = process_text_4017(c, &bs, n, middle_count);
		if (!ADBG_EXPECT_TRUE(c, ret)) {
			Do_ADBG_Log("Failed processing with initial_count %zu (previous %zu)",
				n, prev_n);
			goto out;
		}
		prev_n = n;
	}

	ta_crypt_cmd_free_operation(c, s, bs.oph);
	bs.oph = TEE_HANDLE_NULL;
	if (!ADBG_EXPECT_TRUE(c, alloc_oph_4017(c, s, algo, TEE_MODE_DECRYPT,
						key, sizeof(key), &bs.oph)))
		goto out;
	bs.decrypt = true;

	/* Only test matching decryption for levels above 13 */
	if (level > 13) {
		for (n = 0; n < bs.text_size; n++) {
			ret = process_text_4017(c, &bs, n, middle_count);
			if (!ADBG_EXPECT_TRUE(c, ret)) {
				Do_ADBG_Log("Failed processing with initial_count %zu (previous %zu)",
					    n, prev_n);
				goto out;
			}
			prev_n = n;
		}
	}

	ret = true;
out:
	if (bs.oph)
		ta_crypt_cmd_free_operation(c, s, bs.oph);
	free(bs.plain_text);
	return ret;
}

static void xtest_tee_test_4017(ADBG_Case_t *c)
{
	TEEC_Result res = TEEC_SUCCESS;
	uint32_t ret_orig = 0;
	TEEC_Session sess = { };

	res = xtest_teec_open_session(&sess, &crypt_user_ta_uuid, NULL,
				      &ret_orig);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		return;

	Do_ADBG_BeginSubCase(c, "TEE_ALG_AES_ECB_NOPAD");
	ADBG_EXPECT_TRUE(c, do_algo_4017(c, &sess, TEE_ALG_AES_ECB_NOPAD, 0));
	Do_ADBG_EndSubCase(c, "TEE_ALG_AES_ECB_NOPAD");

	Do_ADBG_BeginSubCase(c, "TEE_ALG_AES_CBC_NOPAD");
	ADBG_EXPECT_TRUE(c, do_algo_4017(c, &sess, TEE_ALG_AES_CBC_NOPAD, 0));
	Do_ADBG_EndSubCase(c, "TEE_ALG_AES_CBC_NOPAD");

	Do_ADBG_BeginSubCase(c, "TEE_ALG_AES_CTR");
	ADBG_EXPECT_TRUE(c, do_algo_4017(c, &sess, TEE_ALG_AES_CTR, 0));
	Do_ADBG_EndSubCase(c, "TEE_ALG_AES_CTR");

	Do_ADBG_BeginSubCase(c, "TEE_ALG_AES_CTR 1 extra byte");
	ADBG_EXPECT_TRUE(c, do_algo_4017(c, &sess, TEE_ALG_AES_CTR, 1));
	Do_ADBG_EndSubCase(c, "TEE_ALG_AES_CTR 1 extra byte");

	Do_ADBG_BeginSubCase(c, "TEE_ALG_AES_CTS");
	ADBG_EXPECT_TRUE(c, do_algo_4017(c, &sess, TEE_ALG_AES_CTS, 0));
	Do_ADBG_EndSubCase(c, "TEE_ALG_AES_CTS");

	Do_ADBG_BeginSubCase(c, "TEE_ALG_AES_CTS 1 extra byte");
	ADBG_EXPECT_TRUE(c, do_algo_4017(c, &sess, TEE_ALG_AES_CTS, 1));
	Do_ADBG_EndSubCase(c, "TEE_ALG_AES_CTS 1 extra byte");

	Do_ADBG_BeginSubCase(c, "TEE_ALG_AES_XTS");
	ADBG_EXPECT_TRUE(c, do_algo_4017(c, &sess, TEE_ALG_AES_XTS, 0));
	Do_ADBG_EndSubCase(c, "TEE_ALG_AES_XTS");

	Do_ADBG_BeginSubCase(c, "TEE_ALG_AES_XTS 1 extra byte");
	ADBG_EXPECT_TRUE(c, do_algo_4017(c, &sess, TEE_ALG_AES_XTS, 1));
	Do_ADBG_EndSubCase(c, "TEE_ALG_AES_XTS 1 extra byte");

	Do_ADBG_BeginSubCase(c, "TEE_ALG_AES_GCM");
	ADBG_EXPECT_TRUE(c, do_algo_4017(c, &sess, TEE_ALG_AES_GCM, 0));
	Do_ADBG_EndSubCase(c, "TEE_ALG_AES_GCM");

	Do_ADBG_BeginSubCase(c, "TEE_ALG_AES_GCM 1 extra byte");
	ADBG_EXPECT_TRUE(c, do_algo_4017(c, &sess, TEE_ALG_AES_GCM, 1));
	Do_ADBG_EndSubCase(c, "TEE_ALG_AES_GCM 1 extra byte");

	Do_ADBG_BeginSubCase(c, "TEE_ALG_AES_CCM");
	ADBG_EXPECT_TRUE(c, do_algo_4017(c, &sess, TEE_ALG_AES_CCM, 0));
	Do_ADBG_EndSubCase(c, "TEE_ALG_AES_CCM");

	Do_ADBG_BeginSubCase(c, "TEE_ALG_AES_CCM 1 extra byte");
	ADBG_EXPECT_TRUE(c, do_algo_4017(c, &sess, TEE_ALG_AES_CCM, 1));
	Do_ADBG_EndSubCase(c, "TEE_ALG_AES_CCM 1 extra byte");

	TEEC_CloseSession(&sess);
}

ADBG_CASE_DEFINE(regression, 4017, xtest_tee_test_4017,
		 "Test TEE Internal API Cipher block buffering");
