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

#include <tee_internal_api.h>
#include "cryp_taf.h"

#define ASSERT_PARAM_TYPE(pt)                    \
do {                                             \
	if ((pt) != param_type)                  \
		return TEE_ERROR_BAD_PARAMETERS; \
} while (0)

TEE_Result ta_entry_allocate_operation(uint32_t param_type, TEE_Param params[4])
{
	TEE_Result res;
	TEE_OperationHandle op;

	ASSERT_PARAM_TYPE(TEE_PARAM_TYPES
			  (TEE_PARAM_TYPE_VALUE_INOUT,
			   TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_NONE,
			   TEE_PARAM_TYPE_NONE));

	res = TEE_AllocateOperation(&op,
				    params[0].value.b, params[1].value.a,
				    params[1].value.b);
	params[0].value.a = (uint32_t) op;
	return res;
}

TEE_Result ta_entry_free_operation(uint32_t param_type, TEE_Param params[4])
{
	ASSERT_PARAM_TYPE(TEE_PARAM_TYPES
			  (TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_NONE,
			   TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE));

	TEE_FreeOperation((TEE_OperationHandle) params[0].value.a);
	return TEE_SUCCESS;
}

TEE_Result ta_entry_get_operation_info(uint32_t param_type, TEE_Param params[4])
{
	ASSERT_PARAM_TYPE(TEE_PARAM_TYPES
			  (TEE_PARAM_TYPE_VALUE_INPUT,
			   TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE,
			   TEE_PARAM_TYPE_NONE));
	if (params[1].memref.size < sizeof(TEE_OperationInfo))
		return TEE_ERROR_SHORT_BUFFER;
	params[1].memref.size = sizeof(TEE_OperationInfo);

	TEE_GetOperationInfo((TEE_OperationHandle) params[0].value.a,
			     params[1].memref.buffer);
	return TEE_SUCCESS;
}

TEE_Result ta_entry_reset_operation(uint32_t param_type, TEE_Param params[4])
{
	ASSERT_PARAM_TYPE(TEE_PARAM_TYPES
			  (TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_NONE,
			   TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE));

	TEE_ResetOperation((TEE_OperationHandle) params[0].value.a);
	return TEE_SUCCESS;
}

TEE_Result ta_entry_set_operation_key(uint32_t param_type, TEE_Param params[4])
{
	ASSERT_PARAM_TYPE(TEE_PARAM_TYPES
			  (TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_NONE,
			   TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE));

	return TEE_SetOperationKey((TEE_OperationHandle) params[0].value.a,
				   (TEE_ObjectHandle) params[0].value.b);
}

TEE_Result ta_entry_set_operation_key2(uint32_t param_type, TEE_Param params[4])
{
	ASSERT_PARAM_TYPE(TEE_PARAM_TYPES
			  (TEE_PARAM_TYPE_VALUE_INPUT,
			   TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_NONE,
			   TEE_PARAM_TYPE_NONE));

	return TEE_SetOperationKey2((TEE_OperationHandle) params[0].value.a,
				    (TEE_ObjectHandle) params[0].value.b,
				    (TEE_ObjectHandle) params[1].value.a);
}

TEE_Result ta_entry_copy_operation(uint32_t param_type, TEE_Param params[4])
{
	ASSERT_PARAM_TYPE(TEE_PARAM_TYPES
			  (TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_NONE,
			   TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE));

	TEE_CopyOperation((TEE_OperationHandle) params[0].value.a,
			  (TEE_OperationHandle) params[0].value.b);
	return TEE_SUCCESS;
}

TEE_Result ta_entry_digest_update(uint32_t param_type, TEE_Param params[4])
{
	ASSERT_PARAM_TYPE(TEE_PARAM_TYPES
			  (TEE_PARAM_TYPE_VALUE_INPUT,
			   TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_NONE,
			   TEE_PARAM_TYPE_NONE));

	TEE_DigestUpdate((TEE_OperationHandle) params[0].value.a,
			 params[1].memref.buffer, params[1].memref.size);
	return TEE_SUCCESS;
}

TEE_Result ta_entry_digest_do_final(uint32_t param_type, TEE_Param params[4])
{
	ASSERT_PARAM_TYPE(TEE_PARAM_TYPES
			  (TEE_PARAM_TYPE_VALUE_INPUT,
			   TEE_PARAM_TYPE_MEMREF_INPUT,
			   TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE));
	return TEE_DigestDoFinal((TEE_OperationHandle) params[0].value.a,
				 params[1].memref.buffer, params[1].memref.size,
				 params[2].memref.buffer,
				 &params[2].memref.size);
}

TEE_Result ta_entry_cipher_init(uint32_t param_type, TEE_Param params[4])
{
	void *buffer;
	size_t size;

	if (param_type == TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE)) {
		buffer = NULL;
		size = 0;
	} else if (param_type == TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						 TEE_PARAM_TYPE_MEMREF_INPUT,
						 TEE_PARAM_TYPE_NONE,
						 TEE_PARAM_TYPE_NONE)) {
		buffer = params[1].memref.buffer;
		size = params[1].memref.size;
	} else
		return TEE_ERROR_BAD_PARAMETERS;
	TEE_CipherInit((TEE_OperationHandle) params[0].value.a, buffer, size);
	return TEE_SUCCESS;
}

TEE_Result ta_entry_cipher_update(uint32_t param_type, TEE_Param params[4])
{
	ASSERT_PARAM_TYPE(TEE_PARAM_TYPES
			  (TEE_PARAM_TYPE_VALUE_INPUT,
			   TEE_PARAM_TYPE_MEMREF_INPUT,
			   TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE));
	return TEE_CipherUpdate((TEE_OperationHandle) params[0].value.a,
				params[1].memref.buffer, params[1].memref.size,
				params[2].memref.buffer,
				&params[2].memref.size);
}

TEE_Result ta_entry_cipher_do_final(uint32_t param_type, TEE_Param params[4])
{
	ASSERT_PARAM_TYPE(TEE_PARAM_TYPES
			  (TEE_PARAM_TYPE_VALUE_INPUT,
			   TEE_PARAM_TYPE_MEMREF_INPUT,
			   TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE));
	return TEE_CipherDoFinal((TEE_OperationHandle) params[0].value.a,
				 params[1].memref.buffer, params[1].memref.size,
				 params[2].memref.buffer,
				 &params[2].memref.size);
}

TEE_Result ta_entry_mac_init(uint32_t param_type, TEE_Param params[4])
{
	void *buffer;
	size_t size;

	if (param_type == TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE,
					  TEE_PARAM_TYPE_NONE)) {
		buffer = NULL;
		size = 0;
	} else if (param_type == TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						 TEE_PARAM_TYPE_MEMREF_INPUT,
						 TEE_PARAM_TYPE_NONE,
						 TEE_PARAM_TYPE_NONE)) {
		buffer = params[1].memref.buffer;
		size = params[1].memref.size;
	} else
		return TEE_ERROR_BAD_PARAMETERS;

	TEE_MACInit((TEE_OperationHandle) params[0].value.a, buffer, size);
	return TEE_SUCCESS;
}

TEE_Result ta_entry_mac_update(uint32_t param_type, TEE_Param params[4])
{
	ASSERT_PARAM_TYPE(TEE_PARAM_TYPES
			  (TEE_PARAM_TYPE_VALUE_INPUT,
			   TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_NONE,
			   TEE_PARAM_TYPE_NONE));

	TEE_MACUpdate((TEE_OperationHandle) params[0].value.a,
		      params[1].memref.buffer, params[1].memref.size);
	return TEE_SUCCESS;
}

TEE_Result ta_entry_mac_final_compute(uint32_t param_type, TEE_Param params[4])
{
	ASSERT_PARAM_TYPE(TEE_PARAM_TYPES
			  (TEE_PARAM_TYPE_VALUE_INPUT,
			   TEE_PARAM_TYPE_MEMREF_INPUT,
			   TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE));
	return TEE_MACComputeFinal((TEE_OperationHandle) params[0].value.a,
				   params[1].memref.buffer,
				   params[1].memref.size,
				   params[2].memref.buffer,
				   &params[2].memref.size);
}

TEE_Result ta_entry_mac_final_compare(uint32_t param_type, TEE_Param params[4])
{
	ASSERT_PARAM_TYPE(TEE_PARAM_TYPES
			  (TEE_PARAM_TYPE_VALUE_INPUT,
			   TEE_PARAM_TYPE_MEMREF_INPUT,
			   TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_NONE));
	return TEE_MACCompareFinal((TEE_OperationHandle) params[0].value.a,
				   params[1].memref.buffer,
				   params[1].memref.size,
				   params[2].memref.buffer,
				   params[2].memref.size);
}

TEE_Result ta_entry_allocate_transient_object(uint32_t param_type,
					      TEE_Param params[4])
{
	TEE_Result res;
	TEE_ObjectHandle o;

	ASSERT_PARAM_TYPE(TEE_PARAM_TYPES
			  (TEE_PARAM_TYPE_VALUE_INPUT,
			   TEE_PARAM_TYPE_VALUE_OUTPUT, TEE_PARAM_TYPE_NONE,
			   TEE_PARAM_TYPE_NONE));
	res =
	    TEE_AllocateTransientObject(params[0].value.a, params[0].value.b,
					&o);
	if (res == TEE_SUCCESS)
		params[1].value.a = (uint32_t) o;
	return res;
}

TEE_Result ta_entry_free_transient_object(uint32_t param_type,
					  TEE_Param params[4])
{
	ASSERT_PARAM_TYPE(TEE_PARAM_TYPES
			  (TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_NONE,
			   TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE));
	TEE_FreeTransientObject((TEE_ObjectHandle) params[0].value.a);
	return TEE_SUCCESS;
}

TEE_Result ta_entry_reset_transient_object(uint32_t param_type,
					   TEE_Param params[4])
{
	ASSERT_PARAM_TYPE(TEE_PARAM_TYPES
			  (TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_NONE,
			   TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE));
	TEE_ResetTransientObject((TEE_ObjectHandle) params[0].value.a);
	return TEE_SUCCESS;
}

static TEE_Result unpack_attrs(const uint8_t *buf, size_t blen,
			       TEE_Attribute **attrs, uint32_t *attr_count)
{
	TEE_Result res = TEE_SUCCESS;
	TEE_Attribute *a = NULL;
	size_t num_attrs = 0;
	const size_t num_attrs_size = sizeof(uint32_t);

	if (blen == 0)
		goto out;

	if (((uint32_t) buf & 0x3) != 0 || blen < num_attrs_size)
		return TEE_ERROR_BAD_PARAMETERS;
	num_attrs = *(uint32_t *) (void *)buf;
	if ((blen - num_attrs_size) < (num_attrs * sizeof(TEE_Attribute)))
		return TEE_ERROR_BAD_PARAMETERS;

	if (num_attrs > 0) {
		size_t n;

		a = TEE_Malloc(num_attrs * sizeof(TEE_Attribute), 0);
		if (a == NULL)
			return TEE_ERROR_OUT_OF_MEMORY;
		TEE_MemMove(a, buf + num_attrs_size,
			    num_attrs * sizeof(TEE_Attribute));

		for (n = 0; n < num_attrs; n++) {
			uintptr_t p;

#define TEE_ATTR_BIT_VALUE		  (1 << 29)
			if ((a[n].attributeID & TEE_ATTR_BIT_VALUE) != 0)
				continue; /* Only memrefs need to be updated */

			p = (uintptr_t) a[n].content.ref.buffer;
			if (p == 0)
				continue;

			if ((p + a[n].content.ref.length) > blen) {
				res = TEE_ERROR_BAD_PARAMETERS;
				goto out;
			}
			p += (uintptr_t) buf;
			a[n].content.ref.buffer = (void *)p;
		}
	}

	res = TEE_SUCCESS;
out:
	if (res == TEE_SUCCESS) {
		*attrs = a;
		*attr_count = num_attrs;
	} else {
		TEE_Free(a);
	}
	return res;
}

TEE_Result ta_entry_populate_transient_object(uint32_t param_type,
					      TEE_Param params[4])
{
	TEE_Result res;
	TEE_Attribute *attrs;
	uint32_t attr_count;

	ASSERT_PARAM_TYPE(TEE_PARAM_TYPES
			  (TEE_PARAM_TYPE_VALUE_INPUT,
			   TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_NONE,
			   TEE_PARAM_TYPE_NONE));

	res = unpack_attrs(params[1].memref.buffer, params[1].memref.size,
			   &attrs, &attr_count);
	if (res != TEE_SUCCESS)
		return res;

	res = TEE_PopulateTransientObject((TEE_ObjectHandle) params[0].value.a,
					  attrs, attr_count);
	TEE_Free(attrs);
	return res;
}

TEE_Result ta_entry_copy_object_attributes(uint32_t param_type,
					   TEE_Param params[4])
{
	ASSERT_PARAM_TYPE(TEE_PARAM_TYPES
			  (TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_NONE,
			   TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE));

	TEE_CopyObjectAttributes1((TEE_ObjectHandle) params[0].value.a,
				 (TEE_ObjectHandle) params[0].value.b);
	return TEE_SUCCESS;
}

TEE_Result ta_entry_generate_key(uint32_t param_type, TEE_Param params[4])
{
	TEE_Result res;
	TEE_Attribute *attrs;
	uint32_t attr_count;

	ASSERT_PARAM_TYPE(TEE_PARAM_TYPES
			  (TEE_PARAM_TYPE_VALUE_INPUT,
			   TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_NONE,
			   TEE_PARAM_TYPE_NONE));

	res = unpack_attrs(params[1].memref.buffer, params[1].memref.size,
			   &attrs, &attr_count);
	if (res != TEE_SUCCESS)
		return res;

	res = TEE_GenerateKey((TEE_ObjectHandle) params[0].value.a,
			      params[0].value.b, attrs, attr_count);
	TEE_Free(attrs);
	return res;
}

TEE_Result ta_entry_asymmetric_encrypt(uint32_t param_type, TEE_Param params[4])
{
	TEE_Result res;
	TEE_Attribute *attrs;
	uint32_t attr_count;

	ASSERT_PARAM_TYPE(TEE_PARAM_TYPES
			  (TEE_PARAM_TYPE_VALUE_INPUT,
			   TEE_PARAM_TYPE_MEMREF_INPUT,
			   TEE_PARAM_TYPE_MEMREF_INPUT,
			   TEE_PARAM_TYPE_MEMREF_OUTPUT));

	res = unpack_attrs(params[1].memref.buffer, params[1].memref.size,
			   &attrs, &attr_count);
	if (res != TEE_SUCCESS)
		return res;

	res = TEE_AsymmetricEncrypt((TEE_OperationHandle) params[0].value.a,
				    attrs, attr_count, params[2].memref.buffer,
				    params[2].memref.size,
				    params[3].memref.buffer,
				    &params[3].memref.size);
	TEE_Free(attrs);
	return res;
}

TEE_Result ta_entry_asymmetric_decrypt(uint32_t param_type, TEE_Param params[4])
{
	TEE_Result res;
	TEE_Attribute *attrs;
	uint32_t attr_count;

	ASSERT_PARAM_TYPE(TEE_PARAM_TYPES
			  (TEE_PARAM_TYPE_VALUE_INPUT,
			   TEE_PARAM_TYPE_MEMREF_INPUT,
			   TEE_PARAM_TYPE_MEMREF_INPUT,
			   TEE_PARAM_TYPE_MEMREF_OUTPUT));

	res = unpack_attrs(params[1].memref.buffer, params[1].memref.size,
			   &attrs, &attr_count);
	if (res != TEE_SUCCESS)
		return res;

	res = TEE_AsymmetricDecrypt((TEE_OperationHandle) params[0].value.a,
				    attrs, attr_count, params[2].memref.buffer,
				    params[2].memref.size,
				    params[3].memref.buffer,
				    &params[3].memref.size);
	TEE_Free(attrs);
	return res;
}

TEE_Result ta_entry_asymmetric_sign_digest(uint32_t param_type,
					   TEE_Param params[4])
{
	TEE_Result res;
	TEE_Attribute *attrs;
	uint32_t attr_count;

	ASSERT_PARAM_TYPE(TEE_PARAM_TYPES
			  (TEE_PARAM_TYPE_VALUE_INPUT,
			   TEE_PARAM_TYPE_MEMREF_INPUT,
			   TEE_PARAM_TYPE_MEMREF_INPUT,
			   TEE_PARAM_TYPE_MEMREF_OUTPUT));

	res = unpack_attrs(params[1].memref.buffer, params[1].memref.size,
			   &attrs, &attr_count);
	if (res != TEE_SUCCESS)
		return res;

	res = TEE_AsymmetricSignDigest((TEE_OperationHandle) params[0].value.a,
				       attrs, attr_count,
				       params[2].memref.buffer,
				       params[2].memref.size,
				       params[3].memref.buffer,
				       &params[3].memref.size);
	TEE_Free(attrs);
	return res;
}

TEE_Result ta_entry_asymmetric_verify_digest(uint32_t param_type,
					     TEE_Param params[4])
{
	TEE_Result res;
	TEE_Attribute *attrs;
	uint32_t attr_count;

	ASSERT_PARAM_TYPE(TEE_PARAM_TYPES
			  (TEE_PARAM_TYPE_VALUE_INPUT,
			   TEE_PARAM_TYPE_MEMREF_INPUT,
			   TEE_PARAM_TYPE_MEMREF_INPUT,
			   TEE_PARAM_TYPE_MEMREF_INPUT));

	res = unpack_attrs(params[1].memref.buffer, params[1].memref.size,
			   &attrs, &attr_count);
	if (res != TEE_SUCCESS)
		return res;

	res =
	    TEE_AsymmetricVerifyDigest((TEE_OperationHandle) params[0].value.a,
				       attrs, attr_count,
				       params[2].memref.buffer,
				       params[2].memref.size,
				       params[3].memref.buffer,
				       params[3].memref.size);
	TEE_Free(attrs);
	return res;
}

TEE_Result ta_entry_derive_key(uint32_t param_type, TEE_Param params[4])
{
	TEE_Result res;
	TEE_Attribute *attrs;
	uint32_t attr_count;

	ASSERT_PARAM_TYPE(TEE_PARAM_TYPES
			  (TEE_PARAM_TYPE_VALUE_INPUT,
			   TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_NONE,
			   TEE_PARAM_TYPE_NONE));

	res = unpack_attrs(params[1].memref.buffer, params[1].memref.size,
			   &attrs, &attr_count);
	if (res != TEE_SUCCESS)
		return res;

	TEE_DeriveKey((TEE_OperationHandle) params[0].value.a,
		      attrs, attr_count, (TEE_ObjectHandle) params[0].value.b);
	TEE_Free(attrs);
	return TEE_SUCCESS;
}

TEE_Result ta_entry_random_number_generate(uint32_t param_type,
					   TEE_Param params[4])
{
	ASSERT_PARAM_TYPE(TEE_PARAM_TYPES
			  (TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE,
			   TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE));

	TEE_GenerateRandom(params[0].memref.buffer, params[0].memref.size);
	return TEE_SUCCESS;
}

TEE_Result ta_entry_ae_init(uint32_t param_type, TEE_Param params[4])
{
	ASSERT_PARAM_TYPE(TEE_PARAM_TYPES
			  (TEE_PARAM_TYPE_VALUE_INPUT,
			   TEE_PARAM_TYPE_MEMREF_INPUT,
			   TEE_PARAM_TYPE_VALUE_OUTPUT, TEE_PARAM_TYPE_NONE));
	return TEE_AEInit((TEE_OperationHandle) params[0].value.a,
			  params[1].memref.buffer, params[1].memref.size,
			  params[0].value.b * 8, /* tag_len in bits */
			  params[2].value.a, params[2].value.b);
}

TEE_Result ta_entry_ae_update_aad(uint32_t param_type, TEE_Param params[4])
{
	ASSERT_PARAM_TYPE(TEE_PARAM_TYPES
			  (TEE_PARAM_TYPE_VALUE_INPUT,
			   TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_NONE,
			   TEE_PARAM_TYPE_NONE));

	TEE_AEUpdateAAD((TEE_OperationHandle) params[0].value.a,
			params[1].memref.buffer, params[1].memref.size);
	return TEE_SUCCESS;
}

TEE_Result ta_entry_ae_update(uint32_t param_type, TEE_Param params[4])
{
	ASSERT_PARAM_TYPE(TEE_PARAM_TYPES
			  (TEE_PARAM_TYPE_VALUE_INPUT,
			   TEE_PARAM_TYPE_MEMREF_INPUT,
			   TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE));

	TEE_AEUpdate((TEE_OperationHandle) params[0].value.a,
		     params[1].memref.buffer, params[1].memref.size,
		     params[2].memref.buffer, &params[2].memref.size);
	return TEE_SUCCESS;
}

TEE_Result ta_entry_ae_encrypt_final(uint32_t param_type, TEE_Param params[4])
{
	TEE_Result res;

	ASSERT_PARAM_TYPE(TEE_PARAM_TYPES
			  (TEE_PARAM_TYPE_VALUE_INPUT,
			   TEE_PARAM_TYPE_MEMREF_INPUT,
			   TEE_PARAM_TYPE_MEMREF_OUTPUT,
			   TEE_PARAM_TYPE_MEMREF_OUTPUT));

	res = TEE_AEEncryptFinal((TEE_OperationHandle) params[0].value.a,
				 params[1].memref.buffer, params[1].memref.size,
				 params[2].memref.buffer,
				 &params[2].memref.size,
				 params[3].memref.buffer,
				 &params[3].memref.size);
	return res;
}

TEE_Result ta_entry_ae_decrypt_final(uint32_t param_type, TEE_Param params[4])
{
	ASSERT_PARAM_TYPE(TEE_PARAM_TYPES
			  (TEE_PARAM_TYPE_VALUE_INPUT,
			   TEE_PARAM_TYPE_MEMREF_INPUT,
			   TEE_PARAM_TYPE_MEMREF_OUTPUT,
			   TEE_PARAM_TYPE_MEMREF_INPUT));

	return TEE_AEDecryptFinal((TEE_OperationHandle) params[0].value.a,
				  params[1].memref.buffer,
				  params[1].memref.size,
				  params[2].memref.buffer,
				  &params[2].memref.size,
				  params[3].memref.buffer,
				  params[3].memref.size);
}

TEE_Result ta_entry_get_object_buffer_attribute(uint32_t param_type,
						TEE_Param params[4])
{
	ASSERT_PARAM_TYPE(TEE_PARAM_TYPES
			  (TEE_PARAM_TYPE_VALUE_INPUT,
			   TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE,
			   TEE_PARAM_TYPE_NONE));

	return TEE_GetObjectBufferAttribute((TEE_ObjectHandle) params[0].value.
					    a, params[0].value.b,
					    params[1].memref.buffer,
					    &params[1].memref.size);
}

TEE_Result ta_entry_get_object_value_attribute(uint32_t param_type,
					       TEE_Param params[4])
{
	ASSERT_PARAM_TYPE(TEE_PARAM_TYPES
			  (TEE_PARAM_TYPE_VALUE_INPUT,
			   TEE_PARAM_TYPE_VALUE_OUTPUT, TEE_PARAM_TYPE_NONE,
			   TEE_PARAM_TYPE_NONE));

	return TEE_GetObjectValueAttribute((TEE_ObjectHandle) params[0].value.a,
					   params[0].value.b,
					   &params[1].value.a,
					   &params[1].value.b);
}
