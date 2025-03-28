// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2015, Linaro Limited
 */

#include <string.h>
#include <tee_internal_api_extensions.h>
#include <tee_internal_api.h>
#include <tee_ta_api.h>
#include <trace.h>
#include <utee_defines.h>
#include <util.h>

#include "ta_crypto_perf.h"
#include "ta_crypto_perf_priv.h"

#define CHECK(res, name, action) do {			\
		if ((res) != TEE_SUCCESS) {		\
			DMSG(name ": 0x%08x", (res));	\
			action				\
		}					\
	} while(0)

#define TAG_LEN	128

static uint8_t iv[] = { 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
			0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF };
static int use_iv;

static TEE_OperationHandle crypto_op;
static uint32_t algo;
static TEE_OperationHandle crypto_op_enc_sign = TEE_HANDLE_NULL;
static TEE_ObjectHandle crypto_obj = TEE_HANDLE_NULL;
static TEE_Attribute *asym_perf_attrs;
static uint32_t asym_perf_attr_count;
static uint8_t *crypto_buf;

static bool is_inbuf_a_secure_memref(TEE_Param *param)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	/*
	 * Check secure attribute for the referenced buffer
	 * Trust core on validity of the memref size: test only 1st byte
	 * instead of the overall buffer, and if it's not secure, assume
	 * the buffer is nonsecure.
	 */
	res = TEE_CheckMemoryAccessRights(TEE_MEMORY_ACCESS_ANY_OWNER |
					  TEE_MEMORY_ACCESS_READ |
					  TEE_MEMORY_ACCESS_SECURE,
					  param->memref.buffer, 1);
	return (res == TEE_SUCCESS);
}

static bool is_outbuf_a_secure_memref(TEE_Param *param)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	/*
	 * Check secure attribute for the referenced buffer
	 * Trust core on validity of the memref size: test only 1st byte
	 * instead of the overall buffer, and if it's not secure, assume
	 * the buffer is nonsecure.
	 */
	res = TEE_CheckMemoryAccessRights(TEE_MEMORY_ACCESS_ANY_OWNER |
					  TEE_MEMORY_ACCESS_WRITE |
					  TEE_MEMORY_ACCESS_SECURE,
					  param->memref.buffer, 1);
	return (res == TEE_SUCCESS);
}

#if defined(CFG_CACHE_API)
static TEE_Result flush_memref_buffer(TEE_Param *param)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	res = TEE_CacheFlush(param->memref.buffer,
			     param->memref.size);
	CHECK(res, "TEE_CacheFlush(in)", return res;);
	return res;
}
#else
static __maybe_unused TEE_Result flush_memref_buffer(TEE_Param *param __unused)
{
	return TEE_SUCCESS;
}
#endif /* CFG_CACHE_API */

TEE_Result cmd_cipher_process(uint32_t param_types,
			      TEE_Param params[TEE_NUM_PARAMS],
			      bool use_sdp)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	int n = 0;
	int unit = 0;
	void *in = NULL;
	void *out = NULL;
	size_t insz = 0;
	size_t outsz = 0;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						   TEE_PARAM_TYPE_MEMREF_INOUT,
						   TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_NONE);
	bool secure_in = false;
	bool secure_out = false;
	TEE_Result (*do_update)(TEE_OperationHandle, const void *, size_t,
				void *, size_t *) = NULL;

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	if (use_sdp) {
		/*
		 * Whatever is expected as memory reference, it is mandatory
		 * for SDP aware trusted applications of safely indentify all
		 * memory reference parameters. Hence these tests must be part
		 * of the performance test setup.
		 */
		secure_in = is_inbuf_a_secure_memref(&params[0]);
		secure_out = is_outbuf_a_secure_memref(&params[1]);

		/*
		 * We could invalidate only the caches. We prefer to flush
		 * them in case 2 sub-buffers are accessed by TAs from a single
		 * allocated SDP memory buffer, and those are not cache-aligned.
		 * Invalidating might cause data loss in cache lines. Hence
		 * rather flush them all before accessing (in read or write).
		 */
		if (secure_in) {
			res = flush_memref_buffer(&params[0]);
			CHECK(res, "pre-flush in memref param", return res;);
		}
		if (secure_out) {
			res = flush_memref_buffer(&params[1]);
			CHECK(res, "pre-flush out memref param", return res;);
		}
	}

	in = params[0].memref.buffer;
	insz = params[0].memref.size;
	out = params[1].memref.buffer;
	outsz = params[1].memref.size;
	n = params[2].value.a;
	unit = params[2].value.b;
	if (!unit)
		unit = insz;

	if (algo == TEE_ALG_AES_GCM)
		do_update = TEE_AEUpdate;
	else
		do_update = TEE_CipherUpdate;

	while (n--) {
		uint32_t i = 0;
		for (i = 0; i < insz / unit; i++) {
			res = do_update(crypto_op, in, unit, out, &outsz);
			CHECK(res, "TEE_CipherUpdate/TEE_AEUpdate", return res;);
			in = (void *)((uintptr_t)in + unit);
			out = (void *)((uintptr_t)out + unit);
		}
		if (insz % unit) {
			res = do_update(crypto_op, in, insz % unit, out, &outsz);
			CHECK(res, "TEE_CipherUpdate/TEE_AEUpdate", return res;);
		}
	}

	if (secure_out) {
		/* intentionally flush output data from cache for SDP buffers */
		res = flush_memref_buffer(&params[1]);
		CHECK(res, "post-flush out memref param", return res;);
	}

	return TEE_SUCCESS;
}

TEE_Result cmd_cipher_prepare_key(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result res = TEE_ERROR_GENERIC;
	TEE_ObjectHandle hkey = TEE_HANDLE_NULL;
	TEE_ObjectHandle hkey2 = TEE_HANDLE_NULL;
	TEE_ObjectType objectType;
	TEE_Attribute attr = { };
	uint32_t mode = 0;
	uint32_t op_keysize = 0;
	uint32_t keysize = 0;
	const uint8_t *ivp = NULL;
	size_t ivlen = 0;
	static uint8_t cipher_key[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
	};
	static uint8_t cipher_key2[] = {
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
		0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F
	};
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	mode = params[0].value.a ? TEE_MODE_DECRYPT : TEE_MODE_ENCRYPT;
	keysize = params[0].value.b;
	op_keysize = keysize;

	switch (params[1].value.a) {
	case TA_AES_ECB:
		algo = TEE_ALG_AES_ECB_NOPAD;
		objectType = TEE_TYPE_AES;
		use_iv = 0;
		break;
	case TA_AES_CBC:
		algo = TEE_ALG_AES_CBC_NOPAD;
		objectType = TEE_TYPE_AES;
		use_iv = 1;
		break;
	case TA_AES_CTR:
		algo = TEE_ALG_AES_CTR;
		objectType = TEE_TYPE_AES;
		use_iv = 1;
		break;
	case TA_AES_XTS:
		algo = TEE_ALG_AES_XTS;
		objectType = TEE_TYPE_AES;
		use_iv = 1;
		op_keysize *= 2;
		break;
	case TA_AES_GCM:
		algo = TEE_ALG_AES_GCM;
		objectType = TEE_TYPE_AES;
		use_iv = 1;
		break;
	case TA_SM4_ECB:
		algo = TEE_ALG_SM4_ECB_NOPAD;
		objectType = TEE_TYPE_SM4;
		use_iv = 0;
		break;
	case TA_SM4_CBC:
		algo = TEE_ALG_SM4_CBC_NOPAD;
		objectType = TEE_TYPE_SM4;
		use_iv = 1;
		break;
	case TA_SM4_CTR:
		algo = TEE_ALG_SM4_CTR;
		objectType = TEE_TYPE_SM4;
		use_iv = 1;
		break;
	case TA_SM4_XTS:
		algo = TEE_ALG_SM4_XTS;
		objectType = TEE_TYPE_SM4;
		use_iv = 1;
		op_keysize *= 2;
		break;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	cmd_clean_res();

	res = TEE_AllocateOperation(&crypto_op, algo, mode, op_keysize);
	CHECK(res, "TEE_AllocateOperation", return res;);

	res = TEE_AllocateTransientObject(objectType, keysize, &hkey);
	CHECK(res, "TEE_AllocateTransientObject", return res;);

	attr.attributeID = TEE_ATTR_SECRET_VALUE;
	attr.content.ref.buffer = cipher_key;
	attr.content.ref.length = keysize / 8;

	res = TEE_PopulateTransientObject(hkey, &attr, 1);
	CHECK(res, "TEE_PopulateTransientObject", return res;);

	if (algo == TEE_ALG_AES_XTS || algo == TEE_ALG_SM4_XTS) {
		res = TEE_AllocateTransientObject(objectType, keysize, &hkey2);
		CHECK(res, "TEE_AllocateTransientObject", return res;);

		attr.content.ref.buffer = cipher_key2;

		res = TEE_PopulateTransientObject(hkey2, &attr, 1);
		CHECK(res, "TEE_PopulateTransientObject", return res;);

		res = TEE_SetOperationKey2(crypto_op, hkey, hkey2);
		CHECK(res, "TEE_SetOperationKey2", return res;);

		TEE_FreeTransientObject(hkey2);
	} else {
		res = TEE_SetOperationKey(crypto_op, hkey);
		CHECK(res, "TEE_SetOperationKey", return res;);
	}

	TEE_FreeTransientObject(hkey);

	if (use_iv) {
		ivp = iv;
		ivlen = sizeof(iv);
	} else {
		ivp = NULL;
		ivlen = 0;
	}

	if (algo == TEE_ALG_AES_GCM) {
		return TEE_AEInit(crypto_op, ivp, ivlen, TAG_LEN, 0, 0);
	} else {
		TEE_CipherInit(crypto_op, ivp, ivlen);
		return TEE_SUCCESS;
	}
}

static bool is_mac(uint32_t hash_algo)
{
	switch (hash_algo) {
	case TEE_ALG_HMAC_SHA1:
	case TEE_ALG_HMAC_SHA224:
	case TEE_ALG_HMAC_SHA256:
	case TEE_ALG_HMAC_SHA384:
	case TEE_ALG_HMAC_SHA512:
	case TEE_ALG_HMAC_SM3:
		return true;
	default:
		return false;
	}
}

TEE_Result cmd_hash_process(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result res = TEE_ERROR_GENERIC;
	TEE_OperationInfo info = { };
	int n = 0;
	void *in = NULL;
	void *out = NULL;
	size_t insz = 0;
	size_t outsz = 0;
	uint32_t offset = 0;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_OUTPUT,
						   TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	offset = params[2].value.b;
	in = (uint8_t *)params[0].memref.buffer + offset;
	insz = params[0].memref.size - offset;
	out = params[1].memref.buffer;
	outsz = params[1].memref.size;
	n = params[2].value.a;

	TEE_GetOperationInfo(crypto_op, &info);

	if (is_mac(info.algorithm)) {
		while (n--) {
			TEE_MACInit(crypto_op, NULL, 0);
			res = TEE_MACComputeFinal(crypto_op, in, insz, out, &outsz);
			CHECK(res, "TEE_MACComputeFinal", return res;);
		}
	} else {
		while (n--) {
			res = TEE_DigestDoFinal(crypto_op, in, insz, out, &outsz);
			CHECK(res, "TEE_DigestDoFinal", return res;);
		}
	}

	return TEE_SUCCESS;
}

TEE_Result cmd_hash_prepare_op(uint32_t param_types, TEE_Param params[4])
{
	TEE_ObjectHandle hkey = TEE_HANDLE_NULL;
	TEE_Result res = TEE_ERROR_GENERIC;
	TEE_Attribute attr = { };
	uint32_t key_type = TEE_TYPE_HMAC_SHA1;
	uint32_t mac_key_size = 512;
	uint32_t max_key_size = 0;
	uint32_t hash_algo = 0;
	static uint8_t mac_key[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
		0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F
	};
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	switch (params[0].value.a) {
	case TA_SHA_SHA1:
		hash_algo = TEE_ALG_SHA1;
		break;
	case TA_SHA_SHA224:
		hash_algo = TEE_ALG_SHA224;
		break;
	case TA_SHA_SHA256:
		hash_algo = TEE_ALG_SHA256;
		break;
	case TA_SHA_SHA384:
		hash_algo = TEE_ALG_SHA384;
		break;
	case TA_SHA_SHA512:
		hash_algo = TEE_ALG_SHA512;
		break;
	case TA_SM3:
		hash_algo = TEE_ALG_SM3;
		break;
	case TA_HMAC_SHA1:
		key_type = TEE_TYPE_HMAC_SHA1;
		hash_algo = TEE_ALG_HMAC_SHA1;
		max_key_size = 512;
		break;
	case TA_HMAC_SHA224:
		key_type = TEE_TYPE_HMAC_SHA224;
		hash_algo = TEE_ALG_HMAC_SHA224;
		max_key_size = 512;
		break;
	case TA_HMAC_SHA256:
		key_type = TEE_TYPE_HMAC_SHA256;
		hash_algo = TEE_ALG_HMAC_SHA256;
		max_key_size = 512;
		break;
	case TA_HMAC_SHA384:
		key_type = TEE_TYPE_HMAC_SHA384;
		hash_algo = TEE_ALG_HMAC_SHA384;
		max_key_size = 1024;
		break;
	case TA_HMAC_SHA512:
		key_type = TEE_TYPE_HMAC_SHA512;
		hash_algo = TEE_ALG_HMAC_SHA512;
		max_key_size = 1024;
		break;
	case TA_HMAC_SM3:
		key_type = TEE_TYPE_HMAC_SM3;
		hash_algo = TEE_ALG_HMAC_SM3;
		max_key_size = 512;
		break;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (crypto_op)
		TEE_FreeOperation(crypto_op);

	if (is_mac(hash_algo)) {
		res = TEE_AllocateOperation(&crypto_op, hash_algo, TEE_MODE_MAC,
					    max_key_size);
		CHECK(res, "TEE_AllocateOperation", return res;);

		res = TEE_AllocateTransientObject(key_type, max_key_size, &hkey);
		CHECK(res, "TEE_AllocateTransientObject", return res;);

		attr.attributeID = TEE_ATTR_SECRET_VALUE;
		attr.content.ref.buffer = mac_key;
		attr.content.ref.length = mac_key_size / 8;

		res = TEE_PopulateTransientObject(hkey, &attr, 1);
		CHECK(res, "TEE_PopulateTransientObject", return res;);

		res = TEE_SetOperationKey(crypto_op, hkey);
		CHECK(res, "TEE_SetOperationKey", return res;);

		TEE_FreeTransientObject(hkey);
	} else {
		res = TEE_AllocateOperation(&crypto_op, hash_algo, TEE_MODE_DIGEST, 0);
		CHECK(res, "TEE_AllocateOperation", return res;);
	}
	return TEE_SUCCESS;
}

struct attr_packed {
	uint32_t id;
	uint32_t a;
	uint32_t b;
};

static TEE_Result unpack_attrs(const uint8_t *buf, size_t blen,
			       TEE_Attribute **attrs, uint32_t *attr_count)
{
	TEE_Result res = TEE_SUCCESS;
	TEE_Attribute *a = NULL;
	const struct attr_packed *ap = NULL;
	size_t num_attrs = 0;
	const size_t num_attrs_size = sizeof(uint32_t);

	if (blen == 0)
		goto out;

	if (!IS_ALIGNED_WITH_TYPE(buf, uint32_t) || blen < num_attrs_size)
		return TEE_ERROR_BAD_PARAMETERS;
	num_attrs = *(uint32_t *)(void *)buf;
	if ((blen - num_attrs_size) < (num_attrs * sizeof(*ap)))
		return TEE_ERROR_BAD_PARAMETERS;
	ap = (const struct attr_packed *)(const void *)(buf + num_attrs_size);

	if (num_attrs > 0) {
		size_t n = 0;

		a = TEE_Malloc(num_attrs * sizeof(TEE_Attribute), 0);
		if (!a)
			return TEE_ERROR_OUT_OF_MEMORY;
		for (n = 0; n < num_attrs; n++) {
			uintptr_t p = 0;

			a[n].attributeID = ap[n].id;
			if (ap[n].id & TEE_ATTR_FLAG_VALUE) {
				a[n].content.value.a = ap[n].a;
				a[n].content.value.b = ap[n].b;
				continue;
			}

			a[n].content.ref.length = ap[n].b;
			p = (uintptr_t)ap[n].a;
			if (p) {
				if ((p + a[n].content.ref.length) > blen) {
					res = TEE_ERROR_BAD_PARAMETERS;
					goto out;
				}
				p += (uintptr_t)buf;
			}
			a[n].content.ref.buffer = (void *)p;
		}
	}

out:
	if (res == TEE_SUCCESS) {
		*attrs = a;
		*attr_count = num_attrs;
	} else {
		TEE_Free(a);
	}
	return res;
}

static TEE_Result get_rsa_cipher_algo(uint32_t algo_type)
{
	switch (algo_type) {
	case RSA_NOPAD:
		algo = TEE_ALG_RSA_NOPAD;
		break;
	case RSAES_PKCS1_V1_5:
		algo = TEE_ALG_RSAES_PKCS1_V1_5;
		break;
	case RSAES_PKCS1_OAEP_SHA1:
		algo = TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1;
		break;
	case RSAES_PKCS1_OAEP_SHA224:
		algo = TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA224;
		break;
	case RSAES_PKCS1_OAEP_SHA256:
		algo = TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256;
		break;
	case RSAES_PKCS1_OAEP_SHA384:
		algo = TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA384;
		break;
	case RSAES_PKCS1_OAEP_SHA512:
		algo = TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA512;
		break;
	default:
		EMSG("RSA enc or dec error algo_type");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return TEE_SUCCESS;
}

static TEE_Result get_rsa_hash_algo(uint32_t algo_type)
{
	switch (algo_type) {
	case RSASSA_PKCS1_V1_5_SHA1:
		algo = TEE_ALG_RSASSA_PKCS1_V1_5_SHA1;
		break;
	case RSASSA_PKCS1_V1_5_SHA224:
		algo = TEE_ALG_RSASSA_PKCS1_V1_5_SHA224;
		break;
	case RSASSA_PKCS1_V1_5_SHA256:
		algo = TEE_ALG_RSASSA_PKCS1_V1_5_SHA256;
		break;
	case RSASSA_PKCS1_V1_5_SHA384:
		algo = TEE_ALG_RSASSA_PKCS1_V1_5_SHA384;
		break;
	case RSASSA_PKCS1_V1_5_SHA512:
		algo = TEE_ALG_RSASSA_PKCS1_V1_5_SHA512;
		break;
	case RSASSA_PKCS1_PSS_MGF1_SHA1:
		algo = TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1;
		break;
	case RSASSA_PKCS1_PSS_MGF1_SHA224:
		algo = TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224;
		break;
	case RSASSA_PKCS1_PSS_MGF1_SHA256:
		algo = TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256;
		break;
	case RSASSA_PKCS1_PSS_MGF1_SHA384:
		algo = TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384;
		break;
	case RSASSA_PKCS1_PSS_MGF1_SHA512:
		algo = TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512;
		break;
	default:
		EMSG("RSA sign or verify error algo_type");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return TEE_SUCCESS;
}

static TEE_Result get_ecdsa_hash_algo(uint32_t width_bits)
{
	switch (width_bits) {
	case ECC_CURVE_192:
		algo = __OPTEE_ALG_ECDSA_P192;
		break;
	case ECC_CURVE_224:
		algo = __OPTEE_ALG_ECDSA_P224;
		break;
	case ECC_CURVE_256:
		algo = __OPTEE_ALG_ECDSA_P256;
		break;
	case ECC_CURVE_384:
		algo = __OPTEE_ALG_ECDSA_P384;
		break;
	case ECC_CURVE_521:
		algo = __OPTEE_ALG_ECDSA_P521;
		break;
	default:
		EMSG("ECDSA sign or verify error width_bits");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return TEE_SUCCESS;
}

static TEE_Result get_algo(uint32_t tee_type, uint32_t mode,
			   uint32_t width_bits, uint32_t algo_type)
{
	TEE_Result res = TEE_SUCCESS;

	if (tee_type == ALGO_RSA) {
		if (mode == MODE_ENCRYPT || mode == MODE_DECRYPT) {
			res = get_rsa_cipher_algo(algo_type);
		} else if (mode == MODE_SIGN || mode == MODE_VERIFY) {
			res = get_rsa_hash_algo(algo_type);
		} else {
			EMSG("RSA error mode");
			res = TEE_ERROR_BAD_PARAMETERS;
		}
	} else if (tee_type == ALGO_ECDSA) {
		if (mode == MODE_SIGN || mode == MODE_VERIFY) {
			res = get_ecdsa_hash_algo(width_bits);
		} else {
			EMSG("ECDSA error mode");
			res = TEE_ERROR_BAD_PARAMETERS;
		}
	} else if (tee_type == ALGO_SM2) {
		if (mode == MODE_ENCRYPT || mode == MODE_DECRYPT) {
			algo = TEE_ALG_SM2_PKE;
		} else if (mode == MODE_SIGN || mode == MODE_VERIFY) {
			algo = TEE_ALG_SM2_DSA_SM3;
		} else {
			EMSG("SM2 error mode");
			res = TEE_ERROR_BAD_PARAMETERS;
		}
	} else {
		res = TEE_ERROR_BAD_PARAMETERS;
	}

	return res;
}

static uint32_t get_keypair_type(uint32_t value, uint32_t mode)
{
	switch (value) {
	case ALGO_DH:
		return TEE_TYPE_DH_KEYPAIR;
	case ALGO_RSA:
		return TEE_TYPE_RSA_KEYPAIR;
	case ALGO_ECDSA:
		return TEE_TYPE_ECDSA_KEYPAIR;
	case ALGO_ECDH:
		return TEE_TYPE_ECDH_KEYPAIR;
	case ALGO_X25519:
		return TEE_TYPE_X25519_KEYPAIR;
	case ALGO_SM2:
		if (mode == MODE_ENCRYPT || mode == MODE_DECRYPT) {
			return TEE_TYPE_SM2_PKE_KEYPAIR;
		} else if (mode == MODE_SIGN || mode == MODE_VERIFY) {
			return TEE_TYPE_SM2_DSA_KEYPAIR;
		} else {
			EMSG("The mode[%"PRIu32"] is not valid", mode);
			return TEE_TYPE_ILLEGAL_VALUE;
		}
	default:
		EMSG("The algo[%"PRIu32"] is not valid", value);
		return TEE_TYPE_ILLEGAL_VALUE;
	}
}

TEE_Result cmd_asym_prepare_attrs(uint32_t param_types,
				  TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	crypto_buf = TEE_Malloc(params[0].memref.size, 0);
	if (!crypto_buf)
			return TEE_ERROR_OUT_OF_MEMORY;
	memcpy(crypto_buf, params[0].memref.buffer, params[0].memref.size);

	return unpack_attrs(crypto_buf, params[0].memref.size,
			    &asym_perf_attrs, &asym_perf_attr_count);
}

TEE_Result cmd_asym_free_attrs(uint32_t param_types,
			       TEE_Param params[TEE_NUM_PARAMS] __unused)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	TEE_Free(asym_perf_attrs);
	asym_perf_attrs = NULL;
	TEE_Free(crypto_buf);
	crypto_buf = NULL;

	return TEE_SUCCESS;
}

TEE_Result cmd_asym_process_keypair(uint32_t param_types,
				    TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_ERROR_GENERIC;
	int width_bits = 0;
	int n = 0;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	width_bits = params[0].value.a;
	n = params[0].value.b;

	while (n--) {
		res = TEE_GenerateKey(crypto_obj, width_bits, asym_perf_attrs,
				      asym_perf_attr_count);
		CHECK(res, "TEE_GenerateKey()", break;);
		TEE_ResetTransientObject(crypto_obj);
	}

	return res;
}

TEE_Result cmd_asym_process_rsa_ecc(uint32_t param_types,
				    TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_ERROR_GENERIC;
	int n = 0;
	uint32_t mode = 0;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_OUTPUT,
						   TEE_PARAM_TYPE_NONE);
	size_t dummy_size = params[2].memref.size;
	TEE_Result (*do_asym)(TEE_OperationHandle, const TEE_Attribute *,
			      uint32_t, const void *, size_t, void *,
			      size_t *) = NULL;

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	n = params[0].value.a;
	mode = params[0].value.b;

	if (mode == MODE_VERIFY) {
		while (n--) {
			res = TEE_AsymmetricVerifyDigest(crypto_op,
							 asym_perf_attrs,
							 asym_perf_attr_count,
							 params[1].memref.buffer,
							 params[1].memref.size,
							 params[2].memref.buffer,
							 dummy_size);

			CHECK(res, "TEE processing failed", break;);
		}
	} else {
		if (mode == MODE_ENCRYPT)
			do_asym = TEE_AsymmetricEncrypt;
		else if (mode == MODE_DECRYPT)
			do_asym = TEE_AsymmetricDecrypt;
		else if (mode == MODE_SIGN)
			do_asym = TEE_AsymmetricSignDigest;
		else
			return TEE_ERROR_BAD_PARAMETERS;
		while (n--) {
			res = do_asym(crypto_op, asym_perf_attrs,
				      asym_perf_attr_count,
				      params[1].memref.buffer,
				      params[1].memref.size,
				      params[2].memref.buffer, &dummy_size);

			CHECK(res, "TEE processing failed", break;);
		}
	}

	return res;
}

TEE_Result cmd_asym_prepare_obj(uint32_t param_types,
				TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t tee_type = TEE_TYPE_ILLEGAL_VALUE;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	tee_type = get_keypair_type(params[0].value.a, params[1].value.a);
	if (tee_type == TEE_TYPE_ILLEGAL_VALUE)
		return TEE_ERROR_BAD_PARAMETERS;

	cmd_clean_obj();
	res = TEE_AllocateTransientObject(tee_type, params[0].value.b,
					  &crypto_obj);
	CHECK(res, "TEE_AllocateTransientObject()", return res;);

	return TEE_SUCCESS;
}

TEE_Result cmd_asym_prepare_keypair(uint32_t param_types,
				    TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_ERROR_GENERIC;
	TEE_Attribute *attrs = NULL;
	uint32_t attr_count = 0;
	uint32_t width_bits = 0;
	uint32_t algo_type = 0;
	uint32_t tee_type = 0;
	uint32_t mode = 0;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	mode = params[0].value.b;
	width_bits = params[0].value.a;
	tee_type = params[1].value.a;
	algo_type = params[1].value.b;

	if (get_algo(tee_type, mode, width_bits, algo_type))
		return TEE_ERROR_BAD_PARAMETERS;

	res = unpack_attrs(params[2].memref.buffer, params[2].memref.size,
			   &attrs, &attr_count);
	if (res != TEE_SUCCESS)
		return res;

	res = TEE_GenerateKey(crypto_obj, width_bits, attrs, attr_count);
	CHECK(res, "TEE_GenerateKey()", goto out;);

	cmd_clean_res();
	res = TEE_AllocateOperation(&crypto_op, algo, mode, width_bits);
	CHECK(res, "TEE_AllocateOperation()", goto out;);

	res = TEE_SetOperationKey(crypto_op, crypto_obj);
	CHECK(res, "TEE_SetOperationKey()", goto out;);

	if (mode == MODE_DECRYPT) {
		res = TEE_AllocateOperation(&crypto_op_enc_sign, algo,
					    MODE_ENCRYPT, width_bits);
		CHECK(res, "TEE_AllocateOperation()", goto out;);

		res = TEE_SetOperationKey(crypto_op_enc_sign, crypto_obj);
		CHECK(res, "TEE_SetOperationKey()", goto out;);
	} else if (mode == MODE_VERIFY) {
		res = TEE_AllocateOperation(&crypto_op_enc_sign, algo,
					    MODE_SIGN, width_bits);
		CHECK(res, "TEE_AllocateOperation()", goto out;);

		res = TEE_SetOperationKey(crypto_op_enc_sign, crypto_obj);
		CHECK(res, "TEE_SetOperationKey()", goto out;);
	}

out:
	TEE_Free(attrs);

	return res;
}

TEE_Result cmd_asym_prepare_hash(uint32_t param_types,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_ERROR_GENERIC;
	TEE_OperationHandle hash_op = NULL;
	uint32_t hash_algo = 0;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_INOUT,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	if (params[0].value.a == ALGO_ECDSA)
		hash_algo = TEE_ALG_SHA1;
	else
		hash_algo = TEE_ALG_HASH_ALGO(TEE_ALG_GET_DIGEST_HASH(algo));

	res = TEE_AllocateOperation(&hash_op, hash_algo, TEE_MODE_DIGEST, 0);
	CHECK(res, "TEE_AllocateOperation()", return res;);

	res = TEE_DigestDoFinal(hash_op, params[1].memref.buffer,
				params[1].memref.size, params[2].memref.buffer,
				&params[2].memref.size);
	TEE_FreeOperation(hash_op);
	CHECK(res, "TEE_DigestDoFinal()", return res;);

	return TEE_SUCCESS;
}

TEE_Result cmd_asym_prepare_enc_sign(uint32_t param_types,
				TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_ERROR_GENERIC;
	TEE_Attribute *attrs = NULL;
	uint32_t attr_count = 0;
	uint32_t mode = 0;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_OUTPUT,
						   TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_MEMREF_INPUT);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	mode = params[2].value.a;
	res = unpack_attrs(params[3].memref.buffer, params[3].memref.size,
			   &attrs, &attr_count);
	if (res != TEE_SUCCESS)
		return res;

	if (mode == MODE_DECRYPT)
		res = TEE_AsymmetricEncrypt(crypto_op_enc_sign, NULL, 0,
					    params[0].memref.buffer,
					    params[0].memref.size,
					    params[1].memref.buffer,
					    &params[1].memref.size);
	else
		res = TEE_AsymmetricSignDigest(crypto_op_enc_sign, attrs,
					       attr_count,
					       params[0].memref.buffer,
					       params[0].memref.size,
					       params[1].memref.buffer,
					       &params[1].memref.size);

	TEE_Free(attrs);
	if (mode == MODE_DECRYPT)
		CHECK(res, "TEE_AsymmetricEncrypt", return res;);
	else
		CHECK(res, "TEE_AsymmetricSignDigest", return res;);

	return TEE_SUCCESS;
}

void cmd_clean_obj(void)
{
	if (crypto_obj)
		TEE_FreeTransientObject(crypto_obj);
	crypto_obj = TEE_HANDLE_NULL;
}

void cmd_clean_res(void)
{
	if (crypto_op) {
		TEE_FreeOperation(crypto_op);
		crypto_op = TEE_HANDLE_NULL;
	}
	if (crypto_op_enc_sign) {
		TEE_FreeOperation(crypto_op_enc_sign);
		crypto_op_enc_sign = TEE_HANDLE_NULL;
	}
}
