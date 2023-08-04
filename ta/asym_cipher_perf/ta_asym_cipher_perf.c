// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2023, Huawei Technologies Co., Ltd
 * All rights reserved.
 */

#include <stddef.h>
#include <utee_defines.h>
#include <tee_internal_api_extensions.h>
#include <tee_internal_api.h>
#include <tee_ta_api.h>
#include <string.h>
#include <trace.h>

#include "ta_asym_cipher_perf.h"
#include "ta_asym_cipher_perf_priv.h"

struct attr_packed {
 uint32_t id;
 uint32_t a;
 uint32_t b;
};

#define CHECK(res, name, action) do { \
 if ((res) != TEE_SUCCESS) { \
 printf(name ": 0x%08x", (res)); \
 action \
 } \
 } while(0)

static TEE_OperationHandle crypto_op = NULL;
static TEE_OperationHandle crypto_op_enc_sign = NULL;
static TEE_ObjectHandle crypto_obj = TEE_HANDLE_NULL;
static uint32_t algo;

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

 if (((uintptr_t)buf & 0x3) != 0 || blen < num_attrs_size)
 return TEE_ERROR_BAD_PARAMETERS;
 num_attrs = *(uint32_t *) (void *)buf;
 if ((blen - num_attrs_size) < (num_attrs * sizeof(*ap)))
 return TEE_ERROR_BAD_PARAMETERS;
 ap = (const struct attr_packed *)(const void *)(buf + num_attrs_size);

 if (num_attrs > 0) {
 size_t n;

 a = TEE_Malloc(num_attrs * sizeof(TEE_Attribute), 0);
 if (!a)
 return TEE_ERROR_OUT_OF_MEMORY;
 for (n = 0; n < num_attrs; n++) {
 uintptr_t p;

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
 printf("RSA enc or dec error algo_type\n");
 return TEE_ERROR_BAD_PARAMETERS;
 }

 return 0;
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
 printf("RSA sign or verify error algo_type\n");
 return TEE_ERROR_BAD_PARAMETERS;
 }

 return 0;
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
 printf("ECDSA sign or verify error width_bits\n");
 return TEE_ERROR_BAD_PARAMETERS;
 }

 return 0;
}

static TEE_Result get_algo(uint32_t tee_type, uint32_t mode,
    uint32_t width_bits, uint32_t algo_type)
{
 TEE_Result res = 0;

 if (tee_type == RSA) {
 if (mode == MODE_ENCRYPT || mode == MODE_DECRYPT) {
 res = get_rsa_cipher_algo(algo_type);
 } else if (mode == MODE_SIGN || mode == MODE_VERIFY) {
 res = get_rsa_hash_algo(algo_type);
 } else {
 printf("RSA error mode\n");
 res = TEE_ERROR_BAD_PARAMETERS;
 }
 } else if (tee_type == ECDSA) {
 if (mode == MODE_SIGN || mode == MODE_VERIFY) {
 res = get_ecdsa_hash_algo(width_bits);
 } else {
 printf("ECDSA error mode\n");
 res = TEE_ERROR_BAD_PARAMETERS;
 }
 }

 return res;
}

static TEE_Result get_keypair_type(uint32_t value)
{
 switch (value) {
 case DH:
 return TEE_TYPE_DH_KEYPAIR;
 case RSA:
 return TEE_TYPE_RSA_KEYPAIR;
 case ECDSA:
 return TEE_TYPE_ECDSA_KEYPAIR;
 case ECDH:
 return TEE_TYPE_ECDH_KEYPAIR;
 case X25519:
 return TEE_TYPE_X25519_KEYPAIR;
 default:
 printf("The algo[%u] is err!\n", algo);
 }

 return TEE_ERROR_BAD_PARAMETERS;
}

TEE_Result cmd_process_keypair(uint32_t param_types,
        TEE_Param params[TEE_NUM_PARAMS])
{
 TEE_Result res = TEE_ERROR_GENERIC;
 TEE_Attribute *attrs = NULL;
 uint32_t attr_count = 0;
 int width_bits = 0;
 int n = 0;
 uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
    TEE_PARAM_TYPE_MEMREF_INOUT,
    TEE_PARAM_TYPE_NONE,
    TEE_PARAM_TYPE_NONE);

 if (param_types != exp_param_types)
 return TEE_ERROR_BAD_PARAMETERS;

 res = unpack_attrs(params[1].memref.buffer, params[1].memref.size,
    &attrs, &attr_count);
 if (res != TEE_SUCCESS)
 return res;

 width_bits = params[0].value.a;
 n = params[0].value.b;

 while (n--) {
 res = TEE_GenerateKey(crypto_obj, width_bits, attrs, attr_count);
 CHECK(res, "TEE_GenerateKey", goto out;);
 TEE_ResetTransientObject(crypto_obj);
 }

out:
 TEE_Free(attrs);
 return res;
}

TEE_Result cmd_process_rsa_ecc(uint32_t param_types,
        TEE_Param params[TEE_NUM_PARAMS])
{
 TEE_Result res = TEE_ERROR_GENERIC;
 int n = 0;

 uint32_t mode = 0;
 uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
    TEE_PARAM_TYPE_VALUE_INPUT,
    TEE_PARAM_TYPE_MEMREF_INPUT,
    TEE_PARAM_TYPE_MEMREF_OUTPUT);
 TEE_Attribute *attrs = NULL;
 uint32_t attr_count = 0;

 TEE_Result (*do_asym)(TEE_OperationHandle, const TEE_Attribute *,
       uint32_t, const void *, uint32_t, void *,
       uint32_t *) = NULL;

 if (param_types != exp_param_types)
 return TEE_ERROR_BAD_PARAMETERS;

 res = unpack_attrs(params[0].memref.buffer, params[0].memref.size,
    &attrs, &attr_count);
 if (res != TEE_SUCCESS)
 return res;

 n = params[1].value.a;
 mode = params[1].value.b;

 if (mode == MODE_ENCRYPT)
 do_asym = TEE_AsymmetricEncrypt;
 else if (mode == MODE_DECRYPT)
 do_asym = TEE_AsymmetricDecrypt;
 else if (mode == MODE_SIGN)
 do_asym = TEE_AsymmetricSignDigest;

 if (mode == MODE_VERIFY) {
 while (n--) {
 res = TEE_AsymmetricVerifyDigest(crypto_op, attrs,
 attr_count, params[2].memref.buffer,
 params[2].memref.size, params[3].memref.buffer,
 params[3].memref.size);
 CHECK(res, "TEE_AsymmetricEncrypt", goto out;);
 }
 } else {
 while (n--) {
 res = do_asym(crypto_op, attrs, attr_count,
 params[2].memref.buffer, params[2].memref.size,
 params[3].memref.buffer, &params[3].memref.size);

 CHECK(res, "TEE_AsymmetricEncrypt", goto out;);
 }
 }

out:
 TEE_Free(attrs);
 return res;
}

TEE_Result cmd_prepare_obj(uint32_t param_types, TEE_Param params[4])
{
 TEE_Result res = TEE_ERROR_GENERIC;
 uint32_t tee_type;
 uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
    TEE_PARAM_TYPE_NONE,
    TEE_PARAM_TYPE_NONE,
    TEE_PARAM_TYPE_NONE);

 if (param_types != exp_param_types)
 return TEE_ERROR_BAD_PARAMETERS;

 tee_type = get_keypair_type(params[0].value.a);
 if (tee_type == TEE_ERROR_BAD_PARAMETERS)
 return TEE_ERROR_BAD_PARAMETERS;

 cmd_clean_obj();
 res = TEE_AllocateTransientObject(tee_type, params[0].value.b,
   &crypto_obj);
 CHECK(res, "TEE_AllocateTransientObject", return res;);

 return res;
}

TEE_Result cmd_prepare_keypair(uint32_t param_types, TEE_Param params[4])
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
 CHECK(res, "TEE_GenerateKey", goto out;);

 cmd_clean_op();
 res = TEE_AllocateOperation(&crypto_op, algo, mode, width_bits);
 CHECK(res, "TEE_AllocateOperation", goto out;);

 res = TEE_SetOperationKey(crypto_op, crypto_obj);
 CHECK(res, "TEE_SetOperationKey", goto out;);

 if (mode == MODE_DECRYPT) {
 res = TEE_AllocateOperation(&crypto_op_enc_sign, algo,
     MODE_ENCRYPT, width_bits);
 CHECK(res, "TEE_AllocateOperation", goto out;);

 res = TEE_SetOperationKey(crypto_op_enc_sign, crypto_obj);
 CHECK(res, "TEE_SetOperationKey", goto out;);
 } else if (mode == MODE_VERIFY) {
 res = TEE_AllocateOperation(&crypto_op_enc_sign, algo,
     MODE_SIGN, width_bits);
 CHECK(res, "TEE_AllocateOperation", goto out;);

 res = TEE_SetOperationKey(crypto_op_enc_sign, crypto_obj);
 CHECK(res, "TEE_SetOperationKey", goto out;);
 }

out:
 TEE_Free(attrs);

 return res;
}

TEE_Result cmd_prepare_hash(uint32_t param_types, TEE_Param params[4])
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

 if (params[0].value.a == ECDSA)
 hash_algo = TEE_ALG_SHA1;
 else
 hash_algo = TEE_ALG_HASH_ALGO(TEE_ALG_GET_DIGEST_HASH(algo));

 res = TEE_AllocateOperation(&hash_op, hash_algo, TEE_MODE_DIGEST, 0);
 CHECK(res, "TEE_AllocateOperation", return res;);

 res = TEE_DigestDoFinal(hash_op, params[1].memref.buffer,
 params[1].memref.size, params[2].memref.buffer,
 &params[2].memref.size);
 CHECK(res, "TEE_DigestDoFinal", return res;);

 TEE_FreeOperation(hash_op);

 return res;
}

TEE_Result cmd_prepare_enc_sign(uint32_t param_types,
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
 params[0].memref.buffer, params[0].memref.size,
 params[1].memref.buffer, &params[1].memref.size);
 else
 res = TEE_AsymmetricSignDigest(crypto_op_enc_sign, attrs,
        attr_count,
        params[0].memref.buffer,
        params[0].memref.size,
        params[1].memref.buffer,
        &params[1].memref.size);

 TEE_Free(attrs);
 CHECK(res, "TEE_AsymmetricEncrypt", return res;);

 return TEE_SUCCESS;
}

void cmd_clean_obj(void)
{
 if (crypto_obj)
 TEE_FreeTransientObject(crypto_obj);
 crypto_obj = TEE_HANDLE_NULL;
}

void cmd_clean_op(void)
{
 if (crypto_op) {
 TEE_FreeOperation(crypto_op);
 crypto_op = NULL;
 }
 if (crypto_op_enc_sign) {
 TEE_FreeOperation(crypto_op_enc_sign);
 crypto_op_enc_sign = NULL;
 }
}
