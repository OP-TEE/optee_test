// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2018, Linaro Limited */

#include <mbedtls_taf.h>
#include <mbedtls/aes.h>
#include <mbedtls/base64.h>
#include <mbedtls/bignum.h>
#include <mbedtls/des.h>
#include <mbedtls/md5.h>
#include <mbedtls/rsa.h>
#include <mbedtls/sha1.h>
#include <mbedtls/sha256.h>
#include <mbedtls/x509.h>
#include <mbedtls/x509_crt.h>


TEE_Result
ta_entry_mbedtls_self_tests(uint32_t param_type,
			    TEE_Param params[TEE_NUM_PARAMS] __unused)
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	if (param_type != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

#ifdef CFG_TA_MBEDTLS_SELF_TEST
#define DO_MBEDTLS_SELF_TEST(x) do { \
		if (mbedtls_##x##_self_test(1)) { \
			EMSG("mbedtls_%s_self_test: failed", #x); \
			return TEE_ERROR_GENERIC; \
		} \
	} while (0)

	DO_MBEDTLS_SELF_TEST(aes);
	DO_MBEDTLS_SELF_TEST(des);
	DO_MBEDTLS_SELF_TEST(md5);
	DO_MBEDTLS_SELF_TEST(sha1);
	DO_MBEDTLS_SELF_TEST(sha256);
	DO_MBEDTLS_SELF_TEST(base64);
	DO_MBEDTLS_SELF_TEST(mpi);
	DO_MBEDTLS_SELF_TEST(rsa);
	DO_MBEDTLS_SELF_TEST(x509);

	return TEE_SUCCESS;
#else
	return TEE_ERROR_NOT_IMPLEMENTED;
#endif
}

TEE_Result ta_entry_mbedtls_check_cert(uint32_t param_type,
				    TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_SUCCESS;
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	int ret;
	uint32_t flags;
	mbedtls_x509_crt crt;
	mbedtls_x509_crt trust_crt;

	if (param_type != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	mbedtls_x509_crt_init(&crt);
	mbedtls_x509_crt_init(&trust_crt);

	ret = mbedtls_x509_crt_parse(&crt, params[0].memref.buffer,
				     params[0].memref.size);
	if (ret) {
		EMSG("mbedtls_x509_crt_parse: failed: %#x", ret);
		return TEE_ERROR_BAD_FORMAT;
	}

	ret = mbedtls_x509_crt_parse(&trust_crt, params[1].memref.buffer,
				     params[1].memref.size);
	if (ret) {
		EMSG("mbedtls_x509_crt_parse: failed: %#x", ret);
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

	ret = mbedtls_x509_crt_verify(&crt, &trust_crt, NULL, NULL, &flags,
				      NULL, NULL);
	if (ret) {
		EMSG("mbedtls_x509_crt_verify: failed: %#x", ret);
		res = TEE_ERROR_BAD_FORMAT;

	}

out:
	mbedtls_x509_crt_free(&trust_crt);
	mbedtls_x509_crt_free(&crt);

	return res;

}
