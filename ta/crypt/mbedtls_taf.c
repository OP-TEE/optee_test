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
