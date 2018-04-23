// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018, Linaro Limited */

#include "xtest_test.h"
#include "xtest_helpers.h"

#include <compiler.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ta_crypt.h>
#include <tee_api_types.h>

#include "regression_8100_ca_crt.h"
#include "regression_8100_mid_crt.h"
#include "regression_8100_my_crt.h"

#ifdef CFG_TA_MBEDTLS

static void test_8101(ADBG_Case_t *c __maybe_unused)
{
#ifdef CFG_TA_MBEDTLS_SELF_TEST
	TEEC_Session session = { 0 };
	uint32_t ret_orig;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, xtest_teec_open_session(
					      &session, &crypt_user_ta_uuid,
					      NULL, &ret_orig)))
		return;
	ADBG_EXPECT_TEEC_SUCCESS(c,
		TEEC_InvokeCommand(&session, TA_CRYPT_CMD_MBEDTLS_SELF_TESTS,
				   NULL, &ret_orig));
	TEEC_CloseSession(&session);
#else
	Do_ADBG_Log("CFG_TA_MBEDTLS_SELF_TEST not set, test skipped");
#endif
}
ADBG_CASE_DEFINE(regression, 8101, test_8101, "TA mbedTLS self tests");

static int __printf(2, 3) myasprintf(char **strp, const char *fmt, ...)
{
	char *str = NULL;
	int rc = 0;
	va_list ap;

	va_start(ap, fmt);
	rc = vsnprintf(str, rc, fmt, ap);
	if (rc <= 0)
		goto out;

	str = malloc(rc);
	if (!str) {
		rc = -1;
		goto out;
	}

	rc = vsnprintf(str, rc, fmt, ap);
	if (rc <= 0)
		free(str);
	else
		*strp = str;

out:
	va_end(ap);
	return rc;
}

static void test_8102(ADBG_Case_t *c)
{
	TEEC_Session session = { 0 };
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;
	char *chain = NULL;
	int clen = 0;
	char *trust = NULL;
	int tlen;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, xtest_teec_open_session(
					      &session, &crypt_user_ta_uuid,
					      NULL, &ret_orig)))
		return;

	clen = myasprintf(&chain, "%*s\n%*s",
			  (int)sizeof(regression_8100_my_crt),
			  regression_8100_my_crt,
			  (int)sizeof(regression_8100_mid_crt),
			   regression_8100_mid_crt);
	if (!ADBG_EXPECT_COMPARE_SIGNED(c, clen, !=, -1))
		goto out;
	tlen = myasprintf(&trust, "%*s", (int)sizeof(regression_8100_ca_crt),
			  regression_8100_ca_crt);
	if (!ADBG_EXPECT_COMPARE_SIGNED(c, tlen, !=, -1))
		goto out;

	op.params[0].tmpref.buffer = chain;
	op.params[0].tmpref.size = clen;
	op.params[1].tmpref.buffer = trust;
	op.params[1].tmpref.size = tlen;
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_NONE, TEEC_NONE);

	ADBG_EXPECT_TEEC_SUCCESS(c,
		TEEC_InvokeCommand(&session, TA_CRYPT_CMD_MBEDTLS_CHECK_CERT,
				   &op, &ret_orig));
out:
	free(chain);
	free(trust);
	TEEC_CloseSession(&session);
}
ADBG_CASE_DEFINE(regression, 8102, test_8102, "TA mbedTLS test cert chain");
#endif /*CFG_TA_MBEDTLS*/
