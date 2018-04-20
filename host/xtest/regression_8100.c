// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018, Linaro Limited */

#include "xtest_test.h"
#include "xtest_helpers.h"

#include <ta_crypt.h>
#include <tee_api_types.h>
#include <compiler.h>

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
