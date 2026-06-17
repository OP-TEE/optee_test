// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Vaisala Oyj.
 */

#include <asteec.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <tee_client_api.h>
#include <unistd.h>
#include <util.h>

#include "xtest_helpers.h"
#include "xtest_test.h"

/*
 * Must match MAX_BUF_SIZE defined in optee-os
 * ta/app_secrets/app_secrets_ta.c.
 */
#define ASTEEC_TA_MAX_BUF_SIZE 4096

static TEEC_Result seal(uint32_t login_method, gid_t login_gid,
			const void *plain, size_t plain_len,
			uint8_t **sealed, size_t *sealed_len)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;

	*sealed = NULL;
	*sealed_len = 0;

	res = asteec_seal(login_method, login_gid, plain, plain_len, NULL,
			  sealed_len);
	if (res != TEEC_ERROR_SHORT_BUFFER)
		return res;

	*sealed = malloc(*sealed_len);
	if (!*sealed)
		return TEEC_ERROR_OUT_OF_MEMORY;

	res = asteec_seal(login_method, login_gid, plain, plain_len, *sealed,
			  sealed_len);
	if (res != TEEC_SUCCESS) {
		free(*sealed);
		*sealed = NULL;
	}
	return res;
}

static TEEC_Result unseal(uint32_t login_method, gid_t login_gid,
			  const void *sealed, size_t sealed_len,
			  uint8_t **plain, size_t *plain_len)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;

	*plain = NULL;
	*plain_len = 0;

	res = asteec_unseal(login_method, login_gid, sealed, sealed_len,
			    NULL, plain_len);
	if (res != TEEC_ERROR_SHORT_BUFFER)
		return res;

	*plain = malloc(*plain_len);
	if (!*plain)
		return TEEC_ERROR_OUT_OF_MEMORY;

	res = asteec_unseal(login_method, login_gid, sealed, sealed_len, *plain,
			    plain_len);
	if (res != TEEC_SUCCESS) {
		free(*plain);
		*plain = NULL;
	}
	return res;
}

static TEEC_Result probe_sealing_overhead(ADBG_Case_t *c, size_t *overhead)
{
	uint8_t probe_byte = 0;
	size_t probe_len = 0;
	TEEC_Result res = TEEC_ERROR_GENERIC;

	res = asteec_seal(TEEC_LOGIN_PUBLIC, 0, &probe_byte, sizeof(probe_byte),
			  NULL, &probe_len);
	if (res == TEEC_ERROR_ITEM_NOT_FOUND)
		return res;
	if (!ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_SHORT_BUFFER, res))
		return res;
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, probe_len, >,
					  sizeof(probe_byte)) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, probe_len, <=,
					  ASTEEC_TA_MAX_BUF_SIZE))
		return TEEC_ERROR_GENERIC;

	*overhead = probe_len - sizeof(probe_byte);
	return TEEC_SUCCESS;
}

static void test_unseal_with_different_group(ADBG_Case_t *c, uint8_t *plain,
					     size_t plain_len)
{
	gid_t cur_gid = getegid();
	gid_t other_gid = 0;
	gid_t *groups = NULL;
	uint8_t *sealed = NULL;
	uint8_t *unsealed = NULL;
	size_t sealed_len = 0;
	size_t unsealed_len = 0;
	int ngroups = 0;
	int i = 0;
	bool found_other = false;
	TEEC_Result res = TEEC_ERROR_GENERIC;

	ngroups = getgroups(0, NULL);
	if (!ADBG_EXPECT_COMPARE_SIGNED(c, ngroups, >=, 0))
		goto out;
	if (ngroups > 0) {
		groups = calloc(ngroups, sizeof(*groups));
		if (!ADBG_EXPECT_NOT_NULL(c, groups))
			goto out;
		ngroups = getgroups(ngroups, groups);
		if (!ADBG_EXPECT_COMPARE_SIGNED(c, ngroups, >=, 0))
			goto out;
	}
	for (i = 0; i < ngroups; i++) {
		if (groups[i] != cur_gid) {
			other_gid = groups[i];
			found_other = true;
			break;
		}
	}
	if (!found_other) {
		Do_ADBG_Log("Skipping group-mismatch coverage: caller is in only one group");
		goto out;
	}

	memset(plain, 0xCC, plain_len);

	res = seal(TEEC_LOGIN_GROUP, cur_gid, plain, plain_len,
		   &sealed, &sealed_len);
	if (ADBG_EXPECT_TEEC_SUCCESS(c, res))
		ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_SECURITY,
					unseal(TEEC_LOGIN_GROUP, other_gid,
					       sealed, sealed_len,
					       &unsealed, &unsealed_len));
out:
	free(groups);
	free(sealed);
	free(unsealed);
}

static void xtest_asteec_test_1000(ADBG_Case_t *c)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	uint8_t plain[32] = { };
	size_t sealing_overhead = 0;
	size_t max_plain_len = 0;

	res = probe_sealing_overhead(c, &sealing_overhead);
	if (res == TEEC_ERROR_ITEM_NOT_FOUND) {
		Do_ADBG_Log("skip test, Application Secrets TA not found");
		return;
	}
	if (res != TEEC_SUCCESS)
		return;

	max_plain_len = ASTEEC_TA_MAX_BUF_SIZE - sealing_overhead;

	Do_ADBG_BeginSubCase(c, "Round-trip with 1-byte plaintext");
	{
		uint8_t one_byte = 0xCC;
		uint8_t *sealed = NULL;
		uint8_t *unsealed = NULL;
		size_t sealed_len = 0;
		size_t unsealed_len = 0;

		res = seal(TEEC_LOGIN_PUBLIC, 0, &one_byte, 1,
			   &sealed, &sealed_len);
		if (ADBG_EXPECT_TEEC_SUCCESS(c, res)) {
			ADBG_EXPECT_COMPARE_UNSIGNED(c, sealed_len, ==,
						     1 + sealing_overhead);
			res = unseal(TEEC_LOGIN_PUBLIC, 0, sealed, sealed_len,
				     &unsealed, &unsealed_len);
			if (ADBG_EXPECT_TEEC_SUCCESS(c, res))
				ADBG_EXPECT_BUFFER(c, &one_byte, 1,
						   unsealed, unsealed_len);
		}

		free(sealed);
		free(unsealed);
	}
	Do_ADBG_EndSubCase(c, "Round-trip with 1-byte plaintext");

	Do_ADBG_BeginSubCase(c, "Round-trip with maximum-size plaintext");
	{
		uint8_t *max_plain = malloc(max_plain_len);
		uint8_t *sealed = NULL;
		uint8_t *unsealed = NULL;
		size_t sealed_len = 0;
		size_t unsealed_len = 0;

		if (ADBG_EXPECT_NOT_NULL(c, max_plain)) {
			memset(max_plain, 0xCC, max_plain_len);

			res = seal(TEEC_LOGIN_PUBLIC, 0, max_plain,
				   max_plain_len, &sealed, &sealed_len);
			if (ADBG_EXPECT_TEEC_SUCCESS(c, res)) {
				ADBG_EXPECT_COMPARE_UNSIGNED(c, sealed_len, ==,
							     ASTEEC_TA_MAX_BUF_SIZE);
				res = unseal(TEEC_LOGIN_PUBLIC, 0, sealed,
					     sealed_len, &unsealed,
					     &unsealed_len);
				if (ADBG_EXPECT_TEEC_SUCCESS(c, res))
					ADBG_EXPECT_BUFFER(c, max_plain,
							   max_plain_len,
							   unsealed,
							   unsealed_len);
			}
		}

		free(max_plain);
		free(sealed);
		free(unsealed);
	}
	Do_ADBG_EndSubCase(c, "Round-trip with maximum-size plaintext");

	Do_ADBG_BeginSubCase(c, "Zero-length plaintext rejected");
	{
		uint8_t dummy = 0;
		uint8_t *sealed = NULL;
		size_t sealed_len = 0;

		ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_BAD_PARAMETERS,
					seal(TEEC_LOGIN_PUBLIC, 0, &dummy, 0,
					     &sealed, &sealed_len));

		free(sealed);
	}
	Do_ADBG_EndSubCase(c, "Zero-length plaintext rejected");

	Do_ADBG_BeginSubCase(c, "Plaintext over maximum size rejected");
	{
		const size_t over_len = max_plain_len + 1;
		uint8_t *over = malloc(over_len);
		uint8_t *sealed = NULL;
		size_t sealed_len = 0;

		if (ADBG_EXPECT_NOT_NULL(c, over)) {
			memset(over, 0xCC, over_len);
			ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_BAD_PARAMETERS,
						seal(TEEC_LOGIN_PUBLIC, 0,
						     over, over_len, &sealed,
						     &sealed_len));
		}

		free(over);
		free(sealed);
	}
	Do_ADBG_EndSubCase(c, "Plaintext over maximum size rejected");

	Do_ADBG_BeginSubCase(c,
			     "Same plaintext sealed twice yields different sealed output");
	{
		uint8_t *sealed1 = NULL;
		uint8_t *sealed2 = NULL;
		size_t sealed1_len = 0;
		size_t sealed2_len = 0;

		memset(plain, 0xCC, sizeof(plain));

		res = seal(TEEC_LOGIN_PUBLIC, 0, plain, sizeof(plain),
			   &sealed1, &sealed1_len);
		if (ADBG_EXPECT_TEEC_SUCCESS(c, res)) {
			res = seal(TEEC_LOGIN_PUBLIC, 0, plain, sizeof(plain),
				   &sealed2, &sealed2_len);
			if (ADBG_EXPECT_TEEC_SUCCESS(c, res) &&
			    ADBG_EXPECT_COMPARE_UNSIGNED(c, sealed1_len, ==,
							 sealed2_len)) {
				ADBG_EXPECT_COMPARE_SIGNED(c,
							   memcmp(sealed1, sealed2, sealed1_len),
							   !=, 0);
			}
		}

		free(sealed1);
		free(sealed2);
	}
	Do_ADBG_EndSubCase(c,
			   "Same plaintext sealed twice yields different sealed output");

	Do_ADBG_BeginSubCase(c, "Byte flip in sealed blob rejected");
	{
		uint8_t *sealed = NULL;
		uint8_t *unsealed = NULL;
		size_t sealed_len = 0;
		size_t unsealed_len = 0;

		memset(plain, 0xCC, sizeof(plain));

		res = seal(TEEC_LOGIN_PUBLIC, 0, plain, sizeof(plain),
			   &sealed, &sealed_len);
		if (ADBG_EXPECT_TEEC_SUCCESS(c, res) &&
		    ADBG_EXPECT_COMPARE_UNSIGNED(c, sealed_len, >, 0)) {
			sealed[sealed_len / 2] ^= 0xff;
			ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_SECURITY,
						unseal(TEEC_LOGIN_PUBLIC, 0,
						       sealed, sealed_len,
						       &unsealed,
						       &unsealed_len));
		}

		free(sealed);
		free(unsealed);
	}
	Do_ADBG_EndSubCase(c, "Byte flip in sealed blob rejected");

	Do_ADBG_BeginSubCase(c, "Truncated sealed blob rejected");
	{
		uint8_t *sealed = NULL;
		uint8_t *unsealed = NULL;
		size_t sealed_len = 0;
		size_t unsealed_len = 0;

		memset(plain, 0xCC, sizeof(plain));

		res = seal(TEEC_LOGIN_PUBLIC, 0, plain, sizeof(plain),
			   &sealed, &sealed_len);
		if (ADBG_EXPECT_TEEC_SUCCESS(c, res) &&
		    ADBG_EXPECT_COMPARE_UNSIGNED(c, sealed_len, >, 0))
			ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_SECURITY,
						unseal(TEEC_LOGIN_PUBLIC, 0,
						       sealed, sealed_len - 1,
						       &unsealed,
						       &unsealed_len));

		free(sealed);
		free(unsealed);
	}
	Do_ADBG_EndSubCase(c, "Truncated sealed blob rejected");

	Do_ADBG_BeginSubCase(c, "Undersized sealed blob rejected");
	{
		uint8_t junk[16] = { };
		uint8_t *unsealed = NULL;
		size_t unsealed_len = 0;

		ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_BAD_PARAMETERS,
					unseal(TEEC_LOGIN_PUBLIC, 0, junk,
					       sizeof(junk), &unsealed,
					       &unsealed_len));
		free(unsealed);
	}
	Do_ADBG_EndSubCase(c, "Undersized sealed blob rejected");

	Do_ADBG_BeginSubCase(c, "Round-trip with user login");
	{
		uint8_t *sealed = NULL;
		uint8_t *unsealed = NULL;
		size_t sealed_len = 0;
		size_t unsealed_len = 0;

		memset(plain, 0xCC, sizeof(plain));

		res = seal(TEEC_LOGIN_USER, 0, plain, sizeof(plain),
			   &sealed, &sealed_len);
		if (ADBG_EXPECT_TEEC_SUCCESS(c, res)) {
			res = unseal(TEEC_LOGIN_USER, 0, sealed, sealed_len,
				     &unsealed, &unsealed_len);
			if (ADBG_EXPECT_TEEC_SUCCESS(c, res))
				ADBG_EXPECT_BUFFER(c, plain, sizeof(plain),
						   unsealed, unsealed_len);
		}

		free(sealed);
		free(unsealed);
	}
	Do_ADBG_EndSubCase(c, "Round-trip with user login");

	Do_ADBG_BeginSubCase(c, "Round-trip with group login");
	{
		uint8_t *sealed = NULL;
		uint8_t *unsealed = NULL;
		size_t sealed_len = 0;
		size_t unsealed_len = 0;
		gid_t cur_gid = getegid();

		memset(plain, 0xCC, sizeof(plain));

		res = seal(TEEC_LOGIN_GROUP, cur_gid, plain, sizeof(plain),
			   &sealed, &sealed_len);
		if (ADBG_EXPECT_TEEC_SUCCESS(c, res)) {
			res = unseal(TEEC_LOGIN_GROUP, cur_gid, sealed,
				     sealed_len, &unsealed, &unsealed_len);
			if (ADBG_EXPECT_TEEC_SUCCESS(c, res))
				ADBG_EXPECT_BUFFER(c, plain, sizeof(plain),
						   unsealed, unsealed_len);
		}

		free(sealed);
		free(unsealed);
	}
	Do_ADBG_EndSubCase(c, "Round-trip with group login");

	Do_ADBG_BeginSubCase(c, "Unseal with different login type rejected");
	{
		uint8_t *sealed = NULL;
		uint8_t *unsealed = NULL;
		size_t sealed_len = 0;
		size_t unsealed_len = 0;

		memset(plain, 0xCC, sizeof(plain));

		res = seal(TEEC_LOGIN_USER, 0, plain, sizeof(plain),
			   &sealed, &sealed_len);
		if (ADBG_EXPECT_TEEC_SUCCESS(c, res))
			ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_SECURITY,
						unseal(TEEC_LOGIN_PUBLIC, 0,
						       sealed, sealed_len,
						       &unsealed,
						       &unsealed_len));

		free(sealed);
		free(unsealed);
	}
	Do_ADBG_EndSubCase(c, "Unseal with different login type rejected");

	Do_ADBG_BeginSubCase(c, "Unseal with different group rejected");
	test_unseal_with_different_group(c, plain, sizeof(plain));
	Do_ADBG_EndSubCase(c, "Unseal with different group rejected");
}

ADBG_CASE_DEFINE(asteec, 1000, xtest_asteec_test_1000,
		 "Test Application Secrets TA via libasteec");
