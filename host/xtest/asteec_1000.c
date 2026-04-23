// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Vaisala Oyj.
 */

#include <asteec.h>
#include <inttypes.h>
#include <stdbool.h>
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

/*
 * Must match struct secret_blob_hdr, AS_MAGIC and AS_BLOB_VERSION defined in
 * optee-os ta/app_secrets/app_secrets_ta.c.
 */
#define ASTEEC_BLOB_MAGIC	0x41534543
#define ASTEEC_BLOB_VERSION	1
#define ASTEEC_BLOB_IV_SIZE	12
#define ASTEEC_BLOB_TAG_SIZE	16

#define ASTEEC_TEST_PLAIN_SIZE	32

struct asteec_blob_hdr {
	uint32_t magic;
	uint32_t version;
	uint8_t iv[ASTEEC_BLOB_IV_SIZE];
	uint8_t tag[ASTEEC_BLOB_TAG_SIZE];
};

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

static bool seal_pattern(ADBG_Case_t *c, uint8_t **sealed, size_t *sealed_len)
{
	const struct asteec_blob_hdr *hdr = NULL;
	uint8_t plain[ASTEEC_TEST_PLAIN_SIZE] = { };

	memset(plain, 0xCC, sizeof(plain));

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, seal(TEEC_LOGIN_PUBLIC, 0, plain,
					      sizeof(plain), sealed,
					      sealed_len)))
		return false;
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, *sealed_len, >, sizeof(*hdr)))
		return false;

	hdr = (const struct asteec_blob_hdr *)(const void *)*sealed;
	return ADBG_EXPECT_COMPARE_UNSIGNED(c, hdr->magic, ==,
					    ASTEEC_BLOB_MAGIC) &&
	       ADBG_EXPECT_COMPARE_UNSIGNED(c, hdr->version, ==,
					    ASTEEC_BLOB_VERSION);
}

static void expect_unseal_result(ADBG_Case_t *c, TEEC_Result expected,
				 const uint8_t *sealed, size_t sealed_len)
{
	uint8_t *unsealed = NULL;
	size_t unsealed_len = 0;

	ADBG_EXPECT_TEEC_RESULT(c, expected,
				unseal(TEEC_LOGIN_PUBLIC, 0, sealed, sealed_len,
				       &unsealed, &unsealed_len));
	free(unsealed);
}

static bool probe_sealing_overhead(ADBG_Case_t *c, size_t *overhead)
{
	uint8_t probe_byte = 0;
	size_t probe_len = 0;
	TEEC_Result res = TEEC_ERROR_GENERIC;

	res = asteec_seal(TEEC_LOGIN_PUBLIC, 0, &probe_byte, sizeof(probe_byte),
			  NULL, &probe_len);
	if (res == TEEC_ERROR_ITEM_NOT_FOUND) {
		Do_ADBG_Log("skip test, Application Secrets TA not found");
		return false;
	}
	if (!ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_SHORT_BUFFER, res))
		return false;
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, probe_len, >,
					  sizeof(probe_byte)) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, probe_len, <=,
					  ASTEEC_TA_MAX_BUF_SIZE))
		return false;

	if (overhead)
		*overhead = probe_len - sizeof(probe_byte);
	return true;
}

static void test_round_trip(ADBG_Case_t *c, uint32_t login_method,
			    gid_t login_gid, size_t plain_len,
			    size_t sealing_overhead)
{
	uint8_t *plain = NULL;
	uint8_t *sealed = NULL;
	uint8_t *unsealed = NULL;
	size_t sealed_len = 0;
	size_t unsealed_len = 0;
	TEEC_Result res = TEEC_ERROR_GENERIC;

	plain = malloc(plain_len);
	if (!ADBG_EXPECT_NOT_NULL(c, plain))
		return;
	memset(plain, 0xCC, plain_len);

	res = seal(login_method, login_gid, plain, plain_len, &sealed,
		   &sealed_len);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		goto out;
	ADBG_EXPECT_COMPARE_UNSIGNED(c, sealed_len, ==,
				     plain_len + sealing_overhead);

	res = unseal(login_method, login_gid, sealed, sealed_len, &unsealed,
		     &unsealed_len);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		goto out;
	ADBG_EXPECT_BUFFER(c, plain, plain_len, unsealed, unsealed_len);
out:
	free(plain);
	free(sealed);
	free(unsealed);
}

static void test_seal_zero_length(ADBG_Case_t *c)
{
	uint8_t dummy = 0;
	uint8_t *sealed = NULL;
	size_t sealed_len = 0;

	ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_BAD_PARAMETERS,
				seal(TEEC_LOGIN_PUBLIC, 0, &dummy, 0, &sealed,
				     &sealed_len));
	free(sealed);
}

static void test_seal_oversized(ADBG_Case_t *c, size_t plain_len)
{
	uint8_t *plain = NULL;
	uint8_t *sealed = NULL;
	size_t sealed_len = 0;

	plain = malloc(plain_len);
	if (!ADBG_EXPECT_NOT_NULL(c, plain))
		return;
	memset(plain, 0xCC, plain_len);

	ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_BAD_PARAMETERS,
				seal(TEEC_LOGIN_PUBLIC, 0, plain, plain_len,
				     &sealed, &sealed_len));
	free(plain);
	free(sealed);
}

static void test_seal_randomized(ADBG_Case_t *c)
{
	uint8_t *sealed1 = NULL;
	uint8_t *sealed2 = NULL;
	size_t sealed1_len = 0;
	size_t sealed2_len = 0;

	if (!seal_pattern(c, &sealed1, &sealed1_len) ||
	    !seal_pattern(c, &sealed2, &sealed2_len))
		goto out;
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, sealed1_len, ==, sealed2_len))
		goto out;

	ADBG_EXPECT_COMPARE_SIGNED(c, memcmp(sealed1, sealed2, sealed1_len),
				   !=, 0);
out:
	free(sealed1);
	free(sealed2);
}

static void test_unseal_short_buffer(ADBG_Case_t *c)
{
	uint8_t small[ASTEEC_TEST_PLAIN_SIZE - 1] = { };
	uint8_t *sealed = NULL;
	size_t sealed_len = 0;
	size_t small_len = sizeof(small);

	if (!seal_pattern(c, &sealed, &sealed_len))
		goto out;

	ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_SHORT_BUFFER,
				asteec_unseal(TEEC_LOGIN_PUBLIC, 0, sealed,
					      sealed_len, small, &small_len));
	ADBG_EXPECT_COMPARE_UNSIGNED(c, small_len, ==, ASTEEC_TEST_PLAIN_SIZE);
out:
	free(sealed);
}

static void test_unseal_byte_flip(ADBG_Case_t *c)
{
	uint8_t *sealed = NULL;
	size_t sealed_len = 0;

	if (!seal_pattern(c, &sealed, &sealed_len))
		goto out;

	sealed[sealed_len / 2] ^= 0xff;
	expect_unseal_result(c, TEEC_ERROR_SECURITY, sealed, sealed_len);
out:
	free(sealed);
}

static void test_unseal_bad_magic(ADBG_Case_t *c)
{
	const uint32_t bad_magics[] = { 0, ~ASTEEC_BLOB_MAGIC };
	struct asteec_blob_hdr *hdr = NULL;
	uint8_t *sealed = NULL;
	size_t sealed_len = 0;
	size_t i = 0;

	if (!seal_pattern(c, &sealed, &sealed_len))
		goto out;

	hdr = (struct asteec_blob_hdr *)(void *)sealed;
	for (i = 0; i < ARRAY_SIZE(bad_magics); i++) {
		Do_ADBG_Log("Setting magic to 0x%08" PRIx32, bad_magics[i]);
		hdr->magic = bad_magics[i];
		expect_unseal_result(c, TEEC_ERROR_SECURITY, sealed,
				     sealed_len);
	}
out:
	free(sealed);
}

static void test_unseal_bad_version(ADBG_Case_t *c)
{
	const uint32_t bad_versions[] = {
		0, ASTEEC_BLOB_VERSION + 1, UINT32_MAX
	};
	struct asteec_blob_hdr *hdr = NULL;
	uint8_t *sealed = NULL;
	size_t sealed_len = 0;
	size_t i = 0;

	if (!seal_pattern(c, &sealed, &sealed_len))
		goto out;

	hdr = (struct asteec_blob_hdr *)(void *)sealed;
	for (i = 0; i < ARRAY_SIZE(bad_versions); i++) {
		Do_ADBG_Log("Setting version to %" PRIu32, bad_versions[i]);
		hdr->version = bad_versions[i];
		expect_unseal_result(c, TEEC_ERROR_SECURITY, sealed,
				     sealed_len);
	}
out:
	free(sealed);
}

static void test_unseal_truncated(ADBG_Case_t *c)
{
	uint8_t *sealed = NULL;
	size_t sealed_len = 0;

	if (!seal_pattern(c, &sealed, &sealed_len))
		goto out;

	expect_unseal_result(c, TEEC_ERROR_SECURITY, sealed, sealed_len - 1);
out:
	free(sealed);
}

static void test_unseal_trailing_bytes(ADBG_Case_t *c)
{
	uint8_t *sealed = NULL;
	uint8_t *extended = NULL;
	size_t sealed_len = 0;

	if (!seal_pattern(c, &sealed, &sealed_len))
		goto out;

	extended = malloc(sealed_len + 1);
	if (!ADBG_EXPECT_NOT_NULL(c, extended))
		goto out;
	memcpy(extended, sealed, sealed_len);
	extended[sealed_len] = 0;

	expect_unseal_result(c, TEEC_ERROR_SECURITY, extended, sealed_len + 1);
out:
	free(sealed);
	free(extended);
}

static void test_unseal_bad_size(ADBG_Case_t *c, size_t sealed_len)
{
	uint8_t *junk = NULL;

	junk = calloc(1, sealed_len);
	if (!ADBG_EXPECT_NOT_NULL(c, junk))
		return;

	expect_unseal_result(c, TEEC_ERROR_BAD_PARAMETERS, junk, sealed_len);
	free(junk);
}

static void test_unseal_with_different_login(ADBG_Case_t *c)
{
	uint8_t plain[ASTEEC_TEST_PLAIN_SIZE] = { };
	uint8_t *sealed = NULL;
	uint8_t *unsealed = NULL;
	size_t sealed_len = 0;
	size_t unsealed_len = 0;
	TEEC_Result res = TEEC_ERROR_GENERIC;

	memset(plain, 0xCC, sizeof(plain));

	res = seal(TEEC_LOGIN_USER, 0, plain, sizeof(plain), &sealed,
		   &sealed_len);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, res))
		goto out;

	ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_SECURITY,
				unseal(TEEC_LOGIN_PUBLIC, 0, sealed, sealed_len,
				       &unsealed, &unsealed_len));
out:
	free(sealed);
	free(unsealed);
}

static void test_unseal_with_different_group(ADBG_Case_t *c)
{
	uint8_t plain[ASTEEC_TEST_PLAIN_SIZE] = { };
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

	memset(plain, 0xCC, sizeof(plain));

	res = seal(TEEC_LOGIN_GROUP, cur_gid, plain, sizeof(plain),
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
	size_t sealing_overhead = 0;
	size_t max_plain_len = 0;

	if (!probe_sealing_overhead(c, &sealing_overhead))
		return;

	max_plain_len = ASTEEC_TA_MAX_BUF_SIZE - sealing_overhead;

	Do_ADBG_BeginSubCase(c, "Round-trip with 1-byte plaintext");
	test_round_trip(c, TEEC_LOGIN_PUBLIC, 0, 1, sealing_overhead);
	Do_ADBG_EndSubCase(c, "Round-trip with 1-byte plaintext");

	Do_ADBG_BeginSubCase(c, "Round-trip with maximum-size plaintext");
	test_round_trip(c, TEEC_LOGIN_PUBLIC, 0, max_plain_len,
			sealing_overhead);
	Do_ADBG_EndSubCase(c, "Round-trip with maximum-size plaintext");

	Do_ADBG_BeginSubCase(c, "Zero-length plaintext rejected");
	test_seal_zero_length(c);
	Do_ADBG_EndSubCase(c, "Zero-length plaintext rejected");

	Do_ADBG_BeginSubCase(c, "Plaintext over maximum size rejected");
	test_seal_oversized(c, max_plain_len + 1);
	Do_ADBG_EndSubCase(c, "Plaintext over maximum size rejected");

	Do_ADBG_BeginSubCase(c,
			     "Same plaintext sealed twice yields different sealed output");
	test_seal_randomized(c);
	Do_ADBG_EndSubCase(c,
			   "Same plaintext sealed twice yields different sealed output");

	Do_ADBG_BeginSubCase(c, "Unseal into too small output buffer");
	test_unseal_short_buffer(c);
	Do_ADBG_EndSubCase(c, "Unseal into too small output buffer");
}

ADBG_CASE_DEFINE(asteec, 1000, xtest_asteec_test_1000,
		 "Application Secrets TA round-trip and size limits");

static void xtest_asteec_test_1001(ADBG_Case_t *c)
{
	if (!probe_sealing_overhead(c, NULL))
		return;

	Do_ADBG_BeginSubCase(c, "Byte flip in sealed blob rejected");
	test_unseal_byte_flip(c);
	Do_ADBG_EndSubCase(c, "Byte flip in sealed blob rejected");

	Do_ADBG_BeginSubCase(c, "Invalid magic in sealed blob rejected");
	test_unseal_bad_magic(c);
	Do_ADBG_EndSubCase(c, "Invalid magic in sealed blob rejected");

	Do_ADBG_BeginSubCase(c, "Unsupported version in sealed blob rejected");
	test_unseal_bad_version(c);
	Do_ADBG_EndSubCase(c, "Unsupported version in sealed blob rejected");

	Do_ADBG_BeginSubCase(c, "Truncated sealed blob rejected");
	test_unseal_truncated(c);
	Do_ADBG_EndSubCase(c, "Truncated sealed blob rejected");

	Do_ADBG_BeginSubCase(c, "Sealed blob with trailing bytes rejected");
	test_unseal_trailing_bytes(c);
	Do_ADBG_EndSubCase(c, "Sealed blob with trailing bytes rejected");

	Do_ADBG_BeginSubCase(c, "Sealed blob over maximum size rejected");
	test_unseal_bad_size(c, ASTEEC_TA_MAX_BUF_SIZE + 1);
	Do_ADBG_EndSubCase(c, "Sealed blob over maximum size rejected");

	Do_ADBG_BeginSubCase(c, "Undersized sealed blob rejected");
	test_unseal_bad_size(c, 16);
	Do_ADBG_EndSubCase(c, "Undersized sealed blob rejected");
}

ADBG_CASE_DEFINE(asteec, 1001, xtest_asteec_test_1001,
		 "Application Secrets TA rejects malformed sealed blobs");

static void xtest_asteec_test_1002(ADBG_Case_t *c)
{
	size_t sealing_overhead = 0;

	if (!probe_sealing_overhead(c, &sealing_overhead))
		return;

	Do_ADBG_BeginSubCase(c, "Round-trip with user login");
	test_round_trip(c, TEEC_LOGIN_USER, 0, ASTEEC_TEST_PLAIN_SIZE,
			sealing_overhead);
	Do_ADBG_EndSubCase(c, "Round-trip with user login");

	Do_ADBG_BeginSubCase(c, "Round-trip with group login");
	test_round_trip(c, TEEC_LOGIN_GROUP, getegid(), ASTEEC_TEST_PLAIN_SIZE,
			sealing_overhead);
	Do_ADBG_EndSubCase(c, "Round-trip with group login");

	Do_ADBG_BeginSubCase(c, "Unseal with different login type rejected");
	test_unseal_with_different_login(c);
	Do_ADBG_EndSubCase(c, "Unseal with different login type rejected");

	Do_ADBG_BeginSubCase(c, "Unseal with different group rejected");
	test_unseal_with_different_group(c);
	Do_ADBG_EndSubCase(c, "Unseal with different group rejected");
}

ADBG_CASE_DEFINE(asteec, 1002, xtest_asteec_test_1002,
		 "Application Secrets TA binds sealed blobs to client login");
