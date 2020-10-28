// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2020, Open Mobile Platform LLС.
 */

/*
 * applogin_1000, applogin_1001, applogin_1002
 * Depend on OpenSSL
 * Depend on kernel commit "tee: add support for application-based session login methods"
 * Mailing list archives: https://lists.trustedfirmware.org/pipermail/op-tee/2020-October/000211.html
 * Upstream: <put sha-1 here when known>
 *
 * xtest skips these tests when not built with OpenSSL.
 */

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <util.h>

#include "xtest_test.h"
#include "xtest_helpers.h"
#include "xtest_uuid_helpers.h"

#define TEE_UUID_NS_NAME_SIZE  PATH_MAX

/*
 * TEE Client UUID name space identifier (UUIDv4)
 *
 * Value here is random UUID that is allocated as name space identifier for
 * forming Client UUID's for TEE environment using UUIDv5 scheme.
 */
static const char __maybe_unused *client_uuid_linux_ns =
	"58ac9ca0-2086-4683-a1b8-ec4bc08e01b6";

static void xtest_applogin_test_1000(ADBG_Case_t *c __maybe_unused)
{
#ifdef OPENSSL_FOUND
	TEEC_Result result = TEEC_ERROR_GENERIC;
	uint32_t ret_orig = 0;
	TEEC_Session session = { };
	uint32_t login = UINT32_MAX;
	TEEC_UUID client_uuid = { };
	TEEC_UUID expected_client_uuid = { };
	TEEC_UUID uuid_ns = { };
	char uuid_name[TEE_UUID_NS_NAME_SIZE + 4] = { };
	char app[PATH_MAX] = { };

	result = xtest_uuid_from_str(&uuid_ns, client_uuid_linux_ns);

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, result))
		return;

	if (readlink("/proc/self/exe", app, PATH_MAX) < 0) {
		Do_ADBG_Log(" - 1000 -   skip test, "
			    "/proc/self/exe not readable");
		return;
	}

	sprintf(uuid_name, "app=%s", app);
	uuid_name[TEE_UUID_NS_NAME_SIZE] = 0;

	result = xtest_uuid_v5(&expected_client_uuid, &uuid_ns, uuid_name,
			       strlen(uuid_name));
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, result))
		return;

	result = TEEC_OpenSession(&xtest_teec_ctx, &session, &os_test_ta_uuid,
				  TEEC_LOGIN_APPLICATION, NULL, NULL,
				  &ret_orig);

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, result))
		return;

	result = ta_os_test_cmd_client_identity(&session, &login, &client_uuid);

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, result))
		goto out;

	ADBG_EXPECT_COMPARE_UNSIGNED(c, login, ==, TEEC_LOGIN_APPLICATION);

	ADBG_EXPECT_EQUAL(c, &expected_client_uuid, &client_uuid,
			  sizeof(TEEC_UUID));

out:
	TEEC_CloseSession(&session);
#else /*!OPENSSL_FOUND*/
	/* xtest_uuid_v5() depends on OpenSSL */
	Do_ADBG_Log("OpenSSL not available, skipping test 1000");
#endif
}

ADBG_CASE_DEFINE(applogin, 1000, xtest_applogin_test_1000,
		 "Session: application login");

static void xtest_applogin_test_1001(ADBG_Case_t *c __maybe_unused)
{
#ifdef OPENSSL_FOUND
	TEEC_Result result = TEEC_ERROR_GENERIC;
	uint32_t ret_orig = 0;
	TEEC_Session session = { };
	uint32_t login = UINT32_MAX;
	TEEC_UUID client_uuid = { };
	TEEC_UUID expected_client_uuid = { };
	TEEC_UUID uuid_ns = { };
	char uuid_name[TEE_UUID_NS_NAME_SIZE + 16] = { };
	char app[PATH_MAX] = { };

	result = xtest_uuid_from_str(&uuid_ns, client_uuid_linux_ns);

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, result))
		return;

	if (readlink("/proc/self/exe", app, PATH_MAX) < 0) {
		Do_ADBG_Log(" - 1001 -   skip test, "
			    "/proc/self/exe not readable");
		return;
	}

	sprintf(uuid_name, "uid=%x:app=%s", geteuid(), app);
	uuid_name[TEE_UUID_NS_NAME_SIZE] = 0;

	result = xtest_uuid_v5(&expected_client_uuid, &uuid_ns, uuid_name,
			       strlen(uuid_name));
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, result))
		return;

	result = TEEC_OpenSession(&xtest_teec_ctx, &session, &os_test_ta_uuid,
				  TEEC_LOGIN_USER_APPLICATION, NULL, NULL,
				  &ret_orig);

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, result))
		return;

	result = ta_os_test_cmd_client_identity(&session, &login, &client_uuid);

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, result))
		goto out;

	ADBG_EXPECT_COMPARE_UNSIGNED(c, login, ==, TEEC_LOGIN_USER_APPLICATION);

	ADBG_EXPECT_EQUAL(c, &expected_client_uuid, &client_uuid,
			  sizeof(TEEC_UUID));

out:
	TEEC_CloseSession(&session);
#else /*!OPENSSL_FOUND*/
	/* xtest_uuid_v5() depends on OpenSSL */
	Do_ADBG_Log("OpenSSL not available, skipping test 1001");
#endif
}

ADBG_CASE_DEFINE(applogin, 1001, xtest_applogin_test_1001,
		 "Session: application-user login for current user");

static void xtest_applogin_test_1002(ADBG_Case_t *c __maybe_unused)
{
#ifdef OPENSSL_FOUND
	TEEC_Result result = TEEC_ERROR_GENERIC;
	uint32_t ret_orig = 0;
	TEEC_Session session = { };
	uint32_t login = UINT32_MAX;
	TEEC_UUID client_uuid = { };
	TEEC_UUID expected_client_uuid = { };
	TEEC_UUID uuid_ns = { };
	char uuid_name[TEE_UUID_NS_NAME_SIZE + 16] = { };
	char app[PATH_MAX] = { };
	uint32_t group = 0;

	group = getegid();

	result = xtest_uuid_from_str(&uuid_ns, client_uuid_linux_ns);

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, result))
		return;

	if (readlink("/proc/self/exe", app, PATH_MAX) < 0) {
		Do_ADBG_Log(" - 1002 -   skip test, "
			    "/proc/self/exe not readable");
		return;
	}

	sprintf(uuid_name, "gid=%x:app=%s", group, app);
	uuid_name[TEE_UUID_NS_NAME_SIZE] = 0;

	result = xtest_uuid_v5(&expected_client_uuid, &uuid_ns, uuid_name,
			       strlen(uuid_name));
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, result))
		return;

	result = TEEC_OpenSession(&xtest_teec_ctx, &session, &os_test_ta_uuid,
				  TEEC_LOGIN_GROUP_APPLICATION, &group, NULL,
				  &ret_orig);

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, result))
		return;

	result = ta_os_test_cmd_client_identity(&session, &login, &client_uuid);

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, result))
		goto out;

	ADBG_EXPECT_COMPARE_UNSIGNED(c, login, ==,
				     TEEC_LOGIN_GROUP_APPLICATION);

	ADBG_EXPECT_EQUAL(c, &expected_client_uuid, &client_uuid,
			  sizeof(TEEC_UUID));

out:
	TEEC_CloseSession(&session);
#else /*!OPENSSL_FOUND*/
	/* xtest_uuid_v5() depends on OpenSSL */
	Do_ADBG_Log("OpenSSL not available, skipping test 1002");
#endif
}

ADBG_CASE_DEFINE(applogin, 1002, xtest_applogin_test_1002,
		 "Session: application-group login "
		 "for current user's effective group");
