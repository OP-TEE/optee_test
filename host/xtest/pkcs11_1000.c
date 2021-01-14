// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2018, Linaro Limited
 */

#include <ck_debug.h>
#include <inttypes.h>
#include <pkcs11.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <util.h>

#include "xtest_test.h"
#include "xtest_helpers.h"

#include <regression_4000_data.h>

/*
 * Some PKCS#11 object resources used in the tests
 */
static const CK_BYTE cktest_aes128_key[16];

static const CK_BYTE cktest_aes128_iv[16];

static const CK_AES_CTR_PARAMS cktest_aes_ctr_params = {
	.ulCounterBits = 1,
};

static CK_MECHANISM cktest_aes_ecb_mechanism = {
	CKM_AES_ECB,
	NULL, 0,
};
static CK_MECHANISM cktest_aes_cbc_mechanism = {
	CKM_AES_CBC,
	(CK_BYTE_PTR)cktest_aes128_iv, sizeof(cktest_aes128_iv),
};
static CK_MECHANISM cktest_aes_ctr_mechanism = {
	CKM_AES_CTR,
	(CK_BYTE_PTR)&cktest_aes_ctr_params, sizeof(cktest_aes_ctr_params),
};
static CK_MECHANISM cktest_aes_cts_mechanism = {
	CKM_AES_CTS,
	(CK_BYTE_PTR)cktest_aes128_iv, sizeof(cktest_aes128_iv),
};
static CK_MECHANISM cktest_hmac_md5_mechanism = {
	CKM_MD5_HMAC, NULL, 0,
};
static CK_MECHANISM cktest_hmac_sha1_mechanism = {
	CKM_SHA_1_HMAC, NULL, 0,
};
static CK_MECHANISM cktest_hmac_sha224_mechanism = {
	CKM_SHA224_HMAC, NULL, 0,
};
static CK_MECHANISM cktest_hmac_sha256_mechanism = {
	CKM_SHA256_HMAC, NULL, 0,
};
static CK_MECHANISM cktest_hmac_sha384_mechanism = {
	CKM_SHA384_HMAC, NULL, 0,
};
static CK_MECHANISM cktest_hmac_sha512_mechanism = {
	CKM_SHA512_HMAC, NULL, 0,
};
static CK_MECHANISM cktest_gensecret_keygen_mechanism = {
	CKM_GENERIC_SECRET_KEY_GEN, NULL, 0,
};
static CK_MECHANISM cktest_aes_keygen_mechanism = {
	CKM_AES_KEY_GEN, NULL, 0,
};

/*
 * Util to find a slot on which to open a session
 */
static CK_RV close_lib(void)
{
	return C_Finalize(0);
}

static CK_RV init_lib_and_find_token_slot(CK_SLOT_ID *slot)
{
	CK_RV rv = CKR_GENERAL_ERROR;
	CK_SLOT_ID_PTR slots = NULL;
	CK_ULONG count = 0;

	rv = C_Initialize(0);
	if (rv)
		return rv;

	rv = C_GetSlotList(CK_TRUE, NULL, &count);
	if (rv != CKR_OK)
		goto bail;

	if (count < 1) {
		rv = CKR_GENERAL_ERROR;
		goto bail;
	}

	slots = malloc(count * sizeof(CK_SLOT_ID));
	if (!slots) {
		rv = CKR_HOST_MEMORY;
		goto bail;
	}

	rv = C_GetSlotList(CK_TRUE, slots, &count);
	if (rv)
		goto bail;

	/* Use the last slot */
	*slot = slots[count - 1];

bail:
	free(slots);
	if (rv)
		close_lib();

	return rv;
}

static void xtest_pkcs11_test_1000(ADBG_Case_t *c)
{
	CK_RV rv;

	rv = C_Initialize(NULL);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		return;

	rv = C_Finalize(NULL);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		return;

	rv = C_Initialize(NULL);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		return;

	rv = C_Initialize(NULL);
	ADBG_EXPECT_CK_RESULT(c, CKR_CRYPTOKI_ALREADY_INITIALIZED, rv);

	rv = C_Finalize(NULL);
	ADBG_EXPECT_CK_OK(c, rv);

	rv = C_Finalize(NULL);
	ADBG_EXPECT_CK_RESULT(c, CKR_CRYPTOKI_NOT_INITIALIZED, rv);
}

ADBG_CASE_DEFINE(pkcs11, 1000, xtest_pkcs11_test_1000,
		 "Initialize and close Cryptoki library");

static void xtest_pkcs11_test_1001(ADBG_Case_t *c)
{
	CK_RV rv = CKR_GENERAL_ERROR;
	CK_SLOT_ID_PTR slot_ids = NULL;
	CK_ULONG slot_count = 0;
	CK_ULONG present_slot_count = 0;
	CK_INFO lib_info = { };
	CK_SLOT_INFO slot_info = { };
	CK_TOKEN_INFO token_info = { };
	CK_FUNCTION_LIST_PTR ckfunc_list = NULL;
	size_t i = 0;
	CK_SLOT_ID max_slot_id = 0;
	CK_MECHANISM_TYPE_PTR mecha_types = NULL;
	CK_ULONG mecha_count = 0;
	CK_MECHANISM_INFO mecha_info = { };

	rv = C_Initialize(NULL);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		return;

	Do_ADBG_BeginSubCase(c, "Test C_GetFunctionList()");

	rv = C_GetFunctionList(&ckfunc_list);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	if (!ADBG_EXPECT_NOT_NULL(c, ckfunc_list->C_GetInfo) ||
	    !ADBG_EXPECT_NOT_NULL(c, ckfunc_list->C_GetSlotList) ||
	    !ADBG_EXPECT_NOT_NULL(c, ckfunc_list->C_GetSlotInfo) ||
	    !ADBG_EXPECT_NOT_NULL(c, ckfunc_list->C_GetTokenInfo) ||
	    !ADBG_EXPECT_NOT_NULL(c, ckfunc_list->C_GetMechanismList) ||
	    !ADBG_EXPECT_NOT_NULL(c, ckfunc_list->C_GetMechanismInfo))
		goto out;

	Do_ADBG_EndSubCase(c, "Test C_GetFunctionList()");
	Do_ADBG_BeginSubCase(c, "Test C_GetInfo()");

	rv = C_GetInfo(&lib_info);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	Do_ADBG_EndSubCase(c, "Test C_GetInfo()");
	Do_ADBG_BeginSubCase(c, "Test C_GetSlotList()");

	rv = C_GetSlotList(0, NULL, &slot_count);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, slot_count, !=, 0))
		goto out;

	if (slot_count > 1) {
		/* Ensure case non-NULL-buffer and zero-count is tested */
		CK_SLOT_ID id = 0;

		slot_count = 0;
		rv = C_GetSlotList(0, &id, &slot_count);
		if (!ADBG_EXPECT_CK_RESULT(c, CKR_BUFFER_TOO_SMALL, rv))
			goto out;
	}

	rv = C_GetSlotList(1, NULL, &present_slot_count);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, slot_count, ==,
					  present_slot_count))
		goto out;

	slot_ids = calloc(slot_count, sizeof(CK_SLOT_ID));
	if (!ADBG_EXPECT_NOT_NULL(c, slot_ids))
		goto out;

	slot_count--;
	rv = C_GetSlotList(1, slot_ids, &slot_count);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_BUFFER_TOO_SMALL, rv))
		goto out;

	rv = C_GetSlotList(1, slot_ids, &slot_count);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	Do_ADBG_EndSubCase(c, "Test C_GetSlotList()");
	Do_ADBG_BeginSubCase(c, "Test C_Get{Slot|Token}Info()");

	for (i = 0; i < slot_count; i++) {
		CK_SLOT_ID slot = slot_ids[i];

		rv = C_GetSlotInfo(slot, &slot_info);
		if (!ADBG_EXPECT_CK_OK(c, rv))
			goto out;

		rv = C_GetTokenInfo(slot, &token_info);
		if (!ADBG_EXPECT_CK_OK(c, rv))
			goto out;

		if (max_slot_id < slot)
			max_slot_id = slot;
	}

	Do_ADBG_EndSubCase(c, "Test C_Get{Slot|Token}Info()");
	Do_ADBG_BeginSubCase(c, "Test C_GetMechanism{List|Info}()");

	for (i = 0; i < slot_count; i++) {
		CK_SLOT_ID slot = slot_ids[i];
		size_t j = 0;

		mecha_count = 0;
		rv = C_GetMechanismList(slot, NULL, &mecha_count);
		if (!ADBG_EXPECT_CK_OK(c, rv))
			goto out;

		if (mecha_count == 0)
			continue;

		free(mecha_types);
		mecha_types = calloc(mecha_count, sizeof(*mecha_types));
		if (!ADBG_EXPECT_NOT_NULL(c, mecha_types))
			goto out;

		/* Test specific case: valid buffer reference with 0 count */
		mecha_count = 0;
		rv = C_GetMechanismList(slot, mecha_types, &mecha_count);
		if (!ADBG_EXPECT_CK_RESULT(c, CKR_BUFFER_TOO_SMALL, rv))
			goto out;

		rv = C_GetMechanismList(slot, mecha_types, &mecha_count);
		if (!ADBG_EXPECT_CK_OK(c, rv))
			goto out;

		for (j = 0; j < mecha_count; j++) {
			rv = C_GetMechanismInfo(slot, mecha_types[j],
						&mecha_info);
			if (!ADBG_EXPECT_CK_OK(c, rv))
				goto out;
		}
	}

	Do_ADBG_EndSubCase(c, "Test C_GetMechanism{List|Info}()");
	Do_ADBG_BeginSubCase(c, "Test C_Get*Info() with invalid reference");

	rv = C_GetSlotInfo(max_slot_id + 1, &slot_info);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_SLOT_ID_INVALID, rv))
		goto out;

	rv = C_GetTokenInfo(max_slot_id + 1, &token_info);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_SLOT_ID_INVALID, rv))
		goto out;

	mecha_count = 1;
	if (!mecha_types)
		mecha_types = malloc(sizeof(*mecha_types));
	if (!ADBG_EXPECT_NOT_NULL(c, mecha_types))
		goto out;

	rv = C_GetMechanismList(max_slot_id + 1, mecha_types, &mecha_count);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_SLOT_ID_INVALID, rv))
		goto out;

	rv = C_GetMechanismInfo(max_slot_id + 1, CKM_AES_KEY_GEN, &mecha_info);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_SLOT_ID_INVALID, rv))
		goto out;

	rv = C_GetSlotInfo(ULONG_MAX, &slot_info);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_SLOT_ID_INVALID, rv))
		goto out;

	rv = C_GetTokenInfo(ULONG_MAX, &token_info);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_SLOT_ID_INVALID, rv))
		goto out;

	mecha_count = 1;
	rv = C_GetMechanismList(ULONG_MAX, mecha_types, &mecha_count);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_SLOT_ID_INVALID, rv))
		goto out;

	rv = C_GetMechanismInfo(ULONG_MAX, CKM_AES_KEY_GEN, &mecha_info);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_SLOT_ID_INVALID, rv))
		goto out;

out:
	Do_ADBG_EndSubCase(c, NULL);
	free(slot_ids);
	free(mecha_types);

	rv = C_Finalize(NULL);
	ADBG_EXPECT_CK_OK(c, rv);
}

ADBG_CASE_DEFINE(pkcs11, 1001, xtest_pkcs11_test_1001,
		 "PKCS11: List PKCS#11 slots and get information from");

static void xtest_pkcs11_test_1002(ADBG_Case_t *c)
{
	CK_RV rv = CKR_GENERAL_ERROR;
	CK_SLOT_ID slot = 0;
	CK_SESSION_HANDLE session[3] = { 0 };
	CK_FLAGS session_flags = 0;
	CK_SESSION_INFO session_info = { };
	CK_FUNCTION_LIST_PTR ckfunc_list = NULL;

	rv = init_lib_and_find_token_slot(&slot);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		return;

	rv = C_GetFunctionList(&ckfunc_list);
	if (!ADBG_EXPECT_CK_OK(c, rv) ||
	    !ADBG_EXPECT_NOT_NULL(c, ckfunc_list->C_OpenSession) ||
	    !ADBG_EXPECT_NOT_NULL(c, ckfunc_list->C_CloseSession) ||
	    !ADBG_EXPECT_NOT_NULL(c, ckfunc_list->C_CloseAllSessions) ||
	    !ADBG_EXPECT_NOT_NULL(c, ckfunc_list->C_GetSessionInfo))
		goto bail;

	Do_ADBG_BeginSubCase(c, "Test C_OpenSession()/C_GetSessionInfo()");

	session_flags = CKF_RW_SESSION;

	rv = C_OpenSession(slot, session_flags, NULL, 0, &session[0]);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_SESSION_PARALLEL_NOT_SUPPORTED, rv))
		goto bail;

	session_flags = CKF_SERIAL_SESSION;

	rv = C_OpenSession(slot, session_flags, NULL, 0, &session[0]);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	rv = C_GetSessionInfo(session[0], &session_info);
	if (!ADBG_EXPECT_CK_OK(c, rv) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, session_info.slotID, ==, slot) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, session_info.flags, ==,
					  session_flags) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, session_info.state, ==,
					  CKS_RO_PUBLIC_SESSION) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, session_info.ulDeviceError, ==, 0))
		goto bail;

	session_flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;

	rv = C_OpenSession(slot, session_flags, NULL, 0, &session[1]);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	rv = C_GetSessionInfo(session[1], &session_info);
	if (!ADBG_EXPECT_CK_OK(c, rv) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, session_info.slotID, ==, slot) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, session_info.flags, ==,
					  session_flags) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, session_info.state, ==,
					  CKS_RW_PUBLIC_SESSION) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, session_info.ulDeviceError, ==, 0))
		goto bail;

	rv = C_OpenSession(slot, session_flags, NULL, 0, &session[2]);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	rv = C_GetSessionInfo(session[2], &session_info);
	if (!ADBG_EXPECT_CK_OK(c, rv) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, session_info.slotID, ==, slot) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, session_info.flags, ==,
					  session_flags) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, session_info.state, ==,
					  CKS_RW_PUBLIC_SESSION) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, session_info.ulDeviceError, ==, 0))
		goto bail;

	Do_ADBG_EndSubCase(c, "Test C_OpenSession()/C_GetSessionInfo()");
	Do_ADBG_BeginSubCase(c, "Test C_CloseSession()");

	/* Close 2 of them */
	rv = C_CloseSession(session[0]);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	rv = C_GetSessionInfo(session[0], &session_info);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_SESSION_HANDLE_INVALID, rv))
		goto bail;

	rv = C_GetSessionInfo(session[1], &session_info);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	rv = C_GetSessionInfo(session[2], &session_info);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	/* Close all remaining sessions, later calls should failed on session */
	rv = C_CloseAllSessions(slot);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	rv = C_CloseSession(session[1]);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_SESSION_HANDLE_INVALID, rv))
		goto bail;

	rv = C_CloseSession(session[2]);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_SESSION_HANDLE_INVALID, rv))
		goto bail;

	rv = C_GetSessionInfo(session[1], &session_info);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_SESSION_HANDLE_INVALID, rv))
		goto bail;

	rv = C_GetSessionInfo(session[2], &session_info);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_SESSION_HANDLE_INVALID, rv))
		goto bail;

	/* Open a session, should be closed from library closure */
	rv = C_OpenSession(slot, session_flags, NULL, 0, &session[0]);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

bail:
	Do_ADBG_EndSubCase(c, NULL);
	rv = close_lib();
	ADBG_EXPECT_CK_OK(c, rv);
}

ADBG_CASE_DEFINE(pkcs11, 1002, xtest_pkcs11_test_1002,
		 "PKCS11: Open and close PKCS#11 sessions");

/*
 * Helpers for tests where we must log into the token.
 * These define the genuine PINs and label to be used with the test token.
 */
static CK_UTF8CHAR test_token_so_pin[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8 , 9, 10, };
static CK_UTF8CHAR test_token_user_pin[] = {
	1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
};
static CK_UTF8CHAR test_token_label[] = "PKCS11 TA test token";

static CK_RV init_test_token(CK_SLOT_ID slot)
{
	return C_InitToken(slot, test_token_so_pin, sizeof(test_token_so_pin),
			   test_token_label);
}

/* Login as user, eventually reset user PIN if needed */
static CK_RV init_user_test_token(CK_SLOT_ID slot)
{
	CK_FLAGS session_flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_RV rv = CKR_GENERAL_ERROR;

	rv = C_OpenSession(slot, session_flags, NULL, 0, &session);
	if (rv)
		return rv;

	rv = C_Login(session, CKU_USER,	test_token_user_pin,
		     sizeof(test_token_user_pin));
	if (rv == CKR_OK) {
		C_Logout(session);
		C_CloseSession(session);
		return rv;
	}

	rv = C_Login(session, CKU_SO, test_token_so_pin,
		     sizeof(test_token_so_pin));
	if (rv) {
		C_CloseSession(session);

		rv = init_test_token(slot);
		if (rv)
			return rv;

		rv = C_OpenSession(slot, session_flags, NULL, 0, &session);
		if (rv)
			return rv;

		rv = C_Login(session, CKU_SO, test_token_so_pin,
			     sizeof(test_token_so_pin));
		if (rv) {
			C_CloseSession(session);
			return rv;
		}
	}

	rv = C_InitPIN(session, test_token_user_pin,
		       sizeof(test_token_user_pin));

	C_Logout(session);
	C_CloseSession(session);

	return rv;
}

static CK_RV test_already_initialized_token(ADBG_Case_t *c, CK_SLOT_ID slot)
{
	CK_RV rv = CKR_GENERAL_ERROR;
	CK_TOKEN_INFO token_info = { };
	/* Same content as test_token_so_pin[] but 1 more byte */
	CK_UTF8CHAR pin1[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, };
	/* Same content as test_token_so_pin[] but 1 different byte */
	CK_UTF8CHAR pin2[] = { 0, 1, 2, 3, 4, 5, 6, 6, 8, 9, 10, };
	CK_FLAGS flags = 0;

	Do_ADBG_BeginSubCase(c, "C_InitToken() on initialized token");

	rv = C_GetTokenInfo(slot, &token_info);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	rv = C_InitToken(slot, test_token_so_pin,
			 sizeof(test_token_so_pin) - 1, test_token_label);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, !=, CKR_OK))
		goto out;

	rv = C_InitToken(slot, pin1, sizeof(pin1), test_token_label);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, !=, CKR_OK))
		goto out;

	rv = C_InitToken(slot, pin2, sizeof(pin2), test_token_label);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, !=, CKR_OK))
		goto out;

	rv = C_GetTokenInfo(slot, &token_info);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	flags = token_info.flags;

	/* Token should have set CKF_SO_PIN_COUNT_LOW to 1 */
	if (!ADBG_EXPECT_TRUE(c, !!(flags & CKF_SO_PIN_COUNT_LOW))) {
		rv = CKR_GENERAL_ERROR;
		goto out;
	}

	rv = init_test_token(slot);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	rv = C_GetTokenInfo(slot, &token_info);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	flags = token_info.flags;

	/*
	 * Token should have reset CKF_SO_PIN_COUNT_LOW to 0.
	 * Other flags should show a sane initialized state.
	 */
	if (!ADBG_EXPECT_TRUE(c, !(flags & CKF_SO_PIN_COUNT_LOW)) ||
	    !ADBG_EXPECT_TRUE(c, !!(flags & CKF_TOKEN_INITIALIZED)) ||
	    !ADBG_EXPECT_TRUE(c, !(flags & CKF_ERROR_STATE)) ||
	    !ADBG_EXPECT_TRUE(c, !(flags & CKF_USER_PIN_INITIALIZED))) {
		rv = CKR_GENERAL_ERROR;
		goto out;
	}

	rv = init_user_test_token(slot);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	rv = C_GetTokenInfo(slot, &token_info);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	flags = token_info.flags;

	if (!ADBG_EXPECT_TRUE(c, !(flags & CKF_USER_PIN_COUNT_LOW)) ||
	    !ADBG_EXPECT_TRUE(c, !(flags & CKF_USER_PIN_FINAL_TRY)) ||
	    !ADBG_EXPECT_TRUE(c, !(flags & CKF_USER_PIN_LOCKED)) ||
	    !ADBG_EXPECT_TRUE(c, !(flags & CKF_USER_PIN_TO_BE_CHANGED)) ||
	    !ADBG_EXPECT_TRUE(c, !!(flags & CKF_USER_PIN_INITIALIZED)) ||
	    !ADBG_EXPECT_TRUE(c, !(flags & CKF_ERROR_STATE))) {
		rv = CKR_GENERAL_ERROR;
		goto out;
	}

out:
	Do_ADBG_EndSubCase(c, "C_InitToken() on initialized token");

	return rv;
}

static CK_RV test_uninitialized_token(ADBG_Case_t *c, CK_SLOT_ID slot)
{
	CK_RV rv = CKR_GENERAL_ERROR;
	CK_TOKEN_INFO token_info = { };
	CK_FLAGS flags = 0;

	Do_ADBG_BeginSubCase(c, "C_InitToken() on uninitialized token");

	rv = init_test_token(slot);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	rv = C_GetTokenInfo(slot, &token_info);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	flags = token_info.flags;

	if (!ADBG_EXPECT_TRUE(c, !!(flags & CKF_TOKEN_INITIALIZED)) ||
	    !ADBG_EXPECT_TRUE(c, !(flags & CKF_ERROR_STATE)) ||
	    !ADBG_EXPECT_TRUE(c, !(flags & CKF_USER_PIN_INITIALIZED))) {
		rv = CKR_GENERAL_ERROR;
		goto out;
	}

	rv = init_user_test_token(slot);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	rv = C_GetTokenInfo(slot, &token_info);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	flags = token_info.flags;

	if (!ADBG_EXPECT_TRUE(c, !!(flags & CKF_TOKEN_INITIALIZED)) ||
	    !ADBG_EXPECT_TRUE(c, !(flags & CKF_USER_PIN_COUNT_LOW)) ||
	    !ADBG_EXPECT_TRUE(c, !(flags & CKF_USER_PIN_FINAL_TRY)) ||
	    !ADBG_EXPECT_TRUE(c, !(flags & CKF_USER_PIN_LOCKED)) ||
	    !ADBG_EXPECT_TRUE(c, !(flags & CKF_USER_PIN_TO_BE_CHANGED)) ||
	    !ADBG_EXPECT_TRUE(c, !!(flags & CKF_USER_PIN_INITIALIZED)) ||
	    !ADBG_EXPECT_TRUE(c, !(flags & CKF_ERROR_STATE)))
		rv = CKR_GENERAL_ERROR;

out:
	Do_ADBG_EndSubCase(c, "C_InitToken() on uninitialized token");

	return rv;
}

static CK_RV test_login_logout(ADBG_Case_t *c, CK_SLOT_ID slot)
{
	CK_FLAGS session_flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_RV rv = CKR_GENERAL_ERROR;

	Do_ADBG_BeginSubCase(c, "Test C_Login()/C_Logout()");

	rv = C_OpenSession(slot, session_flags, NULL, 0, &session);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	/* Logout: should fail as we did not log in yet */
	rv = C_Logout(session);
	ADBG_EXPECT_CK_RESULT(c, CKR_USER_NOT_LOGGED_IN, rv);

	/* Login/re-log/logout user */
	rv = C_Login(session, CKU_USER, test_token_user_pin,
		     sizeof(test_token_user_pin));
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	rv = C_Login(session, CKU_USER, test_token_user_pin,
		     sizeof(test_token_user_pin));
	ADBG_EXPECT_CK_RESULT(c, CKR_USER_ALREADY_LOGGED_IN, rv);

	rv = C_Logout(session);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	/* Login/re-log/logout security officer */
	rv = C_Login(session, CKU_SO, test_token_so_pin,
		     sizeof(test_token_so_pin));
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	rv = C_Login(session, CKU_SO, test_token_so_pin,
		     sizeof(test_token_so_pin));
	ADBG_EXPECT_CK_RESULT(c, CKR_USER_ALREADY_LOGGED_IN, rv);

	rv = C_Logout(session);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	/* Login user then SO and reverse */
	rv = C_Login(session, CKU_SO, test_token_so_pin,
		     sizeof(test_token_so_pin));
	ADBG_EXPECT_CK_OK(c, rv);

	rv = C_Login(session, CKU_USER, test_token_user_pin,
		     sizeof(test_token_user_pin));
	ADBG_EXPECT_CK_RESULT(c, CKR_USER_ANOTHER_ALREADY_LOGGED_IN, rv);

	rv = C_Logout(session);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	rv = C_Login(session, CKU_USER, test_token_user_pin,
		     sizeof(test_token_user_pin));
	ADBG_EXPECT_CK_OK(c, rv);

	rv = C_Login(session, CKU_SO, test_token_so_pin,
		     sizeof(test_token_so_pin));
	ADBG_EXPECT_CK_RESULT(c, CKR_USER_ANOTHER_ALREADY_LOGGED_IN, rv);

	rv = C_Logout(session);
	ADBG_EXPECT_CK_OK(c, rv);

	/* Login context specifc, in an invalid case (need an operation) */
	rv = C_Login(session, CKU_CONTEXT_SPECIFIC, test_token_user_pin,
		     sizeof(test_token_user_pin));
	ADBG_EXPECT_CK_RESULT(c, CKR_OPERATION_NOT_INITIALIZED, rv);

	rv = C_CloseSession(session);
	ADBG_EXPECT_CK_OK(c, rv);

out:
	Do_ADBG_EndSubCase(c, "Test C_Login()/C_Logout()");
	return rv;
}

static CK_RV test_set_pin(ADBG_Case_t *c, CK_SLOT_ID slot,
			  CK_USER_TYPE user_type)
{
	CK_FLAGS session_flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_UTF8CHAR some_pin[] = { 7, 6, 5, 4, 3, 2, 1, 2, 3, 4, 5, 6, 7 };
	CK_UTF8CHAR_PTR old_pin = NULL;
	CK_USER_TYPE ut = user_type;
	size_t old_pin_sz = 0;
	CK_RV rv2 = CKR_OK;
	CK_RV rv = CKR_OK;

	Do_ADBG_BeginSubCase(c, "Test C_SetPIN() user_type %lu", user_type);

	rv = C_OpenSession(slot, session_flags, NULL, 0, &session);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	if (user_type == CKU_SO) {
		old_pin = (CK_UTF8CHAR_PTR)test_token_so_pin;
		old_pin_sz = sizeof(test_token_so_pin);
	} else {
		old_pin = (CK_UTF8CHAR_PTR)test_token_user_pin;
		old_pin_sz = sizeof(test_token_user_pin);
		ut = CKU_USER;
	}

	if (ut == user_type) {
		rv = C_Login(session, ut, old_pin, old_pin_sz);
		if (!ADBG_EXPECT_CK_OK(c, rv))
			goto out_session;
	}

	rv = C_SetPIN(session, old_pin, old_pin_sz, some_pin, sizeof(some_pin));
	if (!ADBG_EXPECT_CK_OK(c, rv)) {
		if (ut == user_type)
			goto out_logout;
		else
			goto out_session;
	}

	if (ut == user_type) {
		rv = C_Logout(session);
		if (!ADBG_EXPECT_CK_OK(c, rv))
			goto out_session;
	}

	rv = C_Login(session, ut, some_pin, sizeof(some_pin));
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out_session;

	rv = C_SetPIN(session, some_pin, sizeof(some_pin), old_pin, old_pin_sz);
	ADBG_EXPECT_CK_OK(c, rv);

out_logout:
	rv2 = C_Logout(session);
	if (!ADBG_EXPECT_CK_OK(c, rv2) && !rv)
		rv = rv2;
out_session:
	rv2 = C_CloseSession(session);
	if (!ADBG_EXPECT_CK_OK(c, rv2) && !rv)
		rv = rv2;
out:
	Do_ADBG_EndSubCase(c, "Test C_SetPIN() user_type %lu", user_type);

	return rv;
}

static void xtest_pkcs11_test_1003(ADBG_Case_t *c)
{
	CK_RV rv = CKR_GENERAL_ERROR;
	CK_FUNCTION_LIST_PTR ckfunc_list = NULL;
	CK_SLOT_ID slot = 0;
	CK_TOKEN_INFO token_info = { };

	rv = C_GetFunctionList(&ckfunc_list);
	if (!ADBG_EXPECT_CK_OK(c, rv) ||
	    !ADBG_EXPECT_NOT_NULL(c, ckfunc_list->C_InitToken) ||
	    !ADBG_EXPECT_NOT_NULL(c, ckfunc_list->C_InitPIN) ||
	    !ADBG_EXPECT_NOT_NULL(c, ckfunc_list->C_SetPIN) ||
	    !ADBG_EXPECT_NOT_NULL(c, ckfunc_list->C_Login) ||
	    !ADBG_EXPECT_NOT_NULL(c, ckfunc_list->C_Logout))
		goto out;

	rv = init_lib_and_find_token_slot(&slot);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		return;

	rv = C_GetTokenInfo(slot, &token_info);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	/* Abort test if token is about to lock */
	if (!ADBG_EXPECT_TRUE(c, !(token_info.flags & CKF_SO_PIN_FINAL_TRY)))
		goto out;

	if (!(token_info.flags & CKF_TOKEN_INITIALIZED)) {
		rv = test_uninitialized_token(c, slot);
		if (rv != CKR_OK)
			goto out;
	}

	rv = test_already_initialized_token(c, slot);
	if (rv != CKR_OK)
		goto out;

	rv = test_login_logout(c, slot);
	if (rv != CKR_OK)
		goto out;

	rv = test_set_pin(c, slot, CKU_USER);
	if (rv != CKR_OK)
		goto out;

	rv = test_set_pin(c, slot, CKU_SO);
	if (rv != CKR_OK)
		goto out;

	/*
	 * CKU_CONTEXT_SPECIFIC is anything not CKU_USER or CKU_SO in order
	 * to skip the initial login.
	 */
	test_set_pin(c, slot, CKU_CONTEXT_SPECIFIC);
out:
	rv = close_lib();
	ADBG_EXPECT_CK_OK(c, rv);
}

ADBG_CASE_DEFINE(pkcs11, 1003, xtest_pkcs11_test_1003,
		 "PKCS11: Login to PKCS#11 token");

static CK_ATTRIBUTE cktest_token_object[] = {
	{ CKA_DECRYPT,	&(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_TOKEN,	&(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_MODIFIABLE, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_CLASS,	&(CK_OBJECT_CLASS){CKO_SECRET_KEY},
						sizeof(CK_OBJECT_CLASS) },
	{ CKA_KEY_TYPE,	&(CK_KEY_TYPE){CKK_AES}, sizeof(CK_KEY_TYPE) },
	{ CKA_VALUE,	(void *)cktest_aes128_key, sizeof(cktest_aes128_key) },
};

static CK_ATTRIBUTE cktest_session_object[] = {
	{ CKA_DECRYPT,	&(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_TOKEN,	&(CK_BBOOL){CK_FALSE}, sizeof(CK_BBOOL) },
	{ CKA_MODIFIABLE, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_KEY_TYPE,	&(CK_KEY_TYPE){CKK_AES}, sizeof(CK_KEY_TYPE) },
	{ CKA_CLASS,	&(CK_OBJECT_CLASS){CKO_SECRET_KEY},
						sizeof(CK_OBJECT_CLASS) },
	{ CKA_VALUE,	(void *)cktest_aes128_key, sizeof(cktest_aes128_key) },
};

/* Create session object and token object from a session */
static void test_create_destroy_single_object(ADBG_Case_t *c, bool persistent)
{
	CK_RV rv = CKR_GENERAL_ERROR;
	CK_SLOT_ID slot = 0;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE obj_hdl = CK_INVALID_HANDLE;
	CK_FLAGS session_flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;

	rv = init_lib_and_find_token_slot(&slot);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		return;

	rv = C_OpenSession(slot, session_flags, NULL, 0, &session);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	if (persistent) {
		rv = C_CreateObject(session, cktest_token_object,
				    ARRAY_SIZE(cktest_token_object),
				    &obj_hdl);
	} else {
		rv = C_CreateObject(session, cktest_session_object,
				    ARRAY_SIZE(cktest_session_object),
				    &obj_hdl);
	}

	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	rv = C_DestroyObject(session, obj_hdl);
	ADBG_EXPECT_CK_OK(c, rv);
out:
	rv = C_CloseSession(session);
	ADBG_EXPECT_CK_OK(c, rv);

	rv = close_lib();
	ADBG_EXPECT_CK_OK(c, rv);
}

static void test_create_destroy_session_objects(ADBG_Case_t *c)
{
	CK_RV rv = CKR_GENERAL_ERROR;
	CK_SLOT_ID slot = 0;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE obj_hdl[512] = { 0 };
	CK_FLAGS session_flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	size_t n = 0;

	for (n = 0; n < ARRAY_SIZE(obj_hdl); n++)
		obj_hdl[n] = CK_INVALID_HANDLE;

	rv = init_lib_and_find_token_slot(&slot);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		return;

	rv = C_OpenSession(slot, session_flags, NULL, 0, &session);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	for (n = 0; n < ARRAY_SIZE(obj_hdl); n++) {
		rv = C_CreateObject(session, cktest_session_object,
				    ARRAY_SIZE(cktest_session_object),
				    obj_hdl + n);

		if (rv == CKR_DEVICE_MEMORY || !ADBG_EXPECT_CK_OK(c, rv))
			break;
	}

	Do_ADBG_Log("    created object count: %zu", n);

	rv = C_CloseSession(session);
	ADBG_EXPECT_CK_OK(c, rv);

	rv = C_OpenSession(slot, session_flags, NULL, 0, &session);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	rv = C_CreateObject(session, cktest_session_object,
			    ARRAY_SIZE(cktest_session_object),
			    obj_hdl);

	ADBG_EXPECT_CK_OK(c, rv);

out:
	rv = C_CloseSession(session);
	ADBG_EXPECT_CK_OK(c, rv);

	rv = close_lib();
	ADBG_EXPECT_CK_OK(c, rv);
}

/* Create session object and token object from a session */
static void test_create_objects_in_session(ADBG_Case_t *c, bool readwrite)
{
	CK_RV rv = CKR_GENERAL_ERROR;
	CK_SLOT_ID slot = 0;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE token_obj_hld = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE session_obj_hld = CK_INVALID_HANDLE;
	CK_FLAGS session_flags = CKF_SERIAL_SESSION;

	rv = init_lib_and_find_token_slot(&slot);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		return;

	if (readwrite)
		session_flags |= CKF_RW_SESSION;

	rv = C_OpenSession(slot, session_flags, NULL, 0, &session);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	rv = C_CreateObject(session, cktest_token_object,
			    ARRAY_SIZE(cktest_token_object),
			    &token_obj_hld);

	if (readwrite) {
		if (!ADBG_EXPECT_CK_OK(c, rv))
			goto out;
	} else {
		if (!ADBG_EXPECT_CK_RESULT(c, CKR_SESSION_READ_ONLY, rv))
			goto out;
	}

	rv = C_CreateObject(session, cktest_session_object,
			    ARRAY_SIZE(cktest_session_object),
			    &session_obj_hld);

	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out_tobj;

	rv = C_DestroyObject(session, session_obj_hld);
	ADBG_EXPECT_CK_OK(c, rv);

out_tobj:
	if (readwrite) {
		rv = C_DestroyObject(session, token_obj_hld);
		ADBG_EXPECT_CK_OK(c, rv);
	}
out:
	rv = C_CloseSession(session);
	ADBG_EXPECT_CK_OK(c, rv);

	rv = close_lib();
	ADBG_EXPECT_CK_OK(c, rv);
}

static void xtest_pkcs11_test_1004(ADBG_Case_t *c)
{
	Do_ADBG_BeginSubCase(c, "Create and destroy a volatile object");
	test_create_destroy_single_object(c, false /*!persistent*/);
	Do_ADBG_EndSubCase(c, "Create and destroy a volatile object");

	Do_ADBG_BeginSubCase(c, "Create and destroy a persistent object");
	test_create_destroy_single_object(c, true /*persistent*/);
	Do_ADBG_EndSubCase(c, "Create and destroy a persistent object");

	Do_ADBG_BeginSubCase(c, "Create and destroy many session objects");
	test_create_destroy_session_objects(c);
	Do_ADBG_EndSubCase(c, "Create and destroy many session objects");

	Do_ADBG_BeginSubCase(c, "Create objects in a read-only session");
	test_create_objects_in_session(c, false /*!readwrite*/);
	Do_ADBG_EndSubCase(c, "Create objects in a read-only session");

	Do_ADBG_BeginSubCase(c, "Create objects in a read/write session");
	test_create_objects_in_session(c, true /*readwrite*/);
	Do_ADBG_EndSubCase(c, "Create objects in a read/write session");
}

ADBG_CASE_DEFINE(pkcs11, 1004, xtest_pkcs11_test_1004,
		 "PKCS11: create/destroy PKCS#11 simple objects");


static const CK_MECHANISM_TYPE allowed_only_aes_ecb[] = {
	CKM_AES_ECB,
};
static const CK_MECHANISM_TYPE allowed_not_aes_ecb[] = {
	CKM_AES_CBC, CKM_AES_CBC_PAD, CKM_AES_CTR, CKM_AES_CTS,
	CKM_AES_GCM, CKM_AES_CCM,
};
static const CK_MECHANISM_TYPE allowed_only_aes_cbcnopad[] = {
	CKM_AES_CBC,
};
static const CK_MECHANISM_TYPE allowed_not_aes_cbcnopad[] = {
	CKM_AES_ECB, CKM_AES_CBC_PAD, CKM_AES_CTR, CKM_AES_CTS,
	CKM_AES_GCM, CKM_AES_CCM,
};
static const CK_MECHANISM_TYPE allowed_only_aes_ctr[] = {
	CKM_AES_CTR,
};
static const CK_MECHANISM_TYPE allowed_not_aes_ctr[] = {
	CKM_AES_ECB, CKM_AES_CBC, CKM_AES_CBC_PAD, CKM_AES_CTS,
	CKM_AES_GCM, CKM_AES_CCM,
};
static const CK_MECHANISM_TYPE allowed_only_aes_cts[] = {
	CKM_AES_CTS,
};
static const CK_MECHANISM_TYPE allowed_not_aes_cts[] = {
	CKM_AES_ECB, CKM_AES_CBC, CKM_AES_CBC_PAD, CKM_AES_CTR,
	CKM_AES_GCM, CKM_AES_CCM,
};

#define CKTEST_AES_KEY \
	{ CKA_CLASS,	&(CK_OBJECT_CLASS){CKO_SECRET_KEY},	\
			sizeof(CK_OBJECT_CLASS) },		\
	{ CKA_KEY_TYPE,	&(CK_KEY_TYPE){CKK_AES},		\
			sizeof(CK_KEY_TYPE) },			\
	{ CKA_VALUE,	(void *)cktest_aes128_key,		\
			sizeof(cktest_aes128_key) }

#define CKTEST_AES_ALLOWED_KEY(_allowed) \
	{ CKA_ALLOWED_MECHANISMS, (void *)_allowed, sizeof(_allowed), }

#define CK_KEY_ALLOWED_AES_TEST(_label, _allowed) \
	static CK_ATTRIBUTE _label[] = {				\
		CKTEST_AES_KEY,						\
		{ CKA_ENCRYPT,	&(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) }, \
		{ CKA_DECRYPT,	&(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) }, \
		CKTEST_AES_ALLOWED_KEY(_allowed),			\
	}

#define CK_KEY_ALLOWED_AES_ENC_TEST(_label, _allowed) \
	static CK_ATTRIBUTE _label[] = {				\
		CKTEST_AES_KEY,						\
		{ CKA_ENCRYPT,	&(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) }, \
		CKTEST_AES_ALLOWED_KEY(_allowed),			\
	}
#define CK_KEY_ALLOWED_AES_DEC_TEST(_label, _allowed) \
	static CK_ATTRIBUTE _label[] = {				\
		CKTEST_AES_KEY,						\
		{ CKA_DECRYPT,	&(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) }, \
		CKTEST_AES_ALLOWED_KEY(_allowed),			\
	}

CK_KEY_ALLOWED_AES_TEST(cktest_aes_only_ecb, allowed_only_aes_ecb);
CK_KEY_ALLOWED_AES_TEST(cktest_aes_not_ecb, allowed_not_aes_ecb);
CK_KEY_ALLOWED_AES_TEST(cktest_aes_only_cbcnopad, allowed_only_aes_cbcnopad);
CK_KEY_ALLOWED_AES_TEST(cktest_aes_not_cbcnopad, allowed_not_aes_cbcnopad);
CK_KEY_ALLOWED_AES_TEST(cktest_aes_only_cts, allowed_only_aes_cts);
CK_KEY_ALLOWED_AES_TEST(cktest_aes_not_cts, allowed_not_aes_cts);
CK_KEY_ALLOWED_AES_TEST(cktest_aes_only_ctr, allowed_only_aes_ctr);
CK_KEY_ALLOWED_AES_TEST(cktest_aes_not_ctr, allowed_not_aes_ctr);

struct cktest_allowed_test {
	CK_ATTRIBUTE_PTR attr_key;
	CK_ULONG attr_count;
	CK_MECHANISM_PTR mechanism;
};

#define CKTEST_KEY_MECHA(key, mecha) {	\
		.attr_key = key,		\
		.attr_count = ARRAY_SIZE(key),	\
		.mechanism = mecha,		\
	}

static const struct cktest_allowed_test cktest_allowed_valid[] = {
	CKTEST_KEY_MECHA(cktest_aes_only_ecb, &cktest_aes_ecb_mechanism),
	CKTEST_KEY_MECHA(cktest_aes_only_cbcnopad, &cktest_aes_cbc_mechanism),
	CKTEST_KEY_MECHA(cktest_aes_only_cts, &cktest_aes_cts_mechanism),
	CKTEST_KEY_MECHA(cktest_aes_only_ctr, &cktest_aes_ctr_mechanism),
};

static const struct cktest_allowed_test cktest_allowed_invalid[] = {
	CKTEST_KEY_MECHA(cktest_aes_not_ecb, &cktest_aes_ecb_mechanism),
	CKTEST_KEY_MECHA(cktest_aes_not_cbcnopad, &cktest_aes_cbc_mechanism),
	CKTEST_KEY_MECHA(cktest_aes_not_cts, &cktest_aes_cts_mechanism),
	CKTEST_KEY_MECHA(cktest_aes_not_ctr, &cktest_aes_ctr_mechanism),
};

/* Create session object and token object from a session */
static CK_RV cipher_init_final(ADBG_Case_t *c, CK_SESSION_HANDLE session,
				CK_ATTRIBUTE_PTR attr_key, CK_ULONG attr_count,
				CK_MECHANISM_PTR mechanism, uint32_t mode,
				CK_RV expected_rc)
{
	CK_RV rv2 = CKR_GENERAL_ERROR;
	CK_RV rv = CKR_GENERAL_ERROR;
	CK_OBJECT_HANDLE object = CK_INVALID_HANDLE;

	switch (mode) {
	case TEE_MODE_ENCRYPT:
	case TEE_MODE_DECRYPT:
		break;
	default:
		ADBG_EXPECT_TRUE(c, false);
	}

	rv = C_CreateObject(session, attr_key, attr_count, &object);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		return rv;

	if (mode == TEE_MODE_ENCRYPT)
		rv = C_EncryptInit(session, mechanism, object);
	if (mode == TEE_MODE_DECRYPT)
		rv = C_DecryptInit(session, mechanism, object);

	if (!ADBG_EXPECT_CK_RESULT(c, expected_rc, rv)) {
		rv = CKR_GENERAL_ERROR;
		goto out;
	}

	if (rv) {
		/*
		 * If we're here it was the expected error code above and
		 * we're supposed to return OK below.
		 */
		rv = CKR_OK;
	} else {
		if (mode == TEE_MODE_ENCRYPT)
			rv = C_EncryptFinal(session, NULL, NULL);
		if (mode == TEE_MODE_DECRYPT)
			rv = C_DecryptFinal(session, NULL, NULL);

		/* Only check that the operation is no more active */
		if (!ADBG_EXPECT_TRUE(c, rv != CKR_BUFFER_TOO_SMALL))
			rv = CKR_GENERAL_ERROR;
	}

out:
	rv2 = C_DestroyObject(session, object);
	ADBG_EXPECT_CK_OK(c, rv2);

	if (rv)
		return rv;
	else
		return rv2;
}

CK_KEY_ALLOWED_AES_ENC_TEST(cktest_aes_enc_only_cts, allowed_only_aes_cts);

CK_KEY_ALLOWED_AES_DEC_TEST(cktest_aes_dec_only_ctr, allowed_only_aes_ctr);

static void xtest_pkcs11_test_1005(ADBG_Case_t *c)
{
	CK_RV rv = CKR_GENERAL_ERROR;
	CK_SLOT_ID slot = 0;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_FLAGS session_flags = CKF_SERIAL_SESSION;
	size_t n = 0;

	rv = init_lib_and_find_token_slot(&slot);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		return;

	rv = C_OpenSession(slot, session_flags, NULL, 0, &session);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	for (n = 0; n < ARRAY_SIZE(cktest_allowed_valid); n++) {

		Do_ADBG_BeginSubCase(c, "valid usage #%zu", n);

		rv = cipher_init_final(c, session,
					cktest_allowed_valid[n].attr_key,
					cktest_allowed_valid[n].attr_count,
					cktest_allowed_valid[n].mechanism,
					TEE_MODE_ENCRYPT,
					CKR_OK);

		ADBG_EXPECT_CK_OK(c, rv);

		Do_ADBG_EndSubCase(c, NULL);
		if (rv)
			goto out;

	}

	for (n = 0; n < ARRAY_SIZE(cktest_allowed_invalid); n++) {
		Do_ADBG_BeginSubCase(c, "invalid usage #%zu", n);

		rv = cipher_init_final(c, session,
					cktest_allowed_invalid[n].attr_key,
					cktest_allowed_invalid[n].attr_count,
					cktest_allowed_invalid[n].mechanism,
					TEE_MODE_ENCRYPT,
					CKR_KEY_FUNCTION_NOT_PERMITTED);

		ADBG_EXPECT_CK_OK(c, rv);

		Do_ADBG_EndSubCase(c, NULL);
		if (rv)
			goto out;

	}

out:
	rv = C_CloseSession(session);
	ADBG_EXPECT_CK_OK(c, rv);

	rv = close_lib();
	ADBG_EXPECT_CK_OK(c, rv);
}


ADBG_CASE_DEFINE(pkcs11, 1005, xtest_pkcs11_test_1005,
		"PKCS11: Check ciphering with valid and invalid keys #1");

static void xtest_pkcs11_test_1006(ADBG_Case_t *c)
{
	CK_RV rv = CKR_GENERAL_ERROR;
	CK_SLOT_ID slot = 0;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_FLAGS session_flags = CKF_SERIAL_SESSION;

	rv = init_lib_and_find_token_slot(&slot);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		return;

	rv = C_OpenSession(slot, session_flags, NULL, 0, &session);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	/* Encrypt only AES CTS key */
	rv = cipher_init_final(c, session,
				cktest_aes_enc_only_cts,
				ARRAY_SIZE(cktest_aes_enc_only_cts),
				&cktest_aes_cts_mechanism,
				TEE_MODE_ENCRYPT,
				CKR_OK);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	rv = cipher_init_final(c, session,
				cktest_aes_enc_only_cts,
				ARRAY_SIZE(cktest_aes_enc_only_cts),
				&cktest_aes_cts_mechanism,
				TEE_MODE_DECRYPT,
				CKR_KEY_FUNCTION_NOT_PERMITTED);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	/* Decrypt only AES CTR key */
	rv = cipher_init_final(c, session,
				cktest_aes_dec_only_ctr,
				ARRAY_SIZE(cktest_aes_dec_only_ctr),
				&cktest_aes_ctr_mechanism,
				TEE_MODE_ENCRYPT,
				CKR_KEY_FUNCTION_NOT_PERMITTED);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	rv = cipher_init_final(c, session,
				cktest_aes_dec_only_ctr,
				ARRAY_SIZE(cktest_aes_dec_only_ctr),
				&cktest_aes_ctr_mechanism,
				TEE_MODE_ENCRYPT,
				CKR_KEY_FUNCTION_NOT_PERMITTED);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

out:
	rv = C_CloseSession(session);
	ADBG_EXPECT_CK_OK(c, rv);

	rv = close_lib();
	ADBG_EXPECT_CK_OK(c, rv);
}
ADBG_CASE_DEFINE(pkcs11, 1006, xtest_pkcs11_test_1006,
		"PKCS11: Check ciphering with valid and invalid keys #2");

static CK_RV open_cipher_session(ADBG_Case_t *c,
				 CK_SLOT_ID slot, CK_SESSION_HANDLE_PTR session,
				 CK_ATTRIBUTE_PTR attr_key, CK_ULONG attr_count,
				 CK_MECHANISM_PTR mechanism, uint32_t mode)
{
	CK_RV rv = CKR_GENERAL_ERROR;
	CK_OBJECT_HANDLE object = CK_INVALID_HANDLE;
	CK_FLAGS session_flags = CKF_SERIAL_SESSION;

	switch (mode) {
	case TEE_MODE_ENCRYPT:
	case TEE_MODE_DECRYPT:
		break;
	default:
		ADBG_EXPECT_TRUE(c, false);
		return CKR_GENERAL_ERROR;
	}

	rv = C_OpenSession(slot, session_flags, NULL, 0, session);
	if (rv == CKR_DEVICE_MEMORY)
		return rv;
	if (!ADBG_EXPECT_CK_OK(c, rv))
		return rv;

	rv = C_CreateObject(*session, attr_key, attr_count, &object);
	if (rv == CKR_DEVICE_MEMORY)
		return rv;
	if (!ADBG_EXPECT_CK_OK(c, rv))
		return rv;

	if (mode == TEE_MODE_ENCRYPT)
		rv = C_EncryptInit(*session, mechanism, object);
	if (mode == TEE_MODE_DECRYPT)
		rv = C_DecryptInit(*session, mechanism, object);

	if (rv == CKR_DEVICE_MEMORY)
		return rv;
	if (!ADBG_EXPECT_CK_OK(c, rv))
		return CKR_GENERAL_ERROR;

	return rv;
}

static void xtest_pkcs11_test_1007(ADBG_Case_t *c)
{
	CK_RV rv = CKR_GENERAL_ERROR;
	CK_SLOT_ID slot = 0;
	CK_SESSION_HANDLE sessions[128];
	size_t n = 0;

	for (n = 0; n < ARRAY_SIZE(sessions); n++)
		sessions[n] = CK_INVALID_HANDLE;

	rv = init_lib_and_find_token_slot(&slot);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		return;

	for (n = 0; n < ARRAY_SIZE(sessions); n++) {

		rv = open_cipher_session(c, slot, &sessions[n],
					 cktest_allowed_valid[0].attr_key,
					 cktest_allowed_valid[0].attr_count,
					 cktest_allowed_valid[0].mechanism,
					 TEE_MODE_ENCRYPT);

		/* Failure due to memory allocation is not a error case */
		if (rv == CKR_DEVICE_MEMORY)
			break;

		if (!ADBG_EXPECT_CK_OK(c, rv))
			goto out;
	}

	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, n, >, 0))
		goto out;

	Do_ADBG_Log("    created sessions count: %zu", n);

	/* Closing session with out bound and invalid IDs (or negative ID) */
	rv = C_CloseSession(sessions[n - 1] + 1024);
	ADBG_EXPECT_CK_RESULT(c, CKR_SESSION_HANDLE_INVALID, rv);
	rv = C_CloseSession(CK_INVALID_HANDLE);
	ADBG_EXPECT_CK_RESULT(c, CKR_SESSION_HANDLE_INVALID, rv);
	rv = C_CloseSession(~0);
	ADBG_EXPECT_CK_RESULT(c, CKR_SESSION_HANDLE_INVALID, rv);

	/* Closing each session: all related resources shall be free */
	for (n = 0; n < ARRAY_SIZE(sessions); n++) {
		if (sessions[n] == CK_INVALID_HANDLE)
			continue;

		rv = C_CloseSession(sessions[n]);
		ADBG_EXPECT_CK_OK(c, rv);
		sessions[n] = CK_INVALID_HANDLE;
	}

	/* Open and close another session */
	rv = open_cipher_session(c, slot, &sessions[0],
				 cktest_allowed_valid[0].attr_key,
				 cktest_allowed_valid[0].attr_count,
				 cktest_allowed_valid[0].mechanism,
				 TEE_MODE_ENCRYPT);

	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	rv = C_CloseSession(sessions[0]);
	ADBG_EXPECT_CK_OK(c, rv);
	sessions[0] = CK_INVALID_HANDLE;

out:
	for (n = 0; n < ARRAY_SIZE(sessions); n++) {
		if (sessions[n] == CK_INVALID_HANDLE)
			continue;

		rv = C_CloseSession(sessions[n]);
		ADBG_EXPECT_CK_OK(c, rv);
	}

	rv = close_lib();
	ADBG_EXPECT_CK_OK(c, rv);
}
ADBG_CASE_DEFINE(pkcs11, 1007, xtest_pkcs11_test_1007,
		"PKCS11: Check operations release at session closure");

#define CK_MAC_KEY_HMAC(_type, _key_array) \
	{								\
		{ CKA_SIGN, 	&(CK_BBOOL){CK_TRUE},			\
				sizeof(CK_BBOOL) },			\
		{ CKA_VERIFY, 	&(CK_BBOOL){CK_TRUE},			\
				sizeof(CK_BBOOL) },			\
		{ CKA_CLASS,	&(CK_OBJECT_CLASS){CKO_SECRET_KEY},	\
				sizeof(CK_OBJECT_CLASS) },		\
		{ CKA_KEY_TYPE,	&(CK_KEY_TYPE){_type},			\
				sizeof(CK_KEY_TYPE) },			\
		{ CKA_VALUE,	(void *)(_key_array),			\
				sizeof(_key_array) }			\
	}

static CK_ATTRIBUTE cktest_hmac_md5_key[] =
	CK_MAC_KEY_HMAC(CKK_MD5_HMAC, mac_data_md5_key1);

static CK_ATTRIBUTE cktest_hmac_sha1_key[] =
	CK_MAC_KEY_HMAC(CKK_SHA_1_HMAC, mac_data_sha1_key1);

static CK_ATTRIBUTE cktest_hmac_sha224_key[] =
	CK_MAC_KEY_HMAC(CKK_SHA224_HMAC, mac_data_sha224_key1);

static CK_ATTRIBUTE cktest_hmac_sha256_key1[] =
	CK_MAC_KEY_HMAC(CKK_SHA256_HMAC, mac_data_sha256_key1);

static CK_ATTRIBUTE cktest_hmac_sha256_key2[] =
	CK_MAC_KEY_HMAC(CKK_SHA256_HMAC, mac_data_sha256_key2);

static CK_ATTRIBUTE cktest_hmac_sha384_key[] =
	CK_MAC_KEY_HMAC(CKK_SHA384_HMAC, mac_data_sha384_key1);

static CK_ATTRIBUTE cktest_hmac_sha512_key[] =
	CK_MAC_KEY_HMAC(CKK_SHA512_HMAC, mac_data_sha512_key1);

struct mac_test {
	CK_ATTRIBUTE_PTR attr_key;
	CK_ULONG attr_count;
	CK_MECHANISM_PTR mechanism;
	size_t in_incr;
	const uint8_t *in;
	size_t in_len;
	const uint8_t *out;
	size_t out_len;
	bool multiple_incr;
};

#define CKTEST_MAC_TEST(key, mecha, input_incr, input, output, incr) {	\
		.attr_key = key,		\
		.attr_count = ARRAY_SIZE(key),	\
		.mechanism = mecha,		\
		.in_incr = input_incr,		\
		.in = input,				\
		.in_len = ARRAY_SIZE(input),		\
		.out = output,				\
		.out_len = ARRAY_SIZE(output),		\
		.multiple_incr = incr			\
	}

static const struct mac_test cktest_mac_cases[] = {
	CKTEST_MAC_TEST(cktest_hmac_md5_key, &cktest_hmac_md5_mechanism,
			4, mac_data_md5_in1, mac_data_md5_out1, false),
	CKTEST_MAC_TEST(cktest_hmac_sha1_key, &cktest_hmac_sha1_mechanism,
			5, mac_data_sha1_in1, mac_data_sha1_out1, false),
	CKTEST_MAC_TEST(cktest_hmac_sha224_key, &cktest_hmac_sha224_mechanism,
			8, mac_data_sha224_in1, mac_data_sha224_out1, false),
	CKTEST_MAC_TEST(cktest_hmac_sha256_key1, &cktest_hmac_sha256_mechanism,
			1, mac_data_sha256_in1, mac_data_sha256_out1, false),
	CKTEST_MAC_TEST(cktest_hmac_sha256_key2, &cktest_hmac_sha256_mechanism,
			7, mac_data_sha256_in2, mac_data_sha256_out2, false),
	CKTEST_MAC_TEST(cktest_hmac_sha384_key, &cktest_hmac_sha384_mechanism,
			11, mac_data_sha384_in1, mac_data_sha384_out1, false),
	CKTEST_MAC_TEST(cktest_hmac_sha512_key, &cktest_hmac_sha512_mechanism,
			13, mac_data_sha512_in1, mac_data_sha512_out1, false),
};

static void xtest_pkcs11_test_1008(ADBG_Case_t *c)
{
	CK_RV rv = CKR_GENERAL_ERROR;
	CK_SLOT_ID slot = 0;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_FLAGS session_flags = CKF_SERIAL_SESSION;
	CK_OBJECT_HANDLE key_handle = CK_INVALID_HANDLE;
	uint8_t out[512] = { 0 };
	CK_ULONG out_size = 0;
	struct mac_test const *test = NULL;
	size_t n = 0;

	rv = init_lib_and_find_token_slot(&slot);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		return;

	rv = C_OpenSession(slot, session_flags, NULL, 0, &session);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto err_close_lib;

	for (n = 0; n < ARRAY_SIZE(cktest_mac_cases); n++) {

		test = &cktest_mac_cases[n];
		Do_ADBG_BeginSubCase(c, "Sign case %zu algo (%s)", n,
				     ckm2str(test->mechanism->mechanism));

		rv = C_CreateObject(session, test->attr_key, test->attr_count,
				    &key_handle);
		if (!ADBG_EXPECT_CK_OK(c, rv))
			goto err;

		/* Test signature in 1 step */
		if (test->in != NULL) {
			rv = C_SignInit(session, test->mechanism, key_handle);
			if (!ADBG_EXPECT_CK_OK(c, rv))
				goto err_destr_obj;

			/* Pass input buffer of size 0 */
			rv = C_SignUpdate(session,
					  (void *)test->in, 0);
			if (!ADBG_EXPECT_CK_OK(c, rv))
				goto err_destr_obj;

			rv = C_SignUpdate(session,
					  (void *)test->in, test->in_len);
			if (!ADBG_EXPECT_CK_OK(c, rv))
				goto err_destr_obj;

			/* Test too short buffer case */
			out_size = 1;
			rv = C_SignFinal(session, out, &out_size);
			if (!ADBG_EXPECT_CK_RESULT(c, CKR_BUFFER_TOO_SMALL, rv))
				goto err_destr_obj;

			/*
			 * Test NULL buffer case with size as 0
			 * to get the out_size
			 */
			out_size = 0;
			rv = C_SignFinal(session, NULL, &out_size);
			if (!ADBG_EXPECT_CK_OK(c, rv))
				goto err_destr_obj;

			/* Get to full output */
			memset(out, 0, out_size);
			rv = C_SignFinal(session, out, &out_size);
			if (!ADBG_EXPECT_CK_OK(c, rv))
				goto err_destr_obj;

			(void)ADBG_EXPECT_BUFFER(c, test->out,
						 test->out_len,
						 out, out_size);
		}

		/* Test 2 step update signature */
		rv = C_SignInit(session, test->mechanism, key_handle);
		if (!ADBG_EXPECT_CK_OK(c, rv))
			goto err_destr_obj;

		if (test->in != NULL) {
			rv = C_SignUpdate(session,
					  (void *)test->in, test->in_incr);
			if (!ADBG_EXPECT_CK_OK(c, rv))
				goto err_destr_obj;

			rv = C_SignUpdate(session,
					  (void *)(test->in + test->in_incr),
					  test->in_len - test->in_incr);
			if (!ADBG_EXPECT_CK_OK(c, rv))
				goto err_destr_obj;
		}

		out_size = sizeof(out);
		memset(out, 0, sizeof(out));

		rv = C_SignFinal(session, out, &out_size);
		if (!ADBG_EXPECT_CK_OK(c, rv))
			goto err_destr_obj;

		(void)ADBG_EXPECT_BUFFER(c, test->out,
					 test->out_len, out, out_size);

		/* Test 3 signature in one shot */
		if (test->in != NULL) {
			rv = C_SignInit(session, test->mechanism, key_handle);
			if (!ADBG_EXPECT_CK_OK(c, rv))
				goto err_destr_obj;

			/* Test too short buffer case */
			out_size = 1;
			rv = C_Sign(session,(void *)test->in, test->in_len,
				    out, &out_size);
			if (!ADBG_EXPECT_CK_RESULT(c, CKR_BUFFER_TOO_SMALL, rv))
				goto err_destr_obj;

			/*
			 * Test NULL buffer case with size as 0
			 * to get the out_size
			 */
			out_size = 0;
			rv = C_Sign(session, (void *)test->in, test->in_len,
				    NULL, &out_size);
			if (!ADBG_EXPECT_CK_OK(c, rv))
				goto err_destr_obj;

			/* Get to full output */
			memset(out, 0, out_size);
			rv = C_Sign(session,(void *)test->in, test->in_len,
				    out, &out_size);
			if (!ADBG_EXPECT_CK_OK(c, rv))
				goto err_destr_obj;

			(void)ADBG_EXPECT_BUFFER(c, test->out,
						 test->out_len,
						 out, out_size);
		}

		rv = C_DestroyObject(session, key_handle);
		if (!ADBG_EXPECT_CK_OK(c, rv))
			goto err;

		Do_ADBG_EndSubCase(c, NULL);
	}
	goto out;

err_destr_obj:
	ADBG_EXPECT_CK_OK(c, C_DestroyObject(session, key_handle));
err:
	Do_ADBG_EndSubCase(c, NULL);
out:
	ADBG_EXPECT_CK_OK(c, C_CloseSession(session));
err_close_lib:
	ADBG_EXPECT_CK_OK(c, close_lib());
}
ADBG_CASE_DEFINE(pkcs11, 1008, xtest_pkcs11_test_1008,
		 "PKCS11: Check Compliance of C_Sign - HMAC algorithms");

static void xtest_pkcs11_test_1009(ADBG_Case_t *c)
{
	CK_RV rv = CKR_GENERAL_ERROR;
	CK_SLOT_ID slot = 0;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_FLAGS session_flags = CKF_SERIAL_SESSION;
	CK_OBJECT_HANDLE key_handle = CK_INVALID_HANDLE;
	struct mac_test const *test = NULL;
	size_t n = 0;

	rv = init_lib_and_find_token_slot(&slot);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		return;

	rv = C_OpenSession(slot, session_flags, NULL, 0, &session);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto err_close_lib;

	for (n = 0; n < ARRAY_SIZE(cktest_mac_cases); n++) {

		test = &cktest_mac_cases[n];
		Do_ADBG_BeginSubCase(c, "Verify case %zu algo (%s)", n,
				     ckm2str(test->mechanism->mechanism));

		rv = C_CreateObject(session, test->attr_key, test->attr_count,
				    &key_handle);
		if (!ADBG_EXPECT_CK_OK(c, rv))
			goto err;

		/* Test Verification in 1 step */
		if (test->in != NULL) {
			rv = C_VerifyInit(session, test->mechanism, key_handle);
			if (!ADBG_EXPECT_CK_OK(c, rv))
				goto err_destr_obj;

			/* Pass input buffer with size 0 - No affect */
			rv = C_VerifyUpdate(session, (void *)test->in, 0);
			if (!ADBG_EXPECT_CK_OK(c, rv))
				goto err_destr_obj;

			rv = C_VerifyUpdate(session, (void *)test->in,
					    test->in_len);
			if (!ADBG_EXPECT_CK_OK(c, rv))
				goto err_destr_obj;

			rv = C_VerifyFinal(session,
					   (void *)test->out, test->out_len);
			if (!ADBG_EXPECT_CK_OK(c, rv))
				goto err_destr_obj;

		}

		/* Test 2 step update verification*/
		rv = C_VerifyInit(session, test->mechanism, key_handle);
		if (!ADBG_EXPECT_CK_OK(c, rv))
			goto err_destr_obj;

		if (test->in != NULL) {
			rv = C_VerifyUpdate(session,
					    (void *)test->in, test->in_incr);
			if (!ADBG_EXPECT_CK_OK(c, rv))
				goto err_destr_obj;

			rv = C_VerifyUpdate(session,
					    (void *)(test->in + test->in_incr),
					    test->in_len - test->in_incr);
			if (!ADBG_EXPECT_CK_OK(c, rv))
				goto err_destr_obj;
		}

		rv = C_VerifyFinal(session, (void *)test->out, test->out_len);
		if (!ADBG_EXPECT_CK_OK(c, rv))
			goto err_destr_obj;

		/* Error as Operation has already completed */
		rv = C_Verify(session,
			      (void *)test->in, test->in_len,
			      (void *)test->out, test->out_len);
		if (!ADBG_EXPECT_CK_RESULT(c, CKR_OPERATION_NOT_INITIALIZED,
					   rv))
			goto err_destr_obj;

		/* Test 3 verification in one shot */
		if (test->in != NULL) {
			rv = C_VerifyInit(session, test->mechanism, key_handle);
			if (!ADBG_EXPECT_CK_OK(c, rv))
				goto err_destr_obj;

			rv = C_Verify(session,
				      (void *)test->in, test->in_len,
				      (void *)test->out, test->out_len);
			if (!ADBG_EXPECT_CK_OK(c, rv))
				goto err_destr_obj;

			/* Try calling Verify again */
			rv = C_Verify(session,
				      (void *)test->in, test->in_len,
				      (void *)test->out, test->out_len);
			if (!ADBG_EXPECT_CK_RESULT(c,
						  CKR_OPERATION_NOT_INITIALIZED,
						  rv))
				goto err_destr_obj;
		}

		/*
		 * Test 4 verification 
		 * Error - Signature Length Range with C_VerifyFinal
		 */
		if (test->in != NULL) {
			rv = C_VerifyInit(session, test->mechanism, key_handle);
			if (!ADBG_EXPECT_CK_OK(c, rv))
				goto err_destr_obj;

			rv = C_VerifyUpdate(session, (void *)test->in,
					    test->in_len);
			if (!ADBG_EXPECT_CK_OK(c, rv))
				goto err_destr_obj;

			rv = C_VerifyFinal(session, (void *)test->out, 3);
			if (!ADBG_EXPECT_CK_RESULT(c, CKR_SIGNATURE_LEN_RANGE,
						   rv))
				goto err_destr_obj;
		}

		/*
		 * Test 5 verification
		 * Error - Signature Length Range with C_Verify
		 */
		if (test->in != NULL) {
			rv = C_VerifyInit(session, test->mechanism, key_handle);
			if (!ADBG_EXPECT_CK_OK(c, rv))
				goto err_destr_obj;

			rv = C_Verify(session,
				      (void *)test->in, test->in_len,
				      (void *)test->out, 0);
			if (!ADBG_EXPECT_CK_RESULT(c, CKR_SIGNATURE_LEN_RANGE,
						   rv))
				goto err_destr_obj;
		}

		/* Test 6 verification - Invalid Operation sequence */
		if (test->in != NULL) {
			rv = C_VerifyInit(session, test->mechanism, key_handle);
			if (!ADBG_EXPECT_CK_OK(c, rv))
				goto err_destr_obj;

			rv = C_Verify(session,
				      (void *)test->in, test->in_len,
				      (void *)test->out, test->out_len);
			if (!ADBG_EXPECT_CK_OK(c, rv))
				goto err_destr_obj;

			/* Init session has already terminated with C_Verify */
			rv = C_VerifyUpdate(session, (void *)test->in,
					    test->in_len);
			if (!ADBG_EXPECT_CK_RESULT(c,
						  CKR_OPERATION_NOT_INITIALIZED,
						  rv))
				goto err_destr_obj;
		}

		rv = C_DestroyObject(session, key_handle);
		if (!ADBG_EXPECT_CK_OK(c, rv))
			goto err;

		Do_ADBG_EndSubCase(c, NULL);
	}
	goto out;

err_destr_obj:
	ADBG_EXPECT_CK_OK(c, C_DestroyObject(session, key_handle));
err:
	Do_ADBG_EndSubCase(c, NULL);
out:
	ADBG_EXPECT_CK_OK(c, C_CloseSession(session));
err_close_lib:
	ADBG_EXPECT_CK_OK(c, close_lib());
}
ADBG_CASE_DEFINE(pkcs11, 1009, xtest_pkcs11_test_1009,
		 "PKCS11: Check Compliance of C_Verify - HMAC Algorithms");

/* Bad key type */
static CK_ATTRIBUTE cktest_generate_gensecret_object_error1[] = {
	{ CKA_CLASS, &(CK_OBJECT_CLASS){CKO_SECRET_KEY},
						sizeof(CK_OBJECT_CLASS) },
	{ CKA_KEY_TYPE, &(CK_KEY_TYPE){CKK_AES}, sizeof(CK_KEY_TYPE) },
	{ CKA_VALUE_LEN, &(CK_ULONG){16}, sizeof(CK_ULONG) },
};

/* Missing VALUE_LEN */
static CK_ATTRIBUTE cktest_generate_gensecret_object_error2[] = {
	{ CKA_CLASS, &(CK_OBJECT_CLASS){CKO_SECRET_KEY},
						sizeof(CK_OBJECT_CLASS) },
	{ CKA_KEY_TYPE, &(CK_KEY_TYPE){CKK_GENERIC_SECRET},
						sizeof(CK_KEY_TYPE) },
};

/* Bad object class */
static CK_ATTRIBUTE cktest_generate_gensecret_object_error3[] = {
	{ CKA_CLASS, &(CK_OBJECT_CLASS){CKO_DATA}, sizeof(CK_OBJECT_CLASS) },
	{ CKA_KEY_TYPE, &(CK_KEY_TYPE){CKK_GENERIC_SECRET},
						sizeof(CK_KEY_TYPE) },
	{ CKA_VALUE_LEN, &(CK_ULONG){16 * 8}, sizeof(CK_ULONG) },
};

/* Invalid template with CKA_LOCAL */
static CK_ATTRIBUTE cktest_generate_gensecret_object_error4[] = {
	{ CKA_VALUE_LEN, &(CK_ULONG){16 * 8}, sizeof(CK_ULONG) },
	{ CKA_LOCAL, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
};

/* Valid template to generate a generic secret */
static CK_ATTRIBUTE cktest_generate_gensecret_object_valid1[] = {
	{ CKA_CLASS, &(CK_OBJECT_CLASS){CKO_SECRET_KEY},
						sizeof(CK_OBJECT_CLASS) },
	{ CKA_KEY_TYPE, &(CK_KEY_TYPE){CKK_GENERIC_SECRET},
						sizeof(CK_KEY_TYPE) },
	{ CKA_SIGN, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_VERIFY, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_VALUE_LEN, &(CK_ULONG){16 * 8}, sizeof(CK_ULONG) },
};

/* Valid template to generate a generic secret with only VALUE_LEN */
static CK_ATTRIBUTE cktest_generate_gensecret_object_valid2[] = {
	{ CKA_VALUE_LEN, &(CK_ULONG){16 * 8}, sizeof(CK_ULONG) },
	{ CKA_SIGN, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
};


/* Valid template to generate an all AES purpose key */
static CK_ATTRIBUTE cktest_generate_aes_object[] = {
	{ CKA_CLASS, &(CK_OBJECT_CLASS){CKO_SECRET_KEY},
						sizeof(CK_OBJECT_CLASS) },
	{ CKA_KEY_TYPE, &(CK_KEY_TYPE){CKK_AES}, sizeof(CK_KEY_TYPE) },
	{ CKA_ENCRYPT, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_DECRYPT, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_VALUE_LEN, &(CK_ULONG){16}, sizeof(CK_ULONG) },
};

static void xtest_pkcs11_test_1010(ADBG_Case_t *c)
{
	CK_RV rv = CKR_GENERAL_ERROR;
	CK_SLOT_ID slot = 0;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_FLAGS session_flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	CK_OBJECT_HANDLE key_handle = CK_INVALID_HANDLE;
	struct mac_test const *test = &cktest_mac_cases[0];
	uint8_t out[512] = { 0 };
	CK_ULONG out_len = 512;

	rv = init_lib_and_find_token_slot(&slot);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		return;

	rv = C_OpenSession(slot, session_flags, NULL, 0, &session);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto close_lib;

	/*
	 * Generate Generic Secret key using invalid templates
	 */
	Do_ADBG_BeginSubCase(c, "Generate Secret Key with Invalid Templates");

	/* NULL Template with !null template length */
	rv = C_GenerateKey(session, &cktest_gensecret_keygen_mechanism, NULL,
			   3, &key_handle);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_ARGUMENTS_BAD, rv))
		goto err;

	rv = C_GenerateKey(session, &cktest_gensecret_keygen_mechanism,
			   cktest_generate_gensecret_object_error1,
			   ARRAY_SIZE(cktest_generate_gensecret_object_error1),
			   &key_handle);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_TEMPLATE_INCONSISTENT, rv))
		goto err;

	rv = C_GenerateKey(session, &cktest_gensecret_keygen_mechanism,
			   cktest_generate_gensecret_object_error2,
			   ARRAY_SIZE(cktest_generate_gensecret_object_error2),
			   &key_handle);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_TEMPLATE_INCOMPLETE, rv))
		goto err;

	rv = C_GenerateKey(session, &cktest_gensecret_keygen_mechanism,
			   cktest_generate_gensecret_object_error3,
			   ARRAY_SIZE(cktest_generate_gensecret_object_error3),
			   &key_handle);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_TEMPLATE_INCONSISTENT, rv))
		goto err;

	rv = C_GenerateKey(session, &cktest_gensecret_keygen_mechanism,
			   cktest_generate_gensecret_object_error4,
			   ARRAY_SIZE(cktest_generate_gensecret_object_error4),
			   &key_handle);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_TEMPLATE_INCONSISTENT, rv))
		goto err;

	Do_ADBG_EndSubCase(c, NULL);

	/*
	 * Generate a Generic Secret object.
	 * Try to encrypt with, it should fail...
	 */
	Do_ADBG_BeginSubCase(c, "Generate Generic Secret Key - Try Encrypting");

	rv = C_GenerateKey(session, &cktest_gensecret_keygen_mechanism,
			   cktest_generate_gensecret_object_valid1,
			   ARRAY_SIZE(cktest_generate_gensecret_object_valid1),
			   &key_handle);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto err;

	rv = C_EncryptInit(session, &cktest_aes_cbc_mechanism, key_handle);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_KEY_FUNCTION_NOT_PERMITTED, rv))
		goto err_destr_obj;

	rv = C_DestroyObject(session, key_handle);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto err;

	Do_ADBG_EndSubCase(c, NULL);

	/*
	 * Generate a Generic Secret object.
	 * Try to sign with it, it should pass...
	 */
	Do_ADBG_BeginSubCase(c, "Generate Generic Secret Key - Try Signing");
	rv = C_GenerateKey(session, &cktest_gensecret_keygen_mechanism,
			   cktest_generate_gensecret_object_valid2,
			   ARRAY_SIZE(cktest_generate_gensecret_object_valid2),
			   &key_handle);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto err;

	rv = C_SignInit(session, test->mechanism, key_handle);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto err_destr_obj;

	rv = C_Sign(session, (void *)test->in, test->in_len,
		      (void *)out, &out_len);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto err_destr_obj;

	rv = C_DestroyObject(session, key_handle);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto err;

	Do_ADBG_EndSubCase(c, NULL);

	/*
	 * Generate a 128 bit AES Secret Key.
	 * Try to encrypt with, it should pass...
	 */
	Do_ADBG_BeginSubCase(c, "Generate AES Key - Try Encrypting");

	rv = C_GenerateKey(session, &cktest_aes_keygen_mechanism,
			   cktest_generate_aes_object,
			   ARRAY_SIZE(cktest_generate_aes_object),
			   &key_handle);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto err;

	rv = C_EncryptInit(session, &cktest_aes_cbc_mechanism, key_handle);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto err_destr_obj;

	rv = C_EncryptFinal(session, NULL, NULL);
	/* Only check that the operation is no more active */
	if (!ADBG_EXPECT_TRUE(c, rv != CKR_BUFFER_TOO_SMALL))
		goto err;

	rv = C_DestroyObject(session, key_handle);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto err;

	Do_ADBG_EndSubCase(c, NULL);

	goto out;

err_destr_obj:
	ADBG_EXPECT_CK_OK(c, C_DestroyObject(session, key_handle));
err:
	Do_ADBG_EndSubCase(c, NULL);
out:
	ADBG_EXPECT_CK_OK(c, C_CloseSession(session));
close_lib:
	ADBG_EXPECT_CK_OK(c, close_lib());
}
ADBG_CASE_DEFINE(pkcs11, 1010, xtest_pkcs11_test_1010,
		 "PKCS11: Key Generation");

static CK_RV create_data_object(CK_SESSION_HANDLE session,
				CK_OBJECT_HANDLE *obj_handle,
				CK_BBOOL token, CK_BBOOL private,
				const char *label)
{
	CK_OBJECT_CLASS class = CKO_DATA;
	CK_ATTRIBUTE object_template[] = {
		{ CKA_CLASS, &class, sizeof(CK_OBJECT_CLASS) },
		{ CKA_TOKEN, &token, sizeof(CK_BBOOL) },
		{ CKA_PRIVATE, &private, sizeof(CK_BBOOL) },
		{ CKA_LABEL, (CK_UTF8CHAR_PTR)label, strlen(label) },
	};

	return C_CreateObject(session, object_template,
			      ARRAY_SIZE(object_template), obj_handle);
}

static CK_RV test_find_objects(ADBG_Case_t *c, CK_SESSION_HANDLE session,
			       CK_ATTRIBUTE_PTR find_template,
			       CK_ULONG attr_count,
			       CK_OBJECT_HANDLE_PTR obj_found,
			       CK_ULONG obj_count,
			       CK_ULONG expected_cnt)
{
	CK_RV rv = CKR_GENERAL_ERROR;
	CK_ULONG hdl_count = 0;

	rv = C_FindObjectsInit(session, find_template, attr_count);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		return rv;

	rv = C_FindObjects(session, obj_found, obj_count, &hdl_count);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		return rv;
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, hdl_count, ==, expected_cnt))
		return CKR_GENERAL_ERROR;

	rv = C_FindObjectsFinal(session);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		return rv;

	return rv;
}

static void destroy_persistent_objects(ADBG_Case_t *c, CK_SLOT_ID slot)
{
	uint32_t rv = CKR_GENERAL_ERROR;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_FLAGS session_flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	CK_OBJECT_HANDLE obj_hdl = CK_INVALID_HANDLE;
	CK_ULONG count = 1;
	CK_ATTRIBUTE cktest_find_all_token_objs[] = {
		{ CKA_TOKEN, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	};

	rv = init_user_test_token(slot);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		return;

	rv = C_OpenSession(slot, session_flags, NULL, 0, &session);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		return;

	/* Login to destroy private objects */
	rv = C_Login(session, CKU_USER, test_token_user_pin,
		     sizeof(test_token_user_pin));
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	rv = C_FindObjectsInit(session, cktest_find_all_token_objs,
			       ARRAY_SIZE(cktest_find_all_token_objs));
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto bail;

	while (1) {
		rv = C_FindObjects(session, &obj_hdl, 1, &count);
		if (!ADBG_EXPECT_CK_OK(c, rv))
			goto bail;
		if (!count)
			break;

		rv = C_DestroyObject(session, obj_hdl);
		ADBG_EXPECT_CK_OK(c, rv);
	}

	rv = C_FindObjectsFinal(session);
	ADBG_EXPECT_CK_OK(c, rv);

	rv = C_Logout(session);
	ADBG_EXPECT_CK_OK(c, rv);

bail:
	rv = C_CloseSession(session);
	ADBG_EXPECT_CK_OK(c, rv);
}

static void xtest_pkcs11_test_1011(ADBG_Case_t *c)
{
	CK_RV rv = CKR_GENERAL_ERROR;
	CK_SLOT_ID slot = 0;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_FLAGS session_flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	CK_OBJECT_HANDLE obj_hdl[10] = { };
	CK_OBJECT_HANDLE obj_found[10] = { };
	const char *label = "Common Label";
	CK_ULONG hdl_count = 0;
	size_t n = 0;
	uint32_t i = 0;
	uint32_t object_id = 0;
	bool logged_in = false;
	CK_ATTRIBUTE find_template[] = {
		{ CKA_LABEL, (CK_UTF8CHAR_PTR)label, strlen(label) },
	};
	CK_ATTRIBUTE find_token_template[] = {
		{ CKA_LABEL, (CK_UTF8CHAR_PTR)label, strlen(label) },
		{ CKA_TOKEN, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	};
	CK_ATTRIBUTE find_session_template[] = {
		{ CKA_LABEL, (CK_UTF8CHAR_PTR)label, strlen(label) },
		{ CKA_TOKEN, &(CK_BBOOL){CK_FALSE}, sizeof(CK_BBOOL) },
	};
	CK_BBOOL bToken = CK_FALSE;
	CK_ATTRIBUTE get_attr_template[] = {
		{ CKA_TOKEN, &bToken, sizeof(bToken) },
	};

	for (n = 0; n < ARRAY_SIZE(obj_hdl); n++)
		obj_hdl[n] = CK_INVALID_HANDLE;
	for (n = 0; n < ARRAY_SIZE(obj_found); n++)
		obj_found[n] = CK_INVALID_HANDLE;

	rv = init_lib_and_find_token_slot(&slot);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		return;

	rv = init_test_token(slot);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		return;

	rv = init_user_test_token(slot);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		return;

	rv = C_OpenSession(slot, session_flags, NULL, 0, &session);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto close_lib;

	/*
	 * Sub test: Create Session Public/Private,
	 * Token Public/Private objects and find them
	 */
	Do_ADBG_BeginSubCase(c, "Find created Data objects when logged in");

	/* Session Public Obj CKA_TOKEN = CK_FALSE, CKA_PRIVATE = CK_FALSE */
	rv = create_data_object(session, &obj_hdl[object_id++], CK_FALSE,
				CK_FALSE, label);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	/* Token Public Obj CKA_TOKEN = CK_TRUE, CKA_PRIVATE = CK_FALSE */
	rv = create_data_object(session, &obj_hdl[object_id++], CK_TRUE,
				CK_FALSE, label);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	/*
	 * Token Private Obj CKA_TOKEN = CK_TRUE, CKA_PRIVATE = CK_TRUE
	 * Expected error as User not logged in
	 */
	rv = create_data_object(session, &obj_hdl[object_id], CK_TRUE,
				CK_TRUE, label);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_USER_NOT_LOGGED_IN, rv))
		goto out;

	/* Login to Test Token */
	rv = C_Login(session, CKU_USER,	test_token_user_pin,
		     sizeof(test_token_user_pin));
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	logged_in = true;

	/* Token Private Obj CKA_TOKEN = CK_TRUE, CKA_PRIVATE = CK_TRUE */
	rv = create_data_object(session, &obj_hdl[object_id++], CK_TRUE,
				CK_TRUE, label);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	/* Session Private Obj CKA_TOKEN = CK_FALSE, CKA_PRIVATE = CK_TRUE */
	rv = create_data_object(session, &obj_hdl[object_id++], CK_FALSE,
				CK_TRUE, label);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	rv = test_find_objects(c, session, find_template,
			       ARRAY_SIZE(find_template),
			       obj_found, ARRAY_SIZE(obj_found), 4);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	/*
	 * Check if object handles returned when creating objects with this
	 * session are still valid
	 */
	for (i = 0; i < object_id; i++) {
		rv = C_GetAttributeValue(session, obj_hdl[i], get_attr_template,
					 ARRAY_SIZE(get_attr_template));
		if (!ADBG_EXPECT_CK_OK(c, rv))
			goto out;
	}

	Do_ADBG_EndSubCase(c, NULL);

	/*
	 * Sub test: Pass NULL template with count as 0. All objects should
	 * get returned
	 */
	Do_ADBG_BeginSubCase(c, "Find all objects by passing NULL template");

	rv = test_find_objects(c, session, NULL, 0, obj_found,
			       ARRAY_SIZE(obj_found), 4);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	Do_ADBG_EndSubCase(c, NULL);

	/*
	 * Sub test: finalize search without getting the handles found
	 */
	Do_ADBG_BeginSubCase(c, "Initiate and finalize straight a search");

	rv = C_FindObjectsInit(session, find_template,
			       ARRAY_SIZE(find_template));
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	rv = C_FindObjectsFinal(session);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	/*
	 * Check if object handles returned when creating objects with this
	 * session are still valid
	 */
	for (i = 0; i < object_id; i++) {
		rv = C_GetAttributeValue(session, obj_hdl[i], get_attr_template,
					 ARRAY_SIZE(get_attr_template));
		if (!ADBG_EXPECT_CK_OK(c, rv))
			goto out;
	}
	Do_ADBG_EndSubCase(c, NULL);

	/*
	 * Sub test: Logout and find objects. We will find only public
	 * objects (2)
	 */
	Do_ADBG_BeginSubCase(c, "Find created Data objects when logged out");

	rv = C_Logout(session);
	ADBG_EXPECT_CK_OK(c, rv);

	logged_in = false;

	rv = test_find_objects(c, session, find_template,
			       ARRAY_SIZE(find_template),
			       obj_found, ARRAY_SIZE(obj_found), 2);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	Do_ADBG_EndSubCase(c, NULL);

	/*
	 * Sub test
	 */
	Do_ADBG_BeginSubCase(c, "Find objects 1 by 1 and match handles");

	for (n = 0; n < ARRAY_SIZE(obj_found); n++)
		obj_found[n] = CK_INVALID_HANDLE;

	rv = C_FindObjectsInit(session, find_template,
			       ARRAY_SIZE(find_template));
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	rv = C_FindObjects(session, obj_found, 1, &hdl_count);
	if (!ADBG_EXPECT_CK_OK(c, rv) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, hdl_count, ==, 1) ||
	    !ADBG_EXPECT_TRUE(c, (obj_found[0] == obj_hdl[0]) ||
				 (obj_found[0] == obj_hdl[1])))
		goto out;

	rv = C_FindObjects(session, &obj_found[1], 1, &hdl_count);
	if (!ADBG_EXPECT_CK_OK(c, rv) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, hdl_count, ==, 1) ||
	    !ADBG_EXPECT_TRUE(c, (obj_found[1] == obj_hdl[0]) ||
				 (obj_found[1] == obj_hdl[1])) ||
	    !ADBG_EXPECT_TRUE(c, (obj_found[1] != obj_found[0])))
		goto out;

	rv = C_FindObjects(session, obj_found, 1, &hdl_count);
	if (!ADBG_EXPECT_CK_OK(c, rv) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, hdl_count, ==, 0))
		goto out;

	rv = C_FindObjectsFinal(session);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	Do_ADBG_EndSubCase(c, NULL);

	/*
	 * Sub test: Find objects with CKA_TOKEN=TRUE
	 */
	Do_ADBG_BeginSubCase(c, "Find persistent objects");

	rv = test_find_objects(c, session, find_token_template,
			       ARRAY_SIZE(find_token_template),
			       obj_found, ARRAY_SIZE(obj_found), 1);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	Do_ADBG_EndSubCase(c, NULL);

	/*
	 * Sub test: Find only session objects
	 */
	Do_ADBG_BeginSubCase(c, "Find session objects");

	rv = test_find_objects(c, session, find_session_template,
			       ARRAY_SIZE(find_session_template),
			       obj_found, ARRAY_SIZE(obj_found), 1);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	Do_ADBG_EndSubCase(c, NULL);

	/*
	 * Sub test:
	 */
	Do_ADBG_BeginSubCase(c, "Login again and find Data objects");

	/* Login to Test Token */
	rv = C_Login(session, CKU_USER,	test_token_user_pin,
		     sizeof(test_token_user_pin));
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	logged_in = true;

	rv = test_find_objects(c, session, find_template,
			       ARRAY_SIZE(find_template),
			       obj_found, ARRAY_SIZE(obj_found), 3);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	rv = C_Logout(session);
	ADBG_EXPECT_CK_OK(c, rv);

	logged_in = false;

	Do_ADBG_EndSubCase(c, NULL);

	/*
	 * Sub test: Close session and open new session, find objects
	 * without logging and after logging
	 */
	Do_ADBG_BeginSubCase(c, "Find objects from brand new session");

	rv = C_CloseSession(session);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto destr_obj;

	rv = C_OpenSession(slot, session_flags, NULL, 0, &session);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto destr_obj;

	rv = test_find_objects(c, session, find_template,
			       ARRAY_SIZE(find_template),
			       obj_found, ARRAY_SIZE(obj_found), 1);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	/* Login to Test Token */
	rv = C_Login(session, CKU_USER,	test_token_user_pin,
		     sizeof(test_token_user_pin));
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	logged_in = true;

	rv = test_find_objects(c, session, find_template,
			       ARRAY_SIZE(find_template),
			       obj_found, ARRAY_SIZE(obj_found), 2);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	rv = C_Logout(session);
	ADBG_EXPECT_CK_OK(c, rv);

	logged_in = false;

	Do_ADBG_EndSubCase(c, NULL);

	/*
	 * Sub test: invalid call cases
	 */
	Do_ADBG_BeginSubCase(c, "Invalid cases");

	rv = C_FindObjectsFinal(session);
	ADBG_EXPECT_CK_RESULT(c, CKR_OPERATION_NOT_INITIALIZED, rv);

	rv = C_FindObjects(session,
			   obj_found, ARRAY_SIZE(obj_found), &hdl_count);
	ADBG_EXPECT_CK_RESULT(c, CKR_OPERATION_NOT_INITIALIZED, rv);

	rv = C_FindObjectsInit(session, find_template,
			       ARRAY_SIZE(find_template));
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	rv = C_FindObjectsInit(session, find_template,
			       ARRAY_SIZE(find_template));
	ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, !=, CKR_OK);

	rv = C_FindObjectsFinal(session);
	ADBG_EXPECT_CK_OK(c, rv);

	rv = C_FindObjectsInit(session, find_template,
			       ARRAY_SIZE(find_template));
	ADBG_EXPECT_CK_OK(c, rv);

	/*
	 * Intentionally do not finalize the active object search. It should be
	 * released together with the session closure.
	 */
	Do_ADBG_EndSubCase(c, NULL);

out:
	if (logged_in)
		ADBG_EXPECT_CK_OK(c, C_Logout(session));

	ADBG_EXPECT_CK_OK(c, C_CloseSession(session));

destr_obj:
	destroy_persistent_objects(c, slot);
close_lib:
	ADBG_EXPECT_CK_OK(c, close_lib());
}
ADBG_CASE_DEFINE(pkcs11, 1011, xtest_pkcs11_test_1011,
		 "PKCS11: Test Find Objects");
