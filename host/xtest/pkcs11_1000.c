// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2018, Linaro Limited
 */

#include <assert.h>
#include <ck_debug.h>
#include <inttypes.h>
#ifdef OPENSSL_FOUND
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#endif
#include <pkcs11.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <utee_defines.h>
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
static CK_MECHANISM cktest_aes_cmac_mechanism = {
	CKM_AES_CMAC, NULL, 0,
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

static const CK_ULONG cktest_general_mechanism_hmac_len = 8;

static CK_MECHANISM cktest_aes_cmac_general_mechanism = {
	CKM_AES_CMAC_GENERAL,
	(CK_VOID_PTR)&cktest_general_mechanism_hmac_len,
	sizeof(CK_ULONG),
};
static CK_MECHANISM cktest_hmac_general_md5_mechanism = {
	CKM_MD5_HMAC_GENERAL,
	(CK_VOID_PTR)&cktest_general_mechanism_hmac_len,
	sizeof(CK_ULONG),
};
static CK_MECHANISM cktest_hmac_general_sha1_mechanism = {
	CKM_SHA_1_HMAC_GENERAL,
	(CK_VOID_PTR)&cktest_general_mechanism_hmac_len,
	sizeof(CK_ULONG),
};
static CK_MECHANISM cktest_hmac_general_sha224_mechanism = {
	CKM_SHA224_HMAC_GENERAL,
	(CK_VOID_PTR)&cktest_general_mechanism_hmac_len,
	sizeof(CK_ULONG),
};
static CK_MECHANISM cktest_hmac_general_sha256_mechanism = {
	CKM_SHA256_HMAC_GENERAL,
	(CK_VOID_PTR)&cktest_general_mechanism_hmac_len,
	sizeof(CK_ULONG),
};
static CK_MECHANISM cktest_hmac_general_sha384_mechanism = {
	CKM_SHA384_HMAC_GENERAL,
	(CK_VOID_PTR)&cktest_general_mechanism_hmac_len,
	sizeof(CK_ULONG),
};
static CK_MECHANISM cktest_hmac_general_sha512_mechanism = {
	CKM_SHA512_HMAC_GENERAL,
	(CK_VOID_PTR)&cktest_general_mechanism_hmac_len,
	sizeof(CK_ULONG),
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
	Do_ADBG_BeginSubCase(c, "Test C_GetMechanismList() with larger result buffer");

	for (i = 0; i < slot_count; i++) {
		CK_SLOT_ID slot = slot_ids[i];
		CK_ULONG real_mecha_count = 0;
		CK_ULONG alloc_mecha_count = 0;
		uint8_t *data_ptr = NULL;
		size_t j = 0;

		rv = C_GetMechanismList(slot, NULL, &real_mecha_count);
		if (!ADBG_EXPECT_CK_OK(c, rv))
			goto out;

		if (real_mecha_count == 0)
			continue;

		/* Allocate more memory for mechanisms than required */
		alloc_mecha_count = real_mecha_count + 16;
		mecha_count = alloc_mecha_count;

		free(mecha_types);
		mecha_types = calloc(mecha_count, sizeof(*mecha_types));
		if (!ADBG_EXPECT_NOT_NULL(c, mecha_types))
			goto out;
		memset(mecha_types, 0xCC,
		       alloc_mecha_count * sizeof(*mecha_types));

		rv = C_GetMechanismList(slot, mecha_types, &mecha_count);
		if (!ADBG_EXPECT_CK_OK(c, rv))
			goto out;

		if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, mecha_count, ==,
						  real_mecha_count))
			goto out;

		data_ptr = (uint8_t *)mecha_types;
		for (j = real_mecha_count * sizeof(*mecha_types);
		     j < alloc_mecha_count * sizeof(*mecha_types); j++)
			if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, data_ptr[j], ==,
							  0xCC))
				break;
	}

	Do_ADBG_EndSubCase(c, "Test C_GetMechanismList() with larger result buffer");
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

		/*
		 * Check that return value is expected so that operation is
		 * released
		 */
		if (!ADBG_EXPECT_CK_RESULT(c, CKR_ARGUMENTS_BAD, rv)) {
			rv = CKR_GENERAL_ERROR;
			goto out;
		}

		rv = CKR_OK;
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

#define CK_MAC_KEY_AES(_key_array) \
	{								\
		{ CKA_SIGN,	&(CK_BBOOL){CK_TRUE},			\
				sizeof(CK_BBOOL) },			\
		{ CKA_VERIFY,	&(CK_BBOOL){CK_TRUE},			\
				sizeof(CK_BBOOL) },			\
		{ CKA_CLASS,	&(CK_OBJECT_CLASS){CKO_SECRET_KEY},	\
				sizeof(CK_OBJECT_CLASS) },		\
		{ CKA_KEY_TYPE,	&(CK_KEY_TYPE){CKK_AES},		\
				sizeof(CK_KEY_TYPE) },			\
		{ CKA_VALUE,	(void *)(_key_array),			\
				sizeof(_key_array) },			\
	}

static CK_ATTRIBUTE cktest_aes_cmac_key1[] =
	CK_MAC_KEY_AES(mac_cmac_vect1_key);

static CK_ATTRIBUTE cktest_aes_cmac_key2[] =
	CK_MAC_KEY_AES(mac_cmac_vect5_key);

static CK_ATTRIBUTE cktest_aes_cmac_key3[] =
	CK_MAC_KEY_AES(mac_cmac_vect9_key);

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
				sizeof(_key_array) },			\
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
		.multiple_incr = incr,			\
	}

#define CKTEST_CMAC_TEST(key, mecha, input_incr, input, output, incr) {	\
		.attr_key = key,		\
		.attr_count = ARRAY_SIZE(key),	\
		.mechanism = mecha,		\
		.in_incr = input_incr,		\
		.in = input,				\
		.in_len = 0,				\
		.out = output,				\
		.out_len = ARRAY_SIZE(output),		\
		.multiple_incr = incr,			\
	}

static const struct mac_test cktest_mac_cases[] = {
	CKTEST_CMAC_TEST(cktest_aes_cmac_key1, &cktest_aes_cmac_mechanism,
			 0, NULL, mac_cmac_vect1_out, false),
	CKTEST_CMAC_TEST(cktest_aes_cmac_key2, &cktest_aes_cmac_mechanism,
			 0, NULL, mac_cmac_vect5_out, false),
	CKTEST_CMAC_TEST(cktest_aes_cmac_key3, &cktest_aes_cmac_mechanism,
			 0, NULL, mac_cmac_vect9_out, false),
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
	CKTEST_CMAC_TEST(cktest_aes_cmac_key1,
			 &cktest_aes_cmac_general_mechanism, 0, NULL,
			 mac_cmac_vect1_out, false),
	CKTEST_CMAC_TEST(cktest_aes_cmac_key2,
			 &cktest_aes_cmac_general_mechanism, 0, NULL,
			 mac_cmac_vect5_out, false),
	CKTEST_CMAC_TEST(cktest_aes_cmac_key3,
			 &cktest_aes_cmac_general_mechanism, 0, NULL,
			 mac_cmac_vect9_out, false),
	CKTEST_MAC_TEST(cktest_hmac_md5_key,
			&cktest_hmac_general_md5_mechanism, 4,
			mac_data_md5_in1, mac_data_md5_out1, false),
	CKTEST_MAC_TEST(cktest_hmac_sha1_key,
			&cktest_hmac_general_sha1_mechanism, 5,
			mac_data_sha1_in1, mac_data_sha1_out1, false),
	CKTEST_MAC_TEST(cktest_hmac_sha224_key,
			&cktest_hmac_general_sha224_mechanism, 8,
			mac_data_sha224_in1, mac_data_sha224_out1, false),
	CKTEST_MAC_TEST(cktest_hmac_sha256_key1,
			&cktest_hmac_general_sha256_mechanism, 1,
			mac_data_sha256_in1, mac_data_sha256_out1, false),
	CKTEST_MAC_TEST(cktest_hmac_sha256_key2,
			&cktest_hmac_general_sha256_mechanism, 7,
			mac_data_sha256_in2, mac_data_sha256_out2, false),
	CKTEST_MAC_TEST(cktest_hmac_sha384_key,
			&cktest_hmac_general_sha384_mechanism, 11,
			mac_data_sha384_in1, mac_data_sha384_out1, false),
	CKTEST_MAC_TEST(cktest_hmac_sha512_key,
			&cktest_hmac_general_sha512_mechanism, 13,
			mac_data_sha512_in1, mac_data_sha512_out1, false),
};

static bool ckm_is_hmac_general(struct mac_test const *test)
{
	switch (test->mechanism->mechanism) {
	case CKM_AES_CMAC_GENERAL:
	case CKM_MD5_HMAC_GENERAL:
	case CKM_SHA_1_HMAC_GENERAL:
	case CKM_SHA224_HMAC_GENERAL:
	case CKM_SHA256_HMAC_GENERAL:
	case CKM_SHA384_HMAC_GENERAL:
	case CKM_SHA512_HMAC_GENERAL:
		return true;
	default:
		return false;
	}
}

static size_t get_mac_test_len(struct mac_test const *test)
{
	if (ckm_is_hmac_general(test))
		return (size_t)cktest_general_mechanism_hmac_len;

	return test->out_len;
}

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

			/*
			 * Test NULL buffer case with size as non-zero
			 * to get the out_size
			 */
			out_size = 42;
			rv = C_SignFinal(session, NULL, &out_size);
			if (!ADBG_EXPECT_CK_OK(c, rv))
				goto err_destr_obj;

			/* Get to full output */
			memset(out, 0, out_size);
			rv = C_SignFinal(session, out, &out_size);
			if (!ADBG_EXPECT_CK_OK(c, rv))
				goto err_destr_obj;

			(void)ADBG_EXPECT_BUFFER(c, test->out,
						 get_mac_test_len(test),
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
					 get_mac_test_len(test), out,
					 out_size);

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

			/*
			 * Test NULL buffer case with size as non-zero
			 * to get the out_size
			 */
			out_size = 42;
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
						 get_mac_test_len(test),
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
					   (void *)test->out,
					   get_mac_test_len(test));
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

		rv = C_VerifyFinal(session, (void *)test->out,
				   get_mac_test_len(test));
		if (!ADBG_EXPECT_CK_OK(c, rv))
			goto err_destr_obj;

		/* Error as Operation has already completed */
		rv = C_Verify(session,
			      (void *)test->in, test->in_len,
			      (void *)test->out, get_mac_test_len(test));
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
				      (void *)test->out,
				      get_mac_test_len(test));
			if (!ADBG_EXPECT_CK_OK(c, rv))
				goto err_destr_obj;

			/* Try calling Verify again */
			rv = C_Verify(session,
				      (void *)test->in, test->in_len,
				      (void *)test->out,
				      get_mac_test_len(test));
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
			if (!ADBG_EXPECT_CK_RESULT(c,
						   ckm_is_hmac_general(test) ?
						   CKR_OK :
						   CKR_SIGNATURE_LEN_RANGE,
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

			rv = C_VerifyInit(session, test->mechanism, key_handle);
			if (!ADBG_EXPECT_CK_OK(c, rv))
				goto err_destr_obj;

			rv = C_Verify(session,
				      (void *)test->in, test->in_len,
				      (void *)test->out,
				      TEE_MAX_HASH_SIZE + 1);
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
				      (void *)test->out,
				      get_mac_test_len(test));
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
	{ CKA_VALUE_LEN, &(CK_ULONG){16}, sizeof(CK_ULONG) },
};

/* Invalid template with CKA_LOCAL */
static CK_ATTRIBUTE cktest_generate_gensecret_object_error4[] = {
	{ CKA_VALUE_LEN, &(CK_ULONG){16}, sizeof(CK_ULONG) },
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
	{ CKA_VALUE_LEN, &(CK_ULONG){16}, sizeof(CK_ULONG) },
};

/* Valid template to generate a generic secret with only VALUE_LEN */
static CK_ATTRIBUTE cktest_generate_gensecret_object_valid2[] = {
	{ CKA_VALUE_LEN, &(CK_ULONG){16}, sizeof(CK_ULONG) },
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
	struct mac_test test_sign = CKTEST_MAC_TEST(cktest_hmac_md5_key,
						    &cktest_hmac_md5_mechanism,
						    4, mac_data_md5_in1,
						    mac_data_md5_out1, false);
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

	rv = C_SignInit(session, test_sign.mechanism, key_handle);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto err_destr_obj;

	rv = C_Sign(session, (void *)test_sign.in, test_sign.in_len,
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

static void xtest_pkcs11_test_1012(ADBG_Case_t *c)
{
	CK_RV rv = CKR_GENERAL_ERROR;
	CK_SLOT_ID slot = 0;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_FLAGS session_flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	CK_OBJECT_HANDLE obj_hdl = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE key_hdl = CK_INVALID_HANDLE;
	size_t i = 0;

	CK_OBJECT_CLASS obj_class = CKO_DATA;
	CK_BBOOL obj_token = CK_FALSE;
	CK_BBOOL obj_private = CK_FALSE;
	uint8_t obj_value[5] = { 1, 2, 3, 4, 5 };
	const char *obj_label = "Label";

	CK_ATTRIBUTE object_template[] = {
		{ CKA_CLASS, &obj_class, sizeof(obj_class) },
		{ CKA_TOKEN, &obj_token, sizeof(obj_token) },
		{ CKA_PRIVATE, &obj_private, sizeof(obj_private) },
		{ CKA_VALUE, obj_value, sizeof(obj_value) },
		{ CKA_LABEL, (CK_UTF8CHAR_PTR)obj_label, strlen(obj_label) },
	};

	CK_OBJECT_CLASS secret_class = CKO_SECRET_KEY;
	CK_BBOOL secret_token = CK_FALSE;
	CK_BBOOL secret_private = CK_FALSE;
	CK_KEY_TYPE secret_key_type = CKK_GENERIC_SECRET;
	CK_ULONG secret_len = 32;
	CK_MECHANISM_TYPE secret_allowed_mecha[] = { CKM_SHA_1_HMAC,
						     CKM_SHA224_HMAC,
						     CKM_SHA256_HMAC };

	CK_ATTRIBUTE secret_template[] = {
		{ CKA_CLASS, &secret_class, sizeof(secret_class) },
		{ CKA_TOKEN, &secret_token, sizeof(secret_token) },
		{ CKA_PRIVATE, &secret_private, sizeof(secret_private) },
		{ CKA_KEY_TYPE, &secret_key_type, sizeof(secret_key_type) },
		{ CKA_VALUE_LEN, &secret_len, sizeof(secret_len) },
		{ CKA_ALLOWED_MECHANISMS, secret_allowed_mecha,
		  sizeof(secret_allowed_mecha) }
	};

	CK_BBOOL g_token = CK_TRUE;
	CK_BBOOL g_private = CK_TRUE;
	CK_OBJECT_CLASS g_class = ~0;
	uint8_t g_value[128] = { 0 };
	CK_MECHANISM_TYPE g_mecha_list[10] = { 0 };

	uint8_t *data_ptr = NULL;

	CK_ATTRIBUTE get_attr_template_bc[] = {
		{ CKA_TOKEN, &g_token, sizeof(g_token) },
		{ CKA_CLASS, &g_class, sizeof(g_class) },
	};

	CK_ATTRIBUTE get_attr_template_cb[] = {
		{ CKA_CLASS, &g_class, sizeof(g_class) },
		{ CKA_TOKEN, &g_token, sizeof(g_token) },
	};

	CK_ATTRIBUTE get_attr_template_query_bc[] = {
		{ CKA_TOKEN, NULL, 0 },
		{ CKA_CLASS, NULL, 0 },
	};

	CK_ATTRIBUTE get_attr_template_query_cb[] = {
		{ CKA_CLASS, NULL, 0 },
		{ CKA_TOKEN, NULL, 0 },
	};

	CK_ATTRIBUTE get_attr_template_ve[] = {
		{ CKA_VALUE, &g_value, sizeof(obj_value) },
	};

	CK_ATTRIBUTE get_attr_template_vl[] = {
		{ CKA_VALUE, &g_value, sizeof(g_value) },
	};

	CK_ATTRIBUTE get_attr_template_bvecb[] = {
		{ CKA_TOKEN, &g_token, sizeof(g_token) },
		{ CKA_VALUE, &g_value, sizeof(obj_value) },
		{ CKA_CLASS, &g_class, sizeof(g_class) },
		{ CKA_TOKEN, &g_private, sizeof(g_private) },
	};

	CK_ATTRIBUTE get_attr_template_bvlcb[] = {
		{ CKA_TOKEN, &g_token, sizeof(g_token) },
		{ CKA_VALUE, &g_value, sizeof(g_value) },
		{ CKA_CLASS, &g_class, sizeof(g_class) },
		{ CKA_TOKEN, &g_private, sizeof(g_private) },
	};

	CK_ATTRIBUTE get_attr_template_am[] = {
		{ CKA_ALLOWED_MECHANISMS, &g_mecha_list, sizeof(g_mecha_list) },
	};

	rv = init_lib_and_find_token_slot(&slot);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		return;

	rv = init_test_token(slot);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto close_lib;

	rv = init_user_test_token(slot);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto close_lib;

	rv = C_OpenSession(slot, session_flags, NULL, 0, &session);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto close_lib;

	/* Session Public Obj CKA_TOKEN = CK_FALSE, CKA_PRIVATE = CK_FALSE */
	rv = C_CreateObject(session, object_template,
			    ARRAY_SIZE(object_template), &obj_hdl);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	/*
	 * Sub test: Test Boolean (1 byte) + object class (CK_ULONG)
	 */
	Do_ADBG_BeginSubCase(c, "Get Attribute - boolean + class");
	g_token = CK_TRUE;
	g_class = ~0;

	rv = C_GetAttributeValue(session, obj_hdl, get_attr_template_bc,
				 ARRAY_SIZE(get_attr_template_bc));
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	ADBG_EXPECT_COMPARE_UNSIGNED(c, g_class, ==, CKO_DATA);
	ADBG_EXPECT_COMPARE_UNSIGNED(c, g_token, ==, CK_FALSE);

	Do_ADBG_EndSubCase(c, NULL);

	/*
	 * Sub test: object class (CK_ULONG) + Test Boolean (1 byte)
	 */
	Do_ADBG_BeginSubCase(c, "Get Attribute - class + boolean");
	g_token = CK_TRUE;
	g_class = ~0;

	rv = C_GetAttributeValue(session, obj_hdl, get_attr_template_cb,
				 ARRAY_SIZE(get_attr_template_cb));
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	ADBG_EXPECT_COMPARE_UNSIGNED(c, g_class, ==, CKO_DATA);
	ADBG_EXPECT_COMPARE_UNSIGNED(c, g_token, ==, CK_FALSE);

	Do_ADBG_EndSubCase(c, NULL);

	/*
	 * Sub test: Query size boolean (1 byte) + object class (CK_ULONG)
	 */
	Do_ADBG_BeginSubCase(c, "Get Attribute - query size boolean + class");
	g_token = CK_TRUE;
	g_class = ~0;

	rv = C_GetAttributeValue(session, obj_hdl, get_attr_template_query_bc,
				 ARRAY_SIZE(get_attr_template_query_bc));
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	ADBG_EXPECT_COMPARE_UNSIGNED(c,
		get_attr_template_query_bc[0].ulValueLen, ==, 1);
	ADBG_EXPECT_COMPARE_UNSIGNED(c,
		get_attr_template_query_bc[1].ulValueLen, ==, sizeof(CK_ULONG));

	Do_ADBG_EndSubCase(c, NULL);

	/*
	 * Sub test: Query size object class (CK_ULONG) + boolean (1 byte)
	 */
	Do_ADBG_BeginSubCase(c, "Get Attribute - query size class + boolean");
	g_token = CK_TRUE;
	g_class = ~0;

	rv = C_GetAttributeValue(session, obj_hdl, get_attr_template_query_cb,
				 ARRAY_SIZE(get_attr_template_query_cb));
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	ADBG_EXPECT_COMPARE_UNSIGNED(c,
		get_attr_template_query_cb[0].ulValueLen, ==, sizeof(CK_ULONG));
	ADBG_EXPECT_COMPARE_UNSIGNED(c,
		get_attr_template_query_cb[1].ulValueLen, ==, 1);

	Do_ADBG_EndSubCase(c, NULL);

	/*
	 * Sub test: value with exact size
	 */
	Do_ADBG_BeginSubCase(c, "Get Attribute - value with exact size buffer");
	memset(g_value, 0xCC, sizeof(g_value));

	rv = C_GetAttributeValue(session, obj_hdl, get_attr_template_ve,
				 ARRAY_SIZE(get_attr_template_ve));
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	ADBG_EXPECT_COMPARE_UNSIGNED(c, get_attr_template_ve[0].ulValueLen, ==, sizeof(obj_value));
	ADBG_EXPECT_EQUAL(c, g_value, obj_value, sizeof(obj_value));
	for (i = sizeof(obj_value); i < sizeof(g_value); i++)
		if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, g_value[i], ==, 0xCC))
			break;

	Do_ADBG_EndSubCase(c, NULL);

	/*
	 * Sub test: value with larger buffer
	 */
	Do_ADBG_BeginSubCase(c, "Get Attribute - value with larger buffer");
	memset(g_value, 0xCC, sizeof(g_value));

	rv = C_GetAttributeValue(session, obj_hdl, get_attr_template_vl,
				 ARRAY_SIZE(get_attr_template_vl));
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	ADBG_EXPECT_COMPARE_UNSIGNED(c, get_attr_template_vl[0].ulValueLen, ==, sizeof(obj_value));
	ADBG_EXPECT_EQUAL(c, g_value, obj_value, sizeof(obj_value));
	for (i = sizeof(obj_value); i < sizeof(g_value); i++)
		if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, g_value[i], ==, 0xCC))
			break;

	Do_ADBG_EndSubCase(c, NULL);

	/*
	 * Sub test: bool + value with exact size + class + bool
	 */
	Do_ADBG_BeginSubCase(c, "Get Attribute - bool + value with exact size + class + bool");
	memset(g_value, 0xCC, sizeof(g_value));
	g_token = CK_TRUE;
	g_private = CK_TRUE;
	g_class = ~0;

	rv = C_GetAttributeValue(session, obj_hdl, get_attr_template_bvecb,
				 ARRAY_SIZE(get_attr_template_bvecb));
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	ADBG_EXPECT_COMPARE_UNSIGNED(c, get_attr_template_bvecb[1].ulValueLen,
				     ==, sizeof(obj_value));
	ADBG_EXPECT_EQUAL(c, g_value, obj_value, sizeof(obj_value));
	for (i = sizeof(obj_value); i < sizeof(g_value); i++)
		if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, g_value[i], ==, 0xCC))
			break;

	ADBG_EXPECT_COMPARE_UNSIGNED(c, g_class, ==, CKO_DATA);
	ADBG_EXPECT_COMPARE_UNSIGNED(c, g_token, ==, CK_FALSE);
	ADBG_EXPECT_COMPARE_UNSIGNED(c, g_private, ==, CK_FALSE);

	Do_ADBG_EndSubCase(c, NULL);

	/*
	 * Sub test: bool + value with larger buffer + class + bool
	 */
	Do_ADBG_BeginSubCase(c, "Get Attribute - bool + value with larger buffer + class + bool");
	memset(g_value, 0xCC, sizeof(g_value));
	g_token = CK_TRUE;
	g_private = CK_TRUE;
	g_class = ~0;

	rv = C_GetAttributeValue(session, obj_hdl, get_attr_template_bvlcb,
				 ARRAY_SIZE(get_attr_template_bvlcb));
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	ADBG_EXPECT_COMPARE_UNSIGNED(c, get_attr_template_bvlcb[1].ulValueLen,
				     ==, sizeof(obj_value));
	ADBG_EXPECT_EQUAL(c, g_value, obj_value, sizeof(obj_value));
	for (i = sizeof(obj_value); i < sizeof(g_value); i++)
		if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, g_value[i], ==, 0xCC))
			break;

	ADBG_EXPECT_COMPARE_UNSIGNED(c, g_class, ==, CKO_DATA);
	ADBG_EXPECT_COMPARE_UNSIGNED(c, g_token, ==, CK_FALSE);
	ADBG_EXPECT_COMPARE_UNSIGNED(c, g_private, ==, CK_FALSE);

	Do_ADBG_EndSubCase(c, NULL);

	/*
	 * Sub test: allowed mechanism list
	 */
	Do_ADBG_BeginSubCase(c, "Get Attribute - allowed mechanism list");
	memset(g_mecha_list, 0xCC, sizeof(g_mecha_list));

	rv = C_GenerateKey(session, &cktest_gensecret_keygen_mechanism,
			   secret_template, ARRAY_SIZE(secret_template),
			   &key_hdl);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	rv = C_GetAttributeValue(session, key_hdl, get_attr_template_am,
				 ARRAY_SIZE(get_attr_template_am));
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	ADBG_EXPECT_COMPARE_UNSIGNED(c, get_attr_template_am[0].ulValueLen, ==,
				     sizeof(secret_allowed_mecha));

	for (i = 0; i < sizeof(secret_allowed_mecha) / sizeof(*secret_allowed_mecha); i++)
		if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, g_mecha_list[i], ==, secret_allowed_mecha[i]))
			break;

	data_ptr = (uint8_t *)g_mecha_list;
	for (i = sizeof(secret_allowed_mecha); i < sizeof(g_mecha_list); i++)
		if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, data_ptr[i], ==, 0xCC))
			break;

	Do_ADBG_EndSubCase(c, NULL);

out:
	ADBG_EXPECT_CK_OK(c, C_CloseSession(session));

close_lib:
	ADBG_EXPECT_CK_OK(c, close_lib());
}
ADBG_CASE_DEFINE(pkcs11, 1012, xtest_pkcs11_test_1012,
		 "PKCS11: Serializer tests");

static void xtest_pkcs11_test_1013(ADBG_Case_t *c)
{
	CK_RV rv = CKR_GENERAL_ERROR;
	CK_SLOT_ID slot = 0;
	CK_SESSION_HANDLE rw_session = CK_INVALID_HANDLE;
	CK_SESSION_HANDLE ro_session = CK_INVALID_HANDLE;
	CK_FLAGS rw_session_flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	CK_FLAGS ro_session_flags = CKF_SERIAL_SESSION;
	CK_OBJECT_HANDLE obj_hdl = CK_INVALID_HANDLE;
	const char *label = "Dummy Objects";
	bool ro_logged_in = false;

	rv = init_lib_and_find_token_slot(&slot);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		return;

	rv = init_test_token(slot);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto close_lib;

	rv = init_user_test_token(slot);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto close_lib;

	/* Open a RW session */
	rv = C_OpenSession(slot, rw_session_flags, NULL, 0, &rw_session);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto close_lib;

	/* Open a RO session */
	rv = C_OpenSession(slot, ro_session_flags, NULL, 0, &ro_session);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto close_lib;

	/*
	 * Sub test: Check object creation from a R/O Public session
	 */
	Do_ADBG_BeginSubCase(c, "Create objects in R/O Public Session");

	/* Session Public Obj CKA_TOKEN = CK_FALSE, CKA_PRIVATE = CK_FALSE */
	rv = create_data_object(ro_session, &obj_hdl, CK_FALSE,
				CK_FALSE, label);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	/* Session Private Obj CKA_TOKEN = CK_FALSE, CKA_PRIVATE = CK_TRUE */
	rv = create_data_object(ro_session, &obj_hdl, CK_FALSE,
				CK_TRUE, label);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_USER_NOT_LOGGED_IN, rv))
		goto out;

	/* Token Public Obj CKA_TOKEN = CK_TRUE, CKA_PRIVATE = CK_FALSE */
	rv = create_data_object(ro_session, &obj_hdl, CK_TRUE,
				CK_FALSE, label);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_SESSION_READ_ONLY, rv))
		goto out;

	/* Token Private Obj CKA_TOKEN = CK_TRUE, CKA_PRIVATE = CK_TRUE */
	rv = create_data_object(ro_session, &obj_hdl, CK_TRUE,
				CK_TRUE, label);
	/* For Token object creation, SESSION_READ_ONLY will take priority */
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_SESSION_READ_ONLY, rv))
		goto out;

	Do_ADBG_EndSubCase(c, NULL);

	/*
	 * Sub test: Check access for a R/W Public session
	 */
	Do_ADBG_BeginSubCase(c, "Create objects in R/O Public Session");

	/* Session Public Obj CKA_TOKEN = CK_FALSE, CKA_PRIVATE = CK_FALSE */
	rv = create_data_object(rw_session, &obj_hdl, CK_FALSE,
				CK_FALSE, label);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	/* Session Private Obj CKA_TOKEN = CK_FALSE, CKA_PRIVATE = CK_TRUE */
	rv = create_data_object(rw_session, &obj_hdl, CK_FALSE,
				CK_TRUE, label);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_USER_NOT_LOGGED_IN, rv))
		goto out;

	/* Token Public Obj CKA_TOKEN = CK_TRUE, CKA_PRIVATE = CK_FALSE */
	rv = create_data_object(rw_session, &obj_hdl, CK_TRUE,
				CK_FALSE, label);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	/* Token Private Obj CKA_TOKEN = CK_TRUE, CKA_PRIVATE = CK_TRUE */
	rv = create_data_object(rw_session, &obj_hdl, CK_TRUE,
				CK_TRUE, label);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_USER_NOT_LOGGED_IN, rv))
		goto out;

	Do_ADBG_EndSubCase(c, NULL);

	/*
	 * Sub test: Check access for a R/O User session
	 */
	Do_ADBG_BeginSubCase(c, "Create objects in R/O User Session");

	/* Login to Test Token */
	rv = C_Login(ro_session, CKU_USER, test_token_user_pin,
		     sizeof(test_token_user_pin));
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	ro_logged_in = true;

	/* Session Public Obj CKA_TOKEN = CK_FALSE, CKA_PRIVATE = CK_FALSE */
	rv = create_data_object(ro_session, &obj_hdl, CK_FALSE,
				CK_FALSE, label);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	/* Session Private Obj CKA_TOKEN = CK_FALSE, CKA_PRIVATE = CK_TRUE */
	rv = create_data_object(ro_session, &obj_hdl, CK_FALSE,
				CK_TRUE, label);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	/* Token Public Obj CKA_TOKEN = CK_TRUE, CKA_PRIVATE = CK_FALSE */
	rv = create_data_object(ro_session, &obj_hdl, CK_TRUE,
				CK_FALSE, label);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_SESSION_READ_ONLY, rv))
		goto out;

	/* Token Private Obj CKA_TOKEN = CK_TRUE, CKA_PRIVATE = CK_TRUE */
	rv = create_data_object(ro_session, &obj_hdl, CK_TRUE,
				CK_TRUE, label);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_SESSION_READ_ONLY, rv))
		goto out;

	Do_ADBG_EndSubCase(c, NULL);

	/*
	 * Sub test: Check access for a R/W User session
	 */
	Do_ADBG_BeginSubCase(c, "Create objects in R/W User Session");

	/* Session Public Obj CKA_TOKEN = CK_FALSE, CKA_PRIVATE = CK_FALSE */
	rv = create_data_object(rw_session, &obj_hdl, CK_FALSE,
				CK_FALSE, label);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	/* Session Private Obj CKA_TOKEN = CK_FALSE, CKA_PRIVATE = CK_TRUE */
	rv = create_data_object(rw_session, &obj_hdl, CK_FALSE,
				CK_TRUE, label);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	/* Token Public Obj CKA_TOKEN = CK_TRUE, CKA_PRIVATE = CK_FALSE */
	rv = create_data_object(rw_session, &obj_hdl, CK_TRUE,
				CK_FALSE, label);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	/* Token Private Obj CKA_TOKEN = CK_TRUE, CKA_PRIVATE = CK_TRUE */
	rv = create_data_object(rw_session, &obj_hdl, CK_TRUE,
				CK_TRUE, label);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	/* Log out */
	ADBG_EXPECT_CK_OK(c, C_Logout(ro_session));
	ro_logged_in = false;

	/* Close RO session */
	ADBG_EXPECT_CK_OK(c, C_CloseSession(ro_session));
	ro_session = CK_INVALID_HANDLE;

	Do_ADBG_EndSubCase(c, NULL);

	/*
	 * Sub test: Check access for a R/W SO session
	 */
	Do_ADBG_BeginSubCase(c, "Create objects in R/W SO Session");

	/* Login as security officer in RW session */
	rv = C_Login(rw_session, CKU_SO, test_token_so_pin,
		     sizeof(test_token_so_pin));
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	/* Session Public Obj CKA_TOKEN = CK_FALSE, CKA_PRIVATE = CK_FALSE */
	rv = create_data_object(rw_session, &obj_hdl, CK_FALSE,
				CK_FALSE, label);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto logout;

	/* Session Private Obj CKA_TOKEN = CK_FALSE, CKA_PRIVATE = CK_TRUE */
	rv = create_data_object(rw_session, &obj_hdl, CK_FALSE,
				CK_TRUE, label);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_USER_NOT_LOGGED_IN, rv))
		goto logout;

	/* Token Public Obj CKA_TOKEN = CK_TRUE, CKA_PRIVATE = CK_FALSE */
	rv = create_data_object(rw_session, &obj_hdl, CK_TRUE,
				CK_FALSE, label);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto logout;

	/* Token Private Obj CKA_TOKEN = CK_TRUE, CKA_PRIVATE = CK_TRUE */
	rv = create_data_object(rw_session, &obj_hdl, CK_TRUE,
				CK_TRUE, label);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_USER_NOT_LOGGED_IN, rv))
		goto logout;

logout:
	ADBG_EXPECT_CK_OK(c, C_Logout(rw_session));
out:
	if (ro_logged_in)
		ADBG_EXPECT_CK_OK(c, C_Logout(ro_session));

	if (ro_session != CK_INVALID_HANDLE)
		ADBG_EXPECT_CK_OK(c, C_CloseSession(ro_session));

	ADBG_EXPECT_CK_OK(c, C_CloseSession(rw_session));

	Do_ADBG_EndSubCase(c, NULL);

	destroy_persistent_objects(c, slot);
close_lib:
	ADBG_EXPECT_CK_OK(c, close_lib());

}
ADBG_CASE_DEFINE(pkcs11, 1013, xtest_pkcs11_test_1013,
		 "PKCS11: Object creation upon session type");

static void xtest_pkcs11_test_1014(ADBG_Case_t *c)
{
	CK_RV rv = CKR_GENERAL_ERROR;
	CK_SLOT_ID slot = 0;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_FLAGS session_flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	CK_OBJECT_HANDLE obj_hdl = CK_INVALID_HANDLE;
	const char *id = "1";
	const char *label = "Dummy Objects";
	const char *new_label = "New Object lable";
	size_t n = 0;
	char *g_label[100] = { };
	char *g_id[100] = { };
	CK_MECHANISM_TYPE secret_allowed_mecha[] = { CKM_SHA_1_HMAC,
						     CKM_SHA224_HMAC,
						     CKM_SHA256_HMAC };
	CK_ATTRIBUTE secret_key_template[] = {
		{ CKA_CLASS, &(CK_OBJECT_CLASS){CKO_SECRET_KEY},
						sizeof(CK_OBJECT_CLASS) },
		{ CKA_TOKEN, &(CK_BBOOL){CK_FALSE}, sizeof(CK_BBOOL) },
		{ CKA_PRIVATE, &(CK_BBOOL){CK_FALSE}, sizeof(CK_BBOOL) },
		{ CKA_MODIFIABLE, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
		{ CKA_COPYABLE, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
		{ CKA_DESTROYABLE, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
		{ CKA_EXTRACTABLE, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
		{ CKA_KEY_TYPE, &(CK_KEY_TYPE){CKK_GENERIC_SECRET},
						sizeof(CK_KEY_TYPE) },
		{ CKA_LABEL, (CK_UTF8CHAR_PTR)label, strlen(label) },
		{ CKA_VALUE,	(void *)cktest_aes128_key, sizeof(cktest_aes128_key) },
		{ CKA_SIGN, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
		{ CKA_VERIFY, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
		{ CKA_ENCRYPT, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
		{ CKA_DECRYPT, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
		{ CKA_ALLOWED_MECHANISMS, secret_allowed_mecha,
		  sizeof(secret_allowed_mecha) },
	};
	CK_BBOOL g_derive = CK_FALSE;
	CK_BBOOL g_sign = CK_FALSE;
	CK_BBOOL g_verify = CK_FALSE;
	CK_BBOOL g_encrypt = CK_FALSE;
	CK_BBOOL g_decrypt = CK_FALSE;
	CK_BBOOL g_wrap = CK_FALSE;
	CK_BBOOL g_unwrap = CK_FALSE;
	uint32_t g_len = 0;
	CK_ATTRIBUTE get_template[] = {
		{ CKA_LABEL, (CK_UTF8CHAR_PTR)g_label, sizeof(g_label) },
		{ CKA_ID, (CK_BYTE_PTR)g_id, sizeof(g_id) },
		{ CKA_DERIVE, &g_derive, sizeof(CK_BBOOL) },
		{ CKA_SIGN, &g_sign, sizeof(CK_BBOOL) },
		{ CKA_VERIFY, &g_verify, sizeof(CK_BBOOL) },
		{ CKA_ENCRYPT, &g_encrypt, sizeof(CK_BBOOL) },
		{ CKA_DECRYPT, &g_decrypt, sizeof(CK_BBOOL) },
		{ CKA_WRAP, &g_wrap, sizeof(CK_BBOOL) },
		{ CKA_UNWRAP, &g_unwrap, sizeof(CK_BBOOL) },
		{ CKA_VALUE_LEN, &g_len, sizeof(CK_ULONG) },
	};
	CK_ATTRIBUTE set_template[] = {
		{ CKA_LABEL, (CK_UTF8CHAR_PTR)new_label, strlen(new_label) },
		{ CKA_ID, (CK_BYTE_PTR)id, strlen(id) },
		{ CKA_DERIVE, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
		{ CKA_WRAP, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
		{ CKA_UNWRAP, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
		{ CKA_SIGN, &(CK_BBOOL){CK_FALSE}, sizeof(CK_BBOOL) },
		{ CKA_VERIFY, &(CK_BBOOL){CK_FALSE}, sizeof(CK_BBOOL) },
		{ CKA_ENCRYPT, &(CK_BBOOL){CK_FALSE}, sizeof(CK_BBOOL) },
		{ CKA_DECRYPT, &(CK_BBOOL){CK_FALSE}, sizeof(CK_BBOOL) },
		/* CKA_SENSITIVE -> CK_FALSE to CK_TRUE is allowed */
		{ CKA_SENSITIVE, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
		/* CKA_EXTRACTABLE -> CK_TRUE to CK_FALSE is allowed */
		{ CKA_EXTRACTABLE, &(CK_BBOOL){CK_FALSE}, sizeof(CK_BBOOL) },
		/* CKA_COPYABLE -> CK_TRUE to CK_FALSE is allowed */
		{ CKA_COPYABLE, &(CK_BBOOL){CK_FALSE}, sizeof(CK_BBOOL) },
	};
	CK_ATTRIBUTE set_inv_template1[] = {
		/* Attributes Not Modifiable */
		{ CKA_CLASS, &(CK_OBJECT_CLASS){CKO_DATA},
						sizeof(CK_OBJECT_CLASS) },
		{ CKA_LOCAL, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
		{ CKA_ALWAYS_SENSITIVE, &(CK_BBOOL){CK_FALSE},
							sizeof(CK_BBOOL) },
		{ CKA_NEVER_EXTRACTABLE, &(CK_BBOOL){CK_FALSE},
							sizeof(CK_BBOOL) },
		{ CKA_TOKEN,	&(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
		{ CKA_PRIVATE,	&(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
		{ CKA_MODIFIABLE, &(CK_BBOOL){CK_FALSE}, sizeof(CK_BBOOL) },
		{ CKA_DESTROYABLE, &(CK_BBOOL){CK_FALSE}, sizeof(CK_BBOOL) },
		/* Change not allowed from CK_TRUE -> CK_FALSE */
		{ CKA_SENSITIVE, &(CK_BBOOL){CK_FALSE}, sizeof(CK_BBOOL) },
		/* Change not allowed from CK_FALSE -> CK_TRUE */
		{ CKA_EXTRACTABLE, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
		{ CKA_COPYABLE, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	};
	CK_ATTRIBUTE set_inv_template2[] = {
		{ CKA_APPLICATION, (CK_UTF8CHAR_PTR)label, sizeof(label) },
	};
	CK_ATTRIBUTE set_trusted_template[] = {
		{ CKA_TRUSTED, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	};

	rv = init_lib_and_find_token_slot(&slot);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		return;

	rv = init_test_token(slot);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto close_lib;

	rv = init_user_test_token(slot);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto close_lib;

	/* Open a RW session */
	rv = C_OpenSession(slot, session_flags, NULL, 0, &session);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto close_lib;

	/* Create a secret key object */
	rv = C_CreateObject(session, secret_key_template,
			    ARRAY_SIZE(secret_key_template), &obj_hdl);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto close_session;

	Do_ADBG_BeginSubCase(c, "Set attributes on secret key object");

	rv = C_GetAttributeValue(session, obj_hdl, get_template,
				 ARRAY_SIZE(get_template));
	if (!ADBG_EXPECT_CK_OK(c, rv) ||
	    !ADBG_EXPECT_BUFFER(c, label, strlen(label), g_label,
				get_template[0].ulValueLen) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_derive, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_wrap, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_unwrap, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_encrypt, ==, CK_TRUE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_decrypt, ==, CK_TRUE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_sign, ==, CK_TRUE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_verify, ==, CK_TRUE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_len, ==, 16) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, get_template[1].ulValueLen, ==, 0))
		goto out;

	rv = C_SetAttributeValue(session, obj_hdl, set_template,
				 ARRAY_SIZE(set_template));
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	get_template[0].ulValueLen = sizeof(g_label);
	get_template[1].ulValueLen = sizeof(g_id);
	rv = C_GetAttributeValue(session, obj_hdl, get_template,
				 ARRAY_SIZE(get_template));
	if (!ADBG_EXPECT_CK_OK(c, rv) ||
	    !ADBG_EXPECT_BUFFER(c, new_label, strlen(new_label), g_label,
				get_template[0].ulValueLen) ||
	    !ADBG_EXPECT_BUFFER(c, id, strlen(id), g_id,
				get_template[1].ulValueLen) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_derive, ==, CK_TRUE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_wrap, ==, CK_TRUE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_unwrap, ==, CK_TRUE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_encrypt, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_decrypt, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_sign, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_verify, ==, CK_FALSE))
		goto out;

	Do_ADBG_EndSubCase(c, NULL);

	Do_ADBG_BeginSubCase(c, "Test Invalid template with R/O Attributes");

	for (n = 0; n < ARRAY_SIZE(set_inv_template1); n++) {
		rv = C_SetAttributeValue(session, obj_hdl,
					 &set_inv_template1[n], 1);
		if (!ADBG_EXPECT_CK_RESULT(c, CKR_ATTRIBUTE_READ_ONLY, rv))
			goto out;
	}

	Do_ADBG_EndSubCase(c, NULL);

	Do_ADBG_BeginSubCase(c, "Test Invalid template with Invalid Attribute");

	rv = C_SetAttributeValue(session, obj_hdl, set_inv_template2,
				 ARRAY_SIZE(set_inv_template2));
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_ATTRIBUTE_TYPE_INVALID, rv))
		goto out;

	Do_ADBG_EndSubCase(c, NULL);

	Do_ADBG_BeginSubCase(c, "Set CKA_TRUSTED with and w/o SO Login");

	rv = C_SetAttributeValue(session, obj_hdl, set_trusted_template,
				 ARRAY_SIZE(set_trusted_template));
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_ATTRIBUTE_READ_ONLY, rv))
		goto out;

	/* Login as SO in RW session */
	rv = C_Login(session, CKU_SO, test_token_so_pin,
		     sizeof(test_token_so_pin));
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	rv = C_SetAttributeValue(session, obj_hdl, set_trusted_template,
				 ARRAY_SIZE(set_trusted_template));
	ADBG_EXPECT_CK_OK(c, rv);

	ADBG_EXPECT_CK_OK(c, C_Logout(session));
out:
	ADBG_EXPECT_CK_OK(c, C_DestroyObject(session, obj_hdl));

	Do_ADBG_EndSubCase(c, NULL);

close_session:
	ADBG_EXPECT_CK_OK(c, C_CloseSession(session));

close_lib:
	ADBG_EXPECT_CK_OK(c, close_lib());
}
ADBG_CASE_DEFINE(pkcs11, 1014, xtest_pkcs11_test_1014,
		 "PKCS11: Test C_SetAttributeValue()");

static void xtest_pkcs11_test_1015(ADBG_Case_t *c)
{
	CK_RV rv = CKR_GENERAL_ERROR;
	CK_SLOT_ID slot = 0;
	CK_SESSION_HANDLE rw_session = CK_INVALID_HANDLE;
	CK_SESSION_HANDLE ro_session = CK_INVALID_HANDLE;
	CK_FLAGS rw_session_flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	CK_FLAGS ro_session_flags = CKF_SERIAL_SESSION;
	CK_OBJECT_HANDLE obj_hdl = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE obj_hdl_ro = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE obj_hdl_cp = CK_INVALID_HANDLE;
	const char *label = "Dummy Objects";
	CK_ATTRIBUTE secret_key_create_template[] = {
		{ CKA_CLASS, &(CK_OBJECT_CLASS){CKO_SECRET_KEY},
						sizeof(CK_OBJECT_CLASS) },
		{ CKA_KEY_TYPE,	&(CK_KEY_TYPE){CKK_AES}, sizeof(CK_KEY_TYPE) },
		{ CKA_TOKEN, &(CK_BBOOL){CK_FALSE}, sizeof(CK_BBOOL) },
		{ CKA_PRIVATE, &(CK_BBOOL){CK_FALSE}, sizeof(CK_BBOOL) },
		{ CKA_MODIFIABLE, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
		{ CKA_COPYABLE, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
		{ CKA_DESTROYABLE, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
		{ CKA_EXTRACTABLE, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
		{ CKA_VALUE,	(void *)cktest_aes128_key, sizeof(cktest_aes128_key) },
	};
	CK_ATTRIBUTE secret_key_template[] = {
		{ CKA_CLASS, &(CK_OBJECT_CLASS){CKO_SECRET_KEY},
						sizeof(CK_OBJECT_CLASS) },
		{ CKA_KEY_TYPE,	&(CK_KEY_TYPE){CKK_AES}, sizeof(CK_KEY_TYPE) },
		{ CKA_TOKEN, &(CK_BBOOL){CK_FALSE}, sizeof(CK_BBOOL) },
		{ CKA_PRIVATE, &(CK_BBOOL){CK_FALSE}, sizeof(CK_BBOOL) },
		{ CKA_MODIFIABLE, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
		{ CKA_COPYABLE, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
		{ CKA_DESTROYABLE, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
		{ CKA_EXTRACTABLE, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
		{ CKA_VALUE_LEN, &(CK_ULONG){16}, sizeof(CK_ULONG) },
	};
	CK_BBOOL g_token = CK_FALSE;
	CK_BBOOL g_private = CK_FALSE;
	CK_BBOOL g_modify = CK_FALSE;
	CK_BBOOL g_copy = CK_FALSE;
	CK_BBOOL g_destroy = CK_FALSE;
	CK_BBOOL g_extract = CK_FALSE;
	CK_BBOOL g_sensitive = CK_FALSE;
	CK_BBOOL g_nextract = CK_FALSE;
	CK_BBOOL g_asensitive = CK_FALSE;
	CK_BBOOL g_local =  CK_FALSE;
	CK_BYTE g_value[16] = { };
	CK_ATTRIBUTE get_template[] = {
		{ CKA_TOKEN, &g_token, sizeof(CK_BBOOL) },
		{ CKA_PRIVATE, &g_private, sizeof(CK_BBOOL) },
		{ CKA_MODIFIABLE, &g_modify, sizeof(CK_BBOOL) },
		{ CKA_COPYABLE, &g_copy, sizeof(CK_BBOOL) },
		{ CKA_DESTROYABLE, &g_destroy, sizeof(CK_BBOOL) },
		{ CKA_EXTRACTABLE, &g_extract, sizeof(CK_BBOOL) },
		{ CKA_SENSITIVE, &g_sensitive, sizeof(CK_BBOOL) },
		{ CKA_NEVER_EXTRACTABLE, &g_nextract, sizeof(CK_BBOOL) },
		{ CKA_ALWAYS_SENSITIVE, &g_asensitive, sizeof(CK_BBOOL) },
		{ CKA_LOCAL, &g_local, sizeof(CK_BBOOL) },
	};
	CK_ATTRIBUTE get_value_template[] = {
		{ CKA_VALUE, &g_value, sizeof(g_value) }
	};
	CK_ATTRIBUTE copy_template[] = {
		{ CKA_TOKEN, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
		{ CKA_MODIFIABLE, &(CK_BBOOL){CK_FALSE}, sizeof(CK_BBOOL) },
		{ CKA_EXTRACTABLE, &(CK_BBOOL){CK_FALSE}, sizeof(CK_BBOOL) },
		{ CKA_SENSITIVE, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	};
	CK_ATTRIBUTE copy_template_inv[] = {
		{ CKA_APPLICATION, (CK_UTF8CHAR_PTR)label, sizeof(label) },
	};
	CK_ATTRIBUTE copy_template_priv[] = {
		{ CKA_PRIVATE, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	};
	CK_ATTRIBUTE set_template[] = {
		{ CKA_COPYABLE, &(CK_BBOOL){CK_FALSE}, sizeof(CK_BBOOL) },
	};

	rv = init_lib_and_find_token_slot(&slot);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		return;

	rv = init_test_token(slot);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto close_lib;

	rv = init_user_test_token(slot);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto close_lib;

	/* Open a RW session */
	rv = C_OpenSession(slot, rw_session_flags, NULL, 0, &rw_session);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto close_lib;

	/* Open a RO session */
	rv = C_OpenSession(slot, ro_session_flags, NULL, 0, &ro_session);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto close_session;

	/*
	 * All objects in this test are session objects hence released at
	 * session closure on test completion.
	 */

	/* Generate a secret key object in rw session */
	rv = C_GenerateKey(rw_session, &cktest_aes_keygen_mechanism,
			   secret_key_template,
			   ARRAY_SIZE(secret_key_template), &obj_hdl);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto close_session;

	/* Check its attribute values */
	rv = C_GetAttributeValue(rw_session, obj_hdl, get_template,
				 ARRAY_SIZE(get_template));
	if (!ADBG_EXPECT_CK_OK(c, rv) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_token, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_private, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_modify, ==, CK_TRUE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_copy, ==, CK_TRUE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_destroy, ==, CK_TRUE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_local, ==, CK_TRUE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_extract, ==, CK_TRUE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_nextract, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_sensitive, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_asensitive, ==, CK_FALSE))
		goto close_session;

	/* Check that we can get (secret) CKA_VALUE */
	get_value_template[0].ulValueLen = sizeof(g_value);
	rv = C_GetAttributeValue(rw_session, obj_hdl, get_value_template,
				 ARRAY_SIZE(get_value_template));
	if (!ADBG_EXPECT_CK_OK(c, rv) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, get_value_template[0].ulValueLen,
					  ==, sizeof(g_value)))
		goto close_session;

	/* Create a secret key object in ro session*/
	rv = C_CreateObject(ro_session, secret_key_create_template,
			    ARRAY_SIZE(secret_key_create_template), &obj_hdl_ro);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto close_session;

	/*
	 * Duplicate the object generated in RW session using C_GenerateKey() to
	 * another object. Pass Template as NULL and test the attributes of
	 * new created object.
	 */
	Do_ADBG_BeginSubCase(c, "Copy Local Obj with NULL Template");
	rv = C_CopyObject(rw_session, obj_hdl, NULL, 0, &obj_hdl_cp);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	/*
	 * Check its attribute values, should match the original object.
	 * CKA_LOCAL shall be TRUE even in copied object as original object
	 * was generated using C_GenerateKey()
	 */
	rv = C_GetAttributeValue(rw_session, obj_hdl_cp, get_template,
				 ARRAY_SIZE(get_template));
	if (!ADBG_EXPECT_CK_OK(c, rv) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_token, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_private, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_modify, ==, CK_TRUE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_copy, ==, CK_TRUE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_destroy, ==, CK_TRUE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_local, ==, CK_TRUE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_extract, ==, CK_TRUE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_nextract, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_sensitive, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_asensitive, ==, CK_FALSE))
		goto out;

	rv = C_DestroyObject(rw_session, obj_hdl_cp);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	obj_hdl_cp = CK_INVALID_HANDLE;

	Do_ADBG_EndSubCase(c, NULL);

	/*
	 * Duplicate the object generated in RO session using C_CreateObject()
	 * to another object. Pass Template as NULL and test the attributes of
	 * new created object.
	 */
	Do_ADBG_BeginSubCase(c, "Copy a non-local object with NULL Template");

	/* Copy ro session object */
	rv = C_CopyObject(ro_session, obj_hdl_ro, NULL, 0, &obj_hdl_cp);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	/*
	 * Check its attribute values, should match the original object.
	 * CKA_LOCAL shall be FALSE even in copied object as original object
	 * was generated using C_CreateObject()
	 */
	rv = C_GetAttributeValue(ro_session, obj_hdl_cp, get_template,
				 ARRAY_SIZE(get_template));
	if (!ADBG_EXPECT_CK_OK(c, rv) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_token, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_private, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_modify, ==, CK_TRUE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_copy, ==, CK_TRUE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_destroy, ==, CK_TRUE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_local, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_extract, ==, CK_TRUE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_nextract, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_sensitive, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_asensitive, ==, CK_FALSE))
		goto out;

	rv = C_DestroyObject(ro_session, obj_hdl_cp);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	obj_hdl_cp = CK_INVALID_HANDLE;

	Do_ADBG_EndSubCase(c, NULL);

	/*
	 * Test copying object with a valid template and check if attributes
	 * get modified as indicated in the template. Checks modification of
	 * attributes like CKA_TOKEN, CKA_MODIFIABLE which were not modifiable
	 * via C_SetAttributeValue(). Also modifies the CKA_SENSITIVE,
	 * CKA_EXTRACTABLE and checks corresponding values of RO attributes
	 * CKA_ALWAYS_SENSITIVE and CKA_NEVER_EXTRACTABLE.
	 */
	Do_ADBG_BeginSubCase(c, "Copy Object with Valid Template");

	/*
	 * Copy Session Object as a Token object
	 * Properties CKA_MODIFIABLE turned to FALSE
	 * CKA_EXTRACTABLE changed from TRUE to FALSE
	 * CKA_NEVER_EXTRACTABLE should be FALSE.
	 * CKA_SENSITIVE set to TRUE
	 * However CKA_ALWAYS_SENSITIVE should be FALSE
	 */
	rv = C_CopyObject(rw_session, obj_hdl, copy_template,
			  ARRAY_SIZE(copy_template), &obj_hdl_cp);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	/* Check the changed attribute values */
	rv = C_GetAttributeValue(rw_session, obj_hdl_cp, get_template,
				 ARRAY_SIZE(get_template));
	if (!ADBG_EXPECT_CK_OK(c, rv) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_token, ==, CK_TRUE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_modify, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_extract, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_nextract, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_sensitive, ==, CK_TRUE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_asensitive, ==, CK_FALSE))
		goto out;

	/* Check that we cannot anymore get (secret) CKA_VALUE */
	get_value_template[0].ulValueLen = sizeof(g_value);
	rv = C_GetAttributeValue(rw_session, obj_hdl_cp, get_value_template,
				 ARRAY_SIZE(get_value_template));
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_ATTRIBUTE_SENSITIVE, rv) ||
	    !(get_value_template[0].ulValueLen == CK_UNAVAILABLE_INFORMATION))
		goto close_session;

	/*
	 * The copied object has CKA_MODIFIABLE set to FALSE. Check if
	 * call to C_SetAttributeValue() returns CKR_ACTION_PROHIBITED
	 */
	rv = C_SetAttributeValue(rw_session, obj_hdl_cp, set_template,
				 ARRAY_SIZE(set_template));
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_ACTION_PROHIBITED, rv))
		goto out;

	rv = C_DestroyObject(rw_session, obj_hdl_cp);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	obj_hdl_cp = CK_INVALID_HANDLE;

	Do_ADBG_EndSubCase(c, NULL);

	/*
	 * Test changing the CKA_PRIVATE to TRUE when copying object.
	 * Fails when user is not logged in. Passes after user logs in
	 */
	Do_ADBG_BeginSubCase(c, "Copy Object as a Private Object");

	/* The first attempt will fail as user is not logged in */
	rv = C_CopyObject(rw_session, obj_hdl, copy_template_priv,
			  ARRAY_SIZE(copy_template_priv), &obj_hdl_cp);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_USER_NOT_LOGGED_IN, rv))
		goto out;

	/* Login to Test Token and repeat*/
	rv = C_Login(rw_session, CKU_USER, test_token_user_pin,
		     sizeof(test_token_user_pin));
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	/* Try copying a public object to a private object - should pass */
	rv = C_CopyObject(rw_session, obj_hdl, copy_template_priv,
			  ARRAY_SIZE(copy_template_priv), &obj_hdl_cp);
	if (!ADBG_EXPECT_CK_OK(c, rv)) {
		ADBG_EXPECT_CK_OK(c, C_Logout(rw_session));
		goto out;
	}

	if (!ADBG_EXPECT_CK_OK(c, C_Logout(rw_session)))
		goto out;

	Do_ADBG_EndSubCase(c, NULL);

	Do_ADBG_BeginSubCase(c, "Copy Object with Invalid Template");

	rv = C_CopyObject(rw_session, obj_hdl, copy_template_inv,
			  ARRAY_SIZE(copy_template_inv), &obj_hdl_cp);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_ATTRIBUTE_TYPE_INVALID, rv))
		goto out;

	Do_ADBG_EndSubCase(c, NULL);

	Do_ADBG_BeginSubCase(c, "Copy Object with COPYABLE false");

	rv = C_SetAttributeValue(rw_session, obj_hdl, set_template,
				 ARRAY_SIZE(set_template));
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	rv = C_CopyObject(rw_session, obj_hdl, copy_template,
			  ARRAY_SIZE(copy_template), &obj_hdl_cp);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_ACTION_PROHIBITED, rv))
		goto out;

	Do_ADBG_EndSubCase(c, NULL);

	Do_ADBG_BeginSubCase(c, "Copy session object to token in RO session");

	rv = C_CopyObject(ro_session, obj_hdl_ro, copy_template,
			  ARRAY_SIZE(copy_template), &obj_hdl_cp);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_SESSION_READ_ONLY, rv))
		goto out;

out:
	Do_ADBG_EndSubCase(c, NULL);

	/* Destroy any token objects which may have been created */
	destroy_persistent_objects(c, slot);

close_session:
	/* Closing session will also destroy all session objects */
	if (ro_session != CK_INVALID_HANDLE)
		ADBG_EXPECT_CK_OK(c, C_CloseSession(ro_session));

	ADBG_EXPECT_CK_OK(c, C_CloseSession(rw_session));

close_lib:
	ADBG_EXPECT_CK_OK(c, close_lib());
}
ADBG_CASE_DEFINE(pkcs11, 1015, xtest_pkcs11_test_1015,
		 "PKCS11: Test C_CopyObject()");

static void xtest_pkcs11_test_1016(ADBG_Case_t *c)
{
	CK_RV rv = CKR_GENERAL_ERROR;
	CK_SLOT_ID slot = 0;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_FLAGS session_flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	uint8_t buffer[64] = { 0 };
	size_t i = 0;

	rv = init_lib_and_find_token_slot(&slot);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		return;

	rv = init_test_token(slot);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto close_lib;

	rv = init_user_test_token(slot);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto close_lib;

	rv = C_OpenSession(slot, session_flags, NULL, 0, &session);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto close_lib;

	Do_ADBG_BeginSubCase(c, "Seed random bytes");

	memset(buffer, 0xCC, sizeof(buffer));

	rv = C_SeedRandom(session, buffer, sizeof(buffer));
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	Do_ADBG_EndSubCase(c, NULL);

	Do_ADBG_BeginSubCase(c, "Seed random bytes with zero length buffer");

	rv = C_SeedRandom(session, buffer, 0);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	rv = C_SeedRandom(session, NULL, 0);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	Do_ADBG_EndSubCase(c, NULL);

	Do_ADBG_BeginSubCase(c, "Generate random bytes");

	memset(buffer, 0xCC, sizeof(buffer));

	rv = C_GenerateRandom(session, buffer, 61);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	/* Verify that end of buffer is still 0xCC */
	for (i = 61; i < sizeof(buffer); i++)
		if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, buffer[i], ==, 0xCC))
			break;

	Do_ADBG_EndSubCase(c, NULL);

	Do_ADBG_BeginSubCase(c, "Generate random bytes with zero length buffer");

	memset(buffer, 0xCC, sizeof(buffer));

	rv = C_GenerateRandom(session, buffer, 0);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	/* Verify that whole buffer is still 0xCC */
	for (i = 0; i < sizeof(buffer); i++)
		if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, buffer[i], ==, 0xCC))
			break;

	rv = C_GenerateRandom(session, NULL, 0);
	ADBG_EXPECT_CK_OK(c, rv);

out:
	Do_ADBG_EndSubCase(c, NULL);

	ADBG_EXPECT_CK_OK(c, C_CloseSession(session));

close_lib:
	ADBG_EXPECT_CK_OK(c, close_lib());
}
ADBG_CASE_DEFINE(pkcs11, 1016, xtest_pkcs11_test_1016,
		 "PKCS11: Random number generator tests");

static CK_RV derive_sym_key(CK_SESSION_HANDLE session,
			    CK_OBJECT_HANDLE parent_key,
			    CK_MECHANISM_TYPE mechanism, size_t data_len,
			    CK_OBJECT_HANDLE_PTR derv_key_hdl, size_t key_len,
			    CK_OBJECT_CLASS key_class, CK_KEY_TYPE key_type,
			    CK_BBOOL sensitive, CK_BBOOL extble)
{
	CK_RV rv = CKR_GENERAL_ERROR;
	uint8_t buffer[512] = { 0 };
	uint8_t iv[16] = { 0 };
	CK_MECHANISM mech_derive = { 0 };
	CK_KEY_DERIVATION_STRING_DATA key_derv_param = { 0 };
	CK_AES_CBC_ENCRYPT_DATA_PARAMS aes_cbc_param = { };
	CK_ATTRIBUTE derived_key_template[] = {
		{ CKA_CLASS, &key_class, sizeof(key_class) },
		{ CKA_KEY_TYPE, &key_type, sizeof(key_type) },
		{ CKA_ENCRYPT, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
		{ CKA_DECRYPT, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
		{ CKA_SENSITIVE, &sensitive, sizeof(sensitive) },
		{ CKA_EXTRACTABLE, &extble, sizeof(extble) },
		{ CKA_VALUE_LEN, &key_len, sizeof(key_len) }
	};

	if (data_len > sizeof(buffer))
		return rv;

	switch (mechanism) {
	case CKM_AES_ECB_ENCRYPT_DATA:
		key_derv_param.pData = buffer;
		key_derv_param.ulLen = data_len;
		mech_derive.mechanism = mechanism;
		mech_derive.pParameter = &key_derv_param;
		mech_derive.ulParameterLen = sizeof(key_derv_param);
		break;
	case CKM_AES_CBC_ENCRYPT_DATA:
		memcpy(aes_cbc_param.iv, iv, 16);
		aes_cbc_param.pData = buffer;
		aes_cbc_param.length = data_len;
		mech_derive.mechanism = mechanism;
		mech_derive.pParameter = &aes_cbc_param;
		mech_derive.ulParameterLen = sizeof(aes_cbc_param);
		break;
	case CKM_AES_ECB:
		/* Not a derivation algorithm */
		mech_derive.mechanism = mechanism;
		mech_derive.pParameter = NULL;
		mech_derive.ulParameterLen = 0;
		break;
	default:
		return rv;
	}

	/* Don't use VALUE_LEN parameter if key_len passed is 0 */
	if (key_len)
		rv = C_DeriveKey(session, &mech_derive, parent_key,
				 derived_key_template,
				 ARRAY_SIZE(derived_key_template),
				 derv_key_hdl);
	else
		/* last attribute in template is the derived key size */
		rv = C_DeriveKey(session, &mech_derive, parent_key,
				 derived_key_template,
				 ARRAY_SIZE(derived_key_template) - 1,
				 derv_key_hdl);
	return rv;
}

static void xtest_pkcs11_test_1017(ADBG_Case_t *c)
{
	CK_RV rv = CKR_GENERAL_ERROR;
	CK_SLOT_ID slot = 0;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_FLAGS session_flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	CK_OBJECT_HANDLE derv_key_hdl = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE aes_key1 = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE aes_key2 = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE aes_key_enc = CK_INVALID_HANDLE;
	size_t data_len = 0;
	size_t key_len = 0;
	CK_BBOOL g_extract = CK_FALSE;
	CK_BBOOL g_sensitive = CK_FALSE;
	CK_BBOOL g_nextract = CK_FALSE;
	CK_BBOOL g_asensitive = CK_FALSE;
	CK_BBOOL g_local =  CK_FALSE;
	CK_OBJECT_CLASS g_class = CKO_VENDOR_DEFINED;
	CK_KEY_TYPE g_key_type = CKK_VENDOR_DEFINED;
	uint8_t g_val[516] = { 0 };
	CK_ULONG secret_len = 0;
	CK_ATTRIBUTE get_template[] = {
		{ CKA_CLASS, &g_class, sizeof(CK_OBJECT_CLASS) },
		{ CKA_KEY_TYPE,	&g_key_type, sizeof(CK_KEY_TYPE) },
		{ CKA_EXTRACTABLE, &g_extract, sizeof(CK_BBOOL) },
		{ CKA_SENSITIVE, &g_sensitive, sizeof(CK_BBOOL) },
		{ CKA_NEVER_EXTRACTABLE, &g_nextract, sizeof(CK_BBOOL) },
		{ CKA_ALWAYS_SENSITIVE, &g_asensitive, sizeof(CK_BBOOL) },
		{ CKA_LOCAL, &g_local, sizeof(CK_BBOOL) },
		{ CKA_VALUE_LEN, &secret_len, sizeof(secret_len) },
		/*
		 * CKA_VALUE should remain last attribute in template,
		 * in this test case as we check the length returned
		 * from last index of the get_template in this test.
		 */
		{ CKA_VALUE, g_val, sizeof(g_val) },
	};
	uint32_t idx = ARRAY_SIZE(get_template) - 1;
	CK_ATTRIBUTE parent_template1[] = {
		{ CKA_SENSITIVE, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
		{ CKA_EXTRACTABLE, &(CK_BBOOL){CK_FALSE}, sizeof(CK_BBOOL) },
		{ CKA_VALUE_LEN, &(CK_ULONG){16}, sizeof(CK_ULONG) },
		{ CKA_DERIVE, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	};
	CK_ATTRIBUTE parent_template2[] = {
		{ CKA_SENSITIVE, &(CK_BBOOL){CK_FALSE}, sizeof(CK_BBOOL) },
		{ CKA_EXTRACTABLE, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
		{ CKA_VALUE_LEN, &(CK_ULONG){16}, sizeof(CK_ULONG) },
		{ CKA_ENCRYPT, &(CK_BBOOL){CK_FALSE}, sizeof(CK_BBOOL) },
		{ CKA_DERIVE, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	};
	CK_ATTRIBUTE parent_template_wo_derive[] = {
		{ CKA_SENSITIVE, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
		{ CKA_EXTRACTABLE, &(CK_BBOOL){CK_FALSE}, sizeof(CK_BBOOL) },
		{ CKA_VALUE_LEN, &(CK_ULONG){16}, sizeof(CK_ULONG) },
	};
	CK_ATTRIBUTE parent_template_w_enc_der[] = {
		{ CKA_VALUE_LEN, &(CK_ULONG){16}, sizeof(CK_ULONG) },
		{ CKA_ENCRYPT, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
		{ CKA_DERIVE, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	};

	rv = init_lib_and_find_token_slot(&slot);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		return;

	rv = init_test_token(slot);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto close_lib;

	rv = init_user_test_token(slot);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto close_lib;

	rv = C_OpenSession(slot, session_flags, NULL, 0, &session);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto close_lib;

	/*
	 * Parent AES Key 1
	 * SENSITIVE = TRUE, EXTRACTABLE = FALSE
	 * ALWAYS_SENSITIVE = TRUE, NEVER_EXTRACTABLE = TRUE
	 */
	rv = C_GenerateKey(session, &cktest_aes_keygen_mechanism,
			   parent_template1, ARRAY_SIZE(parent_template1),
			   &aes_key1);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto close_session;

	/*
	 * Parent AES Key 2
	 * SENSITIVE = FALSE, EXTRACTABLE = TRUE
	 * ALWAYS_SENSITIVE = FALSE, NEVER_EXTRACTABLE = FALSE
	 */
	rv = C_GenerateKey(session, &cktest_aes_keygen_mechanism,
			   parent_template2, ARRAY_SIZE(parent_template2),
			   &aes_key2);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto close_session;

	Do_ADBG_BeginSubCase(c, "Derive Generic secret - AES-ECB Mechanism");

	/*
	 * Use AES key 1 as Parent key
	 * 1. VALUE_LEN attribute not given in derivation template. Length
	 * of key should be same as that of data length.
	 * 2. Derivation template has SENSITIVE = TRUE, EXTRACTABLE = FALSE
	 * Parent key has ALWAYS_SENSITIVE = TRUE, NEVER_EXTRACTABLE = TRUE
	 * So derived key, ALWAYS_SENSITIVE will be same as SENSITIVE and
	 * NEVER_EXTRACTABLE will be opposite of EXTRACTABLE
	 * 3. LOCAL should be false
	 */
	data_len = 512;
	key_len = 0;
	rv = derive_sym_key(session, aes_key1, CKM_AES_ECB_ENCRYPT_DATA,
			    data_len, &derv_key_hdl, key_len, CKO_SECRET_KEY,
			    CKK_GENERIC_SECRET, CK_TRUE, CK_FALSE);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	rv = C_GetAttributeValue(session, derv_key_hdl, get_template,
				 ARRAY_SIZE(get_template) - 1);
	if (!ADBG_EXPECT_CK_OK(c, rv) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, secret_len, ==, data_len) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_class, ==, CKO_SECRET_KEY) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_key_type, ==,
					  CKK_GENERIC_SECRET) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_local, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_sensitive, ==, CK_TRUE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_extract, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_asensitive, ==, CK_TRUE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_nextract, ==, CK_TRUE))
		goto out;

	rv = C_DestroyObject(session, derv_key_hdl);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	Do_ADBG_EndSubCase(c, NULL);

	Do_ADBG_BeginSubCase(c, "Derive AES key using AES-EBC");

	/*
	 * Use AES key 2 as Parent key
	 * 1. VALUE_LEN < DATA_LEN, Derived key should have VALUE_LEN key size
	 * 2. Derivation template has SENSITIVE = TRUE, EXTRACTABLE = FALSE
	 * Parent key has ALWAYS_SENSITIVE = FALSE, NEVER_EXTRACTABLE = FALSE
	 * So derived key, ALWAYS_SENSITIVE will be FALSE and
	 * NEVER_EXTRACTABLE will be FALSE
	 * 3. LOCAL should be false
	 */
	data_len = 32;
	key_len = 16;
	rv = derive_sym_key(session, aes_key2, CKM_AES_ECB_ENCRYPT_DATA,
			    data_len, &derv_key_hdl, key_len, CKO_SECRET_KEY,
			    CKK_AES, CK_TRUE, CK_FALSE);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	/* This being a SENSITIVE object, we can't get the VALUE */
	rv = C_GetAttributeValue(session, derv_key_hdl, get_template,
				 ARRAY_SIZE(get_template) - 1);
	if (!ADBG_EXPECT_CK_OK(c, rv) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, secret_len, ==, key_len) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_class, ==, CKO_SECRET_KEY) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_key_type, ==, CKK_AES) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_local, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_sensitive, ==, CK_TRUE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_extract, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_asensitive, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_nextract, ==, CK_FALSE))
		goto out;

	rv = C_DestroyObject(session, derv_key_hdl);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	Do_ADBG_EndSubCase(c, NULL);

	Do_ADBG_BeginSubCase(c, "Derive AES key using AES-CBC");

	/*
	 * Use AES key 1 as Parent key
	 * 1. VALUE_LEN = DATA_LEN, Derived key should have VALUE_LEN key size
	 * 2. Derivation template has SENSITIVE = FALSE, EXTRACTABLE = FALSE
	 * Parent key has ALWAYS_SENSITIVE = TRUE, NEVER_EXTRACTABLE = TRUE
	 * So derived key, ALWAYS_SENSITIVE will be same as SENSITIVE and
	 * NEVER_EXTRACTABLE will be opposite of EXTRACTABLE
	 * 3. LOCAL should be false
	 */
	data_len = 32;
	key_len = 32;
	rv = derive_sym_key(session, aes_key1, CKM_AES_CBC_ENCRYPT_DATA,
			    data_len, &derv_key_hdl, key_len, CKO_SECRET_KEY,
			    CKK_AES, CK_FALSE, CK_FALSE);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	rv = C_GetAttributeValue(session, derv_key_hdl, get_template,
				 ARRAY_SIZE(get_template) - 1);
	if (!ADBG_EXPECT_CK_OK(c, rv) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, secret_len, ==, key_len) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_class, ==, CKO_SECRET_KEY) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_key_type, ==, CKK_AES) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_local, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_sensitive, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_extract, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_asensitive, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_nextract, ==, CK_TRUE))
		goto out;

	rv = C_DestroyObject(session, derv_key_hdl);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	Do_ADBG_EndSubCase(c, NULL);

	Do_ADBG_BeginSubCase(c, "Derive Generic secret key using AES-CBC");
	/*
	 * Use AES key 2 as Parent key
	 * 1. VALUE_LEN < DATA_LEN, Derived key should have VALUE_LEN key size
	 * 2. Derivation template has SENSITIVE = FALSE, EXTRACTABLE = TRUE
	 * Parent key has ALWAYS_SENSITIVE = TRUE, NEVER_EXTRACTABLE = TRUE
	 * So derived key, ALWAYS_SENSITIVE will be same as SENSITIVE and
	 * NEVER_EXTRACTABLE will be opposite of EXTRACTABLE
	 * 3. LOCAL should be false
	 */
	data_len = 512;
	key_len = 256;
	rv = derive_sym_key(session, aes_key2, CKM_AES_CBC_ENCRYPT_DATA,
			    data_len, &derv_key_hdl, key_len, CKO_SECRET_KEY,
			    CKK_GENERIC_SECRET, CK_FALSE, CK_TRUE);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	rv = C_GetAttributeValue(session, derv_key_hdl, get_template,
				 ARRAY_SIZE(get_template));
	if (!ADBG_EXPECT_CK_OK(c, rv) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, get_template[idx].ulValueLen, ==,
					  key_len) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, secret_len, ==, key_len) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_class, ==, CKO_SECRET_KEY) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_key_type, ==,
					  CKK_GENERIC_SECRET) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_local, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_sensitive, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_extract, ==, CK_TRUE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_asensitive, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_nextract, ==, CK_FALSE))
		goto out;

	rv = C_DestroyObject(session, derv_key_hdl);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	Do_ADBG_EndSubCase(c, NULL);

	Do_ADBG_BeginSubCase(c, "Invalid parameters during derivation");

	/* Length of data used for derivation < key length */
	data_len = 16;
	key_len = 32;
	rv = derive_sym_key(session, aes_key1, CKM_AES_ECB_ENCRYPT_DATA,
			    data_len, &derv_key_hdl, key_len, CKO_SECRET_KEY,
			    CKK_AES, CK_FALSE, CK_TRUE);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_DATA_LEN_RANGE, rv))
		goto out;

	/* Data is not multiple of 16 */
	data_len = 18;
	key_len = 32;
	rv = derive_sym_key(session, aes_key1, CKM_AES_ECB_ENCRYPT_DATA,
			    data_len, &derv_key_hdl, key_len, CKO_SECRET_KEY,
			    CKK_AES, CK_FALSE, CK_TRUE);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_DATA_LEN_RANGE, rv))
		goto out;

	/* Wrong Mechanism */
	rv = derive_sym_key(session, aes_key1, CKM_AES_ECB,
			    data_len, &derv_key_hdl, key_len, CKO_SECRET_KEY,
			    CKK_AES, CK_FALSE, CK_TRUE);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_MECHANISM_INVALID, rv))
		goto out;

	Do_ADBG_EndSubCase(c, NULL);

	Do_ADBG_BeginSubCase(c, "Failure if operation already active");

	/* Generate an AES key which can perform Encryption */
	rv = C_GenerateKey(session, &cktest_aes_keygen_mechanism,
			   parent_template_w_enc_der,
			   ARRAY_SIZE(parent_template_w_enc_der),
			   &aes_key_enc);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	rv = C_EncryptInit(session, &cktest_aes_cbc_mechanism, aes_key_enc);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	/*
	 * Initializing the encryption operation again should not alter or
	 * terminate already started operation.
	 */
	rv = C_EncryptInit(session, &cktest_aes_cbc_mechanism, aes_key_enc);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_OPERATION_ACTIVE, rv))
		goto out;

	data_len = 32;
	key_len = 32;
	rv = derive_sym_key(session, aes_key2, CKM_AES_ECB_ENCRYPT_DATA,
			    data_len, &derv_key_hdl, key_len, CKO_SECRET_KEY,
			    CKK_AES, CK_FALSE, CK_TRUE);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_OPERATION_ACTIVE, rv))
		goto out;

	rv = C_EncryptFinal(session, NULL, NULL);
	/* Only check that the operation is no more active */
	if (!ADBG_EXPECT_TRUE(c, rv != CKR_BUFFER_TOO_SMALL))
		goto out;

	Do_ADBG_EndSubCase(c, NULL);

	Do_ADBG_BeginSubCase(c, "Failure if parent key CKA_ENCRYPT is TRUE");

	data_len = 32;
	key_len = 32;
	rv = derive_sym_key(session, aes_key_enc, CKM_AES_ECB_ENCRYPT_DATA,
			    data_len, &derv_key_hdl, key_len, CKO_SECRET_KEY,
			    CKK_AES, CK_FALSE, CK_TRUE);
	/*
	 * Not strictly expecting FUNCTION_FAILED but expecting a failure
	 * as we have added a restriction that keys with attribute CKA_ENCRYPT
	 * set can't be used for derivation.
	 */
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_FUNCTION_FAILED, rv))
		goto out;

	Do_ADBG_EndSubCase(c, NULL);

	Do_ADBG_BeginSubCase(c, "Failure if parent key CKA_DERIVE is FALSE");

	rv = C_DestroyObject(session, aes_key1);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	rv = C_GenerateKey(session, &cktest_aes_keygen_mechanism,
			   parent_template_wo_derive,
			   ARRAY_SIZE(parent_template_wo_derive),
			   &aes_key1);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	data_len = 32;
	key_len = 32;
	rv = derive_sym_key(session, aes_key1, CKM_AES_ECB_ENCRYPT_DATA,
			    data_len, &derv_key_hdl, key_len, CKO_SECRET_KEY,
			    CKK_AES, CK_FALSE, CK_TRUE);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_KEY_TYPE_INCONSISTENT, rv))
		goto out;

out:
	Do_ADBG_EndSubCase(c, NULL);

close_session:
	ADBG_EXPECT_CK_OK(c, C_CloseSession(session));

close_lib:
	ADBG_EXPECT_CK_OK(c, close_lib());
}
ADBG_CASE_DEFINE(pkcs11, 1017, xtest_pkcs11_test_1017,
		 "PKCS11: AES Key Derivation tests");

/* Digest test patterns */
static const char digest_test_pattern[] = "The quick brown fox jumps over the lazy dog";
static const char digest_test_pattern_empty[] = "";

/* MD5 checksums for digest test patterns */
static const uint8_t digest_test_pattern_md5[] = {
	0x9e, 0x10, 0x7d, 0x9d, 0x37, 0x2b, 0xb6, 0x82, 0x6b, 0xd8, 0x1d, 0x35,
	0x42, 0xa4, 0x19, 0xd6
};
static const uint8_t digest_test_pattern_empty_md5[] = {
	0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9, 0x80, 0x09, 0x98,
	0xec, 0xf8, 0x42, 0x7e
};

/* SHA-1 checksums for digest test patterns */
static const uint8_t digest_test_pattern_sha1[] = {
	0x2f, 0xd4, 0xe1, 0xc6, 0x7a, 0x2d, 0x28, 0xfc, 0xed, 0x84, 0x9e, 0xe1,
	0xbb, 0x76, 0xe7, 0x39, 0x1b, 0x93, 0xeb, 0x12
};
static const uint8_t digest_test_pattern_empty_sha1[] = {
	0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef,
	0x95, 0x60, 0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09
};

/* SHA-224 checksums for digest test patterns */
static const uint8_t digest_test_pattern_sha224[] = {
	0x73, 0x0e, 0x10, 0x9b, 0xd7, 0xa8, 0xa3, 0x2b, 0x1c, 0xb9, 0xd9, 0xa0,
	0x9a, 0xa2, 0x32, 0x5d, 0x24, 0x30, 0x58, 0x7d, 0xdb, 0xc0, 0xc3, 0x8b,
	0xad, 0x91, 0x15, 0x25
};
static const uint8_t digest_test_pattern_empty_sha224[] = {
	0xd1, 0x4a, 0x02, 0x8c, 0x2a, 0x3a, 0x2b, 0xc9, 0x47, 0x61, 0x02, 0xbb,
	0x28, 0x82, 0x34, 0xc4, 0x15, 0xa2, 0xb0, 0x1f, 0x82, 0x8e, 0xa6, 0x2a,
	0xc5, 0xb3, 0xe4, 0x2f
};

/* SHA-256 checksums for digest test patterns */
static const uint8_t digest_test_pattern_sha256[] = {
	0xd7, 0xa8, 0xfb, 0xb3, 0x07, 0xd7, 0x80, 0x94, 0x69, 0xca, 0x9a, 0xbc,
	0xb0, 0x08, 0x2e, 0x4f, 0x8d, 0x56, 0x51, 0xe4, 0x6d, 0x3c, 0xdb, 0x76,
	0x2d, 0x02, 0xd0, 0xbf, 0x37, 0xc9, 0xe5, 0x92
};
static const uint8_t digest_test_pattern_empty_sha256[] = {
	0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8,
	0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
	0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
};

/* SHA-384 checksums for digest test patterns */
static const uint8_t digest_test_pattern_sha384[] = {
	0xca, 0x73, 0x7f, 0x10, 0x14, 0xa4, 0x8f, 0x4c, 0x0b, 0x6d, 0xd4, 0x3c,
	0xb1, 0x77, 0xb0, 0xaf, 0xd9, 0xe5, 0x16, 0x93, 0x67, 0x54, 0x4c, 0x49,
	0x40, 0x11, 0xe3, 0x31, 0x7d, 0xbf, 0x9a, 0x50, 0x9c, 0xb1, 0xe5, 0xdc,
	0x1e, 0x85, 0xa9, 0x41, 0xbb, 0xee, 0x3d, 0x7f, 0x2a, 0xfb, 0xc9, 0xb1
};
static const uint8_t digest_test_pattern_empty_sha384[] = {
	0x38, 0xb0, 0x60, 0xa7, 0x51, 0xac, 0x96, 0x38, 0x4c, 0xd9, 0x32, 0x7e,
	0xb1, 0xb1, 0xe3, 0x6a, 0x21, 0xfd, 0xb7, 0x11, 0x14, 0xbe, 0x07, 0x43,
	0x4c, 0x0c, 0xc7, 0xbf, 0x63, 0xf6, 0xe1, 0xda, 0x27, 0x4e, 0xde, 0xbf,
	0xe7, 0x6f, 0x65, 0xfb, 0xd5, 0x1a, 0xd2, 0xf1, 0x48, 0x98, 0xb9, 0x5b
};

/* SHA-512 checksums for digest test patterns */
static const uint8_t digest_test_pattern_sha512[] = {
	0x07, 0xe5, 0x47, 0xd9, 0x58, 0x6f, 0x6a, 0x73, 0xf7, 0x3f, 0xba, 0xc0,
	0x43, 0x5e, 0xd7, 0x69, 0x51, 0x21, 0x8f, 0xb7, 0xd0, 0xc8, 0xd7, 0x88,
	0xa3, 0x09, 0xd7, 0x85, 0x43, 0x6b, 0xbb, 0x64, 0x2e, 0x93, 0xa2, 0x52,
	0xa9, 0x54, 0xf2, 0x39, 0x12, 0x54, 0x7d, 0x1e, 0x8a, 0x3b, 0x5e, 0xd6,
	0xe1, 0xbf, 0xd7, 0x09, 0x78, 0x21, 0x23, 0x3f, 0xa0, 0x53, 0x8f, 0x3d,
	0xb8, 0x54, 0xfe, 0xe6
};
static const uint8_t digest_test_pattern_empty_sha512[] = {
	0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd, 0xf1, 0x54, 0x28, 0x50,
	0xd6, 0x6d, 0x80, 0x07, 0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc,
	0x83, 0xf4, 0xa9, 0x21, 0xd3, 0x6c, 0xe9, 0xce, 0x47, 0xd0, 0xd1, 0x3c,
	0x5d, 0x85, 0xf2, 0xb0, 0xff, 0x83, 0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f,
	0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81, 0xa5, 0x38, 0x32, 0x7a,
	0xf9, 0x27, 0xda, 0x3e
};

#define DIGEST_TEST(_test_name, _mecha, _data, _digest) \
	{ \
		.test_name = _test_name, \
		.mecha = _mecha, \
		.data = _data, \
		.data_size = sizeof(_data) - 1, \
		.digest = _digest, \
		.digest_size = sizeof(_digest) \
	}

/* Digest simple test suite */
static struct {
	const char *test_name;
	CK_MECHANISM_TYPE mecha;
	const void *data;
	CK_ULONG data_size;
	const uint8_t *digest;
	CK_ULONG digest_size;
} digest_test_patterns[] = {
	DIGEST_TEST("CKM_MD5/empty", CKM_MD5, digest_test_pattern_empty,
		    digest_test_pattern_empty_md5),
	DIGEST_TEST("CKM_MD5/test pattern", CKM_MD5, digest_test_pattern,
		    digest_test_pattern_md5),
	DIGEST_TEST("CKM_SHA_1/empty", CKM_SHA_1, digest_test_pattern_empty,
		    digest_test_pattern_empty_sha1),
	DIGEST_TEST("CKM_SHA_1/test pattern", CKM_SHA_1, digest_test_pattern,
		    digest_test_pattern_sha1),
	DIGEST_TEST("CKM_SHA224/empty", CKM_SHA224, digest_test_pattern_empty,
		    digest_test_pattern_empty_sha224),
	DIGEST_TEST("CKM_SHA224/test pattern", CKM_SHA224, digest_test_pattern,
		    digest_test_pattern_sha224),
	DIGEST_TEST("CKM_SHA256/empty", CKM_SHA256, digest_test_pattern_empty,
		    digest_test_pattern_empty_sha256),
	DIGEST_TEST("CKM_SHA256/test pattern", CKM_SHA256, digest_test_pattern,
		    digest_test_pattern_sha256),
	DIGEST_TEST("CKM_SHA384/empty", CKM_SHA384, digest_test_pattern_empty,
		    digest_test_pattern_empty_sha384),
	DIGEST_TEST("CKM_SHA384/test pattern", CKM_SHA384, digest_test_pattern,
		    digest_test_pattern_sha384),
	DIGEST_TEST("CKM_SHA512/empty", CKM_SHA512, digest_test_pattern_empty,
		    digest_test_pattern_empty_sha512),
	DIGEST_TEST("CKM_SHA512/test pattern", CKM_SHA512, digest_test_pattern,
		    digest_test_pattern_sha512),
};

static CK_ATTRIBUTE digest_generate_aes_object[] = {
	{ CKA_CLASS, &(CK_OBJECT_CLASS){ CKO_SECRET_KEY },
	  sizeof(CK_OBJECT_CLASS) },
	{ CKA_KEY_TYPE, &(CK_KEY_TYPE){ CKK_AES }, sizeof(CK_KEY_TYPE) },
	{ CKA_TOKEN, &(CK_BBOOL){ CK_FALSE }, sizeof(CK_BBOOL) },
	{ CKA_PRIVATE, &(CK_BBOOL){ CK_FALSE }, sizeof(CK_BBOOL) },
	{ CKA_SENSITIVE, &(CK_BBOOL){ CK_FALSE }, sizeof(CK_BBOOL) },
	{ CKA_EXTRACTABLE, &(CK_BBOOL){ CK_TRUE }, sizeof(CK_BBOOL) },
	{ CKA_VALUE_LEN, &(CK_ULONG){ 16 }, sizeof(CK_ULONG) },
};

static CK_ATTRIBUTE digest_generate_gensecret_object[] = {
	{ CKA_CLASS, &(CK_OBJECT_CLASS){ CKO_SECRET_KEY },
	  sizeof(CK_OBJECT_CLASS) },
	{ CKA_KEY_TYPE, &(CK_KEY_TYPE){ CKK_GENERIC_SECRET },
	  sizeof(CK_KEY_TYPE) },
	{ CKA_TOKEN, &(CK_BBOOL){ CK_FALSE }, sizeof(CK_BBOOL) },
	{ CKA_PRIVATE, &(CK_BBOOL){ CK_FALSE }, sizeof(CK_BBOOL) },
	{ CKA_SENSITIVE, &(CK_BBOOL){ CK_FALSE }, sizeof(CK_BBOOL) },
	{ CKA_EXTRACTABLE, &(CK_BBOOL){ CK_TRUE }, sizeof(CK_BBOOL) },
	{ CKA_VALUE_LEN, &(CK_ULONG){ 32 }, sizeof(CK_ULONG) },
};

static CK_ATTRIBUTE digest_data_object[] = {
	{ CKA_CLASS, &(CK_OBJECT_CLASS){ CKO_DATA },
	  sizeof(CK_OBJECT_CLASS) },
	{ CKA_TOKEN, &(CK_BBOOL){ CK_FALSE }, sizeof(CK_BBOOL) },
	{ CKA_PRIVATE, &(CK_BBOOL){ CK_FALSE }, sizeof(CK_BBOOL) },
};

static void xtest_pkcs11_test_1018(ADBG_Case_t *c)
{
	CK_RV rv = CKR_GENERAL_ERROR;
	CK_SLOT_ID slot = 0;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_FLAGS session_flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	bool logged_in = false;
	uint8_t data[128] = { 0 };
	CK_ULONG data_size = 0;
	uint8_t digest[64] = { 0 };
	CK_ULONG digest_size = 0;
	const uint8_t *expect_digest = NULL;
	CK_ULONG expect_digest_size = 0;
	CK_MECHANISM mechanism = { CKM_MD5, NULL, 0 };
	uint8_t secret_data[128] = { 0 };
	CK_ULONG secret_data_size __maybe_unused = 0;
	CK_ATTRIBUTE digest_get_secret_value[] = {
		{ CKA_VALUE, &secret_data, sizeof(secret_data) },
	};
	CK_OBJECT_HANDLE key_handle = CK_INVALID_HANDLE;
#ifdef OPENSSL_FOUND
	EVP_MD_CTX *mdctx = NULL;
	unsigned char hash[EVP_MAX_MD_SIZE] = { 0 };
	unsigned int md_len = 0;
	int ret = 0;
#endif
	size_t i = 0;

	rv = init_lib_and_find_token_slot(&slot);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		return;

	rv = init_test_token(slot);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto close_lib;

	rv = init_user_test_token(slot);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto close_lib;

	rv = C_OpenSession(slot, session_flags, NULL, 0, &session);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto close_lib;

	/* Test out simple successful cases with init+update+final*/
	for (i = 0; i < ARRAY_SIZE(digest_test_patterns); i++) {
		Do_ADBG_BeginSubCase(c, "Simple digest tests - update - %s",
				     digest_test_patterns[i].test_name);

		mechanism.mechanism = digest_test_patterns[i].mecha;
		memset(data, 0xCC, sizeof(data));
		memset(digest, 0xCC, sizeof(digest));
		digest_size = sizeof(digest);

		memcpy(data, digest_test_patterns[i].data,
		       digest_test_patterns[i].data_size);
		data_size = digest_test_patterns[i].data_size;

		expect_digest = digest_test_patterns[i].digest;
		expect_digest_size = digest_test_patterns[i].digest_size;

		rv = C_DigestInit(session, &mechanism);
		if (!ADBG_EXPECT_CK_OK(c, rv))
			goto out;

		rv = C_DigestUpdate(session, data, data_size);
		if (!ADBG_EXPECT_CK_OK(c, rv))
			goto out;

		rv = C_DigestFinal(session, digest, &digest_size);
		if (!ADBG_EXPECT_CK_OK(c, rv))
			goto out;

		if (!ADBG_EXPECT_BUFFER(c, expect_digest, expect_digest_size,
					digest,	digest_size))
			goto out;

		/* Verify that end of buffer is still 0xCC */
		for (i = expect_digest_size; i < sizeof(digest); i++)
			if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, digest[i], ==,
							  0xCC))
				goto out;

		Do_ADBG_EndSubCase(c, NULL);
	}

	/* Test out simple successful cases */
	for (i = 0; i < ARRAY_SIZE(digest_test_patterns); i++) {
		Do_ADBG_BeginSubCase(c, "Simple digest tests - oneshot - %s",
				     digest_test_patterns[i].test_name);

		mechanism.mechanism = digest_test_patterns[i].mecha;
		memset(data, 0xCC, sizeof(data));
		memset(digest, 0xCC, sizeof(digest));
		digest_size = sizeof(digest);

		memcpy(data, digest_test_patterns[i].data,
		       digest_test_patterns[i].data_size);
		data_size = digest_test_patterns[i].data_size;

		expect_digest = digest_test_patterns[i].digest;
		expect_digest_size = digest_test_patterns[i].digest_size;

		rv = C_DigestInit(session, &mechanism);
		if (!ADBG_EXPECT_CK_OK(c, rv))
			goto out;

		rv = C_Digest(session, data, data_size, digest, &digest_size);
		if (!ADBG_EXPECT_CK_OK(c, rv))
			goto out;

		if (!ADBG_EXPECT_BUFFER(c, expect_digest, expect_digest_size,
					digest,	digest_size))
			goto out;

		/* Verify that end of buffer is still 0xCC */
		for (i = expect_digest_size; i < sizeof(digest); i++)
			if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, digest[i], ==,
							  0xCC))
				goto out;

		Do_ADBG_EndSubCase(c, NULL);
	}

	/* Test out key updates */

	Do_ADBG_BeginSubCase(c, "Simple digest tests - AES key update - SHA-256");

	/* Login to Test Token */
	rv = C_Login(session, CKU_USER,	test_token_user_pin,
		     sizeof(test_token_user_pin));
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	logged_in = true;

	/* Generate AES key */
	rv = C_GenerateKey(session, &cktest_aes_keygen_mechanism,
			   digest_generate_aes_object,
			   ARRAY_SIZE(digest_generate_aes_object),
			   &key_handle);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	memset(secret_data, 0xCC, sizeof(data));
	digest_get_secret_value[0].ulValueLen = sizeof(secret_data);

	/* Get value of generated secret for verification purposes */
	rv = C_GetAttributeValue(session, key_handle, digest_get_secret_value,
				 ARRAY_SIZE(digest_get_secret_value));
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	secret_data_size = digest_get_secret_value[0].ulValueLen;

	/* Calculate digest with PKCS11 */
	mechanism.mechanism = CKM_SHA256;

	memset(data, 0xCC, sizeof(data));
	memset(digest, 0xCC, sizeof(digest));
	digest_size = sizeof(digest);

	memcpy(data, digest_test_patterns[0].data,
	       digest_test_patterns[0].data_size);
	data_size = digest_test_patterns[0].data_size;

	rv = C_DigestInit(session, &mechanism);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	rv = C_DigestUpdate(session, data, data_size);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	rv = C_DigestKey(session, key_handle);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	rv = C_DigestFinal(session, digest, &digest_size);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	/* Verify digest with openssl */
#ifdef OPENSSL_FOUND
	mdctx = EVP_MD_CTX_create();
	if (!ADBG_EXPECT_NOT_NULL(c, mdctx))
		goto out;
	ret = EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
	if (!ADBG_EXPECT_COMPARE_SIGNED(c, ret, ==, 1))
		goto out;
	ret = EVP_DigestUpdate(mdctx, data, data_size);
	if (!ADBG_EXPECT_COMPARE_SIGNED(c, ret, ==, 1))
		goto out;
	ret = EVP_DigestUpdate(mdctx, secret_data, secret_data_size);
	if (!ADBG_EXPECT_COMPARE_SIGNED(c, ret, ==, 1))
		goto out;
	ret = EVP_DigestFinal_ex(mdctx, hash, &md_len);
	if (!ADBG_EXPECT_COMPARE_SIGNED(c, ret, ==, 1))
		goto out;
	EVP_MD_CTX_destroy(mdctx);
	mdctx = NULL;

	if (!ADBG_EXPECT_BUFFER(c, hash, md_len, digest, digest_size))
		goto out;
#else
	Do_ADBG_Log("OpenSSL not available, skipping C_DigestKey verification");
#endif

	ADBG_EXPECT_CK_OK(c, C_DestroyObject(session, key_handle));
	key_handle = CK_INVALID_HANDLE;

	Do_ADBG_EndSubCase(c, NULL);

	Do_ADBG_BeginSubCase(c, "Simple digest tests - generic secret key update - SHA-256");

	/* Generate generic secret key */
	rv = C_GenerateKey(session, &cktest_gensecret_keygen_mechanism,
			   digest_generate_gensecret_object,
			   ARRAY_SIZE(digest_generate_gensecret_object),
			   &key_handle);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	memset(secret_data, 0xCC, sizeof(data));
	digest_get_secret_value[0].ulValueLen = sizeof(secret_data);

	/* Get value of generated secret for verification purposes */
	rv = C_GetAttributeValue(session, key_handle, digest_get_secret_value,
				 ARRAY_SIZE(digest_get_secret_value));
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	secret_data_size = digest_get_secret_value[0].ulValueLen;

	/* Calculate digest with PKCS11 */
	mechanism.mechanism = CKM_SHA256;

	memset(data, 0xCC, sizeof(data));
	memset(digest, 0xCC, sizeof(digest));
	digest_size = sizeof(digest);

	memcpy(data, digest_test_patterns[0].data,
	       digest_test_patterns[0].data_size);
	data_size = digest_test_patterns[0].data_size;

	rv = C_DigestInit(session, &mechanism);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	rv = C_DigestUpdate(session, data, data_size);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	rv = C_DigestKey(session, key_handle);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	rv = C_DigestFinal(session, digest, &digest_size);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	/* Verify digest with openssl */
#ifdef OPENSSL_FOUND
	mdctx = EVP_MD_CTX_create();
	if (!ADBG_EXPECT_NOT_NULL(c, mdctx))
		goto out;
	ret = EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
	if (!ADBG_EXPECT_COMPARE_SIGNED(c, ret, ==, 1))
		goto out;
	ret = EVP_DigestUpdate(mdctx, data, data_size);
	if (!ADBG_EXPECT_COMPARE_SIGNED(c, ret, ==, 1))
		goto out;
	ret = EVP_DigestUpdate(mdctx, secret_data, secret_data_size);
	if (!ADBG_EXPECT_COMPARE_SIGNED(c, ret, ==, 1))
		goto out;
	ret = EVP_DigestFinal_ex(mdctx, hash, &md_len);
	if (!ADBG_EXPECT_COMPARE_SIGNED(c, ret, ==, 1))
		goto out;
	EVP_MD_CTX_destroy(mdctx);
	mdctx = NULL;

	if (!ADBG_EXPECT_BUFFER(c, hash, md_len, digest, digest_size))
		goto out;
#else
	Do_ADBG_Log("OpenSSL not available, skipping C_DigestKey verification");
#endif

	ADBG_EXPECT_CK_OK(c, C_DestroyObject(session, key_handle));
	key_handle = CK_INVALID_HANDLE;

	Do_ADBG_EndSubCase(c, NULL);

	Do_ADBG_BeginSubCase(c, "Query digest size - C_DigestFinal");

	mechanism.mechanism = digest_test_patterns[0].mecha;

	memset(data, 0xCC, sizeof(data));
	memset(digest, 0xCC, sizeof(digest));
	digest_size = 0;

	memcpy(data, digest_test_patterns[0].data,
	       digest_test_patterns[0].data_size);
	data_size = digest_test_patterns[0].data_size;

	expect_digest = digest_test_patterns[0].digest;
	expect_digest_size = digest_test_patterns[0].digest_size;

	rv = C_DigestInit(session, &mechanism);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	rv = C_DigestUpdate(session, data, data_size);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	rv = C_DigestFinal(session, NULL, &digest_size);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, digest_size, ==,
					  expect_digest_size))
		goto out;

	rv = C_DigestFinal(session, digest, &digest_size);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	if (!ADBG_EXPECT_BUFFER(c, expect_digest, expect_digest_size,
				digest,	digest_size))
		goto out;

	Do_ADBG_EndSubCase(c, NULL);

	Do_ADBG_BeginSubCase(c, "Query digest size - C_Digest");

	mechanism.mechanism = digest_test_patterns[0].mecha;

	memset(data, 0xCC, sizeof(data));
	memset(digest, 0xCC, sizeof(digest));
	digest_size = 0;

	memcpy(data, digest_test_patterns[0].data,
	       digest_test_patterns[0].data_size);
	data_size = digest_test_patterns[0].data_size;

	expect_digest = digest_test_patterns[0].digest;
	expect_digest_size = digest_test_patterns[0].digest_size;

	rv = C_DigestInit(session, &mechanism);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	rv = C_Digest(session, data, data_size, NULL, &digest_size);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, digest_size, ==,
					  expect_digest_size))
		goto out;

	rv = C_Digest(session, data, data_size, digest, &digest_size);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	if (!ADBG_EXPECT_BUFFER(c, expect_digest, expect_digest_size,
				digest,	digest_size))
		goto out;

	Do_ADBG_EndSubCase(c, NULL);

	Do_ADBG_BeginSubCase(c, "Query digest size - buffer too small");

	mechanism.mechanism = CKM_SHA256;

	memset(data, 0xCC, sizeof(data));
	memset(digest, 0xCC, sizeof(digest));
	digest_size = 0;

	memcpy(data, digest_test_patterns[0].data,
	       digest_test_patterns[0].data_size);
	data_size = digest_test_patterns[0].data_size;

	rv = C_DigestInit(session, &mechanism);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	rv = C_DigestUpdate(session, data, data_size);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	rv = C_DigestFinal(session, digest, &digest_size);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_BUFFER_TOO_SMALL, rv))
		goto out;

	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, digest_size, ==, 32))
		goto out;

	rv = C_DigestFinal(session, digest, &digest_size);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	Do_ADBG_EndSubCase(c, NULL);

	/* Test bad arguments & operation terminations */

	Do_ADBG_BeginSubCase(c, "Test bad arguments - C_DigestUpdate");

	mechanism.mechanism = CKM_SHA256;

	memset(data, 0xCC, sizeof(data));
	memset(digest, 0xCC, sizeof(digest));
	digest_size = sizeof(digest);

	memcpy(data, digest_test_patterns[0].data,
	       digest_test_patterns[0].data_size);
	data_size = digest_test_patterns[0].data_size;

	rv = C_DigestInit(session, &mechanism);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	rv = C_DigestUpdate(session, NULL, 10);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_ARGUMENTS_BAD, rv))
		goto out;

	rv = C_DigestUpdate(session, data, data_size);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_OPERATION_NOT_INITIALIZED, rv))
		goto out;

	Do_ADBG_EndSubCase(c, NULL);

	Do_ADBG_BeginSubCase(c, "Test bad arguments - C_DigestFinal with NULL digest");

	mechanism.mechanism = CKM_SHA256;

	memset(data, 0xCC, sizeof(data));
	memset(digest, 0xCC, sizeof(digest));
	digest_size = sizeof(digest);

	memcpy(data, digest_test_patterns[0].data,
	       digest_test_patterns[0].data_size);
	data_size = digest_test_patterns[0].data_size;

	rv = C_DigestInit(session, &mechanism);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	rv = C_DigestUpdate(session, data, data_size);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	rv = C_DigestFinal(session, NULL, NULL);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_ARGUMENTS_BAD, rv))
		goto out;

	rv = C_DigestFinal(session, digest, &digest_size);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_OPERATION_NOT_INITIALIZED, rv))
		goto out;

	Do_ADBG_EndSubCase(c, NULL);

	Do_ADBG_BeginSubCase(c, "Test bad arguments - C_DigestFinal with digest but NULL size");

	mechanism.mechanism = CKM_SHA256;

	memset(data, 0xCC, sizeof(data));
	memset(digest, 0xCC, sizeof(digest));
	digest_size = sizeof(digest);

	memcpy(data, digest_test_patterns[0].data,
	       digest_test_patterns[0].data_size);
	data_size = digest_test_patterns[0].data_size;

	rv = C_DigestInit(session, &mechanism);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	rv = C_DigestUpdate(session, data, data_size);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	rv = C_DigestFinal(session, digest, NULL);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_ARGUMENTS_BAD, rv))
		goto out;

	rv = C_DigestFinal(session, digest, &digest_size);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_OPERATION_NOT_INITIALIZED, rv))
		goto out;

	Do_ADBG_EndSubCase(c, NULL);

	Do_ADBG_BeginSubCase(c, "Test bad arguments - C_Digest with NULL data but non-zero size");

	mechanism.mechanism = CKM_SHA256;

	memset(data, 0xCC, sizeof(data));
	memset(digest, 0xCC, sizeof(digest));
	digest_size = sizeof(digest);

	memcpy(data, digest_test_patterns[0].data,
	       digest_test_patterns[0].data_size);
	data_size = digest_test_patterns[0].data_size;

	rv = C_DigestInit(session, &mechanism);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	rv = C_Digest(session, NULL, 10, digest, &digest_size);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_ARGUMENTS_BAD, rv))
		goto out;

	rv = C_Digest(session, data, data_size, digest, &digest_size);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_OPERATION_NOT_INITIALIZED, rv))
		goto out;

	Do_ADBG_EndSubCase(c, NULL);

	Do_ADBG_BeginSubCase(c, "Test bad arguments - C_Digest with NULL digest");

	mechanism.mechanism = CKM_SHA256;

	memset(data, 0xCC, sizeof(data));
	memset(digest, 0xCC, sizeof(digest));
	digest_size = sizeof(digest);

	memcpy(data, digest_test_patterns[0].data,
	       digest_test_patterns[0].data_size);
	data_size = digest_test_patterns[0].data_size;

	rv = C_DigestInit(session, &mechanism);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	rv = C_Digest(session, data, data_size, NULL, NULL);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_ARGUMENTS_BAD, rv))
		goto out;

	rv = C_Digest(session, data, data_size, digest, &digest_size);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_OPERATION_NOT_INITIALIZED, rv))
		goto out;

	Do_ADBG_EndSubCase(c, NULL);

	Do_ADBG_BeginSubCase(c, "Test bad arguments - C_DigestFinal with digest but NULL size");

	mechanism.mechanism = CKM_SHA256;

	memset(data, 0xCC, sizeof(data));
	memset(digest, 0xCC, sizeof(digest));
	digest_size = sizeof(digest);

	memcpy(data, digest_test_patterns[0].data,
	       digest_test_patterns[0].data_size);
	data_size = digest_test_patterns[0].data_size;

	rv = C_DigestInit(session, &mechanism);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	rv = C_Digest(session, data, data_size, digest, NULL);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_ARGUMENTS_BAD, rv))
		goto out;

	rv = C_Digest(session, data, data_size, digest, &digest_size);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_OPERATION_NOT_INITIALIZED, rv))
		goto out;

	Do_ADBG_EndSubCase(c, NULL);

	Do_ADBG_BeginSubCase(c, "Test bad arguments - C_DigestKey with invalid key handle");

	rv = C_CreateObject(session, digest_data_object,
			    ARRAY_SIZE(digest_data_object), &key_handle);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	mechanism.mechanism = CKM_SHA256;

	memset(data, 0xCC, sizeof(data));
	memset(digest, 0xCC, sizeof(digest));
	digest_size = sizeof(digest);

	memcpy(data, digest_test_patterns[0].data,
	       digest_test_patterns[0].data_size);
	data_size = digest_test_patterns[0].data_size;

	rv = C_DigestInit(session, &mechanism);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	rv = C_DigestKey(session, 9999);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_KEY_HANDLE_INVALID, rv))
		goto out;

	rv = C_DigestKey(session, key_handle);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_OPERATION_NOT_INITIALIZED, rv))
		goto out;

	Do_ADBG_EndSubCase(c, NULL);

	Do_ADBG_BeginSubCase(c, "Test bad arguments - C_DigestKey with non-secret key type");

	mechanism.mechanism = CKM_SHA256;

	memset(data, 0xCC, sizeof(data));
	memset(digest, 0xCC, sizeof(digest));
	digest_size = sizeof(digest);

	memcpy(data, digest_test_patterns[0].data,
	       digest_test_patterns[0].data_size);
	data_size = digest_test_patterns[0].data_size;

	rv = C_DigestInit(session, &mechanism);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	rv = C_DigestKey(session, key_handle);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_KEY_INDIGESTIBLE, rv))
		goto out;

	rv = C_DigestKey(session, key_handle);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_OPERATION_NOT_INITIALIZED, rv))
		goto out;

	ADBG_EXPECT_CK_OK(c, C_DestroyObject(session, key_handle));
	key_handle = CK_INVALID_HANDLE;

out:
#ifdef OPENSSL_FOUND
	if (!ADBG_EXPECT_POINTER(c, NULL, mdctx)) {
		Do_ADBG_Log("Unexpected failure in openssl functions: %d",
			    ret);
		EVP_MD_CTX_destroy(mdctx);
	}
#endif

	Do_ADBG_EndSubCase(c, NULL);

	if (logged_in)
		ADBG_EXPECT_CK_OK(c, C_Logout(session));

	if (key_handle != CK_INVALID_HANDLE) {
		ADBG_EXPECT_CK_OK(c, C_DestroyObject(session, key_handle));
		key_handle = CK_INVALID_HANDLE;
	}

	ADBG_EXPECT_CK_OK(c, C_CloseSession(session));

close_lib:
	ADBG_EXPECT_CK_OK(c, close_lib());
}
ADBG_CASE_DEFINE(pkcs11, 1018, xtest_pkcs11_test_1018,
		 "PKCS11: Digest tests");

/**
 *    0:d=0  hl=2 l=  22 cons: SEQUENCE
 *    2:d=1  hl=2 l=  20 cons:  SET
 *    4:d=2  hl=2 l=  18 cons:   SEQUENCE
 *    6:d=3  hl=2 l=   3 prim:    OBJECT            :commonName
 *   11:d=3  hl=2 l=  11 prim:    UTF8STRING        :common name
 */
static uint8_t subject_common_name[] = {
	0x30, 0x16, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c,
	0x0b, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x20, 0x6e, 0x61, 0x6d, 0x65
};

/**
 *    0:d=0  hl=2 l=   8 prim: OBJECT            :prime256v1
 */
static uint8_t ecdsa_nist_p256[] = {
	0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03,
	0x01, 0x07
};

/**
 *    0:d=0  hl=2 l=   5 prim: OBJECT            :secp384r1
 */
static uint8_t ecdsa_nist_p384[] = {
	0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22
};

/**
 *    0:d=0  hl=2 l=   5 prim: OBJECT            :secp521r1
 */
static uint8_t ecdsa_nist_p521[] = {
	0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23
};

#define EC_SIGN_TEST(_test_name, _mecha, _data) \
	{ \
		.test_name = _test_name, \
		.mecha = _mecha, \
		.data = _data, \
		.data_size = sizeof(_data) - 1, \
	}

/* List of elliptic curve signing multi stage digest mechas */
static struct {
	const char *test_name;
	CK_MECHANISM_TYPE mecha;
	const void *data;
	CK_ULONG data_size;
} ec_sign_tests[] = {
	EC_SIGN_TEST("CKM_ECDSA_SHA1", CKM_ECDSA_SHA1, digest_test_pattern),
	EC_SIGN_TEST("CKM_ECDSA_SHA224", CKM_ECDSA_SHA224, digest_test_pattern),
	EC_SIGN_TEST("CKM_ECDSA_SHA256", CKM_ECDSA_SHA256, digest_test_pattern),
	EC_SIGN_TEST("CKM_ECDSA_SHA384", CKM_ECDSA_SHA384, digest_test_pattern),
	EC_SIGN_TEST("CKM_ECDSA_SHA512", CKM_ECDSA_SHA512, digest_test_pattern),
};

static int test_ec_operations(ADBG_Case_t *c, CK_SESSION_HANDLE session,
			      const char *curve_name, uint8_t *curve,
			      size_t curve_size)
{
	CK_RV rv = CKR_GENERAL_ERROR;

	CK_OBJECT_HANDLE public_key = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE private_key = CK_INVALID_HANDLE;

	CK_MECHANISM mechanism = {
		CKM_EC_KEY_PAIR_GEN, NULL, 0
	};
	CK_MECHANISM sign_mechanism = {
		CKM_ECDSA, NULL, 0
	};
	CK_BYTE id[] = { 123 };

	CK_ATTRIBUTE public_key_template[] = {
		{ CKA_ENCRYPT, &(CK_BBOOL){ CK_FALSE }, sizeof(CK_BBOOL) },
		{ CKA_VERIFY, &(CK_BBOOL){ CK_TRUE }, sizeof(CK_BBOOL) },
		{ CKA_WRAP, &(CK_BBOOL){ CK_FALSE }, sizeof(CK_BBOOL) },
		{ CKA_EC_PARAMS, ecdsa_nist_p256, sizeof(ecdsa_nist_p256) }
	};

	CK_ATTRIBUTE private_key_template[] = {
		{ CKA_TOKEN, &(CK_BBOOL){ CK_FALSE }, sizeof(CK_BBOOL) },
		{ CKA_PRIVATE, &(CK_BBOOL){ CK_TRUE }, sizeof(CK_BBOOL) },
		{ CKA_SUBJECT, subject_common_name,
		  sizeof(subject_common_name) },
		{ CKA_ID, id, sizeof(id) },
		{ CKA_SENSITIVE, &(CK_BBOOL){ CK_TRUE }, sizeof(CK_BBOOL) },
		{ CKA_DECRYPT, &(CK_BBOOL){ CK_FALSE }, sizeof(CK_BBOOL) },
		{ CKA_SIGN, &(CK_BBOOL){ CK_TRUE }, sizeof(CK_BBOOL) },
		{ CKA_UNWRAP, &(CK_BBOOL){ CK_FALSE }, sizeof(CK_BBOOL) }
	};

	CK_OBJECT_CLASS g_class = 0;
	CK_KEY_TYPE g_key_type = 0;
	CK_BYTE g_id[32] = { 0 };
	CK_DATE g_start_date = { 0 };
	CK_DATE g_end_date = { 0 };
	CK_BBOOL g_derive = CK_FALSE;
	CK_BBOOL g_local = CK_FALSE;
	CK_MECHANISM_TYPE g_keygen_mecha = 0;
	CK_BYTE g_subject[64] = { 0 };
	CK_BBOOL g_encrypt = CK_FALSE;
	CK_BBOOL g_verify = CK_FALSE;
	CK_BBOOL g_verify_recover = CK_FALSE;
	CK_BBOOL g_wrap = CK_FALSE;
	CK_BBOOL g_trusted = CK_FALSE;
	CK_BYTE g_public_key_info[1024] = { 0 };
	CK_BBOOL g_sensitive = CK_FALSE;
	CK_BBOOL g_decrypt = CK_FALSE;
	CK_BBOOL g_sign = CK_FALSE;
	CK_BBOOL g_sign_recover = CK_FALSE;
	CK_BBOOL g_unwrap = CK_FALSE;
	CK_BBOOL g_extract = CK_FALSE;
	CK_BBOOL g_asensitive = CK_FALSE;
	CK_BBOOL g_nextract = CK_FALSE;
	CK_BBOOL g_wrap_with_trusted = CK_FALSE;
	CK_BBOOL g_always_authenticate = CK_FALSE;

	CK_ATTRIBUTE get_public_template[] = {
		{ CKA_CLASS, &g_class, sizeof(CK_OBJECT_CLASS) },
		{ CKA_KEY_TYPE,	&g_key_type, sizeof(CK_KEY_TYPE) },
		{ CKA_ID, g_id, sizeof(g_id) },
		{ CKA_START_DATE, &g_start_date, sizeof(CK_DATE) },
		{ CKA_END_DATE, &g_end_date, sizeof(CK_DATE) },
		{ CKA_DERIVE, &g_derive, sizeof(CK_BBOOL) },
		{ CKA_LOCAL, &g_local, sizeof(CK_BBOOL) },
		{ CKA_KEY_GEN_MECHANISM, &g_keygen_mecha, sizeof(CK_MECHANISM_TYPE) },
		{ CKA_SUBJECT, g_subject, sizeof(g_subject) },
		{ CKA_ENCRYPT, &g_encrypt, sizeof(CK_BBOOL) },
		{ CKA_VERIFY, &g_verify, sizeof(CK_BBOOL) },
		{ CKA_VERIFY_RECOVER, &g_verify_recover, sizeof(CK_BBOOL) },
		{ CKA_WRAP, &g_wrap, sizeof(CK_BBOOL) },
		{ CKA_TRUSTED, &g_trusted, sizeof(CK_BBOOL) },
		{ CKA_PUBLIC_KEY_INFO, g_public_key_info, sizeof(g_public_key_info) },
	};

	CK_ATTRIBUTE get_private_template[] = {
		{ CKA_CLASS, &g_class, sizeof(CK_OBJECT_CLASS) },
		{ CKA_KEY_TYPE,	&g_key_type, sizeof(CK_KEY_TYPE) },
		{ CKA_ID, g_id, sizeof(g_id) },
		{ CKA_START_DATE, &g_start_date, sizeof(CK_DATE) },
		{ CKA_END_DATE, &g_end_date, sizeof(CK_DATE) },
		{ CKA_DERIVE, &g_derive, sizeof(CK_BBOOL) },
		{ CKA_LOCAL, &g_local, sizeof(CK_BBOOL) },
		{ CKA_KEY_GEN_MECHANISM, &g_keygen_mecha, sizeof(CK_MECHANISM_TYPE) },
		{ CKA_SUBJECT, g_subject, sizeof(g_subject) },
		{ CKA_SENSITIVE, &g_sensitive, sizeof(CK_BBOOL) },
		{ CKA_DECRYPT, &g_decrypt, sizeof(CK_BBOOL) },
		{ CKA_SIGN, &g_sign, sizeof(CK_BBOOL) },
		{ CKA_SIGN_RECOVER, &g_sign_recover, sizeof(CK_BBOOL) },
		{ CKA_UNWRAP, &g_unwrap, sizeof(CK_BBOOL) },
		{ CKA_EXTRACTABLE, &g_extract, sizeof(CK_BBOOL) },
		{ CKA_ALWAYS_SENSITIVE, &g_asensitive, sizeof(CK_BBOOL) },
		{ CKA_NEVER_EXTRACTABLE, &g_nextract, sizeof(CK_BBOOL) },
		{ CKA_WRAP_WITH_TRUSTED, &g_wrap_with_trusted, sizeof(CK_BBOOL) },
		{ CKA_ALWAYS_AUTHENTICATE, &g_always_authenticate, sizeof(CK_BBOOL) },
		{ CKA_PUBLIC_KEY_INFO, g_public_key_info, sizeof(g_public_key_info) },
	};

	uint8_t signature[512] = { 0 };
	CK_ULONG signature_len = 0;

	size_t i = 0;

	Do_ADBG_BeginSubCase(c, "%s: Generate key pair",
			     curve_name);

	public_key_template[3].pValue = curve;
	public_key_template[3].ulValueLen = curve_size;

	rv = C_GenerateKeyPair(session, &mechanism, public_key_template,
			       ARRAY_SIZE(public_key_template),
			       private_key_template,
			       ARRAY_SIZE(private_key_template),
			       &public_key, &private_key);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto err;

	/* reset get public key template */
	memset(g_id, 0, sizeof(g_id));
	memset(g_subject, 0, sizeof(g_subject));
	memset(g_public_key_info, 0, sizeof(g_public_key_info));
	get_public_template[2].ulValueLen = sizeof(g_id);
	get_public_template[8].ulValueLen = sizeof(g_subject);
	get_public_template[14].ulValueLen = sizeof(g_public_key_info);

	rv = C_GetAttributeValue(session, public_key, get_public_template,
				 ARRAY_SIZE(get_public_template));
	if (!ADBG_EXPECT_CK_OK(c, rv) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_class, ==, CKO_PUBLIC_KEY) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_key_type, ==, CKK_EC) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_derive, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_local, ==, CK_TRUE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_keygen_mecha, ==,
					  CKM_EC_KEY_PAIR_GEN) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_encrypt, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_verify, ==, CK_TRUE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_verify_recover, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_wrap, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_trusted, ==, CK_FALSE))
		goto err_destr_obj;

	/* reset get private key template */
	memset(g_id, 0, sizeof(g_id));
	memset(g_subject, 0, sizeof(g_subject));
	memset(g_public_key_info, 0, sizeof(g_public_key_info));
	get_private_template[2].ulValueLen = sizeof(g_id);
	get_private_template[8].ulValueLen = sizeof(g_subject);
	get_private_template[19].ulValueLen = sizeof(g_public_key_info);

	rv = C_GetAttributeValue(session, private_key, get_private_template,
				 ARRAY_SIZE(get_private_template));
	if (!ADBG_EXPECT_CK_OK(c, rv) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_class, ==, CKO_PRIVATE_KEY) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_key_type, ==, CKK_EC) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_derive, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_local, ==, CK_TRUE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_keygen_mecha, ==,
					  CKM_EC_KEY_PAIR_GEN) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_sensitive, ==, CK_TRUE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_decrypt, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_sign, ==, CK_TRUE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_sign_recover, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_unwrap, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_extract, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_asensitive, ==, CK_TRUE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_nextract, ==, CK_TRUE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_wrap_with_trusted, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_always_authenticate, ==, CK_FALSE))
		goto err_destr_obj;

	Do_ADBG_EndSubCase(c, NULL);

	Do_ADBG_BeginSubCase(c,
			     "%s: Sign & verify tests - oneshot - CKM_ECDSA",
			     curve_name);

	sign_mechanism.mechanism = CKM_ECDSA;
	memset(signature, 0, sizeof(signature));
	signature_len = sizeof(signature);

	rv = C_SignInit(session, &sign_mechanism, private_key);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto err_destr_obj;

	rv = C_Sign(session, (void *)digest_test_pattern_sha256,
		    sizeof(digest_test_pattern_sha256), (void *)signature,
		    &signature_len);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto err_destr_obj;

	rv = C_VerifyInit(session, &sign_mechanism, public_key);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto err_destr_obj;

	rv = C_Verify(session, (void *)digest_test_pattern_sha256,
		    sizeof(digest_test_pattern_sha256), (void *)signature,
		    signature_len);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto err_destr_obj;

	Do_ADBG_EndSubCase(c, NULL);

	for (i = 0; i < ARRAY_SIZE(ec_sign_tests); i++) {
		Do_ADBG_BeginSubCase(c, "%s: Sign & verify - oneshot - %s",
				     curve_name, ec_sign_tests[i].test_name);

		sign_mechanism.mechanism = ec_sign_tests[i].mecha;
		memset(signature, 0, sizeof(signature));
		signature_len = sizeof(signature);

		rv = C_SignInit(session, &sign_mechanism, private_key);
		if (!ADBG_EXPECT_CK_OK(c, rv))
			goto err_destr_obj;

		rv = C_Sign(session, (void *)ec_sign_tests[i].data,
			    ec_sign_tests[i].data_size,
			    (void *)signature, &signature_len);
		if (!ADBG_EXPECT_CK_OK(c, rv))
			goto err_destr_obj;

		rv = C_VerifyInit(session, &sign_mechanism, public_key);
		if (!ADBG_EXPECT_CK_OK(c, rv))
			goto err_destr_obj;

		rv = C_Verify(session, (void *)ec_sign_tests[i].data,
			      ec_sign_tests[i].data_size,
			      (void *)signature, signature_len);
		if (!ADBG_EXPECT_CK_OK(c, rv))
			goto err_destr_obj;

		Do_ADBG_EndSubCase(c, NULL);
	}

	Do_ADBG_BeginSubCase(c, "%s: Destroy keys", curve_name);

	rv = C_DestroyObject(session, private_key);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto err_destr_obj;

	rv = C_DestroyObject(session, public_key);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto err;

	Do_ADBG_EndSubCase(c, NULL);

	return 1;

err_destr_obj:
	ADBG_EXPECT_CK_OK(c, C_DestroyObject(session, private_key));
	ADBG_EXPECT_CK_OK(c, C_DestroyObject(session, public_key));
err:
	Do_ADBG_EndSubCase(c, NULL);

	return 0;
}

static void xtest_pkcs11_test_1019(ADBG_Case_t *c)
{
	CK_RV rv = CKR_GENERAL_ERROR;
	CK_SLOT_ID slot = 0;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_FLAGS session_flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	int ret = 0;

	rv = init_lib_and_find_token_slot(&slot);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		return;

	rv = init_test_token(slot);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto close_lib;

	rv = init_user_test_token(slot);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto close_lib;

	rv = C_OpenSession(slot, session_flags, NULL, 0, &session);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto close_lib;

	/* Login to Test Token */
	rv = C_Login(session, CKU_USER,	test_token_user_pin,
		     sizeof(test_token_user_pin));
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	ret = test_ec_operations(c, session, "P-256", ecdsa_nist_p256,
				 sizeof(ecdsa_nist_p256));
	if (!ret)
		goto out;
	ret = test_ec_operations(c, session, "P-384", ecdsa_nist_p384,
				 sizeof(ecdsa_nist_p384));
	if (!ret)
		goto out;

	if (level > 0) {
		ret = test_ec_operations(c, session, "P-521", ecdsa_nist_p521,
					 sizeof(ecdsa_nist_p521));
		if (!ret)
			goto out;
	}
out:
	ADBG_EXPECT_CK_OK(c, C_CloseSession(session));
close_lib:
	ADBG_EXPECT_CK_OK(c, close_lib());
}
ADBG_CASE_DEFINE(pkcs11, 1019, xtest_pkcs11_test_1019,
		 "PKCS11: Elliptic Curve key generation and signing");

#define WRAPPED_TEST_KEY_SIZE	48

static void xtest_pkcs11_test_1020(ADBG_Case_t *c)
{
	CK_RV rv = CKR_GENERAL_ERROR;
	CK_SLOT_ID slot = 0;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_FLAGS session_flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	CK_OBJECT_HANDLE wrapping_key1 = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE wrapping_key2 = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE wrapping_key_inv = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE key_sz24 = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE key_sens = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE key_inv = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE unwrapped_key = CK_INVALID_HANDLE;
	CK_ATTRIBUTE set_w_unw_template[] = {
		{ CKA_WRAP, &(CK_BBOOL){ CK_TRUE }, sizeof(CK_BBOOL) },
		{ CKA_UNWRAP, &(CK_BBOOL){ CK_TRUE }, sizeof(CK_BBOOL) },
	};
	CK_ATTRIBUTE set_wwt_template[] = {
		{ CKA_WRAP_WITH_TRUSTED, &(CK_BBOOL){ CK_TRUE },
		  sizeof(CK_BBOOL) },
	};
	CK_ATTRIBUTE set_trusted_template[] = {
		{ CKA_TRUSTED, &(CK_BBOOL){ CK_TRUE }, sizeof(CK_BBOOL) },
	};
	CK_ATTRIBUTE wrap_template[] = {
		{ CKA_SENSITIVE, &(CK_BBOOL){ CK_TRUE }, sizeof(CK_BBOOL) },
	};
	CK_ATTRIBUTE unwrap_template[] = {
		{ CKA_SENSITIVE, &(CK_BBOOL){ CK_TRUE }, sizeof(CK_BBOOL) },
	};
	CK_ATTRIBUTE wrapping_key_template[] = {
		{ CKA_VALUE_LEN, &(CK_ULONG){ 16 }, sizeof(CK_ULONG) },
		{ CKA_WRAP, &(CK_BBOOL){ CK_TRUE }, sizeof(CK_BBOOL) },
		{ CKA_UNWRAP, &(CK_BBOOL){ CK_TRUE }, sizeof(CK_BBOOL) },
		{ CKA_SENSITIVE, &(CK_BBOOL){ CK_TRUE }, sizeof(CK_BBOOL) },
		{ CKA_EXTRACTABLE, &(CK_BBOOL){ CK_FALSE }, sizeof(CK_BBOOL) },
	};
	CK_ATTRIBUTE wrapping_key_temp_w_indirect[] = {
		{ CKA_VALUE_LEN, &(CK_ULONG){ 16 }, sizeof(CK_ULONG) },
		{ CKA_WRAP, &(CK_BBOOL){ CK_TRUE }, sizeof(CK_BBOOL) },
		{ CKA_UNWRAP, &(CK_BBOOL){ CK_TRUE }, sizeof(CK_BBOOL) },
		{ CKA_WRAP_TEMPLATE, &wrap_template, sizeof(wrap_template) },
		{ CKA_UNWRAP_TEMPLATE, &unwrap_template,
		  sizeof(unwrap_template) },
	};
	CK_ATTRIBUTE unwrap_template2[] = {
		{ CKA_CLASS, &(CK_OBJECT_CLASS){ CKO_SECRET_KEY },
		  sizeof(CK_OBJECT_CLASS) },
		{ CKA_KEY_TYPE,	&(CK_KEY_TYPE){ CKK_AES }, sizeof(CK_KEY_TYPE) },
		{ CKA_TOKEN, &(CK_BBOOL){ CK_TRUE }, sizeof(CK_BBOOL) },
		{ CKA_EXTRACTABLE, &(CK_BBOOL){ CK_FALSE }, sizeof(CK_BBOOL) },
		{ CKA_VALUE_LEN, &(CK_ULONG){ 16 }, sizeof(CK_ULONG) },
	};
	CK_ATTRIBUTE wrapping_key_temp_w_indirect2[] = {
		{ CKA_VALUE_LEN, &(CK_ULONG){ 16 }, sizeof(CK_ULONG) },
		{ CKA_WRAP, &(CK_BBOOL){ CK_TRUE }, sizeof(CK_BBOOL) },
		{ CKA_UNWRAP, &(CK_BBOOL){ CK_TRUE }, sizeof(CK_BBOOL) },
		{ CKA_UNWRAP_TEMPLATE, &unwrap_template2,
		  sizeof(unwrap_template2) },
	};
	CK_ATTRIBUTE wrapping_key_template_inv1[] = {
		{ CKA_VALUE_LEN, &(CK_ULONG){ 16 }, sizeof(CK_ULONG) },
		{ CKA_WRAP, &(CK_BBOOL){ CK_FALSE }, sizeof(CK_BBOOL) },
	};
	CK_ATTRIBUTE key_template[] = {
		{ CKA_VALUE_LEN, &(CK_ULONG){ 16 }, sizeof(CK_ULONG) },
		{ CKA_ENCRYPT, &(CK_BBOOL){ CK_TRUE }, sizeof(CK_BBOOL) },
		{ CKA_DECRYPT, &(CK_BBOOL){ CK_TRUE }, sizeof(CK_BBOOL) },
		{ CKA_EXTRACTABLE, &(CK_BBOOL){ CK_TRUE }, sizeof(CK_BBOOL) },
	};
	CK_ATTRIBUTE key_template_sens[] = {
		{ CKA_VALUE_LEN, &(CK_ULONG){ 16 }, sizeof(CK_ULONG) },
		{ CKA_EXTRACTABLE, &(CK_BBOOL){ CK_TRUE }, sizeof(CK_BBOOL) },
		{ CKA_SENSITIVE, &(CK_BBOOL){ CK_TRUE }, sizeof(CK_BBOOL) },
	};
	CK_ATTRIBUTE key_template_inv1[] = {
		{ CKA_VALUE_LEN, &(CK_ULONG){ 16 }, sizeof(CK_ULONG) },
		{ CKA_EXTRACTABLE, &(CK_BBOOL){ CK_FALSE }, sizeof(CK_BBOOL) },
	};
	CK_ATTRIBUTE key_sz24_template[] = {
		{ CKA_VALUE_LEN, &(CK_ULONG){ 24 }, sizeof(CK_ULONG) },
		{ CKA_EXTRACTABLE, &(CK_BBOOL){ CK_TRUE }, sizeof(CK_BBOOL) },
	};
	CK_ATTRIBUTE new_key_template[] = {
		{ CKA_CLASS, &(CK_OBJECT_CLASS){ CKO_SECRET_KEY },
		  sizeof(CK_OBJECT_CLASS) },
		{ CKA_KEY_TYPE,	&(CK_KEY_TYPE){ CKK_GENERIC_SECRET },
		  sizeof(CK_KEY_TYPE) },
		{ CKA_ENCRYPT, &(CK_BBOOL){ CK_TRUE }, sizeof(CK_BBOOL) },
		{ CKA_DECRYPT, &(CK_BBOOL){ CK_TRUE }, sizeof(CK_BBOOL) },
		{ CKA_EXTRACTABLE, &(CK_BBOOL){ CK_TRUE }, sizeof(CK_BBOOL) },
		{ CKA_SENSITIVE, &(CK_BBOOL){ CK_FALSE}, sizeof(CK_BBOOL) },
	};
	CK_ATTRIBUTE new_key_template_sens[] = {
		{ CKA_CLASS, &(CK_OBJECT_CLASS){ CKO_SECRET_KEY },
		  sizeof(CK_OBJECT_CLASS) },
		{ CKA_KEY_TYPE,	&(CK_KEY_TYPE){ CKK_AES }, sizeof(CK_KEY_TYPE) },
		{ CKA_EXTRACTABLE, &(CK_BBOOL){ CK_TRUE }, sizeof(CK_BBOOL) },
		{ CKA_SENSITIVE, &(CK_BBOOL){ CK_TRUE }, sizeof(CK_BBOOL) },
	};
	CK_ATTRIBUTE new_key_template2[] = {
		{ CKA_DERIVE, &(CK_BBOOL){ CK_TRUE }, sizeof(CK_BBOOL) },
	};
	CK_ATTRIBUTE new_key_template3[] = {
		{ CKA_VALUE_LEN, &(CK_ULONG){ 16 }, sizeof(CK_ULONG) },
		{ CKA_PRIVATE, &(CK_BBOOL){ CK_TRUE }, sizeof(CK_BBOOL) },
	};
	CK_ATTRIBUTE new_key_template4[] = {
		{ CKA_CLASS, &(CK_OBJECT_CLASS){ CKO_SECRET_KEY },
		  sizeof(CK_OBJECT_CLASS) },
		{ CKA_KEY_TYPE,	&(CK_KEY_TYPE){ CKK_GENERIC_SECRET },
		  sizeof(CK_KEY_TYPE) },
		{ CKA_PRIVATE, &(CK_BBOOL){ CK_TRUE }, sizeof(CK_BBOOL) },
	};
	CK_BBOOL g_extract = CK_FALSE;
	CK_BBOOL g_sensitive = CK_TRUE;
	CK_BBOOL g_nextract = CK_TRUE;
	CK_BBOOL g_asensitive = CK_TRUE;
	CK_BBOOL g_local = CK_TRUE;
	CK_BBOOL g_token = CK_FALSE;
	CK_BBOOL g_derive = CK_FALSE;
	CK_OBJECT_CLASS g_class = CKO_VENDOR_DEFINED;
	CK_KEY_TYPE g_key_type = CKK_VENDOR_DEFINED;
	uint8_t g_val[WRAPPED_TEST_KEY_SIZE] = { 0 };
	CK_ULONG key_len = 0;
	uint8_t g_unwrapped_val[WRAPPED_TEST_KEY_SIZE] = { 0 };
	CK_ULONG unwrapped_key_len = 0;
	/* Keep last attribute as CKA_VALUE */
	CK_ATTRIBUTE get_template_unwrapped[] = {
		{ CKA_CLASS, &g_class, sizeof(CK_OBJECT_CLASS) },
		{ CKA_KEY_TYPE,	&g_key_type, sizeof(CK_KEY_TYPE) },
		{ CKA_EXTRACTABLE, &g_extract, sizeof(CK_BBOOL) },
		{ CKA_SENSITIVE, &g_sensitive, sizeof(CK_BBOOL) },
		{ CKA_NEVER_EXTRACTABLE, &g_nextract, sizeof(CK_BBOOL) },
		{ CKA_ALWAYS_SENSITIVE, &g_asensitive, sizeof(CK_BBOOL) },
		{ CKA_LOCAL, &g_local, sizeof(CK_BBOOL) },
		{ CKA_TOKEN, &g_token, sizeof(CK_BBOOL) },
		{ CKA_DERIVE, &g_derive, sizeof(CK_BBOOL) },
		{ CKA_VALUE_LEN, &unwrapped_key_len,
		  sizeof(unwrapped_key_len) },
		{ CKA_VALUE, g_unwrapped_val, sizeof(g_unwrapped_val) },
	};
	CK_ATTRIBUTE get_template[] = {
		{ CKA_VALUE_LEN, &key_len, sizeof(key_len) },
		{ CKA_VALUE, g_val, sizeof(g_val) },
	};
	uint8_t buf[WRAPPED_TEST_KEY_SIZE] = { 0 };
	CK_ULONG size = 0;

	rv = init_lib_and_find_token_slot(&slot);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		return;

	rv = init_test_token(slot);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto close_lib;

	rv = init_user_test_token(slot);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto close_lib;

	rv = C_OpenSession(slot, session_flags, NULL, 0, &session);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto close_lib;

	/* Wrapping Key - AES Key */
	rv = C_GenerateKey(session, &cktest_aes_keygen_mechanism,
			   wrapping_key_template,
			   ARRAY_SIZE(wrapping_key_template), &wrapping_key1);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto close_session;

	/* Key to be wrapped - AES key */
	rv = C_GenerateKey(session, &cktest_aes_keygen_mechanism,
			   key_template, ARRAY_SIZE(key_template),
			   &key);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto close_session;

	Do_ADBG_BeginSubCase(c, "Test key wrap with AES ECB");

	/*
	 * Test NULL buffer and NULL out_size to verify bad argument processing
	 */
	rv = C_WrapKey(session, &cktest_aes_ecb_mechanism, wrapping_key1, key,
		       NULL, NULL);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_ARGUMENTS_BAD, rv))
		goto out;

	/*
	 * Test NULL buffer case with size as 0 to get the out_size
	 */
	rv = C_WrapKey(session, &cktest_aes_ecb_mechanism, wrapping_key1, key,
		       NULL, &size);
	if (!ADBG_EXPECT_CK_OK(c, rv) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, size, <=, sizeof(buf)))
		goto out;

	/*
	 * Test NULL buffer case with size non zero size to get the out_size
	 */
	size = 1;
	rv = C_WrapKey(session, &cktest_aes_ecb_mechanism, wrapping_key1, key,
		       NULL, &size);
	if (!ADBG_EXPECT_CK_OK(c, rv) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, size, <=, sizeof(buf)))
		goto out;

	/* Test short buffer */
	size = 12;
	rv = C_WrapKey(session, &cktest_aes_ecb_mechanism, wrapping_key1, key,
		       buf, &size);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_BUFFER_TOO_SMALL, rv) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, size, <=, sizeof(buf)))
		goto out;

	rv = C_WrapKey(session, &cktest_aes_ecb_mechanism, wrapping_key1, key,
		       buf, &size);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	/*
	 * Get the size of the original key which was wrapped in key_len.
	 * This will be compared to the length of the key after unwrapping.
	 */
	rv = C_GetAttributeValue(session, key, get_template,
				 ARRAY_SIZE(get_template));
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	Do_ADBG_EndSubCase(c, NULL);

	Do_ADBG_BeginSubCase(c, "Test key unwrap with AES ECB");

	rv = C_UnwrapKey(session, &cktest_aes_ecb_mechanism, wrapping_key1, buf,
			 size, new_key_template, ARRAY_SIZE(new_key_template),
			 &unwrapped_key);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	/*
	 * The key created after unwrapping should have CKA_LOCAL = FALSE,
	 * CKA_ALWAYS_SENSITIVE and CKA_NEVER_EXTRACTABLE as FALSE.
	 * Default value of CKA_EXTRACTABLE if not specified in the template
	 * is TRUE. We have deliberately set CKA_SENSITIVE to false for
	 * both original key and unwrapped_key. This is done to be able to
	 * extract the value of keys and compare them. This is done mainly
	 * for testing. In actual examples, we expect CKA_SENSITIVE of keys
	 * to be wrapped to be TRUE.
	 */
	rv = C_GetAttributeValue(session, unwrapped_key, get_template_unwrapped,
				 ARRAY_SIZE(get_template_unwrapped));
	if (!ADBG_EXPECT_CK_OK(c, rv) ||
	    !ADBG_EXPECT_BUFFER(c, g_unwrapped_val, unwrapped_key_len, g_val,
				key_len) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_class, ==, CKO_SECRET_KEY) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_key_type, ==,
					  CKK_GENERIC_SECRET) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_local, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_sensitive, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_extract, ==, CK_TRUE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_asensitive, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_nextract, ==, CK_FALSE))
		goto out;

	rv = C_DestroyObject(session, unwrapped_key);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	Do_ADBG_EndSubCase(c, NULL);

	Do_ADBG_BeginSubCase(c, "Invalid UnWrap cases");

	/* Failure when unwrapping as a private session key */
	rv = C_UnwrapKey(session, &cktest_aes_ecb_mechanism, wrapping_key1, buf,
			 size, new_key_template4, ARRAY_SIZE(new_key_template4),
			 &unwrapped_key);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_USER_NOT_LOGGED_IN, rv))
		goto out;

	/* Provide incomplete template */
	rv = C_UnwrapKey(session, &cktest_aes_ecb_mechanism, wrapping_key1, buf,
			 size, new_key_template2, ARRAY_SIZE(new_key_template2),
			 &unwrapped_key);

	/*
	 * The error code can also be CKR_TEMPLATE_INCOMPLETE. The
	 * current implementation returns CKR_TEMPLATE_INCONSISTENT
	 */
	if (!ADBG_EXPECT_TRUE(c, rv == CKR_TEMPLATE_INCOMPLETE ||
				 rv == CKR_TEMPLATE_INCONSISTENT))
		goto out;

	/* Try unwrapping with a key without CKA_UNWRAP */
	rv = C_UnwrapKey(session, &cktest_aes_ecb_mechanism, key, buf, size,
			 new_key_template, ARRAY_SIZE(new_key_template),
			 &unwrapped_key);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT, rv))
		goto out;

	Do_ADBG_EndSubCase(c, NULL);

	Do_ADBG_BeginSubCase(c, "Invalid Wrap cases");

	rv = C_GenerateKey(session, &cktest_aes_keygen_mechanism,
			   wrapping_key_template_inv1,
			   ARRAY_SIZE(wrapping_key_template_inv1),
			   &wrapping_key_inv);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	/* Wrapping key used without CKA_WRAP set */
	rv = C_WrapKey(session, &cktest_aes_ecb_mechanism, wrapping_key_inv,
		       key, buf, &size);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_WRAPPING_KEY_TYPE_INCONSISTENT, rv))
		goto out;

	rv = C_DestroyObject(session, wrapping_key_inv);
	ADBG_EXPECT_CK_OK(c, rv);

	/* Use invalid wrapping key handle */
	rv = C_WrapKey(session, &cktest_aes_ecb_mechanism, wrapping_key_inv,
		       key, buf, &size);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_WRAPPING_KEY_HANDLE_INVALID, rv))
		goto out;

	/* CKA_EXTRACTABLE attribute of the key to be wrapped is CKA_FALSE */
	rv = C_GenerateKey(session, &cktest_aes_keygen_mechanism,
			   key_template_inv1, ARRAY_SIZE(key_template_inv1),
			   &key_inv);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	rv = C_WrapKey(session, &cktest_aes_ecb_mechanism, wrapping_key1,
		       key_inv, buf, &size);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_KEY_UNEXTRACTABLE, rv))
		goto out;

	rv = C_DestroyObject(session, key_inv);
	ADBG_EXPECT_CK_OK(c, rv);

	/* Use invalid key handle */
	rv = C_WrapKey(session, &cktest_aes_ecb_mechanism, wrapping_key1,
		       key_inv, buf, &size);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_KEY_HANDLE_INVALID, rv))
		goto out;

	/* Try wrapping the wrapping key */
	rv = C_WrapKey(session, &cktest_aes_ecb_mechanism, wrapping_key1,
		       wrapping_key1, buf, &size);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_WRAPPING_KEY_HANDLE_INVALID, rv))
		goto out;

	/* Use invalid mechanism */
	rv = C_WrapKey(session, &cktest_hmac_md5_mechanism, wrapping_key1, key,
		       buf, &size);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_MECHANISM_INVALID, rv))
		goto out;

	/* Try wrapping when an operation is already active */
	rv = C_EncryptInit(session, &cktest_aes_cbc_mechanism, key);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	rv = C_WrapKey(session, &cktest_aes_ecb_mechanism, wrapping_key1, key,
		       buf, &size);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_OPERATION_ACTIVE, rv))
		goto out;

	rv = C_EncryptFinal(session, NULL, NULL);
	/* Only check that the operation is no more active */
	if (!ADBG_EXPECT_TRUE(c, rv != CKR_BUFFER_TOO_SMALL))
		goto out;

	/*
	 * Try wrapping using CKK_GENERIC_SECRET when mechanism used is
	 * AES_ECB. Generate a secret key object in rw session.
	 */
	rv = C_GenerateKey(session, &cktest_gensecret_keygen_mechanism,
			   cktest_generate_gensecret_object_valid1,
			   ARRAY_SIZE(cktest_generate_gensecret_object_valid1),
			   &key_inv);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	/* Make the Generic secret key wrapping/unwrapping key */
	rv = C_SetAttributeValue(session, key_inv, set_w_unw_template,
				 ARRAY_SIZE(set_w_unw_template));
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	rv = C_WrapKey(session, &cktest_aes_ecb_mechanism, key_inv, key, buf,
		       &size);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_WRAPPING_KEY_TYPE_INCONSISTENT, rv))
		goto out;

	rv = C_DestroyObject(session, key_inv);
	ADBG_EXPECT_CK_OK(c, rv);

	Do_ADBG_EndSubCase(c, NULL);

	Do_ADBG_BeginSubCase(c, "Wrap with different length key");

	/* Generate Key of size 192 bits */
	rv = C_GenerateKey(session, &cktest_aes_keygen_mechanism,
			   key_sz24_template, ARRAY_SIZE(key_sz24_template),
			   &key_sz24);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	size = 0;
	rv = C_WrapKey(session, &cktest_aes_ecb_mechanism, wrapping_key1,
		       key_sz24, buf, &size);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_BUFFER_TOO_SMALL, rv) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, size, ==, 32))
		goto out;

	size = 24;
	rv = C_WrapKey(session, &cktest_aes_ecb_mechanism, wrapping_key1,
		       key_sz24, buf, &size);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_BUFFER_TOO_SMALL, rv) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, size, ==, 32))
		goto out;

	rv = C_WrapKey(session, &cktest_aes_ecb_mechanism, wrapping_key1,
		       key_sz24, buf, &size);
	if (!ADBG_EXPECT_CK_OK(c, rv) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, size, ==, 32))
		goto out;

	Do_ADBG_EndSubCase(c, NULL);

	Do_ADBG_BeginSubCase(c, "Test Wrap/Unwrap with indirect template");

	/* Wrapping Key with indirect templates - AES Key */
	rv = C_GenerateKey(session, &cktest_aes_keygen_mechanism,
			   wrapping_key_temp_w_indirect,
			   ARRAY_SIZE(wrapping_key_temp_w_indirect),
			   &wrapping_key2);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	/*
	 * Attribute mismatch with CKA_WRAP_TEMPLATE.
	 * Error expected when wrapping a key whose template doesn't match with
	 * the CKA_WRAP_TEMPLATE in the wrapping_key. In this example, the
	 * CKA_WRAP_TEMPLATE expects CKA_SENSITIVE of the key to be wrapped to
	 * be TRUE which is not the case here.
	 */
	size = sizeof(buf);
	rv = C_WrapKey(session, &cktest_aes_ecb_mechanism, wrapping_key2, key,
		       buf, &size);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_KEY_HANDLE_INVALID, rv))
		goto out;

	/* Generate SENSITIVE Key */
	rv = C_GenerateKey(session, &cktest_aes_keygen_mechanism,
			   key_template_sens, ARRAY_SIZE(key_template_sens),
			   &key_sens);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	rv = C_WrapKey(session, &cktest_aes_ecb_mechanism, wrapping_key2,
		       key_sens, buf, &size);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	/*
	 * Unwrap to create key with SENSITIVE set as FALSE.
	 * This should fail as indirect attribute CKA_UNWRAP_TEMPLATE restricts
	 * creation of key with CKA_SENSITIVE as FALSE.
	 */
	rv = C_UnwrapKey(session, &cktest_aes_ecb_mechanism, wrapping_key2, buf,
			 size, new_key_template, ARRAY_SIZE(new_key_template),
			 &unwrapped_key);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_TEMPLATE_INCONSISTENT, rv))
		goto out;

	/* Unwrap a wrapped sensitive key to create a SENSITIVE key */
	rv = C_UnwrapKey(session, &cktest_aes_ecb_mechanism, wrapping_key2, buf,
			 size, new_key_template_sens,
			 ARRAY_SIZE(new_key_template_sens), &unwrapped_key);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	/*
	 * Get the attributes of created. Skip last attribute in
	 * get_template_wrapped as that is CKA_VALUE which would give an
	 * error for a sensitive key
	 */
	rv = C_GetAttributeValue(session, unwrapped_key, get_template_unwrapped,
				 ARRAY_SIZE(get_template_unwrapped) - 1);
	if (!ADBG_EXPECT_CK_OK(c, rv) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, unwrapped_key_len, ==, key_len) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_class, ==, CKO_SECRET_KEY) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_key_type, ==, CKK_AES) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_local, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_sensitive, ==, CK_TRUE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_extract, ==, CK_TRUE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_asensitive, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_nextract, ==, CK_FALSE))
		goto out;

	if (!ADBG_EXPECT_CK_OK(c, C_DestroyObject(session, unwrapped_key)) ||
	    !ADBG_EXPECT_CK_OK(c, C_DestroyObject(session, wrapping_key2)) ||
	    !ADBG_EXPECT_CK_OK(c, C_DestroyObject(session, key_sens)))
		goto out;

	/* Create wrapping key with indirect template specifying class & key */
	rv = C_GenerateKey(session, &cktest_aes_keygen_mechanism,
			   wrapping_key_temp_w_indirect2,
			   ARRAY_SIZE(wrapping_key_temp_w_indirect2),
			   &wrapping_key2);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	size = sizeof(buf);
	rv = C_WrapKey(session, &cktest_aes_ecb_mechanism, wrapping_key2, key,
		       buf, &size);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	/* Use minimal new key template just specifying attribute of key */
	rv = C_UnwrapKey(session, &cktest_aes_ecb_mechanism, wrapping_key2, buf,
			 size, new_key_template2, ARRAY_SIZE(new_key_template2),
			 &unwrapped_key);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	rv = C_GetAttributeValue(session, unwrapped_key, get_template_unwrapped,
				 ARRAY_SIZE(get_template_unwrapped) - 1);

	/* Destroy created token object */
	if (!ADBG_EXPECT_CK_OK(c, C_DestroyObject(session, unwrapped_key)))
		goto out;

	if (!ADBG_EXPECT_CK_OK(c, rv) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, unwrapped_key_len, ==, key_len) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_class, ==, CKO_SECRET_KEY) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_key_type, ==, CKK_AES) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_local, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_token, ==, CK_TRUE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_derive, ==, CK_TRUE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_sensitive, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_extract, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_asensitive, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_nextract, ==, CK_FALSE))
		goto out;

	/*
	 * Unwrap with NULL template when CKA_UNWRAP_TEMPLATE has all
	 * attributes to generate a key
	 */
	rv = C_UnwrapKey(session, &cktest_aes_ecb_mechanism, wrapping_key2, buf,
			 size, NULL, 0, &unwrapped_key);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	rv = C_GetAttributeValue(session, unwrapped_key, get_template_unwrapped,
				 ARRAY_SIZE(get_template_unwrapped) - 1);

	/* Destroy created token object */
	if (!ADBG_EXPECT_CK_OK(c, C_DestroyObject(session, unwrapped_key)))
		goto out;

	if (!ADBG_EXPECT_CK_OK(c, rv) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, unwrapped_key_len, ==, key_len) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_class, ==, CKO_SECRET_KEY) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_key_type, ==, CKK_AES) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_local, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_token, ==, CK_TRUE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_derive, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_sensitive, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_extract, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_asensitive, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_nextract, ==, CK_FALSE)) {
		goto out;
	}

	/* Unwrap and try create a Private token object */
	rv = C_UnwrapKey(session, &cktest_aes_ecb_mechanism, wrapping_key2, buf,
			 size, new_key_template3, ARRAY_SIZE(new_key_template3),
			 &unwrapped_key);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_USER_NOT_LOGGED_IN, rv))
		goto out;

	Do_ADBG_EndSubCase(c, NULL);

	Do_ADBG_BeginSubCase(c, "Test usage of CKA_WRAP_WITH_TRUSTED");

	/* Set Attribute WRAP_WITH_TRUSTED on the key */
	rv = C_SetAttributeValue(session, key, set_wwt_template,
				 ARRAY_SIZE(set_wwt_template));
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	/*
	 * Try wrapping the key with attribute CKA_WRAP_WITH_TRUSTED with
	 * normal wrapping key
	 */
	rv = C_WrapKey(session, &cktest_aes_ecb_mechanism, wrapping_key1, key,
		       buf, &size);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_KEY_NOT_WRAPPABLE, rv))
		goto out;

	/* Login as SO in RW session */
	rv = C_Login(session, CKU_SO, test_token_so_pin,
		     sizeof(test_token_so_pin));
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	rv = C_SetAttributeValue(session, wrapping_key1, set_trusted_template,
				 ARRAY_SIZE(set_trusted_template));
	if (!ADBG_EXPECT_CK_OK(c, rv) ||
	    !ADBG_EXPECT_CK_OK(c, C_Logout(session)))
		goto out;

	rv = C_WrapKey(session, &cktest_aes_ecb_mechanism, wrapping_key1, key,
		       buf, &size);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

out:
	Do_ADBG_EndSubCase(c, NULL);
close_session:
	ADBG_EXPECT_CK_OK(c, C_CloseSession(session));

close_lib:
	ADBG_EXPECT_CK_OK(c, close_lib());
}
ADBG_CASE_DEFINE(pkcs11, 1020, xtest_pkcs11_test_1020,
		 "PKCS11: AES Key Wrap/UnWrap tests");

#define RSA_SIGN_TEST(_test_name, _mecha, _data) \
	{ \
		.test_name = _test_name, \
		.mecha = _mecha, \
		.data = _data, \
		.data_size = sizeof(_data) - 1, \
	}

/* List of RSA PKCS signing multi stage digest mechanisms */
static struct {
	const char *test_name;
	CK_MECHANISM_TYPE mecha;
	const void *data;
	CK_ULONG data_size;
} rsa_pkcs_sign_tests[] = {
	RSA_SIGN_TEST("CKM_MD5_RSA_PKCS", CKM_MD5_RSA_PKCS,
		      digest_test_pattern),
	RSA_SIGN_TEST("CKM_SHA1_RSA_PKCS", CKM_SHA1_RSA_PKCS,
		      digest_test_pattern),
	RSA_SIGN_TEST("CKM_SHA224_RSA_PKCS", CKM_SHA224_RSA_PKCS,
		      digest_test_pattern),
	RSA_SIGN_TEST("CKM_SHA256_RSA_PKCS", CKM_SHA256_RSA_PKCS,
		      digest_test_pattern),
	RSA_SIGN_TEST("CKM_SHA384_RSA_PKCS", CKM_SHA384_RSA_PKCS,
		      digest_test_pattern),
	RSA_SIGN_TEST("CKM_SHA512_RSA_PKCS", CKM_SHA512_RSA_PKCS,
		      digest_test_pattern),
};

static int test_rsa_pkcs_operations(ADBG_Case_t *c,
				    CK_SESSION_HANDLE session,
				    const char *rsa_name, uint32_t rsa_bits)
{
	CK_RV rv = CKR_GENERAL_ERROR;

	CK_OBJECT_HANDLE public_key = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE private_key = CK_INVALID_HANDLE;

	CK_MECHANISM mechanism = {
		CKM_RSA_PKCS_KEY_PAIR_GEN, NULL, 0
	};
	CK_MECHANISM sign_mechanism = {
		CKM_RSA_PKCS, NULL, 0
	};
	CK_ULONG modulus_bits = 0;
	CK_BYTE public_exponent[] = { 1, 0, 1 };
	CK_BYTE id[] = { 123 };

	CK_ATTRIBUTE public_key_template[] = {
		{ CKA_ENCRYPT, &(CK_BBOOL){ CK_FALSE }, sizeof(CK_BBOOL) },
		{ CKA_VERIFY, &(CK_BBOOL){ CK_TRUE }, sizeof(CK_BBOOL) },
		{ CKA_WRAP, &(CK_BBOOL){ CK_FALSE }, sizeof(CK_BBOOL) },
		{ CKA_MODULUS_BITS, &modulus_bits, sizeof(CK_ULONG) },
		{ CKA_PUBLIC_EXPONENT, public_exponent,
		  sizeof(public_exponent) }
	};

	CK_ATTRIBUTE private_key_template[] = {
		{ CKA_TOKEN, &(CK_BBOOL){ CK_FALSE }, sizeof(CK_BBOOL) },
		{ CKA_PRIVATE, &(CK_BBOOL){ CK_TRUE }, sizeof(CK_BBOOL) },
		{ CKA_SUBJECT, subject_common_name,
		  sizeof(subject_common_name) },
		{ CKA_ID, id, sizeof(id) },
		{ CKA_SENSITIVE, &(CK_BBOOL){ CK_TRUE }, sizeof(CK_BBOOL) },
		{ CKA_DECRYPT, &(CK_BBOOL){ CK_FALSE }, sizeof(CK_BBOOL) },
		{ CKA_SIGN, &(CK_BBOOL){ CK_TRUE }, sizeof(CK_BBOOL) },
		{ CKA_UNWRAP, &(CK_BBOOL){ CK_FALSE }, sizeof(CK_BBOOL) }
	};

	CK_OBJECT_CLASS g_class = 0;
	CK_KEY_TYPE g_key_type = 0;
	CK_BYTE g_id[32] = { 0 };
	CK_DATE g_start_date = { 0 };
	CK_DATE g_end_date = { 0 };
	CK_BBOOL g_derive = CK_FALSE;
	CK_BBOOL g_local = CK_FALSE;
	CK_MECHANISM_TYPE g_keygen_mecha = 0;
	CK_BYTE g_subject[64] = { 0 };
	CK_BBOOL g_encrypt = CK_FALSE;
	CK_BBOOL g_verify = CK_FALSE;
	CK_BBOOL g_verify_recover = CK_FALSE;
	CK_BBOOL g_wrap = CK_FALSE;
	CK_BBOOL g_trusted = CK_FALSE;
	CK_BYTE g_public_key_info[1024] = { 0 };
	CK_BBOOL g_sensitive = CK_FALSE;
	CK_BBOOL g_decrypt = CK_FALSE;
	CK_BBOOL g_sign = CK_FALSE;
	CK_BBOOL g_sign_recover = CK_FALSE;
	CK_BBOOL g_unwrap = CK_FALSE;
	CK_BBOOL g_extract = CK_FALSE;
	CK_BBOOL g_asensitive = CK_FALSE;
	CK_BBOOL g_nextract = CK_FALSE;
	CK_BBOOL g_wrap_with_trusted = CK_FALSE;
	CK_BBOOL g_always_authenticate = CK_FALSE;

	/* Note: Tests below expects specific order of elements */
	CK_ATTRIBUTE get_public_template[] = {
		{ CKA_CLASS, &g_class, sizeof(CK_OBJECT_CLASS) },
		{ CKA_KEY_TYPE,	&g_key_type, sizeof(CK_KEY_TYPE) },
		{ CKA_ID, g_id, sizeof(g_id) },
		{ CKA_START_DATE, &g_start_date, sizeof(CK_DATE) },
		{ CKA_END_DATE, &g_end_date, sizeof(CK_DATE) },
		{ CKA_DERIVE, &g_derive, sizeof(CK_BBOOL) },
		{ CKA_LOCAL, &g_local, sizeof(CK_BBOOL) },
		{ CKA_KEY_GEN_MECHANISM, &g_keygen_mecha, sizeof(CK_MECHANISM_TYPE) },
		{ CKA_SUBJECT, g_subject, sizeof(g_subject) },
		{ CKA_ENCRYPT, &g_encrypt, sizeof(CK_BBOOL) },
		{ CKA_VERIFY, &g_verify, sizeof(CK_BBOOL) },
		{ CKA_VERIFY_RECOVER, &g_verify_recover, sizeof(CK_BBOOL) },
		{ CKA_WRAP, &g_wrap, sizeof(CK_BBOOL) },
		{ CKA_TRUSTED, &g_trusted, sizeof(CK_BBOOL) },
		{ CKA_PUBLIC_KEY_INFO, g_public_key_info, sizeof(g_public_key_info) },
	};

	/* Note: Tests below expects specific order of elements */
	CK_ATTRIBUTE get_private_template[] = {
		{ CKA_CLASS, &g_class, sizeof(CK_OBJECT_CLASS) },
		{ CKA_KEY_TYPE,	&g_key_type, sizeof(CK_KEY_TYPE) },
		{ CKA_ID, g_id, sizeof(g_id) },
		{ CKA_START_DATE, &g_start_date, sizeof(CK_DATE) },
		{ CKA_END_DATE, &g_end_date, sizeof(CK_DATE) },
		{ CKA_DERIVE, &g_derive, sizeof(CK_BBOOL) },
		{ CKA_LOCAL, &g_local, sizeof(CK_BBOOL) },
		{ CKA_KEY_GEN_MECHANISM, &g_keygen_mecha, sizeof(CK_MECHANISM_TYPE) },
		{ CKA_SUBJECT, g_subject, sizeof(g_subject) },
		{ CKA_SENSITIVE, &g_sensitive, sizeof(CK_BBOOL) },
		{ CKA_DECRYPT, &g_decrypt, sizeof(CK_BBOOL) },
		{ CKA_SIGN, &g_sign, sizeof(CK_BBOOL) },
		{ CKA_SIGN_RECOVER, &g_sign_recover, sizeof(CK_BBOOL) },
		{ CKA_UNWRAP, &g_unwrap, sizeof(CK_BBOOL) },
		{ CKA_EXTRACTABLE, &g_extract, sizeof(CK_BBOOL) },
		{ CKA_ALWAYS_SENSITIVE, &g_asensitive, sizeof(CK_BBOOL) },
		{ CKA_NEVER_EXTRACTABLE, &g_nextract, sizeof(CK_BBOOL) },
		{ CKA_WRAP_WITH_TRUSTED, &g_wrap_with_trusted, sizeof(CK_BBOOL) },
		{ CKA_ALWAYS_AUTHENTICATE, &g_always_authenticate, sizeof(CK_BBOOL) },
		{ CKA_PUBLIC_KEY_INFO, g_public_key_info, sizeof(g_public_key_info) },
	};

	uint8_t signature[512] = { 0 };
	CK_ULONG signature_len = 0;

	size_t i = 0;

	Do_ADBG_BeginSubCase(c, "%s: Generate key pair", rsa_name);

	modulus_bits = rsa_bits;

	rv = C_GenerateKeyPair(session, &mechanism, public_key_template,
			       ARRAY_SIZE(public_key_template),
			       private_key_template,
			       ARRAY_SIZE(private_key_template),
			       &public_key, &private_key);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto err;

	/* reset get public key template */
	memset(g_id, 0, sizeof(g_id));
	assert(get_public_template[2].type == CKA_ID);
	get_public_template[2].ulValueLen = sizeof(g_id);

	memset(g_subject, 0, sizeof(g_subject));
	assert(get_public_template[8].type == CKA_SUBJECT);
	get_public_template[8].ulValueLen = sizeof(g_subject);

	memset(g_public_key_info, 0, sizeof(g_public_key_info));
	assert(get_public_template[14].type == CKA_PUBLIC_KEY_INFO);
	get_public_template[14].ulValueLen = sizeof(g_public_key_info);

	rv = C_GetAttributeValue(session, public_key, get_public_template,
				 ARRAY_SIZE(get_public_template));
	if (!ADBG_EXPECT_CK_OK(c, rv) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_class, ==, CKO_PUBLIC_KEY) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_key_type, ==, CKK_RSA) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_derive, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_local, ==, CK_TRUE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_keygen_mecha, ==,
					  CKM_RSA_PKCS_KEY_PAIR_GEN) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_encrypt, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_verify, ==, CK_TRUE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_verify_recover, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_wrap, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_trusted, ==, CK_FALSE))
		goto err_destr_obj;

	/* reset get private key template */
	memset(g_id, 0, sizeof(g_id));
	assert(get_private_template[2].type == CKA_ID);
	get_private_template[2].ulValueLen = sizeof(g_id);

	memset(g_subject, 0, sizeof(g_subject));
	assert(get_private_template[8].type == CKA_SUBJECT);
	get_private_template[8].ulValueLen = sizeof(g_subject);

	memset(g_public_key_info, 0, sizeof(g_public_key_info));
	assert(get_private_template[19].type == CKA_PUBLIC_KEY_INFO);
	get_private_template[19].ulValueLen = sizeof(g_public_key_info);

	rv = C_GetAttributeValue(session, private_key, get_private_template,
				 ARRAY_SIZE(get_private_template));
	if (!ADBG_EXPECT_CK_OK(c, rv) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_class, ==, CKO_PRIVATE_KEY) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_key_type, ==, CKK_RSA) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_derive, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_local, ==, CK_TRUE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_keygen_mecha, ==,
					  CKM_RSA_PKCS_KEY_PAIR_GEN) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_sensitive, ==, CK_TRUE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_decrypt, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_sign, ==, CK_TRUE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_sign_recover, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_unwrap, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_extract, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_asensitive, ==, CK_TRUE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_nextract, ==, CK_TRUE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_wrap_with_trusted, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_always_authenticate, ==, CK_FALSE))
		goto err_destr_obj;

	Do_ADBG_EndSubCase(c, NULL);

	Do_ADBG_BeginSubCase(c,
			     "%s: Sign & verify tests - oneshot - CKM_RSA_PKCS",
			     rsa_name);

	sign_mechanism.mechanism = CKM_RSA_PKCS;
	memset(signature, 0, sizeof(signature));
	signature_len = sizeof(signature);

	rv = C_SignInit(session, &sign_mechanism, private_key);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto err_destr_obj;

	rv = C_Sign(session, (void *)digest_test_pattern_sha256,
		    sizeof(digest_test_pattern_sha256), (void *)signature,
		    &signature_len);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto err_destr_obj;

	rv = C_VerifyInit(session, &sign_mechanism, public_key);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto err_destr_obj;

	rv = C_Verify(session, (void *)digest_test_pattern_sha256,
		      sizeof(digest_test_pattern_sha256), (void *)signature,
		      signature_len);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto err_destr_obj;

	for (i = 0; i < ARRAY_SIZE(rsa_pkcs_sign_tests); i++) {
		/*
		 * Note: this order of end/begin here is just to get ADBG
		 * SubCases in sync with error handling.
		 */
		Do_ADBG_EndSubCase(c, NULL);

		Do_ADBG_BeginSubCase(c, "%s: Sign & verify - oneshot - %s",
				     rsa_name,
				     rsa_pkcs_sign_tests[i].test_name);

		sign_mechanism.mechanism = rsa_pkcs_sign_tests[i].mecha;
		memset(signature, 0, sizeof(signature));
		signature_len = sizeof(signature);

		rv = C_SignInit(session, &sign_mechanism, private_key);
		if (!ADBG_EXPECT_CK_OK(c, rv))
			goto err_destr_obj;

		rv = C_Sign(session, (void *)rsa_pkcs_sign_tests[i].data,
			    rsa_pkcs_sign_tests[i].data_size,
			    (void *)signature, &signature_len);
		if (!ADBG_EXPECT_CK_OK(c, rv))
			goto err_destr_obj;

		rv = C_VerifyInit(session, &sign_mechanism, public_key);
		if (!ADBG_EXPECT_CK_OK(c, rv))
			goto err_destr_obj;

		rv = C_Verify(session, (void *)rsa_pkcs_sign_tests[i].data,
			      rsa_pkcs_sign_tests[i].data_size,
			      (void *)signature, signature_len);
		if (!ADBG_EXPECT_CK_OK(c, rv))
			goto err_destr_obj;
	}

	rv = C_DestroyObject(session, private_key);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto err_destr_pub_obj;

	rv = C_DestroyObject(session, public_key);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto err;

	Do_ADBG_EndSubCase(c, NULL);

	return 1;

err_destr_obj:
	ADBG_EXPECT_CK_OK(c, C_DestroyObject(session, private_key));
err_destr_pub_obj:
	ADBG_EXPECT_CK_OK(c, C_DestroyObject(session, public_key));
err:
	Do_ADBG_EndSubCase(c, NULL);

	return 0;
}

static void xtest_pkcs11_test_1021(ADBG_Case_t *c)
{
	CK_RV rv = CKR_GENERAL_ERROR;
	CK_SLOT_ID slot = 0;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_FLAGS session_flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	int ret = 0;

	rv = init_lib_and_find_token_slot(&slot);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		return;

	rv = init_test_token(slot);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto close_lib;

	rv = init_user_test_token(slot);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto close_lib;

	rv = C_OpenSession(slot, session_flags, NULL, 0, &session);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto close_lib;

	/* Login to Test Token */
	rv = C_Login(session, CKU_USER,	test_token_user_pin,
		     sizeof(test_token_user_pin));
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	ret = test_rsa_pkcs_operations(c, session, "RSA-1024", 1024);
	if (!ret)
		goto out;
	ret = test_rsa_pkcs_operations(c, session, "RSA-2048", 2048);
	if (!ret)
		goto out;
	if (level > 0) {
		ret = test_rsa_pkcs_operations(c, session, "RSA-3072", 3072);
		if (!ret)
			goto out;
		ret = test_rsa_pkcs_operations(c, session, "RSA-4096", 4096);
		if (!ret)
			goto out;
	}
out:
	ADBG_EXPECT_CK_OK(c, C_CloseSession(session));
close_lib:
	ADBG_EXPECT_CK_OK(c, close_lib());
}
ADBG_CASE_DEFINE(pkcs11, 1021, xtest_pkcs11_test_1021,
		 "PKCS11: RSA PKCS key generation and signing");

#define RSA_PSS_HASH_SIGN_TEST(_test_name, _min_rsa_bits, _mecha, _hash_algo, _mgf_algo, \
			       _salt_len, _data) \
	{ \
		.test_name = _test_name, \
		.min_rsa_bits = _min_rsa_bits, \
		.mecha = _mecha, \
		.hash_algo = _hash_algo, \
		.mgf_algo = _mgf_algo, \
		.salt_len = _salt_len, \
		.data = _data, \
		.data_size = sizeof(_data), \
	}

#define RSA_PSS_CSTR_SIGN_TEST(_test_name, _min_rsa_bits, _mecha, _hash_algo, \
			       _mgf_algo, _salt_len, _data) \
	{ \
		.test_name = _test_name, \
		.min_rsa_bits = _min_rsa_bits, \
		.mecha = _mecha, \
		.hash_algo = _hash_algo, \
		.mgf_algo = _mgf_algo, \
		.salt_len = _salt_len, \
		.data = _data, \
		.data_size = sizeof(_data) - 1, \
	}

/* List of RSA PSS signing multi stage digest mechanisms */
static struct {
	const char *test_name;
	uint32_t min_rsa_bits;
	CK_MECHANISM_TYPE mecha;
	CK_MECHANISM_TYPE hash_algo;
	CK_RSA_PKCS_MGF_TYPE mgf_algo;
	CK_ULONG salt_len;
	const void *data;
	CK_ULONG data_size;
} rsa_pss_sign_tests[] = {
	RSA_PSS_HASH_SIGN_TEST("RSA-PSS/SHA1", 1024, CKM_RSA_PKCS_PSS,
			       CKM_SHA_1, CKG_MGF1_SHA1, 20,
			       digest_test_pattern_sha1),
	RSA_PSS_CSTR_SIGN_TEST("RSA-PSS/SHA1/mech", 1024,
			       CKM_SHA1_RSA_PKCS_PSS, CKM_SHA_1, CKG_MGF1_SHA1,
			       20, digest_test_pattern),
	RSA_PSS_HASH_SIGN_TEST("RSA-PSS/SHA224", 1024, CKM_RSA_PKCS_PSS,
			       CKM_SHA224, CKG_MGF1_SHA224, 28,
			       digest_test_pattern_sha224),
	RSA_PSS_CSTR_SIGN_TEST("RSA-PSS/SHA224/mech", 1024,
			       CKM_SHA224_RSA_PKCS_PSS, CKM_SHA224,
			       CKG_MGF1_SHA224, 28, digest_test_pattern),
	RSA_PSS_HASH_SIGN_TEST("RSA-PSS/SHA256", 1024, CKM_RSA_PKCS_PSS,
			       CKM_SHA256, CKG_MGF1_SHA256, 32,
			       digest_test_pattern_sha256),
	RSA_PSS_CSTR_SIGN_TEST("RSA-PSS/SHA256/mech", 1024,
			       CKM_SHA256_RSA_PKCS_PSS, CKM_SHA256,
			       CKG_MGF1_SHA256, 32, digest_test_pattern),
	RSA_PSS_HASH_SIGN_TEST("RSA-PSS/SHA384", 1024, CKM_RSA_PKCS_PSS,
			       CKM_SHA384, CKG_MGF1_SHA384, 48,
			       digest_test_pattern_sha384),
	RSA_PSS_CSTR_SIGN_TEST("RSA-PSS/SHA384/mech", 1024,
			       CKM_SHA384_RSA_PKCS_PSS, CKM_SHA384,
			       CKG_MGF1_SHA384, 48, digest_test_pattern),
	RSA_PSS_HASH_SIGN_TEST("RSA-PSS/SHA512", 2048, CKM_RSA_PKCS_PSS,
			       CKM_SHA512, CKG_MGF1_SHA512, 64,
			       digest_test_pattern_sha512),
	RSA_PSS_CSTR_SIGN_TEST("RSA-PSS/SHA512/mech", 2048,
			       CKM_SHA512_RSA_PKCS_PSS, CKM_SHA512,
			       CKG_MGF1_SHA512, 64, digest_test_pattern),
};

static int test_rsa_pss_operations(ADBG_Case_t *c,
				    CK_SESSION_HANDLE session,
				    const char *rsa_name, uint32_t rsa_bits)
{
	CK_RV rv = CKR_GENERAL_ERROR;

	CK_OBJECT_HANDLE public_key = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE private_key = CK_INVALID_HANDLE;

	CK_MECHANISM mechanism = {
		CKM_RSA_PKCS_KEY_PAIR_GEN, NULL, 0
	};
	CK_MECHANISM sign_mechanism = {
		CKM_RSA_PKCS_PSS, NULL, 0
	};
	CK_RSA_PKCS_PSS_PARAMS pss_params = {
		CKM_SHA256, CKG_MGF1_SHA256, 32,
	};
	CK_ULONG modulus_bits = 0;
	CK_BYTE public_exponent[] = { 1, 0, 1 };
	CK_BYTE id[] = { 123 };

	CK_ATTRIBUTE public_key_template[] = {
		{ CKA_ENCRYPT, &(CK_BBOOL){ CK_FALSE }, sizeof(CK_BBOOL) },
		{ CKA_VERIFY, &(CK_BBOOL){ CK_TRUE }, sizeof(CK_BBOOL) },
		{ CKA_WRAP, &(CK_BBOOL){ CK_FALSE }, sizeof(CK_BBOOL) },
		{ CKA_MODULUS_BITS, &modulus_bits, sizeof(CK_ULONG) },
		{ CKA_PUBLIC_EXPONENT, public_exponent,
		  sizeof(public_exponent) }
	};

	CK_ATTRIBUTE private_key_template[] = {
		{ CKA_TOKEN, &(CK_BBOOL){ CK_FALSE }, sizeof(CK_BBOOL) },
		{ CKA_PRIVATE, &(CK_BBOOL){ CK_TRUE }, sizeof(CK_BBOOL) },
		{ CKA_SUBJECT, subject_common_name,
		  sizeof(subject_common_name) },
		{ CKA_ID, id, sizeof(id) },
		{ CKA_SENSITIVE, &(CK_BBOOL){ CK_TRUE }, sizeof(CK_BBOOL) },
		{ CKA_DECRYPT, &(CK_BBOOL){ CK_FALSE }, sizeof(CK_BBOOL) },
		{ CKA_SIGN, &(CK_BBOOL){ CK_TRUE }, sizeof(CK_BBOOL) },
		{ CKA_UNWRAP, &(CK_BBOOL){ CK_FALSE }, sizeof(CK_BBOOL) }
	};

	CK_OBJECT_CLASS g_class = 0;
	CK_KEY_TYPE g_key_type = 0;
	CK_BYTE g_id[32] = { 0 };
	CK_DATE g_start_date = { 0 };
	CK_DATE g_end_date = { 0 };
	CK_BBOOL g_derive = CK_FALSE;
	CK_BBOOL g_local = CK_FALSE;
	CK_MECHANISM_TYPE g_keygen_mecha = 0;
	CK_BYTE g_subject[64] = { 0 };
	CK_BBOOL g_encrypt = CK_FALSE;
	CK_BBOOL g_verify = CK_FALSE;
	CK_BBOOL g_verify_recover = CK_FALSE;
	CK_BBOOL g_wrap = CK_FALSE;
	CK_BBOOL g_trusted = CK_FALSE;
	CK_BYTE g_public_key_info[1024] = { 0 };
	CK_BBOOL g_sensitive = CK_FALSE;
	CK_BBOOL g_decrypt = CK_FALSE;
	CK_BBOOL g_sign = CK_FALSE;
	CK_BBOOL g_sign_recover = CK_FALSE;
	CK_BBOOL g_unwrap = CK_FALSE;
	CK_BBOOL g_extract = CK_FALSE;
	CK_BBOOL g_asensitive = CK_FALSE;
	CK_BBOOL g_nextract = CK_FALSE;
	CK_BBOOL g_wrap_with_trusted = CK_FALSE;
	CK_BBOOL g_always_authenticate = CK_FALSE;

	/* Note: Tests below expects specific order of elements */
	CK_ATTRIBUTE get_public_template[] = {
		{ CKA_CLASS, &g_class, sizeof(CK_OBJECT_CLASS) },
		{ CKA_KEY_TYPE,	&g_key_type, sizeof(CK_KEY_TYPE) },
		{ CKA_ID, g_id, sizeof(g_id) },
		{ CKA_START_DATE, &g_start_date, sizeof(CK_DATE) },
		{ CKA_END_DATE, &g_end_date, sizeof(CK_DATE) },
		{ CKA_DERIVE, &g_derive, sizeof(CK_BBOOL) },
		{ CKA_LOCAL, &g_local, sizeof(CK_BBOOL) },
		{ CKA_KEY_GEN_MECHANISM, &g_keygen_mecha, sizeof(CK_MECHANISM_TYPE) },
		{ CKA_SUBJECT, g_subject, sizeof(g_subject) },
		{ CKA_ENCRYPT, &g_encrypt, sizeof(CK_BBOOL) },
		{ CKA_VERIFY, &g_verify, sizeof(CK_BBOOL) },
		{ CKA_VERIFY_RECOVER, &g_verify_recover, sizeof(CK_BBOOL) },
		{ CKA_WRAP, &g_wrap, sizeof(CK_BBOOL) },
		{ CKA_TRUSTED, &g_trusted, sizeof(CK_BBOOL) },
		{ CKA_PUBLIC_KEY_INFO, g_public_key_info, sizeof(g_public_key_info) },
	};

	/* Note: Tests below expects specific order of elements */
	CK_ATTRIBUTE get_private_template[] = {
		{ CKA_CLASS, &g_class, sizeof(CK_OBJECT_CLASS) },
		{ CKA_KEY_TYPE,	&g_key_type, sizeof(CK_KEY_TYPE) },
		{ CKA_ID, g_id, sizeof(g_id) },
		{ CKA_START_DATE, &g_start_date, sizeof(CK_DATE) },
		{ CKA_END_DATE, &g_end_date, sizeof(CK_DATE) },
		{ CKA_DERIVE, &g_derive, sizeof(CK_BBOOL) },
		{ CKA_LOCAL, &g_local, sizeof(CK_BBOOL) },
		{ CKA_KEY_GEN_MECHANISM, &g_keygen_mecha, sizeof(CK_MECHANISM_TYPE) },
		{ CKA_SUBJECT, g_subject, sizeof(g_subject) },
		{ CKA_SENSITIVE, &g_sensitive, sizeof(CK_BBOOL) },
		{ CKA_DECRYPT, &g_decrypt, sizeof(CK_BBOOL) },
		{ CKA_SIGN, &g_sign, sizeof(CK_BBOOL) },
		{ CKA_SIGN_RECOVER, &g_sign_recover, sizeof(CK_BBOOL) },
		{ CKA_UNWRAP, &g_unwrap, sizeof(CK_BBOOL) },
		{ CKA_EXTRACTABLE, &g_extract, sizeof(CK_BBOOL) },
		{ CKA_ALWAYS_SENSITIVE, &g_asensitive, sizeof(CK_BBOOL) },
		{ CKA_NEVER_EXTRACTABLE, &g_nextract, sizeof(CK_BBOOL) },
		{ CKA_WRAP_WITH_TRUSTED, &g_wrap_with_trusted, sizeof(CK_BBOOL) },
		{ CKA_ALWAYS_AUTHENTICATE, &g_always_authenticate, sizeof(CK_BBOOL) },
		{ CKA_PUBLIC_KEY_INFO, g_public_key_info, sizeof(g_public_key_info) },
	};

	uint8_t signature[512] = { 0 };
	CK_ULONG signature_len = 0;

	size_t i = 0;

	Do_ADBG_BeginSubCase(c, "%s: Generate key pair", rsa_name);

	modulus_bits = rsa_bits;

	rv = C_GenerateKeyPair(session, &mechanism, public_key_template,
			       ARRAY_SIZE(public_key_template),
			       private_key_template,
			       ARRAY_SIZE(private_key_template),
			       &public_key, &private_key);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto err;

	/* reset get public key template */
	memset(g_id, 0, sizeof(g_id));
	assert(get_public_template[2].type == CKA_ID);
	get_public_template[2].ulValueLen = sizeof(g_id);

	memset(g_subject, 0, sizeof(g_subject));
	assert(get_public_template[8].type == CKA_SUBJECT);
	get_public_template[8].ulValueLen = sizeof(g_subject);

	memset(g_public_key_info, 0, sizeof(g_public_key_info));
	assert(get_public_template[14].type == CKA_PUBLIC_KEY_INFO);
	get_public_template[14].ulValueLen = sizeof(g_public_key_info);

	rv = C_GetAttributeValue(session, public_key, get_public_template,
				 ARRAY_SIZE(get_public_template));
	if (!ADBG_EXPECT_CK_OK(c, rv) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_class, ==, CKO_PUBLIC_KEY) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_key_type, ==, CKK_RSA) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_derive, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_local, ==, CK_TRUE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_keygen_mecha, ==,
					  CKM_RSA_PKCS_KEY_PAIR_GEN) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_encrypt, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_verify, ==, CK_TRUE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_verify_recover, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_wrap, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_trusted, ==, CK_FALSE))
		goto err_destr_obj;

	/* reset get private key template */
	memset(g_id, 0, sizeof(g_id));
	assert(get_private_template[2].type == CKA_ID);
	get_private_template[2].ulValueLen = sizeof(g_id);

	memset(g_subject, 0, sizeof(g_subject));
	assert(get_private_template[8].type == CKA_SUBJECT);
	get_private_template[8].ulValueLen = sizeof(g_subject);

	memset(g_public_key_info, 0, sizeof(g_public_key_info));
	assert(get_private_template[19].type == CKA_PUBLIC_KEY_INFO);
	get_private_template[19].ulValueLen = sizeof(g_public_key_info);

	rv = C_GetAttributeValue(session, private_key, get_private_template,
				 ARRAY_SIZE(get_private_template));
	if (!ADBG_EXPECT_CK_OK(c, rv) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_class, ==, CKO_PRIVATE_KEY) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_key_type, ==, CKK_RSA) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_derive, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_local, ==, CK_TRUE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_keygen_mecha, ==,
					  CKM_RSA_PKCS_KEY_PAIR_GEN) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_sensitive, ==, CK_TRUE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_decrypt, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_sign, ==, CK_TRUE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_sign_recover, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_unwrap, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_extract, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_asensitive, ==, CK_TRUE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_nextract, ==, CK_TRUE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_wrap_with_trusted, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_always_authenticate, ==, CK_FALSE))
		goto err_destr_obj;

	for (i = 0; i < ARRAY_SIZE(rsa_pss_sign_tests); i++) {
		/*
		 * Note: this order of end/begin here is just to get ADBG
		 * SubCases in sync with error handling.
		 */
		Do_ADBG_EndSubCase(c, NULL);

		Do_ADBG_BeginSubCase(c, "%s: Sign & verify - oneshot - %s",
				     rsa_name,
				     rsa_pss_sign_tests[i].test_name);

		sign_mechanism.mechanism = rsa_pss_sign_tests[i].mecha;
		sign_mechanism.pParameter = &pss_params;
		sign_mechanism.ulParameterLen = sizeof(pss_params);
		pss_params.hashAlg = rsa_pss_sign_tests[i].hash_algo;
		pss_params.mgf = rsa_pss_sign_tests[i].mgf_algo;
		pss_params.sLen = rsa_pss_sign_tests[i].salt_len;

		memset(signature, 0, sizeof(signature));
		signature_len = sizeof(signature);

		rv = C_SignInit(session, &sign_mechanism, private_key);
		if (rsa_bits >= rsa_pss_sign_tests[i].min_rsa_bits) {
			if (!ADBG_EXPECT_CK_OK(c, rv))
				goto err_destr_obj;
		} else {
			if (!ADBG_EXPECT_CK_RESULT(c, CKR_KEY_SIZE_RANGE, rv))
				goto err_destr_obj;
			continue;
		}

		rv = C_Sign(session, (void *)rsa_pss_sign_tests[i].data,
			    rsa_pss_sign_tests[i].data_size,
			    (void *)signature, &signature_len);
		if (!ADBG_EXPECT_CK_OK(c, rv))
			goto err_destr_obj;

		rv = C_VerifyInit(session, &sign_mechanism, public_key);
		if (!ADBG_EXPECT_CK_OK(c, rv))
			goto err_destr_obj;

		rv = C_Verify(session, (void *)rsa_pss_sign_tests[i].data,
			      rsa_pss_sign_tests[i].data_size,
			      (void *)signature, signature_len);
		if (!ADBG_EXPECT_CK_OK(c, rv))
			goto err_destr_obj;
	}

	rv = C_DestroyObject(session, private_key);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto err_destr_pub_obj;

	rv = C_DestroyObject(session, public_key);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto err;

	Do_ADBG_EndSubCase(c, NULL);

	return 1;

err_destr_obj:
	ADBG_EXPECT_CK_OK(c, C_DestroyObject(session, private_key));
err_destr_pub_obj:
	ADBG_EXPECT_CK_OK(c, C_DestroyObject(session, public_key));
err:
	Do_ADBG_EndSubCase(c, NULL);

	return 0;
}

static void xtest_pkcs11_test_1022(ADBG_Case_t *c)
{
	CK_RV rv = CKR_GENERAL_ERROR;
	CK_SLOT_ID slot = 0;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_FLAGS session_flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	int ret = 0;

	rv = init_lib_and_find_token_slot(&slot);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		return;

	rv = init_test_token(slot);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto close_lib;

	rv = init_user_test_token(slot);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto close_lib;

	rv = C_OpenSession(slot, session_flags, NULL, 0, &session);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto close_lib;

	/* Login to Test Token */
	rv = C_Login(session, CKU_USER,	test_token_user_pin,
		     sizeof(test_token_user_pin));
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	ret = test_rsa_pss_operations(c, session, "RSA-1024", 1024);
	if (!ret)
		goto out;
	ret = test_rsa_pss_operations(c, session, "RSA-2048", 2048);
	if (!ret)
		goto out;
	if (level > 0) {
		ret = test_rsa_pss_operations(c, session, "RSA-3072", 3072);
		if (!ret)
			goto out;
		ret = test_rsa_pss_operations(c, session, "RSA-4096", 4096);
		if (!ret)
			goto out;
	}
out:
	ADBG_EXPECT_CK_OK(c, C_CloseSession(session));
close_lib:
	ADBG_EXPECT_CK_OK(c, close_lib());
}
ADBG_CASE_DEFINE(pkcs11, 1022, xtest_pkcs11_test_1022,
		 "PKCS11: RSA PSS key generation and signing");

static const char rsa_oaep_message[] = "Hello World";
static char rsa_oaep_label[] = "TestLabel";

#define RSA_OAEP_CRYPT_TEST(_test_name, _min_rsa_bits, _hash_algo, _mgf_algo, \
			    _source_data, _source_data_len) \
	{ \
		.test_name = _test_name, \
		.min_rsa_bits = _min_rsa_bits, \
		.hash_algo = _hash_algo, \
		.mgf_algo = _mgf_algo, \
		.source_data = _source_data, \
		.source_data_len = _source_data_len, \
	}

/* List of RSA OAEP crypto params to test out */
static struct {
	const char *test_name;
	uint32_t min_rsa_bits;
	CK_MECHANISM_TYPE hash_algo;
	CK_RSA_PKCS_MGF_TYPE mgf_algo;
	void *source_data;
	size_t source_data_len;
} rsa_oaep_crypt_tests[] = {
	RSA_OAEP_CRYPT_TEST("RSA-OAEP/SHA1", 1024, CKM_SHA_1, CKG_MGF1_SHA1,
			    NULL, 0),
	RSA_OAEP_CRYPT_TEST("RSA-OAEP/SHA1/label", 1024, CKM_SHA_1,
			    CKG_MGF1_SHA1, rsa_oaep_label,
			    sizeof(rsa_oaep_label)),
	RSA_OAEP_CRYPT_TEST("RSA-OAEP/SHA224", 1024, CKM_SHA224,
			    CKG_MGF1_SHA224, NULL, 0),
	RSA_OAEP_CRYPT_TEST("RSA-OAEP/SHA224/label", 1024, CKM_SHA224,
			    CKG_MGF1_SHA224, rsa_oaep_label,
			    sizeof(rsa_oaep_label)),
	RSA_OAEP_CRYPT_TEST("RSA-OAEP/SHA256", 1024, CKM_SHA256,
			    CKG_MGF1_SHA256, NULL, 0),
	RSA_OAEP_CRYPT_TEST("RSA-OAEP/SHA256/label", 1024, CKM_SHA256,
			    CKG_MGF1_SHA256, rsa_oaep_label,
			    sizeof(rsa_oaep_label)),
	RSA_OAEP_CRYPT_TEST("RSA-OAEP/SHA384", 1024, CKM_SHA384,
			    CKG_MGF1_SHA384, NULL, 0),
	RSA_OAEP_CRYPT_TEST("RSA-OAEP/SHA384/label", 1024, CKM_SHA384,
			    CKG_MGF1_SHA384, rsa_oaep_label,
			    sizeof(rsa_oaep_label)),
	RSA_OAEP_CRYPT_TEST("RSA-OAEP/SHA512", 2048, CKM_SHA512,
			    CKG_MGF1_SHA512, NULL, 0),
	RSA_OAEP_CRYPT_TEST("RSA-OAEP/SHA512/label", 2048, CKM_SHA512,
			    CKG_MGF1_SHA512, rsa_oaep_label,
			    sizeof(rsa_oaep_label)),
};

static int test_rsa_oaep_operations(ADBG_Case_t *c,
				    CK_SESSION_HANDLE session,
				    const char *rsa_name, uint32_t rsa_bits)
{
	CK_RV rv = CKR_GENERAL_ERROR;
	CK_OBJECT_HANDLE public_key = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE private_key = CK_INVALID_HANDLE;

	CK_MECHANISM mechanism = {
		CKM_RSA_PKCS_KEY_PAIR_GEN, NULL, 0
	};
	CK_MECHANISM crypt_mechanism = {
		CKM_RSA_PKCS_OAEP, NULL, 0
	};
	CK_RSA_PKCS_OAEP_PARAMS oaep_params = {
		CKM_SHA256, CKG_MGF1_SHA256, CKZ_DATA_SPECIFIED, NULL, 0
	};
	CK_BYTE public_exponent[] = { 1, 0, 1 };
	CK_BYTE id[] = { 123 };
	CK_ULONG modulus_bits = 0;
	CK_ATTRIBUTE public_key_template[] = {
		{ CKA_ENCRYPT, &(CK_BBOOL){ CK_TRUE }, sizeof(CK_BBOOL) },
		{ CKA_VERIFY, &(CK_BBOOL){ CK_TRUE }, sizeof(CK_BBOOL) },
		{ CKA_WRAP, &(CK_BBOOL){ CK_FALSE }, sizeof(CK_BBOOL) },
		{ CKA_MODULUS_BITS, &modulus_bits, sizeof(CK_ULONG) },
		{ CKA_PUBLIC_EXPONENT, public_exponent,
		  sizeof(public_exponent) }
	};
	CK_ATTRIBUTE private_key_template[] = {
		{ CKA_TOKEN, &(CK_BBOOL){ CK_FALSE }, sizeof(CK_BBOOL) },
		{ CKA_PRIVATE, &(CK_BBOOL){ CK_TRUE }, sizeof(CK_BBOOL) },
		{ CKA_SUBJECT, subject_common_name,
		  sizeof(subject_common_name) },
		{ CKA_ID, id, sizeof(id) },
		{ CKA_SENSITIVE, &(CK_BBOOL){ CK_TRUE }, sizeof(CK_BBOOL) },
		{ CKA_DECRYPT, &(CK_BBOOL){ CK_TRUE }, sizeof(CK_BBOOL) },
		{ CKA_SIGN, &(CK_BBOOL){ CK_TRUE }, sizeof(CK_BBOOL) },
		{ CKA_UNWRAP, &(CK_BBOOL){ CK_FALSE }, sizeof(CK_BBOOL) }
	};

	CK_OBJECT_CLASS g_class = 0;
	CK_KEY_TYPE g_key_type = 0;
	CK_BYTE g_id[32] = { 0 };
	CK_DATE g_start_date = { 0 };
	CK_DATE g_end_date = { 0 };
	CK_BBOOL g_derive = CK_FALSE;
	CK_BBOOL g_local = CK_FALSE;
	CK_MECHANISM_TYPE g_keygen_mecha = 0;
	CK_BYTE g_subject[64] = { 0 };
	CK_BBOOL g_encrypt = CK_FALSE;
	CK_BBOOL g_verify = CK_FALSE;
	CK_BBOOL g_verify_recover = CK_FALSE;
	CK_BBOOL g_wrap = CK_FALSE;
	CK_BBOOL g_trusted = CK_FALSE;
	CK_BYTE g_public_key_info[1024] = { 0 };
	CK_BBOOL g_sensitive = CK_FALSE;
	CK_BBOOL g_decrypt = CK_FALSE;
	CK_BBOOL g_sign = CK_FALSE;
	CK_BBOOL g_sign_recover = CK_FALSE;
	CK_BBOOL g_unwrap = CK_FALSE;
	CK_BBOOL g_extract = CK_FALSE;
	CK_BBOOL g_asensitive = CK_FALSE;
	CK_BBOOL g_nextract = CK_FALSE;
	CK_BBOOL g_wrap_with_trusted = CK_FALSE;
	CK_BBOOL g_always_authenticate = CK_FALSE;

	/* Note: Tests below expects specific order of elements */
	CK_ATTRIBUTE get_public_template[] = {
		{ CKA_CLASS, &g_class, sizeof(CK_OBJECT_CLASS) },
		{ CKA_KEY_TYPE,	&g_key_type, sizeof(CK_KEY_TYPE) },
		{ CKA_ID, g_id, sizeof(g_id) },
		{ CKA_START_DATE, &g_start_date, sizeof(CK_DATE) },
		{ CKA_END_DATE, &g_end_date, sizeof(CK_DATE) },
		{ CKA_DERIVE, &g_derive, sizeof(CK_BBOOL) },
		{ CKA_LOCAL, &g_local, sizeof(CK_BBOOL) },
		{ CKA_KEY_GEN_MECHANISM, &g_keygen_mecha, sizeof(CK_MECHANISM_TYPE) },
		{ CKA_SUBJECT, g_subject, sizeof(g_subject) },
		{ CKA_ENCRYPT, &g_encrypt, sizeof(CK_BBOOL) },
		{ CKA_VERIFY, &g_verify, sizeof(CK_BBOOL) },
		{ CKA_VERIFY_RECOVER, &g_verify_recover, sizeof(CK_BBOOL) },
		{ CKA_WRAP, &g_wrap, sizeof(CK_BBOOL) },
		{ CKA_TRUSTED, &g_trusted, sizeof(CK_BBOOL) },
		{ CKA_PUBLIC_KEY_INFO, g_public_key_info, sizeof(g_public_key_info) },
	};

	/* Note: Tests below expects specific order of elements */
	CK_ATTRIBUTE get_private_template[] = {
		{ CKA_CLASS, &g_class, sizeof(CK_OBJECT_CLASS) },
		{ CKA_KEY_TYPE,	&g_key_type, sizeof(CK_KEY_TYPE) },
		{ CKA_ID, g_id, sizeof(g_id) },
		{ CKA_START_DATE, &g_start_date, sizeof(CK_DATE) },
		{ CKA_END_DATE, &g_end_date, sizeof(CK_DATE) },
		{ CKA_DERIVE, &g_derive, sizeof(CK_BBOOL) },
		{ CKA_LOCAL, &g_local, sizeof(CK_BBOOL) },
		{ CKA_KEY_GEN_MECHANISM, &g_keygen_mecha, sizeof(CK_MECHANISM_TYPE) },
		{ CKA_SUBJECT, g_subject, sizeof(g_subject) },
		{ CKA_SENSITIVE, &g_sensitive, sizeof(CK_BBOOL) },
		{ CKA_DECRYPT, &g_decrypt, sizeof(CK_BBOOL) },
		{ CKA_SIGN, &g_sign, sizeof(CK_BBOOL) },
		{ CKA_SIGN_RECOVER, &g_sign_recover, sizeof(CK_BBOOL) },
		{ CKA_UNWRAP, &g_unwrap, sizeof(CK_BBOOL) },
		{ CKA_EXTRACTABLE, &g_extract, sizeof(CK_BBOOL) },
		{ CKA_ALWAYS_SENSITIVE, &g_asensitive, sizeof(CK_BBOOL) },
		{ CKA_NEVER_EXTRACTABLE, &g_nextract, sizeof(CK_BBOOL) },
		{ CKA_WRAP_WITH_TRUSTED, &g_wrap_with_trusted, sizeof(CK_BBOOL) },
		{ CKA_ALWAYS_AUTHENTICATE, &g_always_authenticate, sizeof(CK_BBOOL) },
		{ CKA_PUBLIC_KEY_INFO, g_public_key_info, sizeof(g_public_key_info) },
	};
	uint8_t ciphertext[512] = { 0 };
	CK_ULONG ciphertext_len = 0;
	uint8_t plaintext[512] = { 0 };
	CK_ULONG plaintext_len = 0;
	size_t i = 0;

	Do_ADBG_BeginSubCase(c, "%s: Generate key pair", rsa_name);

	modulus_bits = rsa_bits;

	rv = C_GenerateKeyPair(session, &mechanism, public_key_template,
			       ARRAY_SIZE(public_key_template),
			       private_key_template,
			       ARRAY_SIZE(private_key_template),
			       &public_key, &private_key);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto err;

	/* reset get public key template */
	memset(g_id, 0, sizeof(g_id));
	assert(get_public_template[2].type == CKA_ID);
	get_public_template[2].ulValueLen = sizeof(g_id);

	memset(g_subject, 0, sizeof(g_subject));
	assert(get_public_template[8].type == CKA_SUBJECT);
	get_public_template[8].ulValueLen = sizeof(g_subject);

	memset(g_public_key_info, 0, sizeof(g_public_key_info));
	assert(get_public_template[14].type == CKA_PUBLIC_KEY_INFO);
	get_public_template[14].ulValueLen = sizeof(g_public_key_info);

	rv = C_GetAttributeValue(session, public_key,
				 get_public_template,
				 ARRAY_SIZE(get_public_template));
	if (!ADBG_EXPECT_CK_OK(c, rv) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_class, ==, CKO_PUBLIC_KEY) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_key_type, ==, CKK_RSA) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_derive, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_local, ==, CK_TRUE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_keygen_mecha, ==,
					  CKM_RSA_PKCS_KEY_PAIR_GEN) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_encrypt, ==, CK_TRUE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_verify, ==, CK_TRUE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_verify_recover, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_wrap, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_trusted, ==, CK_FALSE))
		goto err_destr_obj;

	/* reset get private key template */
	memset(g_id, 0, sizeof(g_id));
	assert(get_private_template[2].type == CKA_ID);
	get_private_template[2].ulValueLen = sizeof(g_id);

	memset(g_subject, 0, sizeof(g_subject));
	assert(get_private_template[8].type == CKA_SUBJECT);
	get_private_template[8].ulValueLen = sizeof(g_subject);

	memset(g_public_key_info, 0, sizeof(g_public_key_info));
	assert(get_private_template[19].type == CKA_PUBLIC_KEY_INFO);
	get_private_template[19].ulValueLen = sizeof(g_public_key_info);

	rv = C_GetAttributeValue(session, private_key,
				 get_private_template,
				 ARRAY_SIZE(get_private_template));
	if (!ADBG_EXPECT_CK_OK(c, rv) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_class, ==, CKO_PRIVATE_KEY) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_key_type, ==, CKK_RSA) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_derive, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_local, ==, CK_TRUE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_keygen_mecha, ==,
					  CKM_RSA_PKCS_KEY_PAIR_GEN) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_sensitive, ==, CK_TRUE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_decrypt, ==, CK_TRUE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_sign, ==, CK_TRUE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_sign_recover, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_unwrap, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_extract, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_asensitive, ==, CK_TRUE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_nextract, ==, CK_TRUE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_wrap_with_trusted, ==, CK_FALSE) ||
	    !ADBG_EXPECT_COMPARE_UNSIGNED(c, g_always_authenticate, ==, CK_FALSE))
		goto err_destr_obj;

	for (i = 0; i < ARRAY_SIZE(rsa_oaep_crypt_tests); i++) {
		/*
		 * Note: this order of end/begin here is just to get ADBG
		 * SubCases in sync with error handling.
		 */
		Do_ADBG_EndSubCase(c, NULL);

		Do_ADBG_BeginSubCase(c, "%s: Encrypt & decrypt - oneshot - %s",
				     rsa_name,
				     rsa_oaep_crypt_tests[i].test_name);

		crypt_mechanism.mechanism = CKM_RSA_PKCS_OAEP;
		crypt_mechanism.pParameter = &oaep_params;
		crypt_mechanism.ulParameterLen = sizeof(oaep_params);
		oaep_params.hashAlg = rsa_oaep_crypt_tests[i].hash_algo;
		oaep_params.mgf = rsa_oaep_crypt_tests[i].mgf_algo;
		oaep_params.pSourceData = rsa_oaep_crypt_tests[i].source_data;
		oaep_params.ulSourceDataLen = rsa_oaep_crypt_tests[i].source_data_len;

		memset(ciphertext, 0, sizeof(ciphertext));
		memset(plaintext, 0, sizeof(plaintext));

		ciphertext_len = 0;

		memcpy(plaintext, rsa_oaep_message, sizeof(rsa_oaep_message));
		plaintext_len = sizeof(rsa_oaep_message);

		rv = C_EncryptInit(session, &crypt_mechanism, public_key);
		if (!ADBG_EXPECT_CK_OK(c, rv))
			goto err_destr_obj;

		rv = C_Encrypt(session, plaintext, plaintext_len, NULL,
			       &ciphertext_len);
		if (!ADBG_EXPECT_CK_OK(c, rv))
			goto err_destr_obj;

		rv = C_Encrypt(session, plaintext, plaintext_len, ciphertext,
			       &ciphertext_len);
		if (rsa_bits >= rsa_oaep_crypt_tests[i].min_rsa_bits) {
			if (!ADBG_EXPECT_CK_OK(c, rv))
				goto err_destr_obj;
		} else {
			if (!ADBG_EXPECT_CK_RESULT(c, CKR_DATA_LEN_RANGE, rv))
				goto err_destr_obj;
			continue;
		}

		memset(plaintext, 0, sizeof(plaintext));
		plaintext_len = 0;

		rv = C_DecryptInit(session, &crypt_mechanism, private_key);
		if (!ADBG_EXPECT_CK_OK(c, rv))
			goto err_destr_obj;

		rv = C_Decrypt(session, ciphertext, ciphertext_len, NULL,
			       &plaintext_len);
		if (!ADBG_EXPECT_CK_OK(c, rv))
			goto err_destr_obj;

		rv = C_Decrypt(session, ciphertext, ciphertext_len, plaintext,
			       &plaintext_len);
		if (!ADBG_EXPECT_CK_OK(c, rv) ||
		    !ADBG_EXPECT_BUFFER(c, rsa_oaep_message,
					sizeof(rsa_oaep_message), plaintext,
					plaintext_len))
			goto err_destr_obj;
	}

	rv = C_DestroyObject(session, private_key);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto err_destr_pub_obj;

	rv = C_DestroyObject(session, public_key);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto err;

	Do_ADBG_EndSubCase(c, NULL);

	return 1;

err_destr_obj:
	ADBG_EXPECT_CK_OK(c, C_DestroyObject(session, private_key));
err_destr_pub_obj:
	ADBG_EXPECT_CK_OK(c, C_DestroyObject(session, public_key));
err:
	Do_ADBG_EndSubCase(c, NULL);

	return 0;
}

static void xtest_pkcs11_test_1023(ADBG_Case_t *c)
{
	CK_RV rv = CKR_GENERAL_ERROR;
	CK_SLOT_ID slot = 0;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_FLAGS session_flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	int ret = 0;

	rv = init_lib_and_find_token_slot(&slot);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		return;

	rv = init_test_token(slot);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto close_lib;

	rv = init_user_test_token(slot);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto close_lib;

	rv = C_OpenSession(slot, session_flags, NULL, 0, &session);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto close_lib;

	/* Login to Test Token */
	rv = C_Login(session, CKU_USER,	test_token_user_pin,
		     sizeof(test_token_user_pin));
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	ret = test_rsa_oaep_operations(c, session, "RSA-1024", 1024);
	if (!ret)
		goto out;
	ret = test_rsa_oaep_operations(c, session, "RSA-2048", 2048);
	if (!ret)
		goto out;
	if (level > 0) {
		ret = test_rsa_oaep_operations(c, session, "RSA-3072", 3072);
		if (!ret)
			goto out;
		ret = test_rsa_oaep_operations(c, session, "RSA-4096", 4096);
		if (!ret)
			goto out;
	}
out:
	ADBG_EXPECT_CK_OK(c, C_CloseSession(session));
close_lib:
	ADBG_EXPECT_CK_OK(c, close_lib());
}
ADBG_CASE_DEFINE(pkcs11, 1023, xtest_pkcs11_test_1023,
		 "PKCS11: RSA OAEP key generation and crypto operations");

#ifdef OPENSSL_FOUND
static const char x509_example_root_ca[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIICDTCCAZOgAwIBAgIBATAKBggqhkjOPQQDAzA+MQswCQYDVQQGEwJGSTEVMBMG\n"
	"A1UECgwMTWFudWZhY3R1cmVyMRgwFgYDVQQDDA9FeGFtcGxlIFJvb3QgQ0EwIBcN\n"
	"MjEwODE0MDc1NTU1WhgPOTk5OTEyMzEyMzU5NTlaMD4xCzAJBgNVBAYTAkZJMRUw\n"
	"EwYDVQQKDAxNYW51ZmFjdHVyZXIxGDAWBgNVBAMMD0V4YW1wbGUgUm9vdCBDQTB2\n"
	"MBAGByqGSM49AgEGBSuBBAAiA2IABP6jFf4PuIo0t78AeONf2ENbip4GdG9rfstp\n"
	"bWMvH/0BIn2ioMbapYSK1WcVlOKUaZRrbRzoYWD7ZpwSYFwtd1XmMQkLJ1baIdrt\n"
	"jibL9yBCYRJJLsmTHn5UiLCoA2EiFaNjMGEwHQYDVR0OBBYEFApC6125F2th+ujZ\n"
	"PVxTtsI8llA1MB8GA1UdIwQYMBaAFApC6125F2th+ujZPVxTtsI8llA1MA8GA1Ud\n"
	"EwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMDA2gAMGUCMACW\n"
	"r0/EpTD1uJ9JLsyC8aGP2rSr44J50K6fT0h3LZWMhL5fGkkNTCdmuWbWZznTswIx\n"
	"APjyNm4f///vWUN3XFd+BRhS2YHR43c0K4oNVyLqigoMoSqu0zXt9Xm+Lsu5iqgJ\n"
	"NQ==\n"
	"-----END CERTIFICATE-----\n";
#endif

static void xtest_pkcs11_test_1024(ADBG_Case_t *c)
{
#ifndef OPENSSL_FOUND
	(void)c;
	Do_ADBG_Log("OpenSSL not available, skipping X.509 Certificate tests");
#else
	CK_RV rv = CKR_GENERAL_ERROR;
	CK_SLOT_ID slot = 0;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_FLAGS session_flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	BIO *x509_bio = NULL;
	X509 *x509_cert = NULL;
	uint8_t *x509_cert_der = NULL;
	int x509_cert_der_size = 0;
	X509_NAME *x509_subject_name = NULL;
	uint8_t *x509_subject_name_der = NULL;
	int x509_subject_name_der_size = 0;
	X509_NAME *x509_issuer_name = NULL;
	uint8_t *x509_issuer_name_der = NULL;
	int x509_issuer_name_der_size = 0;
	ASN1_INTEGER *x509_serial_number = NULL;
	uint8_t *x509_serial_number_der = NULL;
	int x509_serial_number_der_size = 0;
	uint8_t *p = NULL;
	CK_BYTE id[] = { 123 };
	const char *label = "example-root-ca";
	/* Note: Tests below expects specific order of elements */
	CK_ATTRIBUTE certificate_object[] = {
		{ CKA_TOKEN,	&(CK_BBOOL){ CK_FALSE }, sizeof(CK_BBOOL) },
		{ CKA_CLASS,	&(CK_OBJECT_CLASS){ CKO_CERTIFICATE },
		  sizeof(CK_OBJECT_CLASS) },
		{ CKA_CERTIFICATE_TYPE, &(CK_CERTIFICATE_TYPE){ CKC_X_509 },
		  sizeof(CK_CERTIFICATE_TYPE) },
		{ CKA_CERTIFICATE_CATEGORY,
		  &(CK_ULONG){ CK_CERTIFICATE_CATEGORY_UNSPECIFIED },
		  sizeof(CK_ULONG) },
		{ CKA_NAME_HASH_ALGORITHM, &(CK_MECHANISM_TYPE){ CKM_SHA_1 },
		  sizeof(CK_MECHANISM_TYPE) },
		{ CKA_ID, id, sizeof(id) },
		{ CKA_LABEL, (CK_UTF8CHAR_PTR)label, strlen(label) },
		{ CKA_VALUE,	NULL, 0 },
		{ CKA_ISSUER,	NULL, 0 },
		{ CKA_SUBJECT,	NULL, 0 },
		{ CKA_SERIAL_NUMBER,	NULL, 0 },
	};
	/* Note: Tests below expects specific order of elements */
	CK_ATTRIBUTE certificate_object2[] = {
		{ CKA_TOKEN,	&(CK_BBOOL){ CK_FALSE }, sizeof(CK_BBOOL) },
		{ CKA_CLASS,	&(CK_OBJECT_CLASS){ CKO_CERTIFICATE },
		  sizeof(CK_OBJECT_CLASS) },
		{ CKA_CERTIFICATE_TYPE, &(CK_CERTIFICATE_TYPE){ CKC_X_509 },
		  sizeof(CK_CERTIFICATE_TYPE) },
		{ CKA_ID, id, sizeof(id) },
		{ CKA_LABEL, (CK_UTF8CHAR_PTR)label, strlen(label) },
		{ CKA_VALUE,	NULL, 0 },
		{ CKA_ISSUER,	NULL, 0 },
		{ CKA_SUBJECT,	NULL, 0 },
		{ CKA_SERIAL_NUMBER,	NULL, 0 },
	};
	/* Note: Tests below expects specific order of elements */
	/* CKA_CERTIFICATE_CATEGORY is specified below with invalid ID */
	CK_ATTRIBUTE invalid_category_object[] = {
		{ CKA_TOKEN,	&(CK_BBOOL){ CK_FALSE }, sizeof(CK_BBOOL) },
		{ CKA_CLASS,	&(CK_OBJECT_CLASS){ CKO_CERTIFICATE },
		  sizeof(CK_OBJECT_CLASS) },
		{ CKA_CERTIFICATE_TYPE, &(CK_CERTIFICATE_TYPE){ CKC_X_509 },
		  sizeof(CK_CERTIFICATE_TYPE) },
		{ CKA_CERTIFICATE_CATEGORY, &(CK_ULONG){ -1 },
		  sizeof(CK_ULONG) },
		{ CKA_ID, id, sizeof(id) },
		{ CKA_LABEL, (CK_UTF8CHAR_PTR)label, strlen(label) },
		{ CKA_VALUE,	NULL, 0 },
		{ CKA_ISSUER,	NULL, 0 },
		{ CKA_SUBJECT,	NULL, 0 },
		{ CKA_SERIAL_NUMBER,	NULL, 0 },
	};
	/* Note: Tests below expects specific order of elements */
	/* CKA_CERTIFICATE_CATEGORY is specified below with invalid size */
	CK_ATTRIBUTE invalid_category_object2[] = {
		{ CKA_TOKEN,	&(CK_BBOOL){ CK_FALSE }, sizeof(CK_BBOOL) },
		{ CKA_CLASS,	&(CK_OBJECT_CLASS){ CKO_CERTIFICATE },
		  sizeof(CK_OBJECT_CLASS) },
		{ CKA_CERTIFICATE_TYPE, &(CK_CERTIFICATE_TYPE){ CKC_X_509 },
		  sizeof(CK_CERTIFICATE_TYPE) },
		{ CKA_CERTIFICATE_CATEGORY,
		  &(CK_ULONG){ CK_CERTIFICATE_CATEGORY_UNSPECIFIED }, 0 },
		{ CKA_ID, id, sizeof(id) },
		{ CKA_LABEL, (CK_UTF8CHAR_PTR)label, strlen(label) },
		{ CKA_VALUE,	NULL, 0 },
		{ CKA_ISSUER,	NULL, 0 },
		{ CKA_SUBJECT,	NULL, 0 },
		{ CKA_SERIAL_NUMBER,	NULL, 0 },
	};
	/* Note: Tests below expects specific order of elements */
	/* CKA_NAME_HASH_ALGORITHM is specified below with invalid size */
	CK_ATTRIBUTE invalid_name_hash_alg_size[] = {
		{ CKA_TOKEN,	&(CK_BBOOL){ CK_FALSE }, sizeof(CK_BBOOL) },
		{ CKA_CLASS,	&(CK_OBJECT_CLASS){ CKO_CERTIFICATE },
		  sizeof(CK_OBJECT_CLASS) },
		{ CKA_CERTIFICATE_TYPE, &(CK_CERTIFICATE_TYPE){ CKC_X_509 },
		  sizeof(CK_CERTIFICATE_TYPE) },
		{ CKA_NAME_HASH_ALGORITHM, &(CK_MECHANISM_TYPE){ CKM_SHA_1 },
		  sizeof(CK_MECHANISM_TYPE) - 1 },
		{ CKA_ID, id, sizeof(id) },
		{ CKA_LABEL, (CK_UTF8CHAR_PTR)label, strlen(label) },
		{ CKA_VALUE,	NULL, 0 },
		{ CKA_ISSUER,	NULL, 0 },
		{ CKA_SUBJECT,	NULL, 0 },
		{ CKA_SERIAL_NUMBER,	NULL, 0 },
	};
	CK_OBJECT_HANDLE obj_hdl = CK_INVALID_HANDLE;

	rv = init_lib_and_find_token_slot(&slot);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		return;

	rv = init_test_token(slot);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto close_lib;

	rv = init_user_test_token(slot);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto close_lib;

	rv = C_OpenSession(slot, session_flags, NULL, 0, &session);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto close_lib;

	/* Login to Test Token */
	rv = C_Login(session, CKU_USER,	test_token_user_pin,
		     sizeof(test_token_user_pin));
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto close_session;

	Do_ADBG_BeginSubCase(c, "Import X.509 Certificate");

	/* Parse PEM to OpenSSL's internal X509 format */
	x509_bio = BIO_new_mem_buf(x509_example_root_ca, -1);
	if (!ADBG_EXPECT_NOT_NULL(c, x509_bio))
		goto out;

	x509_cert = PEM_read_bio_X509(x509_bio, NULL, 0, NULL);
	if (!ADBG_EXPECT_NOT_NULL(c, x509_cert))
		goto out;

	BIO_free(x509_bio);
	x509_bio = NULL;

	/* Make DER version for storing it in token */
	x509_cert_der_size = i2d_X509(x509_cert, NULL);
	if (!ADBG_EXPECT_COMPARE_SIGNED(c, x509_cert_der_size, >, 0))
		goto out;

	x509_cert_der = OPENSSL_malloc(x509_cert_der_size);
	if (!ADBG_EXPECT_NOT_NULL(c, x509_cert_der))
		goto out;

	p = x509_cert_der;
	x509_cert_der_size = i2d_X509(x509_cert, &p);
	if (!ADBG_EXPECT_COMPARE_SIGNED(c, x509_cert_der_size, >, 0))
		goto out;

	/* Extract needed details from certificate */

	/* Extract subject name */
	x509_subject_name = X509_get_subject_name(x509_cert);
	if (!ADBG_EXPECT_NOT_NULL(c, x509_subject_name))
		goto out;

	x509_subject_name_der_size = i2d_X509_NAME(x509_subject_name, NULL);
	if (!ADBG_EXPECT_COMPARE_SIGNED(c, x509_subject_name_der_size, >, 0))
		goto out;

	x509_subject_name_der = OPENSSL_malloc(x509_subject_name_der_size);
	if (!ADBG_EXPECT_NOT_NULL(c, x509_subject_name_der))
		goto out;

	p = x509_subject_name_der;
	x509_subject_name_der_size = i2d_X509_NAME(x509_subject_name, &p);
	if (!ADBG_EXPECT_COMPARE_SIGNED(c, x509_subject_name_der_size, >, 0))
		goto out;

	/* Extract issuer's name */
	x509_issuer_name = X509_get_issuer_name(x509_cert);
	if (!ADBG_EXPECT_NOT_NULL(c, x509_issuer_name))
		goto out;

	x509_issuer_name_der_size = i2d_X509_NAME(x509_issuer_name, NULL);
	if (!ADBG_EXPECT_COMPARE_SIGNED(c, x509_issuer_name_der_size, >, 0))
		goto out;

	x509_issuer_name_der = OPENSSL_malloc(x509_issuer_name_der_size);
	if (!ADBG_EXPECT_NOT_NULL(c, x509_issuer_name_der))
		goto out;

	p = x509_issuer_name_der;
	x509_issuer_name_der_size = i2d_X509_NAME(x509_issuer_name, &p);
	if (!ADBG_EXPECT_COMPARE_SIGNED(c, x509_issuer_name_der_size, >, 0))
		goto out;

	/* Extract certificate's serial number */
	x509_serial_number = X509_get_serialNumber(x509_cert);
	if (!ADBG_EXPECT_NOT_NULL(c, x509_serial_number))
		goto out;

	x509_serial_number_der_size = i2d_ASN1_INTEGER(x509_serial_number, NULL);
	if (!ADBG_EXPECT_COMPARE_SIGNED(c, x509_serial_number_der_size, >, 0))
		goto out;

	x509_serial_number_der = OPENSSL_malloc(x509_serial_number_der_size);
	if (!ADBG_EXPECT_NOT_NULL(c, x509_serial_number_der))
		goto out;

	p = x509_serial_number_der;
	x509_serial_number_der_size = i2d_ASN1_INTEGER(x509_serial_number, &p);
	if (!ADBG_EXPECT_COMPARE_SIGNED(c, x509_serial_number_der_size, >, 0))
		goto out;

	/* Create the actual object in session */
	assert(certificate_object[7].type == CKA_VALUE);
	certificate_object[7].pValue = x509_cert_der;
	certificate_object[7].ulValueLen = x509_cert_der_size;

	assert(certificate_object[8].type == CKA_ISSUER);
	certificate_object[8].pValue = x509_issuer_name_der;
	certificate_object[8].ulValueLen = x509_issuer_name_der_size;

	assert(certificate_object[9].type == CKA_SUBJECT);
	certificate_object[9].pValue = x509_subject_name_der;
	certificate_object[9].ulValueLen = x509_subject_name_der_size;

	assert(certificate_object[10].type == CKA_SERIAL_NUMBER);
	certificate_object[10].pValue = x509_serial_number_der;
	certificate_object[10].ulValueLen = x509_serial_number_der_size;

	rv = C_CreateObject(session, certificate_object,
			    ARRAY_SIZE(certificate_object), &obj_hdl);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	rv = C_DestroyObject(session, obj_hdl);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	Do_ADBG_EndSubCase(c, NULL);

	Do_ADBG_BeginSubCase(c, "Import X.509 Certificate with default values");

	/* Create the actual object in session */
	assert(certificate_object2[5].type == CKA_VALUE);
	certificate_object2[5].pValue = x509_cert_der;
	certificate_object2[5].ulValueLen = x509_cert_der_size;

	assert(certificate_object2[6].type == CKA_ISSUER);
	certificate_object2[6].pValue = x509_issuer_name_der;
	certificate_object2[6].ulValueLen = x509_issuer_name_der_size;

	assert(certificate_object2[7].type == CKA_SUBJECT);
	certificate_object2[7].pValue = x509_subject_name_der;
	certificate_object2[7].ulValueLen = x509_subject_name_der_size;

	assert(certificate_object2[8].type == CKA_SERIAL_NUMBER);
	certificate_object2[8].pValue = x509_serial_number_der;
	certificate_object2[8].ulValueLen = x509_serial_number_der_size;

	rv = C_CreateObject(session, certificate_object2,
			    ARRAY_SIZE(certificate_object2), &obj_hdl);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	rv = C_DestroyObject(session, obj_hdl);
	if (!ADBG_EXPECT_CK_OK(c, rv))
		goto out;

	Do_ADBG_EndSubCase(c, NULL);

	Do_ADBG_BeginSubCase(c, "Try import with invalid category");

	/* Create the actual object in session */
	assert(invalid_category_object[6].type == CKA_VALUE);
	invalid_category_object[6].pValue = x509_cert_der;
	invalid_category_object[6].ulValueLen = x509_cert_der_size;

	assert(invalid_category_object[7].type == CKA_ISSUER);
	invalid_category_object[7].pValue = x509_issuer_name_der;
	invalid_category_object[7].ulValueLen = x509_issuer_name_der_size;

	assert(invalid_category_object[8].type == CKA_SUBJECT);
	invalid_category_object[8].pValue = x509_subject_name_der;
	invalid_category_object[8].ulValueLen = x509_subject_name_der_size;

	assert(invalid_category_object[9].type == CKA_SERIAL_NUMBER);
	invalid_category_object[9].pValue = x509_serial_number_der;
	invalid_category_object[9].ulValueLen = x509_serial_number_der_size;

	rv = C_CreateObject(session, invalid_category_object,
			    ARRAY_SIZE(invalid_category_object), &obj_hdl);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_ATTRIBUTE_VALUE_INVALID, rv))
		goto out;

	Do_ADBG_EndSubCase(c, NULL);

	Do_ADBG_BeginSubCase(c, "Try import with invalid category size");

	/* Create the actual object in session */
	assert(invalid_category_object2[6].type == CKA_VALUE);
	invalid_category_object2[6].pValue = x509_cert_der;
	invalid_category_object2[6].ulValueLen = x509_cert_der_size;

	assert(invalid_category_object2[7].type == CKA_ISSUER);
	invalid_category_object2[7].pValue = x509_issuer_name_der;
	invalid_category_object2[7].ulValueLen = x509_issuer_name_der_size;

	assert(invalid_category_object2[8].type == CKA_SUBJECT);
	invalid_category_object2[8].pValue = x509_subject_name_der;
	invalid_category_object2[8].ulValueLen = x509_subject_name_der_size;

	assert(invalid_category_object2[9].type == CKA_SERIAL_NUMBER);
	invalid_category_object2[9].pValue = x509_serial_number_der;
	invalid_category_object2[9].ulValueLen = x509_serial_number_der_size;

	rv = C_CreateObject(session, invalid_category_object2,
			    ARRAY_SIZE(invalid_category_object2), &obj_hdl);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_ATTRIBUTE_VALUE_INVALID, rv))
		goto out;

	Do_ADBG_EndSubCase(c, NULL);

	Do_ADBG_BeginSubCase(c, "Try import with invalid name hash alg size");

	/* Create the actual object in session */
	assert(invalid_name_hash_alg_size[6].type == CKA_VALUE);
	invalid_name_hash_alg_size[6].pValue = x509_cert_der;
	invalid_name_hash_alg_size[6].ulValueLen = x509_cert_der_size;

	assert(invalid_name_hash_alg_size[7].type == CKA_ISSUER);
	invalid_name_hash_alg_size[7].pValue = x509_issuer_name_der;
	invalid_name_hash_alg_size[7].ulValueLen = x509_issuer_name_der_size;

	assert(invalid_name_hash_alg_size[8].type == CKA_SUBJECT);
	invalid_name_hash_alg_size[8].pValue = x509_subject_name_der;
	invalid_name_hash_alg_size[8].ulValueLen = x509_subject_name_der_size;

	assert(invalid_name_hash_alg_size[9].type == CKA_SERIAL_NUMBER);
	invalid_name_hash_alg_size[9].pValue = x509_serial_number_der;
	invalid_name_hash_alg_size[9].ulValueLen = x509_serial_number_der_size;

	rv = C_CreateObject(session, invalid_name_hash_alg_size,
			    ARRAY_SIZE(invalid_name_hash_alg_size), &obj_hdl);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_ATTRIBUTE_VALUE_INVALID, rv))
		goto out;

out:
	OPENSSL_free(x509_serial_number_der);
	OPENSSL_free(x509_issuer_name_der);
	OPENSSL_free(x509_subject_name_der);
	OPENSSL_free(x509_cert_der);
	X509_free(x509_cert);
	BIO_free(x509_bio);

	Do_ADBG_EndSubCase(c, NULL);
close_session:
	ADBG_EXPECT_CK_OK(c, C_CloseSession(session));
close_lib:
	ADBG_EXPECT_CK_OK(c, close_lib());
#endif
}
ADBG_CASE_DEFINE(pkcs11, 1024, xtest_pkcs11_test_1024,
		 "PKCS11: X509 Certificate operations");
