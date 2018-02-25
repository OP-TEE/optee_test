/*
 * Copyright (c) 2018, Linaro Limited
 * Copyright (c) 2014, STMicroelectronics International N.V.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <malloc.h>

#include <assert.h>
#include <tee_api_types.h>
#include <ta_crypt.h>
#include <utee_defines.h>
#include <util.h>

#include <pkcs11.h>

#include "xtest_test.h"
#include "xtest_helpers.h"

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

/*
 * Util to find a slot on which to open a session
 */
static CK_RV close_lib(void)
{
	return C_Finalize(0);
}

static CK_RV init_lib_and_find_token_slot(CK_SLOT_ID *slot)
{
	CK_RV rv;
	CK_SLOT_ID_PTR slots;
	CK_ULONG count;

	rv = C_Initialize(0);
	if (rv)
		return rv;

	rv = C_GetSlotList(CK_TRUE, NULL, &count);
	if (rv != CKR_BUFFER_TOO_SMALL)
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

	/* Use the 1st slot */
	*slot = *slots;

bail:
	free(slots);
	if (rv)
		close_lib();

	return rv;
}

static void xtest_tee_test_4101(ADBG_Case_t *c)
{
	CK_RV rv;

	rv = C_Initialize(NULL);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
		return;

	rv = C_Finalize(NULL);
	ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK);
		return;

	rv = C_Initialize(NULL);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
		return;

	rv = C_Initialize(NULL);
	ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==,
					CKR_CRYPTOKI_ALREADY_INITIALIZED);

	rv = C_Finalize(NULL);
	ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK);
}

static void xtest_tee_test_4102(ADBG_Case_t *c)
{
	CK_RV rv;
	CK_SLOT_ID_PTR slot_ids = NULL;
	CK_ULONG slot_count;
	CK_ULONG slot_count2;
	CK_INFO lib_info;
	CK_SLOT_INFO slot_info;
	CK_TOKEN_INFO token_info;
	CK_FUNCTION_LIST_PTR ckfunc_list;
	size_t i;
	size_t j;
	CK_MECHANISM_TYPE_PTR mecha_types = NULL;

	rv = C_Initialize(NULL);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
		return;

	rv = C_GetInfo(&lib_info);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
		goto out;

	rv = C_GetFunctionList(&ckfunc_list);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
		goto out;

	slot_count2 = 0;
	rv = C_GetSlotList(0, NULL, &slot_count2);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_BUFFER_TOO_SMALL))
		goto out;

	slot_count = 0;

	rv = C_GetSlotList(1, NULL, &slot_count);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_BUFFER_TOO_SMALL))
		goto out;

	slot_ids = calloc(slot_count, sizeof(CK_SLOT_ID));
	if (!ADBG_EXPECT_TRUE(c, !slot_count || slot_ids))
		goto out;

	rv = C_GetSlotList(1, slot_ids, &slot_count);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
		goto out;

	for (i = 0; i < slot_count; i++) {
		CK_SLOT_ID slot = *(slot_ids + i);
		CK_ULONG mecha_count;

		rv = C_GetSlotInfo(slot, &slot_info);
		if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
			goto out;

		rv = C_GetTokenInfo(slot, &token_info);
		if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
			goto out;

		mecha_count = 0;
		rv = C_GetMechanismList(slot, NULL, &mecha_count);
		if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==,
						  CKR_BUFFER_TOO_SMALL))
			goto out;

		mecha_types = calloc(mecha_count, sizeof(CK_MECHANISM_TYPE));
		if (!ADBG_EXPECT_TRUE(c, !mecha_count || mecha_types))
			goto out;

		rv = C_GetMechanismList(slot, mecha_types, &mecha_count);
		if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
			goto out;

		for (j = 0; j < mecha_count; j++) {
			CK_MECHANISM_TYPE type = *(mecha_types + j);
			CK_MECHANISM_INFO mecha_info;

			rv = C_GetMechanismInfo(slot, type, &mecha_info);
			if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
				goto out;
		}

		free(mecha_types);
		mecha_types = NULL;
	}

out:
	free(slot_ids);
	free(mecha_types);

	rv = C_Finalize(NULL);
	ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK);
}

static void xtest_tee_test_4103(ADBG_Case_t *c)
{
	CK_RV rv;
	CK_SLOT_ID slot;
	CK_SESSION_HANDLE session[3];
	CK_FLAGS session_flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;

	rv = init_lib_and_find_token_slot(&slot);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
		return;

	/* Open 3 sessions */
	rv = C_OpenSession(slot, session_flags, NULL, 0, &session[0]);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
		goto bail;

	rv = C_OpenSession(slot, session_flags, NULL, 0, &session[1]);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
		goto bail;

	rv = C_OpenSession(slot, session_flags, NULL, 0, &session[2]);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
		goto bail;

	/* Close 2 of them */
	rv = C_CloseSession(session[0]);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
		goto bail;

	rv = C_CloseSession(session[1]);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
		goto bail;

	/* Close all remaing sessions */
	rv = C_CloseAllSessions(slot);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
		goto bail;

	/* Should failed to close non existing session */
	rv = C_CloseSession(session[2]);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, !=, CKR_OK))
		goto bail;

	/* Last open/closure of a session */
	rv = C_OpenSession(slot, session_flags, NULL, 0, &session[0]);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
		goto bail;

	rv = C_CloseSession(session[0]);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
		goto bail;

	rv = C_OpenSession(slot, session_flags, NULL, 0, &session[1]);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
		goto bail;

bail:
	rv = close_lib();
	ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK);
}

static void xtest_tee_test_4104(ADBG_Case_t *c)
{
	CK_RV rv;
	CK_SLOT_ID slot;
	CK_TOKEN_INFO token_info;
	char pin0[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8 };
	char pin1[] = { 0, 1, 2, 3, 0, 5, 6, 7, 8, 9, 10 };
	char label[] = "sks test token";
	char label32[32];

	rv = init_lib_and_find_token_slot(&slot);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
		return;

	rv = C_GetTokenInfo(slot, &token_info);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
		goto bail;

	if (strlen(label) < 32) {
		int sz = strlen(label);

		memcpy(label32, label, sz);
		memset(&label32[sz], ' ', 32 - sz);
	} else {
		memcpy(label32, label, 32);
	}

	if (token_info.flags & CKF_TOKEN_INITIALIZED) {

		// "Token is already initialized.\n"

		rv = C_InitToken(slot, (CK_UTF8CHAR_PTR)pin1, sizeof(pin1),
				 (CK_UTF8CHAR_PTR)label32);
		if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, !=, CKR_OK))
			goto bail;

		rv = C_GetTokenInfo(slot, &token_info);
		if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
			goto bail;

		/* Token should have set CKF_SO_PIN_COUNT_LOW to 1 */
		if (!ADBG_EXPECT_TRUE(c, !!(token_info.flags &
						CKF_SO_PIN_COUNT_LOW))) {
			rv = CKR_GENERAL_ERROR;
			goto bail;
		}

		rv = C_InitToken(slot, (CK_UTF8CHAR_PTR)pin0, sizeof(pin0),
				 (CK_UTF8CHAR_PTR)label32);
		if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
			goto bail;

		rv = C_GetTokenInfo(slot, &token_info);
		if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
			goto bail;

		/*
		 * Token should have reset CKF_SO_PIN_COUNT_LOW to 0.
		 * Other flags should show a sane initialized state.
		 */
		if (!ADBG_EXPECT_TRUE(c, !(token_info.flags &
						CKF_SO_PIN_COUNT_LOW)) ||
		    !ADBG_EXPECT_TRUE(c, !!(token_info.flags &
						CKF_TOKEN_INITIALIZED)) ||
		    !ADBG_EXPECT_TRUE(c, !(token_info.flags &
						CKF_ERROR_STATE)) ||
		    !ADBG_EXPECT_TRUE(c, !(token_info.flags &
						CKF_USER_PIN_INITIALIZED))) {
			rv = CKR_GENERAL_ERROR;
			goto bail;
		}
	} else {
		//("Token was not yet initialized.\n");
		/*  We must provision the SO PIN */

		rv = C_InitToken(slot, (CK_UTF8CHAR_PTR)pin0, sizeof(pin0),
				 (CK_UTF8CHAR_PTR)label32);
		if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
			goto bail;

		rv = C_GetTokenInfo(slot, &token_info);
		if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
			goto bail;

		if (!ADBG_EXPECT_TRUE(c, !!(token_info.flags &
						CKF_TOKEN_INITIALIZED)) ||
		    !ADBG_EXPECT_TRUE(c, !(token_info.flags &
						CKF_ERROR_STATE)) ||
		    !ADBG_EXPECT_TRUE(c, !(token_info.flags &
						CKF_USER_PIN_INITIALIZED))) {
			rv = CKR_GENERAL_ERROR;
			goto bail;
		}
	}

bail:
	rv = close_lib();
	ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK);
}

/* bad key type */
static CK_ATTRIBUTE cktest_generate_gensecret_object_error1[] = {
	{ CKA_CLASS, &(CK_OBJECT_CLASS){CKO_SECRET_KEY},
						sizeof(CK_OBJECT_CLASS) },
	{ CKA_KEY_TYPE, &(CK_KEY_TYPE){CKK_AES}, sizeof(CK_KEY_TYPE) },
	{ CKA_ENCRYPT, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_VALUE_LEN, &(CK_ULONG){16}, sizeof(CK_ULONG) },
};

/* missing VALUE_LEN */
static CK_ATTRIBUTE cktest_generate_gensecret_object_error2[] = {
	{ CKA_CLASS, &(CK_OBJECT_CLASS){CKO_SECRET_KEY},
						sizeof(CK_OBJECT_CLASS) },
	{ CKA_KEY_TYPE, &(CK_KEY_TYPE){CKK_GENERIC_SECRET},
						sizeof(CK_KEY_TYPE) },
	{ CKA_ENCRYPT, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
};

/* bad object class */
static CK_ATTRIBUTE cktest_generate_gensecret_object_error3[] = {
	{ CKA_CLASS, &(CK_OBJECT_CLASS){CKO_DATA}, sizeof(CK_OBJECT_CLASS) },
	{ CKA_KEY_TYPE, &(CK_KEY_TYPE){CKK_GENERIC_SECRET},
						sizeof(CK_KEY_TYPE) },
	{ CKA_ENCRYPT, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_VALUE_LEN, &(CK_ULONG){16}, sizeof(CK_ULONG) },
};

/* Valid template to generate a generic secret */
static CK_ATTRIBUTE cktest_generate_gensecret_object[] = {
	{ CKA_CLASS, &(CK_OBJECT_CLASS){CKO_SECRET_KEY},
						sizeof(CK_OBJECT_CLASS) },
	{ CKA_KEY_TYPE, &(CK_KEY_TYPE){CKK_GENERIC_SECRET},
						sizeof(CK_KEY_TYPE) },
	{ CKA_ENCRYPT, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_DECRYPT, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_COPYABLE, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_MODIFIABLE, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_EXTRACTABLE, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_VALUE_LEN, &(CK_ULONG){16}, sizeof(CK_ULONG) },
};

/*  Valid template to generate an all AES purpose key */
static CK_ATTRIBUTE cktest_generate_aes_object[] = {
	{ CKA_CLASS, &(CK_OBJECT_CLASS){CKO_SECRET_KEY},
						sizeof(CK_OBJECT_CLASS) },
	{ CKA_KEY_TYPE, &(CK_KEY_TYPE){CKK_AES}, sizeof(CK_KEY_TYPE) },
	{ CKA_ENCRYPT, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_DECRYPT, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_COPYABLE, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_MODIFIABLE, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_EXTRACTABLE, &(CK_BBOOL){CK_TRUE}, sizeof(CK_BBOOL) },
	{ CKA_VALUE_LEN, &(CK_ULONG){16}, sizeof(CK_ULONG) },
};

static CK_MECHANISM mecha_generate_gensecret = {
	CKM_GENERIC_SECRET_KEY_GEN, NULL_PTR, 0
};

static CK_MECHANISM mecha_generate_aes_generic = {
	CKM_AES_KEY_GEN, NULL_PTR, 0
};

/* Generate a generic secret */
static void xtest_tee_test_4105(ADBG_Case_t *c)
{
	CK_RV rv;
	CK_SLOT_ID slot;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE obj_hld;
	CK_FLAGS session_flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;

	rv = init_lib_and_find_token_slot(&slot);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
		return;

	rv = C_OpenSession(slot, session_flags, NULL, 0, &session);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
		goto bail;

	/*
	 * Generate a Generic Secret object.
	 * Try to decrypt with it, it should fail...
	 */
	rv = C_GenerateKey(session, &mecha_generate_gensecret,
			   cktest_generate_gensecret_object,
			   ARRAY_SIZE(cktest_generate_gensecret_object),
			   &obj_hld);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
		goto bail;

	rv = C_EncryptInit(session, &cktest_aes_cbc_mechanism, obj_hld);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==,
					  CKR_KEY_FUNCTION_NOT_PERMITTED))
		goto bail;

	rv = C_DestroyObject(session, obj_hld);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
		goto bail;

	/*
	 * Generate Generic Secret objects using invalid templates
	 */
	rv = C_GenerateKey(session, &mecha_generate_gensecret,
			   cktest_generate_gensecret_object_error1,
			   ARRAY_SIZE(cktest_generate_gensecret_object_error1),
			   &obj_hld);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, !=, CKR_OK))
		goto bail;

	rv = C_GenerateKey(session, &mecha_generate_gensecret,
			   cktest_generate_gensecret_object_error2,
			   ARRAY_SIZE(cktest_generate_gensecret_object_error2),
			   &obj_hld);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, !=, CKR_OK))
		goto bail;

	rv = C_GenerateKey(session, &mecha_generate_gensecret,
			   cktest_generate_gensecret_object_error3,
			   ARRAY_SIZE(cktest_generate_gensecret_object_error3),
			   &obj_hld);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, !=, CKR_OK))
		goto bail;

	/*
	 * Generate a 128bit AES symmetric key
	 * Try to decrypt with it, it should succeed.
	 */
	rv = C_GenerateKey(session, &mecha_generate_aes_generic,
			   cktest_generate_aes_object,
			   ARRAY_SIZE(cktest_generate_aes_object),
			   &obj_hld);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
		goto bail;


	rv = C_EncryptInit(session, &cktest_aes_cbc_mechanism, obj_hld);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
		goto bail;

	rv = C_EncryptFinal(session, NULL, NULL);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
		goto bail;

	rv = C_DestroyObject(session, obj_hld);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
		goto bail;

bail:
	rv = C_CloseSession(session);
	ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK);

	rv = close_lib();
	ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK);
}

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
static void test_create_destroy_single_object(ADBG_Case_t *c, int persistent)
{
	CK_RV rv;
	CK_SLOT_ID slot;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE obj_hld;
	CK_FLAGS session_flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;

	rv = init_lib_and_find_token_slot(&slot);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
		return;

	rv = C_OpenSession(slot, session_flags, NULL, 0, &session);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
		goto bail;

	if (persistent)
		rv = C_CreateObject(session, cktest_token_object,
				    ARRAY_SIZE(cktest_token_object),
				    &obj_hld);
	else
		rv = C_CreateObject(session, cktest_session_object,
				    ARRAY_SIZE(cktest_session_object),
				    &obj_hld);

	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
		goto bail;

	rv = C_DestroyObject(session, obj_hld);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
		goto bail;

bail:
	rv = C_CloseSession(session);
	ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK);

	rv = close_lib();
	ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK);

}

static void test_create_destroy_session_objects(ADBG_Case_t *c)
{
	CK_RV rv;
	CK_SLOT_ID slot;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE obj_hld[512];
	CK_FLAGS session_flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	size_t n;

	rv = init_lib_and_find_token_slot(&slot);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
		return;

	rv = C_OpenSession(slot, session_flags, NULL, 0, &session);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
		goto bail;

	for (n = 0; n < ARRAY_SIZE(obj_hld); n++) {
		rv = C_CreateObject(session, cktest_session_object,
				    ARRAY_SIZE(cktest_session_object),
				    obj_hld + n);

		if (rv == CKR_DEVICE_MEMORY)
			break;

		if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK)) {
			n--;
			break;
		}
	}

	Do_ADBG_Log("    created object count: %zu", n);

	rv = C_CloseSession(session);
	ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK);

	rv = C_OpenSession(slot, session_flags, NULL, 0, &session);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
		goto bail;

	rv = C_CreateObject(session, cktest_session_object,
			    ARRAY_SIZE(cktest_session_object),
			    obj_hld);

	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
		goto bail;

bail:
	rv = C_CloseSession(session);
	ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK);

	rv = close_lib();
	ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK);

}

static void xtest_tee_test_4106(ADBG_Case_t *c)
{
	Do_ADBG_BeginSubCase(c, "Create and destroy a volatile object");
	test_create_destroy_single_object(c, 0);
	Do_ADBG_EndSubCase(c, NULL);

	Do_ADBG_BeginSubCase(c, "Create and destroy a persistent object");
	test_create_destroy_single_object(c, 1);
	Do_ADBG_EndSubCase(c, NULL);

	Do_ADBG_BeginSubCase(c, "Create and destroy a persistent object");
	test_create_destroy_session_objects(c);
	Do_ADBG_EndSubCase(c, NULL);
}

/* Create session object and token object from a session */
static void test_create_objects_in_session(ADBG_Case_t *c, int readwrite)
{
	CK_RV rv;
	CK_SLOT_ID slot;
	CK_SESSION_HANDLE session;
	CK_OBJECT_HANDLE token_obj_hld;
	CK_OBJECT_HANDLE session_obj_hld;
	CK_FLAGS session_flags = CKF_SERIAL_SESSION;

	rv = init_lib_and_find_token_slot(&slot);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
		return;

	if (readwrite)
		session_flags |= CKF_RW_SESSION;

	rv = C_OpenSession(slot, session_flags, NULL, 0, &session);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
		goto bail;

	rv = C_CreateObject(session, cktest_token_object,
			    ARRAY_SIZE(cktest_token_object),
			    &token_obj_hld);

	if (readwrite) {
		if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
			goto bail;
	} else {
		if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==,
						     CKR_SESSION_READ_ONLY))
			goto bail;
	}

	rv = C_CreateObject(session, cktest_session_object,
			    ARRAY_SIZE(cktest_session_object),
			    &session_obj_hld);

	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
		goto bail;

	if (readwrite)
		rv = C_DestroyObject(session, token_obj_hld);

	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
		goto bail;

	rv = C_DestroyObject(session, session_obj_hld);
	ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK);

bail:
	rv = C_CloseSession(session);
	ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK);

	rv = close_lib();
	ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK);
}

static void xtest_tee_test_4107(ADBG_Case_t *c)
{
	Do_ADBG_BeginSubCase(c, "Create objects in a read-only session");
	test_create_objects_in_session(c, 0);
	Do_ADBG_EndSubCase(c, NULL);

	Do_ADBG_BeginSubCase(c, "Create objects in a read/write session");
	test_create_objects_in_session(c, 1);
	Do_ADBG_EndSubCase(c, NULL);
}

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
	CK_RV rv;
	CK_OBJECT_HANDLE object;

	switch (mode) {
	case TEE_MODE_ENCRYPT:
	case TEE_MODE_DECRYPT:
		break;
	default:
		ADBG_EXPECT_TRUE(c, 0);
	}

	rv = C_CreateObject(session, attr_key, attr_count, &object);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
		goto bail;

	if (mode == TEE_MODE_ENCRYPT)
		rv = C_EncryptInit(session, mechanism, object);
	if (mode == TEE_MODE_DECRYPT)
		rv = C_DecryptInit(session, mechanism, object);

	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, expected_rc)) {
		rv = CKR_GENERAL_ERROR;
		goto bail;
	}

	if (rv == CKR_OK) {
		if (mode == TEE_MODE_ENCRYPT)
			rv = C_EncryptFinal(session, NULL, NULL);
		if (mode == TEE_MODE_DECRYPT)
			rv = C_DecryptFinal(session, NULL, NULL);

		if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
			goto bail;
	}

	rv = C_DestroyObject(session, object);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
		goto bail;

bail:
	return rv;
}

CK_KEY_ALLOWED_AES_ENC_TEST(cktest_aes_enc_only_cts, allowed_only_aes_cts);
CK_KEY_ALLOWED_AES_DEC_TEST(cktest_aes_dec_only_ctr, allowed_only_aes_ctr);

static void xtest_tee_test_4108(ADBG_Case_t *c)
{
	CK_RV rv;
	CK_SLOT_ID slot;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_FLAGS session_flags = CKF_SERIAL_SESSION;
	size_t n;

	rv = init_lib_and_find_token_slot(&slot);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
		return;

	rv = C_OpenSession(slot, session_flags, NULL, 0, &session);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
		goto bail;

	for (n = 0; n < ARRAY_SIZE(cktest_allowed_valid); n++) {

		rv = cipher_init_final(c, session,
					cktest_allowed_valid[n].attr_key,
					cktest_allowed_valid[n].attr_count,
					cktest_allowed_valid[n].mechanism,
					TEE_MODE_ENCRYPT,
					CKR_OK);
		if (rv)
			goto bail;
	}

	for (n = 0; n > ARRAY_SIZE(cktest_allowed_invalid); n++) {

		rv = cipher_init_final(c, session,
					cktest_allowed_valid[n].attr_key,
					cktest_allowed_valid[n].attr_count,
					cktest_allowed_valid[n].mechanism,
					TEE_MODE_ENCRYPT,
					CKR_KEY_FUNCTION_NOT_PERMITTED);
		if (rv)
			goto bail;
	}

bail:
	rv = C_CloseSession(session);
	ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK);

	rv = close_lib();
	ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK);
}

static void xtest_tee_test_4109(ADBG_Case_t *c)
{
	CK_RV rv;
	CK_SLOT_ID slot;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_FLAGS session_flags = CKF_SERIAL_SESSION;

	rv = init_lib_and_find_token_slot(&slot);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
		return;

	rv = C_OpenSession(slot, session_flags, NULL, 0, &session);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
		goto bail;

	rv = cipher_init_final(c, session,
				cktest_aes_enc_only_cts,
				ARRAY_SIZE(cktest_aes_enc_only_cts),
				&cktest_aes_cts_mechanism,
				TEE_MODE_ENCRYPT,
				CKR_OK);
	if (rv)
		goto bail;

	rv = cipher_init_final(c, session,
				cktest_aes_enc_only_cts,
				ARRAY_SIZE(cktest_aes_enc_only_cts),
				&cktest_aes_cts_mechanism,
				TEE_MODE_DECRYPT,
				CKR_KEY_FUNCTION_NOT_PERMITTED);
	if (rv)
		goto bail;

	rv = cipher_init_final(c, session,
				cktest_aes_dec_only_ctr,
				ARRAY_SIZE(cktest_aes_dec_only_ctr),
				&cktest_aes_ctr_mechanism,
				TEE_MODE_ENCRYPT,
				CKR_KEY_FUNCTION_NOT_PERMITTED);
	if (rv)
		goto bail;

	rv = cipher_init_final(c, session,
				cktest_aes_dec_only_ctr,
				ARRAY_SIZE(cktest_aes_dec_only_ctr),
				&cktest_aes_ctr_mechanism,
				TEE_MODE_DECRYPT,
				CKR_OK);
	if (rv)
		goto bail;

bail:
	rv = C_CloseSession(session);
	ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK);

	rv = close_lib();
	ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK);
}

/*
 * The test below belongs to the regression 41xx test. As it rely on test
 * vectors define for the 40xx test, this test sequence in implemented here.
 * The test below check compliance of crypto algorithms called throug the SKS
 * PKCS#11 interface.
 */
void run_xtest_tee_test_4110(ADBG_Case_t *c, CK_SLOT_ID slot);
void run_xtest_tee_test_4111(ADBG_Case_t *c, CK_SLOT_ID slot);
void run_xtest_tee_test_4112(ADBG_Case_t *c, CK_SLOT_ID slot);

static void xtest_tee_test_4110(ADBG_Case_t *c)
{
	CK_RV rv;
	CK_SLOT_ID slot;

	rv = init_lib_and_find_token_slot(&slot);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
		return;

	run_xtest_tee_test_4110(c, slot);

	rv = close_lib();
	ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK);
}

static void xtest_tee_test_4111(ADBG_Case_t *c)
{
	CK_RV rv;
	CK_SLOT_ID slot;

	rv = init_lib_and_find_token_slot(&slot);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
		return;

	run_xtest_tee_test_4111(c, slot);

	rv = close_lib();
	ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK);
}

static void xtest_tee_test_4112(ADBG_Case_t *c)
{
	CK_RV rv;
	CK_SLOT_ID slot;

	rv = init_lib_and_find_token_slot(&slot);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
		return;

	run_xtest_tee_test_4112(c, slot);

	rv = close_lib();
	ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK);
}

static CK_RV open_cipher_session(ADBG_Case_t *c,
				 CK_SLOT_ID slot, CK_SESSION_HANDLE_PTR session,
				 CK_ATTRIBUTE_PTR attr_key, CK_ULONG attr_count,
				 CK_MECHANISM_PTR mechanism, uint32_t mode)
{
	CK_RV rv;
	CK_OBJECT_HANDLE object;
	CK_FLAGS session_flags = CKF_SERIAL_SESSION;

	switch (mode) {
	case TEE_MODE_ENCRYPT:
	case TEE_MODE_DECRYPT:
		break;
	default:
		ADBG_EXPECT_TRUE(c, 0);
	}

	rv = C_OpenSession(slot, session_flags, NULL, 0, session);
	if (rv == CKR_DEVICE_MEMORY)
		return rv;
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
		goto bail;

	rv = C_CreateObject(*session, attr_key, attr_count, &object);
	if (rv == CKR_DEVICE_MEMORY)
		return rv;
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
		goto bail;

	if (mode == TEE_MODE_ENCRYPT)
		rv = C_EncryptInit(*session, mechanism, object);
	if (mode == TEE_MODE_DECRYPT)
		rv = C_DecryptInit(*session, mechanism, object);

	if (rv == CKR_DEVICE_MEMORY)
		return rv;
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK)) {
		rv = CKR_GENERAL_ERROR;
		goto bail;
	}

bail:
	return rv;
}

static void xtest_tee_test_4113(ADBG_Case_t *c)
{
	CK_RV rv;
	CK_SLOT_ID slot;
	CK_SESSION_HANDLE sessions[128];
	size_t n;

	for (n = 0; n < ARRAY_SIZE(sessions); n++)
		sessions[n] = CK_INVALID_HANDLE;

	rv = init_lib_and_find_token_slot(&slot);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
		return;

	for (n = 0; n < ARRAY_SIZE(sessions); n++) {


		rv = open_cipher_session(c, slot, sessions + n,
					 cktest_allowed_valid[0].attr_key,
					 cktest_allowed_valid[0].attr_count,
					 cktest_allowed_valid[0].mechanism,
					 TEE_MODE_ENCRYPT);

		if (rv == CKR_DEVICE_MEMORY)
			break;

		if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
			goto bail;
	}

	Do_ADBG_Log("    created sessions count: %zu", n);

	for (n = 0; n < ARRAY_SIZE(sessions); n++) {
		if (sessions[n] == CK_INVALID_HANDLE)
			continue;

		rv = C_CloseSession(sessions[n]);
		ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK);
		sessions[n] = CK_INVALID_HANDLE;
	}

	rv = open_cipher_session(c, slot, sessions + n,
				 cktest_allowed_valid[0].attr_key,
				 cktest_allowed_valid[0].attr_count,
				 cktest_allowed_valid[0].mechanism,
				 TEE_MODE_ENCRYPT);

	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK))
		goto bail;

	rv = C_CloseSession(sessions[0]);
	ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK);
	sessions[0] = CK_INVALID_HANDLE;

bail:
	for (n = 0; n < ARRAY_SIZE(sessions); n++) {
		if (sessions[n] == CK_INVALID_HANDLE)
			continue;

		rv = C_CloseSession(sessions[n]);
		ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK);
	}

	rv = close_lib();
	ADBG_EXPECT_COMPARE_UNSIGNED(c, rv, ==, CKR_OK);
}

ADBG_CASE_DEFINE(regression, 4101, xtest_tee_test_4101,
		"Initialize and close Cryptoki library");
ADBG_CASE_DEFINE(regression, 4102, xtest_tee_test_4102,
		"Connect token and get some token info");
ADBG_CASE_DEFINE(regression, 4103, xtest_tee_test_4103,
		"Open and close PKCS#11 sessions");
ADBG_CASE_DEFINE(regression, 4104, xtest_tee_test_4104,
		"Login tests (TODO: still weak)");
ADBG_CASE_DEFINE(regression, 4105, xtest_tee_test_4105,
		"Generate objects");
ADBG_CASE_DEFINE(regression, 4106, xtest_tee_test_4106,
		"Create and destroy volatile and persistent object");
ADBG_CASE_DEFINE(regression, 4107, xtest_tee_test_4107,
		"Create objects in read-only and read-write sessions");
ADBG_CASE_DEFINE(regression, 4108, xtest_tee_test_4108,
		"Check ciphering with valid and invalid keys #1");
ADBG_CASE_DEFINE(regression, 4109, xtest_tee_test_4109,
		"Check ciphering with valid and invalid keys #2");
ADBG_CASE_DEFINE(regression, 4110, xtest_tee_test_4110,
		"Compliance of ciphering processings");
ADBG_CASE_DEFINE(regression, 4111, xtest_tee_test_4111,
		"Compliance of MAC signing processings");
ADBG_CASE_DEFINE(regression, 4112, xtest_tee_test_4112,
		"Compliance of AES CCM/GCM ciphering processings");
ADBG_CASE_DEFINE(regression, 4113, xtest_tee_test_4113, /*  TODO: rename 4110 */
		"Check operations release at session closure");

