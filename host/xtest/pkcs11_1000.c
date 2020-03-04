/*
 * Copyright (c) 2018, Linaro Limited
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

#include <ck_debug.h>
#include <inttypes.h>
#include <pkcs11.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "xtest_test.h"
#include "xtest_helpers.h"

static void xtest_tee_test_1000(ADBG_Case_t *c)
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

ADBG_CASE_DEFINE(pkcs11, 1000, xtest_tee_test_1000,
		"Initialize and close Cryptoki library");

static void xtest_tee_test_1001(ADBG_Case_t *c)
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
	    !ADBG_EXPECT_NOT_NULL(c, ckfunc_list->C_GetTokenInfo))
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
	Do_ADBG_BeginSubCase(c, "Test C_Get*Info() with invalid reference");

	rv = C_GetSlotInfo(max_slot_id + 1, &slot_info);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_SLOT_ID_INVALID, rv))
		goto out;

	rv = C_GetTokenInfo(max_slot_id + 1, &token_info);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_SLOT_ID_INVALID, rv))
		goto out;

	rv = C_GetSlotInfo(ULONG_MAX, &slot_info);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_SLOT_ID_INVALID, rv))
		goto out;

	rv = C_GetTokenInfo(ULONG_MAX, &token_info);
	if (!ADBG_EXPECT_CK_RESULT(c, CKR_SLOT_ID_INVALID, rv))
		goto out;

out:
	Do_ADBG_EndSubCase(c, NULL);
	free(slot_ids);

	rv = C_Finalize(NULL);
	ADBG_EXPECT_CK_OK(c, rv);
}

ADBG_CASE_DEFINE(pkcs11, 1001, xtest_tee_test_1001,
		 "PKCS11: List PKCS#11 slots and get information from");
