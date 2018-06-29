/*
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
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include "xtest_test.h"
#include "xtest_helpers.h"
#include "tee_api_defines.h"
#include "tee_client_api.h"
#include "xml_client_api.h"

static bool xtest_init = false;

static bool xtest_tee_init(ADBG_Case_t *c)
{
	if (xtest_init)
		return true;

	SHARE_MEM01 = malloc(sizeof(TEEC_SharedMemory));
	if (!ADBG_EXPECT_NOT_NULL(c, SHARE_MEM01))
		goto exit;

	SHARE_MEM02 = malloc(sizeof(TEEC_SharedMemory));
	if (!ADBG_EXPECT_NOT_NULL(c, SHARE_MEM02))
		goto exit;

	SESSION01 = malloc(sizeof(TEEC_Session));
	if (!ADBG_EXPECT_NOT_NULL(c, SESSION01))
		goto exit;

	CONTEXT01 = malloc(sizeof(TEEC_Context));
	if (!ADBG_EXPECT_NOT_NULL(c, CONTEXT01))
		goto exit;

	OPERATION01 = malloc(sizeof(TEEC_Operation));
	if (!ADBG_EXPECT_NOT_NULL(c, OPERATION01))
		goto exit;

	OPERATION02 = malloc(sizeof(TEEC_Operation));
	if (!ADBG_EXPECT_NOT_NULL(c, OPERATION02))
		goto exit;

	xtest_init = true;

	return xtest_init;

exit:
	if (SHARE_MEM01) {
		free(SHARE_MEM01);
		SHARE_MEM01 = NULL;
	}
	if (SHARE_MEM02) {
		free(SHARE_MEM02);
		SHARE_MEM02 = NULL;
	}
	if (SESSION01) {
		free(SESSION01);
		SESSION01 = NULL;
	}
	if (CONTEXT01) {
		free(CONTEXT01);
		CONTEXT01 = NULL;
	}
	if (OPERATION01) {
		free(OPERATION01);
		OPERATION01 = NULL;
	}
	if (OPERATION02) {
		free(OPERATION02);
		OPERATION02 = NULL;
	}

	xtest_init = false;
	return xtest_init;
}

/*29-84-6d*/
static void xtest_tee_7001(ADBG_Case_t *c)
{
	if (!ADBG_EXPECT_TRUE(c, xtest_tee_init(c)))
		return;
	TEEC_SelectApp(CLIENT_APP01, THREAD01_DEFAULT);
	XML_InitializeContext(c, _device, CONTEXT01, TEEC_SUCCESS);
	ADBG_EXPECT(c, TEEC_SUCCESS,
		    AllocateSharedMemory(CONTEXT01, SHARE_MEM01, SIZE_VALUE01,
					 TEEC_MEM_INPUT));
	TEEC_ReleaseSharedMemory(SHARE_MEM01);
	TEEC_FinalizeContext(CONTEXT01);
}
ADBG_CASE_DEFINE(regression, 7001, xtest_tee_7001,
	"Allocate_In RELEASE_SHARED_MEMORY_WHEN_ALLOCATED");

/*29-c2-4c*/
static void xtest_tee_7002(ADBG_Case_t *c)
{
	if (!ADBG_EXPECT_TRUE(c, xtest_tee_init(c)))
		return;
	TEEC_SelectApp(CLIENT_APP01, THREAD01_DEFAULT);
	XML_InitializeContext(c, _device, CONTEXT01, TEEC_SUCCESS);
	ADBG_EXPECT(c, TEEC_ERROR_OUT_OF_MEMORY,
		    AllocateSharedMemory(CONTEXT01, SHARE_MEM01,
					 SIZE_OVER_MEMORY, TEEC_MEM_INPUT));
	TEEC_FinalizeContext(CONTEXT01);
}
ADBG_CASE_DEFINE(regression, 7002, xtest_tee_7002,
	"Allocate_out_of_memory INITIALIZE_CONTEXT_NAMES");

/*29-b0-da*/
static void xtest_tee_7003(ADBG_Case_t *c)
{
	if (!ADBG_EXPECT_TRUE(c, xtest_tee_init(c)))
		return;
	TEEC_SelectApp(CLIENT_APP01, THREAD01_DEFAULT);
	XML_InitializeContext(c, _device, CONTEXT01, TEEC_SUCCESS);
	ADBG_EXPECT(c, TEEC_SUCCESS,
		    AllocateSharedMemory(CONTEXT01, SHARE_MEM01, BIG_SIZE,
					 TEEC_MEM_OUTPUT));
	TEEC_ReleaseSharedMemory(NULL);
	TEEC_ReleaseSharedMemory(SHARE_MEM01);
	TEEC_FinalizeContext(CONTEXT01);
}
ADBG_CASE_DEFINE(regression, 7003, xtest_tee_7003,
	"ReleaseSharedMemory_null RELEASE_SHARED_MEMORY_WHEN_ALLOCATED");

/*29-1c-00*/
static void xtest_tee_7004(ADBG_Case_t *c)
{
	if (!ADBG_EXPECT_TRUE(c, xtest_tee_init(c)))
		return;
	TEEC_SelectApp(CLIENT_APP01, THREAD01_DEFAULT);
	XML_InitializeContext(c, _device, CONTEXT01, TEEC_SUCCESS);
	ADBG_EXPECT(c, TEEC_SUCCESS,
		    AllocateSharedMemory(CONTEXT01, SHARE_MEM01, SIZE_VALUE01,
					 TEEC_MEM_INOUT));
	TEEC_ReleaseSharedMemory(SHARE_MEM01);
	TEEC_FinalizeContext(CONTEXT01);
}
ADBG_CASE_DEFINE(regression, 7004, xtest_tee_7004,
	"Allocate_InOut RELEASE_SHARED_MEMORY_WHEN_ALLOCATED");

/*29-9f-a2*/
static void xtest_tee_7005(ADBG_Case_t *c)
{
	if (!ADBG_EXPECT_TRUE(c, xtest_tee_init(c)))
		return;
	TEEC_SelectApp(CLIENT_APP01, THREAD01_DEFAULT);
	XML_InitializeContext(c, _device, CONTEXT01, TEEC_SUCCESS);
	ADBG_EXPECT(c, TEEC_SUCCESS,
		    RegisterSharedMemory(CONTEXT01, SHARE_MEM01, SIZE_VALUE01,
					 TEEC_MEM_INPUT));
	TEEC_ReleaseSharedMemory(SHARE_MEM01);
	TEEC_FinalizeContext(CONTEXT01);
}
ADBG_CASE_DEFINE(regression, 7005, xtest_tee_7005,
	"Register_In RELEASE_SHARED_MEMORY_WHEN_REGISTERED");

/*29-11-02*/
static void xtest_tee_7006(ADBG_Case_t *c)
{
	if (!ADBG_EXPECT_TRUE(c, xtest_tee_init(c)))
		return;
	TEEC_SelectApp(CLIENT_APP01, THREAD01_DEFAULT);
	XML_InitializeContext(c, _device, CONTEXT01, TEEC_SUCCESS);
	ADBG_EXPECT(c, TEEC_SUCCESS,
		    RegisterSharedMemory(CONTEXT01, SHARE_MEM01, SIZE_VALUE01,
					 TEEC_MEM_OUTPUT));
	TEEC_ReleaseSharedMemory(SHARE_MEM01);
	TEEC_FinalizeContext(CONTEXT01);
}
ADBG_CASE_DEFINE(regression, 7006, xtest_tee_7006,
	"Register_notZeroLength_Out RELEASE_SHARED_MEMORY_WHEN_REGISTERED");

/*29-1f-a2*/
static void xtest_tee_7007(ADBG_Case_t *c)
{
	if (!ADBG_EXPECT_TRUE(c, xtest_tee_init(c)))
		return;
	TEEC_SelectApp(CLIENT_APP01, THREAD01_DEFAULT);
	XML_InitializeContext(c, _device, CONTEXT01, TEEC_SUCCESS);
	ADBG_EXPECT(c, TEEC_SUCCESS,
		    RegisterSharedMemory(CONTEXT01, SHARE_MEM01, BIG_SIZE,
					 TEEC_MEM_INOUT));
	TEEC_ReleaseSharedMemory(SHARE_MEM01);
	TEEC_FinalizeContext(CONTEXT01);
}
ADBG_CASE_DEFINE(regression, 7007, xtest_tee_7007,
	"Register_InOut RELEASE_SHARED_MEMORY_WHEN_REGISTERED");

/*29-2e-8d*/
static void xtest_tee_7008(ADBG_Case_t *c)
{
	if (!ADBG_EXPECT_TRUE(c, xtest_tee_init(c)))
		return;
	TEEC_SelectApp(CLIENT_APP01, THREAD01_DEFAULT);
	XML_InitializeContext(c, _device, CONTEXT01, TEEC_SUCCESS);
	ADBG_EXPECT(c, TEEC_SUCCESS,
		    RegisterSharedMemory(CONTEXT01, SHARE_MEM01, ZERO,
					 TEEC_MEM_OUTPUT));
	TEEC_ReleaseSharedMemory(SHARE_MEM01);
	TEEC_FinalizeContext(CONTEXT01);
}
ADBG_CASE_DEFINE(regression, 7008, xtest_tee_7008,
	"Register_zeroLength_Out RELEASE_SHARED_MEMORY_WHEN_REGISTERED");

/*29-2b-3f*/
static void xtest_tee_7009(ADBG_Case_t *c)
{
	if (!ADBG_EXPECT_TRUE(c, xtest_tee_init(c)))
		return;
	TEEC_SelectApp(CLIENT_APP01, THREAD01_DEFAULT);
	XML_InitializeContext(c, _device, CONTEXT01, TEEC_SUCCESS);
	XML_OpenSession(c, CONTEXT01, SESSION01, &UUID_Unknown,
			TEEC_LOGIN_PUBLIC, NULL, NULL,
			TEEC_ORIGIN_ANY_NOT_TRUSTED_APP, TEEC_UNDEFINED_ERROR);
	TEEC_FinalizeContext(CONTEXT01);
}
ADBG_CASE_DEFINE(regression, 7009, xtest_tee_7009,
	"OpenSession_error_notExistingTA OPEN_SESSION_TARGET_TRUSTED_APP");

/*29-cd-39*/
static void xtest_tee_7010(ADBG_Case_t *c)
{
	if (!ADBG_EXPECT_TRUE(c, xtest_tee_init(c)))
		return;
	TEEC_SelectApp(CLIENT_APP01, THREAD01_DEFAULT);
	XML_InitializeContext(c, _device, CONTEXT01, TEEC_SUCCESS);
	ADBG_EXPECT(c, TEEC_SUCCESS,
		AllocateSharedMemory(CONTEXT01, SHARE_MEM01, ZERO,
				     TEEC_MEM_OUTPUT));
	TEEC_ReleaseSharedMemory(SHARE_MEM01);
	TEEC_FinalizeContext(CONTEXT01);
}
ADBG_CASE_DEFINE(regression, 7010, xtest_tee_7010,
	"Allocate_Out RELEASE_SHARED_MEMORY_WHEN_ALLOCATED");

/*29-a2-e3*/
static void xtest_tee_7013(ADBG_Case_t *c)
{
	if (!ADBG_EXPECT_TRUE(c, xtest_tee_init(c)))
		return;
	TEEC_SelectApp(CLIENT_APP01, THREAD01_DEFAULT);
	XML_InitializeContext(c, _device, CONTEXT01, TEEC_SUCCESS);
	XML_OpenSession(c, CONTEXT01, SESSION01,
			&UUID_TTA_answerSuccessTo_OpenSession_Invoke,
			INVALID_CONNECTION_METHODS, NULL, NULL,
			TEEC_ORIGIN_ANY_NOT_TRUSTED_APP, TEEC_UNDEFINED_ERROR);
	TEEC_FinalizeContext(CONTEXT01);
}
ADBG_CASE_DEFINE(regression, 7013, xtest_tee_7013,
	"OpenSession_error_originTEE OPEN_SESSION_TARGET_TRUSTED_APP");

/*29-db-48*/
static void xtest_tee_7016(ADBG_Case_t *c)
{
	if (!ADBG_EXPECT_TRUE(c, xtest_tee_init(c)))
		return;
	TEEC_SelectApp(CLIENT_APP01, THREAD01_DEFAULT);
	TEEC_CloseSession(NULL);
}
ADBG_CASE_DEFINE(regression, 7016, xtest_tee_7016,
	"CloseSession_null CLOSE_SESSION_IGNORE_SESSION_NULL");

/*29-a1-83*/
static void xtest_tee_7017(ADBG_Case_t *c)
{
	if (!ADBG_EXPECT_TRUE(c, xtest_tee_init(c)))
		return;
	TEEC_SelectApp(CLIENT_APP01, THREAD01_DEFAULT);
	XML_InitializeContext(c, INVALID_NOT_EXISTING_TEE, CONTEXT01,
			      TEEC_UNDEFINED_ERROR);
}
ADBG_CASE_DEFINE(regression, 7017, xtest_tee_7017,
	"InitializeContext_NotExistingTEE INITIALIZE_CONTEXT_NAMES");

/*29-c1-a5*/
static void xtest_tee_7018(ADBG_Case_t *c)
{
	if (!ADBG_EXPECT_TRUE(c, xtest_tee_init(c)))
		return;
	TEEC_SelectApp(CLIENT_APP01, THREAD01_DEFAULT);
	TEEC_FinalizeContext(NULL);
}
ADBG_CASE_DEFINE(regression, 7018, xtest_tee_7018,
	"FinalizeContext_null FINALIZE_CONTEXT_IGNORE_NULL");

/*29-91-aa*/
static void xtest_tee_7019(ADBG_Case_t *c)
{
	if (!ADBG_EXPECT_TRUE(c, xtest_tee_init(c)))
		return;
	TEEC_createThread(CLIENT_APP01, THREAD02);
	TEEC_SelectApp(CLIENT_APP01, THREAD01_DEFAULT);
	XML_InitializeContext(c, _device, CONTEXT01, TEEC_SUCCESS);
	TEEC_SelectApp(CLIENT_APP01, THREAD02);
	thr2_ctx.c = c;
	thr2_ctx.ctx = CONTEXT01;
	ctx_init_finalize(thr2_ctx);
	TEEC_SelectApp(CLIENT_APP01, THREAD01_DEFAULT);
	TEEC_FinalizeContext(CONTEXT01);
}
ADBG_CASE_DEFINE(regression, 7019, xtest_tee_7019,
	"InitializeContext_concurrentContext INITIALIZE_CONTEXT_NAMES");
