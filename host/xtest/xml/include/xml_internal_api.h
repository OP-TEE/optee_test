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

#ifndef XML_INTERNAL_API_H_
#define XML_INTERNAL_API_H_

#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include "tee_client_api.h"
#undef TA_UUID
#include "TTA_TCF.h"
#include "xml_common_api.h"

#define Invoke_MaskUnmaskCancellations Invoke_Simple_Function
#define Invoke_ProcessTAInvoke_Payload_Value Invoke_Simple_Function
#define Invoke_ProcessTAInvoke_Payload_Value_In_Out Invoke_Simple_Function
#define Invoke_ProcessTAInvoke_Payload_Memref Invoke_Simple_Function

#define Invoke_GetPropertyAsBool_withoutEnum Invoke_GetPropertyAsXXX_withoutEnum
#define Invoke_GetPropertyAsU32_withoutEnum Invoke_GetPropertyAsXXX_withoutEnum
#define Invoke_GetPropertyAsUUID_withoutEnum Invoke_GetPropertyAsXXX_withoutEnum
#define Invoke_GetPropertyAsIdentity_withoutEnum \
	Invoke_GetPropertyAsXXX_withoutEnum
#define Invoke_GetPropertyAsBinaryBlock_withoutEnum \
	Invoke_GetPropertyAsXXX_withoutEnum
#define Invoke_GetPropertyAsString_withoutEnum \
	Invoke_GetPropertyAsXXX_withoutEnum

#define Invoke_GetPropertyAsXXXX_fromEnum Invoke_StartPropertyEnumerator

#define Invoke_FreePropertyEnumerator Invoke_ResetPropertyEnumerator
#define Invoke_GetNextProperty_enumNotStarted Invoke_ResetPropertyEnumerator

#define Invoke_ProcessTAInvoke_DeadErrorSuccess \
	Invoke_ProcessInvokeTAOpenSession

#define CLIENT_APP01                    NULL

#define TEEC_UNDEFINED_ERROR 0xDEADDEAD

#define TEEC_ORIGIN_ANY_NOT_TRUSTED_APP  0x00000005
/* same as TEE_ORIGIN_NOT_TRUSTED_APP */

#define SIZE_ZERO 0

#define TEE_ERROR_TOO_SHORT_BUFFER TEE_ERROR_SHORT_BUFFER

/* Test data defines */
static pthread_t THREAD01_DEFAULT;
static pthread_t THREAD02;

static TEEC_SharedMemory *SHARE_MEM01;
static TEEC_SharedMemory *SHARE_MEM02;
static TEEC_Session *SESSION01;
static TEEC_Session *SESSION02;
/* Requires 2 sessions as we are opeing
	multiple sessions at the same time */
static TEEC_Context *CONTEXT01;
static TEEC_Context *CONTEXT02;
static TEEC_Operation *OPERATION01;

/* Return ORIGIN */
static uint32_t ret_orig;

static uint32_t BIG_SIZE = 1024;

char *NO_DATA;
unsigned int ENUMERATOR1;

#define ANY_OWNER_NOT_SET 0
#define ANY_OWNER_SET_ACCESS_READ (TEE_MEMORY_ACCESS_ANY_OWNER | \
				   TEE_MEMORY_ACCESS_READ)
#define ANY_OWNER_SET_ACCESS_WRITE (TEE_MEMORY_ACCESS_ANY_OWNER | \
				    TEE_MEMORY_ACCESS_WRITE)
#define ANY_OWNER_SET_ACCESS_READ_WRITE (TEE_MEMORY_ACCESS_ANY_OWNER | \
					 TEE_MEMORY_ACCESS_READ | \
					 TEE_MEMORY_ACCESS_WRITE)

#define SMALL_SIZE 0xA

#define CMD_TEE_GetInstanceData 0x00000101
#define CMD_TEE_SetInstanceData 0x00000102
#define CMD_TEE_GetPropertyAsU32_withoutEnum 0x00000020

#define NORMAL_SIZE_BUFFER 1
#define TOO_SHORT_BUFFER 0
#define CASE_NOT_NULL 1
#define CASE_NULL 0
#define CASE_BUFFER1_DIFFERS_FIRST 1
#define CASE_BUFFER2_DIFFERS_FIRST 2
#define CASE_EQUAL 0
#define CASE_ERROR_ICA2 3
#define CASE_PAYLOAD_VALUE 4
#define CASE_SUCCESS_ICA2 2
#define CASE_TARGET_DEAD_ICA2 1
#define CASE_CANCEL_TIMEOUT 2
#define CASE_ITEM_NOT_FOUND 3
#define CASE_SUCCESS 0
#define CASE_TARGET_BUSY 4
#define CASE_TARGET_DEAD 1
#define RESULT_EQUAL 0
#define RESULT_INTEGER_GREATER_THAN_ZERO 1
#define RESULT_INTEGER_LOWER_THAN_ZERO 2

#define HINT_ZERO 0
#define SIZE_OVER_MEMORY 0xFFFFFFFE

#define TEE_ORIGIN_NOT_TRUSTED_APP 5
/* same as TEEC_ORIGIN_ANY_NOT_TRUSTED_APP */
#define TEE_PROPSET_IMPLEMENTATION TEE_PROPSET_TEE_IMPLEMENTATION

static char VALUE_PREDEFINED_STRING[] = "this is a test string\0";
static char VALUE_PREDEFINED_U32[] = "48059\0";
static char VALUE_PREDEFINED_UUID[] = "534D4152-542D-4353-4C54-2D54412D3031\0";
static char VALUE_PREDEFINED_IDENTITY[] =
	"F0000000:534D4152-542D-4353-4C54-2D54412D3031\0";

static char *VALUE_NONE;
static char VALUE_PREDEFINED_BINARY_BLOCK[] =
	"VGhpcyBpcyBhIHRleHQgYmluYXJ5IGJsb2Nr\0";
static char VALUE_PREDEFINED_BOOLEAN[] = "true\0";

static uint8_t CHAR1[] = { 0x10 };
/* static uint8_t CHAR2[]={0xAA}; */

static char GPD_CLIENT_identity[] = "gpd.client.identity\0";
static char GPD_TA_appID[] = "gpd.ta.appID\0";
static char GPD_TA_dataSize[] = "gpd.ta.dataSize\0";
static char GPD_TA_instanceKeepAlive[] = "gpd.ta.instanceKeepAlive\0";
static char GPD_TA_multiSession[] = "gpd.ta.multiSession\0";
static char GPD_TA_singleInstance[] = "gpd.ta.singleInstance\0";
static char GPD_TA_stackSize[] = "gpd.ta.stackSize\0";
static char GPD_TEE_ARITH_maxBigIntSize[] = "gpd.tee.arith.maxBigIntSize\0";
static char GPD_TEE_SYSTEM_TIME_protectionLevel[] =
	"gpd.tee.systemTime.protectionLevel\0";
static char GPD_TEE_TA_PERSISTENT_TIME_protectionLevel[] =
	"gpd.tee.TAPersistentTime.protectionLevel\0";
static char GPD_TEE_apiversion[] = "gpd.tee.apiversion\0";
static char GPD_TEE_description[] = "gpd.tee.description\0";
static char GPD_TEE_deviceID[] = "gpd.tee.deviceID\0";
static char PROPERTY_NAME_NOT_VALID_ENCODING[] = "gpd.\t\n\r\0";
static char PROPERTY_NAME_UNKNOWN[] = "unknown\0";
static char SMC_TA_testuuid[] = "smc.ta.testuuid\0";
static char SMC_TA_testbinaryblock[] = "smc.ta.testbinaryblock\0";
static char SMC_TA_testbooltrue[] = "smc.ta.testbooltrue\0";
static char SMC_TA_testidentity[] = "smc.ta.testidentity\0";
static char SMC_TA_teststring[] = "smc.ta.teststring\0";
static char SMC_TA_testu32[] = "smc.ta.testu32\0";
static char STRING_SAMPLE_SIZE_4_CHAR[] = "TEE\0";


/** ALL_TEEC_UUID
 *
 * These constants are the UUID of existing
 * Trusted Applications
 */
/* "SMART-CSLT-TA-01" */
static TEEC_UUID UUID_TTA_testingInternalAPI_TrustedCoreFramework = {
	0x534D4152, 0x542D, 0x4353,
	{ 0x4C, 0x54, 0x2D, 0x54, 0x41, 0x2D, 0x30, 0x31 }
};
/* "SMARTCSLTATCFICA" */
/* Changed endians from the adaptation layer specification description */
static TEEC_UUID UUID_TTA_testingInternalAPI_TrustedCoreFramework_ICA = {
	0x52414D53, 0x4354, 0x4C53,
	{ 0x54, 0x41, 0x54, 0x43, 0x46, 0x49, 0x43, 0x41 }
};
/* "SMARTCSLTTCFICA2" */
/* Changed endians from the adaptation layer specification description */
static TEEC_UUID UUID_TTA_testingInternalAPI_TrustedCoreFramework_ICA2 = {
	0x52414D53, 0x4354, 0x4C53,
	{ 0x54, 0x54, 0x43, 0x46, 0x49, 0x43, 0x41, 0x32 }
};
/* "SMARTCSLMLTINSTC" */
static TEEC_UUID
	UUID_TTA_testingInternalAPI_TrustedCoreFramework_MultipleInstanceTA = {
	0x534D4152, 0x5443, 0x534C,
	{ 0x4D, 0x4C, 0x54, 0x49, 0x4E, 0x53, 0x54, 0x43 }
};
/* "SMARTCSLSGLINSTC" */
static TEEC_UUID
	UUID_TTA_testingInternalAPI_TrustedCoreFramework_SingleInstanceTA = {
	0x534D4152, 0x5443, 0x534C,
	{ 0x53, 0x47, 0x4C, 0x49, 0x4E, 0x53, 0x54, 0x43 }
};
/* "SMART-CUNK-NO-WN" */
static TEEC_UUID UUID_Unknown = {
	0x534D4152, 0x542D, 0x4355,
	{ 0x4E, 0x4B, 0x2D, 0x4E, 0x4F, 0x2D, 0x57, 0x4E }
};


/* XML_VERIFY macro define.
 *
 * Use ADBG_EXPECT or ADBG_EXPECT_NOT depending on the expected return value.
 *
 * ADBG_EXPECT() -> IF(EXP == GOT) RETURN TRUE
 * ADBG_EXPECT() -> IF(EXP != GOT) RETURN TRUE
 */
#define XML_VERIFY(c, exp, got) \
	do { \
		if (exp == TEEC_UNDEFINED_ERROR) \
			ADBG_EXPECT_NOT(c, exp, got); \
		else \
			ADBG_EXPECT(c, exp, got); \
	} while (0)

/* Initialize context using TEEC_InitializeContext and
	check the returned value. */
#define XML_InitializeContext(c, name, context, expected) \
	XML_VERIFY(c, expected, TEEC_InitializeContext(name, context))

/*Open session using TEEC_OpenSession and check
	the returned value and/or returned origin.*/
#define XML_OpenSession(c, context, session, destination, connectionMethod, \
			connectionData, operation, returnOrigin, expected) \
	do { \
		XML_VERIFY(c, expected, \
			   TEEC_OpenSession(context, session, destination, \
					    connectionMethod, connectionData, \
					    operation, &ret_orig)); \
		if ((returnOrigin != 0) && \
		    ((int)returnOrigin != TEEC_ORIGIN_ANY_NOT_TRUSTED_APP)) \
			ADBG_EXPECT(c, (int)returnOrigin, ret_orig); \
		else \
			ADBG_EXPECT_NOT(c, (int)returnOrigin, ret_orig); \
	} while (0)

#define OPERATION_TEEC_PARAM_TYPES(op, p0, p1, p2, p3) \
	op->paramTypes = TEEC_PARAM_TYPES(p0, p1, p2, p3)

/*dummy functions*/
#define TEEC_SelectApp(a, b)    /* do nothing for now */
#define TEEC_createThread(a, b) /* do nothing for now */

static void *cancellation_thread(void *arg)
{
	TEEC_RequestCancellation((TEEC_Operation *)arg);
	return NULL;
}

#define RequestCancellation(op) \
	(void)ADBG_EXPECT(c, 0, \
			  pthread_create(&THREAD02, NULL, cancellation_thread, \
					 (void *)op)); \
	(void)ADBG_EXPECT(c, 0, pthread_join(THREAD02, NULL));

/* Allocates TEEC_SharedMemory inside of the TEE */
static TEEC_Result AllocateSharedMemory(TEEC_Context *ctx,
					TEEC_SharedMemory *shm, uint32_t size,
					uint32_t flags)
{
	shm->flags = flags;
	shm->size = size;
	return TEEC_AllocateSharedMemory(ctx, shm);
}

static TEEC_Result Invoke_Simple_Function(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId)
{
	TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

	return res;
}

static TEEC_Result Invoke_MemFill(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId,
	uint32_t memoryFillSize, uint8_t *charFill)
{
	TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;

	op.params[0].value.a = memoryFillSize;
	op.params[1].value.a = *charFill;

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_VALUE_INPUT, TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

	return res;
}

static TEEC_Result Invoke_GetPropertyAsXXX_withoutEnum(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId,
	TEE_PropSetHandle propSet, char *name, uint32_t kindBuffer,
	char *expectedValue)
{
	TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;
	uint32_t nameLen = 0;
	uint32_t expectedValueLen = 0;

	nameLen = strlen(name) + 1;
	ALLOCATE_AND_FILL_SHARED_MEMORY(CONTEXT01, SHARE_MEM01, BIG_SIZE,
					TEEC_MEM_INPUT, nameLen, name, mem01_exit)

	if (kindBuffer == TOO_SHORT_BUFFER) {
		ALLOCATE_SHARED_MEMORY(CONTEXT01, SHARE_MEM02, 1,
				       TEEC_MEM_OUTPUT, mem02_exit)
	} else {
		ALLOCATE_SHARED_MEMORY(CONTEXT01, SHARE_MEM02, BIG_SIZE,
				       TEEC_MEM_OUTPUT, mem02_exit)
	}

	op.params[0].value.a = (uint32_t)propSet;
	SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM01, nameLen)
	SET_SHARED_MEMORY_OPERATION_PARAMETER(2, 0, SHARE_MEM02,
					      SHARE_MEM02->size)

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_VALUE_INPUT, TEEC_MEMREF_PARTIAL_INPUT,
		TEEC_MEMREF_PARTIAL_OUTPUT, TEEC_NONE);

	res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

	if (res != TEEC_SUCCESS)
		goto exit;

	if (expectedValue != VALUE_NONE) {
		expectedValueLen = strlen(expectedValue) + 1;
		(void)ADBG_EXPECT_COMPARE_SIGNED(c,
						 0, ==,
						 memcmp(op.params[2].memref.
							parent->buffer,
							expectedValue,
							expectedValueLen));
	}

exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM02);
mem02_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
	return res;
}

static TEEC_Result Invoke_MemCompare(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId,
	uint32_t memorySize, uint32_t Case, uint32_t compareResult)
{
	TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;
	uint32_t outValue = 0;

	op.params[0].value.a = memorySize;
	op.params[1].value.a = Case;
	op.params[2].value.a = outValue;

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_VALUE_INPUT, TEEC_VALUE_INPUT, TEEC_VALUE_OUTPUT,
		TEEC_NONE);

	res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

	if (res != TEEC_SUCCESS)
		goto exit;

	if (compareResult == RESULT_EQUAL) {
		(void)ADBG_EXPECT_COMPARE_SIGNED(c, op.params[2].value.a, ==,
						 0);
	} else if (compareResult == RESULT_INTEGER_GREATER_THAN_ZERO) {
		(void)ADBG_EXPECT_COMPARE_SIGNED(c,
						 (int32_t)op.params[2].value.a,
						 >, 0);
	} else if (compareResult == RESULT_INTEGER_LOWER_THAN_ZERO) {
		(void)ADBG_EXPECT_COMPARE_SIGNED(c,
						 (int32_t)op.params[2].value.a,
						 <, 0);
	}

exit:
	return res;
}

static TEEC_Result Invoke_SetInstanceData(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId, char *data)
{
	TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;

	ALLOCATE_AND_FILL_SHARED_MEMORY(CONTEXT01, SHARE_MEM01, BIG_SIZE,
					TEEC_MEM_INPUT,
					strlen(data) + 1, data, mem01_exit)

	SET_SHARED_MEMORY_OPERATION_PARAMETER(0, 0, SHARE_MEM01,
					      SHARE_MEM01->size)

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_MEMREF_PARTIAL_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

	TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
	return res;
}

static TEEC_Result Invoke_GetInstanceData(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId, char *expectedData,
	uint32_t expectedDataSize)
{
	TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;

	ALLOCATE_SHARED_MEMORY(CONTEXT01, SHARE_MEM01, BIG_SIZE,
			       TEEC_MEM_OUTPUT, mem01_exit)

	SET_SHARED_MEMORY_OPERATION_PARAMETER(0, 0, SHARE_MEM01,
					      SHARE_MEM01->size)

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_MEMREF_PARTIAL_OUTPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

	if (res != TEEC_SUCCESS)
		goto exit;

	if (res != TEE_ERROR_GENERIC) {
		(void)ADBG_EXPECT_COMPARE_SIGNED(c, op.params[0].memref.size,
						 ==, expectedDataSize);
		(void)ADBG_EXPECT_COMPARE_SIGNED(c,
						 0, ==,
						 memcmp(SHARE_MEM01->buffer,
							expectedData,
							expectedDataSize));
	}

exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
	return res;
}

static TEEC_Result Invoke_ProcessInvokeTAOpenSession(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId,
	uint32_t TACmd, TEEC_UUID *UUID, uint32_t returnOrigin)
{
	TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;

	ALLOCATE_AND_FILL_SHARED_MEMORY(CONTEXT01, SHARE_MEM01, BIG_SIZE,
					TEEC_MEM_INPUT, 16, UUID, mem01_exit)

	op.params[0].value.a = TACmd;
	SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM01, 16)
	op.params[2].value.a = returnOrigin;

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_VALUE_INPUT, TEEC_MEMREF_PARTIAL_INPUT, TEEC_VALUE_OUTPUT,
		TEEC_NONE);

	res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

	if (TEE_ORIGIN_NOT_TRUSTED_APP == returnOrigin) {
		(void)ADBG_EXPECT_COMPARE_SIGNED(c, op.params[2].value.a, !=,
						 TEE_ORIGIN_TRUSTED_APP);
	} else {
		(void)ADBG_EXPECT_COMPARE_SIGNED(c, op.params[2].value.a, ==,
						 returnOrigin);
	}

exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
	return res;
}

static TEEC_Result Invoke_CheckMemoryAccessRight(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId,
	uint32_t memoryParamType, uint32_t memoryAccessFlags)
{
	TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;
	uint32_t memory_flag;

	switch (memoryParamType) {
	case TEEC_MEMREF_TEMP_INPUT:
	case TEEC_MEMREF_PARTIAL_INPUT:
		memory_flag = TEEC_MEM_INPUT;
		break;
	case TEEC_MEMREF_TEMP_OUTPUT:
	case TEEC_MEMREF_PARTIAL_OUTPUT:
		memory_flag = TEEC_MEM_OUTPUT;
		break;
	case TEEC_MEMREF_TEMP_INOUT:
	case TEEC_MEMREF_PARTIAL_INOUT:
	case TEEC_MEMREF_WHOLE:
		memory_flag = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
		break;
	default:
		memory_flag = 0;
		break;
	}

	ALLOCATE_SHARED_MEMORY(CONTEXT01, SHARE_MEM01, BIG_SIZE,
					memory_flag, mem01_exit)

	op.params[0].value.a = memoryAccessFlags;
	SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM01,
					      SHARE_MEM01->size)

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_VALUE_INPUT, memoryParamType, TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

	TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
	return res;
}

static TEEC_Result Invoke_MemMove(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId, uint32_t memorySize)
{
	TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;

	op.params[0].value.a = memorySize;

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

	return res;
}

static TEEC_Result Invoke_AllocatePropertyEnumerator(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId,
	uint32_t *enumerator)
{
	TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;

	op.params[0].value.a = 0;

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_VALUE_OUTPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

	if (res != TEEC_SUCCESS)
		goto exit;

	*enumerator = op.params[0].value.a;
	/* (void)ADBG_EXPECT_COMPARE_SIGNED(
		c, op.params[0].value.a, == , enumerator); */

exit:
	return res;
}

static TEEC_Result Invoke_StartPropertyEnumerator(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId, uint32_t enumerator,
	TEE_PropSetHandle propSet)
{
	TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;

	op.params[0].value.a = enumerator;
	op.params[1].value.a = (uint32_t)propSet;

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_VALUE_INPUT, TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

	return res;
}

static TEEC_Result Invoke_ResetPropertyEnumerator(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId, uint32_t enumerator)
{
	TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;

	op.params[0].value.a = enumerator;

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

	return res;
}

static TEEC_Result Invoke_GetPropertyName(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId,
	uint32_t enumerator, char *propertyName, uint32_t kindBuffer)
{
	TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;
	uint32_t strLen = 0;

	if (kindBuffer == TOO_SHORT_BUFFER) {
		ALLOCATE_SHARED_MEMORY(CONTEXT01, SHARE_MEM01, 1,
				       TEEC_MEM_OUTPUT, mem01_exit)
	} else {
		ALLOCATE_SHARED_MEMORY(CONTEXT01, SHARE_MEM01, BIG_SIZE,
				       TEEC_MEM_OUTPUT, mem01_exit)
	}

	op.params[0].value.a = enumerator;
	SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM01,
					      SHARE_MEM01->size)

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_VALUE_INPUT, TEEC_MEMREF_PARTIAL_OUTPUT, TEEC_NONE,
		TEEC_NONE);

	res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

	if (res != TEEC_SUCCESS)
		goto exit;

	strLen = strlen(propertyName) + 1;

	(void)ADBG_EXPECT_COMPARE_SIGNED(c, op.params[1].memref.size, ==,
					 strLen);

	(void)ADBG_EXPECT_COMPARE_SIGNED(c,
					 0, ==,
					 memcmp(SHARE_MEM01->buffer,
						propertyName, strLen));

exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
	return res;
}

static TEEC_Result Invoke_Malloc(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId,
	uint32_t memorySize, uint32_t hint)
{
	TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;

	op.params[0].value.a = memorySize;
	op.params[1].value.a = hint;

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_VALUE_INPUT, TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

	return res;
}

static TEEC_Result Invoke_Panic(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId)
{
	TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

	if (res != TEEC_SUCCESS)
		goto exit;

	(void)ADBG_EXPECT_COMPARE_SIGNED(c, org, ==, TEE_ORIGIN_TEE);

exit:
	return res;
}

static TEEC_Result Invoke_Realloc(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId,
	uint32_t oldMemorySize, uint32_t newMemorySize)
{
	TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;

	op.params[0].value.a = oldMemorySize;
	op.params[1].value.a = newMemorySize;

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_VALUE_INPUT, TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

	return res;
}

static TEEC_Result Invoke_Free(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId, uint32_t Case)
{
	TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;

	op.params[0].value.a = Case;

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

	return res;
}

static TEEC_Result Invoke_GetCancellationFlag_RequestedCancel(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId,
	TEEC_Operation *operation)
{
	TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

	return res;
}

#endif /* XML_INTERNAL_API_H_ */
