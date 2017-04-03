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

#ifndef XML_CLIENT_API_H_
#define XML_CLIENT_API_H_

#include <compiler.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <tee_client_api.h>
#include <unistd.h>

#define CLIENT_APP01                    NULL

#define TEEC_UNDEFINED_ERROR 0xDEADDEAD

#define TEEC_ORIGIN_ANY_NOT_TRUSTED_APP  0x00000005

#define OFFSET0 0

/*Test data defines*/
static pthread_t THREAD02;

static TEEC_SharedMemory *SHARE_MEM01;
static TEEC_SharedMemory *SHARE_MEM02;
static TEEC_Session *SESSION01;
static TEEC_Context *CONTEXT01;
static TEEC_Operation *OPERATION01;
static TEEC_Operation *OPERATION02;

/* Return ORIGIN */
static uint32_t ret_orig;

static uint32_t BIG_SIZE = 1024;

static uint32_t IGNORE = 0xFEFEFEFE;
static uint32_t VALUE01 = 0x01234567;
static uint32_t VALUE02 __maybe_unused = 0xFEDCBA98;
static uint32_t SIZE_OVER_MEMORY = 0xFFFFFFFE;
static uint32_t SIZE_VALUE01 = sizeof(VALUE01);
static uint32_t ZERO;

#define INVALID_CONNECTION_METHODS 0x0A
#define COMMAND_TTA_Check_Expected_ParamTypes COMMAND_TTA_Check_ParamTypes

#define TEEC_MEM_INOUT 0x00000003

/* "ItIsNotTotosTEEs" */
static const char *INVALID_NOT_EXISTING_TEE = "ItIsNotTotosTEEs\0";

/** ALL_TEMPORARY_MEMORIES */
uint8_t *TEMP_MEM01;
uint8_t *TEMP_MEM02;

/** ALL_TEEC_UUID
 *
 * These constants are the UUID of existing
 * Trusted Applications
 */
/* "SMARTCSLTERRTOOS" */
static TEEC_UUID UUID_TTA_answerErrorTo_OpenSession __maybe_unused = {
	0x534D4152, 0x5443, 0x534C,
	{ 0x54, 0x45, 0x52, 0x52, 0x54, 0x4F, 0x4F, 0x53 }
};
/* "SMART-CSLT-TA-SU" */
static TEEC_UUID UUID_TTA_answerSuccessTo_OpenSession_Invoke = {
	0x534D4152, 0x542D, 0x4353,
	{ 0x4C, 0x54, 0x2D, 0x54, 0x41, 0x2D, 0x53, 0x55 }
};
/* "SMARTCSLTOS4PARM" */
static TEEC_UUID UUID_TTA_check_OpenSession_with_4_parameters __maybe_unused = {
	0x534D4152, 0x5443, 0x534C,
	{ 0x54, 0x4F, 0x53, 0x34, 0x50, 0x41, 0x52, 0x4D }
};
/* "SMART-CUNK-NO-WN" */
static TEEC_UUID UUID_Unknown = {
	0x534D4152, 0x542D, 0x4355,
	{ 0x4E, 0x4B, 0x2D, 0x4E, 0x4F, 0x2D, 0x57, 0x4E }
};

/*Helper functions/macros*/
#define IDENTIFIER_NOT_USED(x) { if (sizeof(&x)) {} }

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

/*Initialize context using TEEC_InitializeContext and
	check the returned value.*/
#define XML_InitializeContext(c, name, context, expected) \
	XML_VERIFY(c, expected, TEEC_InitializeContext(name, context))

/*Open session using TEEC_OpenSession and
	check the returned value and/or returned origin.*/
#define XML_OpenSession(c, context, session, destination, connectionMethod, \
			connectionData, operation, returnOrigin, expected) \
	do { \
		XML_VERIFY(c, expected, \
			   TEEC_OpenSession(context, session, destination, \
					    connectionMethod, connectionData, \
					    operation, &ret_orig)); \
		if ((returnOrigin != 0) && \
		    (returnOrigin != TEEC_ORIGIN_ANY_NOT_TRUSTED_APP)) \
			ADBG_EXPECT(c, returnOrigin, ret_orig); \
		else \
			ADBG_EXPECT_NOT(c, returnOrigin, ret_orig); \
	} while (0)

#define OPERATION_TEEC_PARAM_TYPES(op, p0, p1, p2, p3) \
	op->paramTypes = TEEC_PARAM_TYPES(p0, p1, p2, p3)

/*dummy functions*/
#define TEEC_SelectApp(a, b)    /*do nothing for now*/
#define TEEC_createThread(a, b) /*do nothing for now*/

/*Allocates TEEC_SharedMemory inside of the TEE*/
static TEEC_Result AllocateSharedMemory(TEEC_Context *ctx,
					TEEC_SharedMemory *shm,
					uint32_t size, uint32_t flags)
{
	shm->flags = flags;
	shm->size = size;
	return TEEC_AllocateSharedMemory(ctx, shm);
}

/*Registers the TEEC_SharedMemory to the TEE*/
static TEEC_Result RegisterSharedMemory(TEEC_Context *ctx,
					TEEC_SharedMemory *shm,
					uint32_t size, uint32_t flags)
{
	shm->flags = flags;
	shm->size = size;
	shm->buffer = malloc(size);
	return TEEC_RegisterSharedMemory(ctx, shm);
}

/*Allocates temporary memory area*/
#define AllocateTempMemory(temp_mem, size) \
	temp_mem = malloc(size)

/*Releases temporary memory area*/
#define ReleaseTempMemory(temp_mem) \
	do { \
		if (temp_mem != NULL) { \
			free(temp_mem); \
			temp_mem = NULL; \
		} \
	} while (0)


/* Assigns a and b to the value parameter */
static inline void TEEC_prepare_OperationEachParameter_value(TEEC_Operation *op,
							     size_t n,
							     uint32_t a,
							     uint32_t b)
{
	if (IGNORE != a)
		op->params[n].value.a = a;

	if (IGNORE != b)
		op->params[n].value.b = b;

}

/*Define TEEC_SharedMemory memory content.*/
#define TEEC_defineMemoryContent_sharedMemory(sh_mem, val, size_val) \
	memcpy(sh_mem->buffer, &val, size_val)

/*Define temp memory content.*/
#define TEEC_defineMemoryContent_tmpMemory(buf, val, size_val) \
	memcpy(buf, &(val), size_val)

#define INVOKE_REMEMBER_EXP_PARAM_TYPES(session, cmd, p0, p1, p2, p3, exp) \
	do { \
		memset(OPERATION01, 0x00, sizeof(TEEC_Operation)); \
		OPERATION01->paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, \
							   TEEC_NONE, \
							   TEEC_NONE, \
							   TEEC_NONE); \
		OPERATION01->params[0].value.a = \
			TEEC_PARAM_TYPES((p0), (p1), (p2), (p3)); \
		ADBG_EXPECT(c, exp, \
			    TEEC_InvokeCommand(session, cmd, OPERATION01, \
					       &ret_orig));  \
		ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TRUSTED_APP, \
					      ret_orig); \
	} while (0)

/*Compares two memories and checks if their length and content is the same */
#define TEEC_checkMemoryContent_sharedMemory(op, param_num, shrm, exp_buf, \
					     exp_blen) \
	do { \
		if ((exp_buf) == IGNORE) { \
			ADBG_EXPECT((c), exp_blen, \
				    (op)->params[(param_num)].memref.size); \
		} else { \
			ADBG_EXPECT_COMPARE_POINTER((c), (shrm), ==, \
						    (op)->params[(param_num)].\
							memref.parent); \
			ADBG_EXPECT_BUFFER((c), &(exp_buf), (exp_blen), \
					   (shrm)->buffer, \
					   (op)->params[(param_num)].\
						memref.size); \
		} \
	} while (0)

/*
 * Compares the content of the memory cells in OP with the expected value
 * contained.
 */
#define TEEC_checkMemoryContent_tmpMemory(op, param_num, \
	buf, exp_buf, exp_blen) \
	do { \
		if ((exp_buf) == 0) { \
			ADBG_EXPECT((c), exp_blen, \
				    (op)->params[(param_num)].tmpref.size); \
		} else { \
			ADBG_EXPECT_COMPARE_POINTER((c), (buf), ==, \
						    (op)->params[(param_num)].\
							tmpref.buffer); \
			ADBG_EXPECT_BUFFER((c), &(exp_buf), (exp_blen), \
					   (buf), \
					   (op)->params[(param_num)].\
						memref.size); \
		} \
	} while (0)

/*
 * Compares the content of the memory cells in OP with the expected value
 * contained.
 */
#define TEEC_checkContent_Parameter_value(op, param_num, exp_a, exp_b) \
	do { \
		if (IGNORE != exp_a) \
			ADBG_EXPECT((c), exp_a, \
				    (op)->params[(param_num)].value.a); \
		if (IGNORE != exp_b) \
			ADBG_EXPECT((c), exp_b, \
				    (op)->params[(param_num)].value.b); \
	} while (0)

/*Invoke command using TEEC_InvokeCommand and check the returned value.*/
#define XML_InvokeCommand(c, session, cmd, operation, returnOrigin, expected) \
	do { \
		ADBG_EXPECT(c, expected, \
			    TEEC_InvokeCommand(session, cmd, operation, \
					       &ret_orig)); \
		if (returnOrigin != 0) \
			ADBG_EXPECT(c, (int)returnOrigin, ret_orig); \
	} while (0)

#define RequestCancellation(op) \
	(void)ADBG_EXPECT(c, 0, \
			  pthread_create(&THREAD02, NULL, cancellation_thread, \
					 (void *)op)); \
	(void)ADBG_EXPECT(c, 0, pthread_join(THREAD02, NULL));

struct ctx_thr {
	ADBG_Case_t *c;
	TEEC_Context *ctx;
};

static struct ctx_thr thr2_ctx;

static void *context_thread(void *arg)
{
	/*
	 * Sleep 0.5 seconds before cancellation to make sure that the other
	 * thread is in RPC_WAIT.
	 */
	XML_InitializeContext(((struct ctx_thr *)arg)->c, _device,
			      ((struct ctx_thr *)arg)->ctx, TEEC_SUCCESS);
	TEEC_FinalizeContext(((struct ctx_thr *)arg)->ctx);

	return NULL;
}

#define ctx_init_finalize(t_ctx) \
	(void)ADBG_EXPECT(c, 0, \
			  pthread_create(&THREAD02, NULL, context_thread, \
					 (void *)&t_ctx)); \
	(void)ADBG_EXPECT(c, 0, pthread_join(THREAD02, NULL));

#ifdef WITH_GP_TESTS
/*
 * Required by Global Platform test suite for v1.0
 */
static uint32_t BIG_VALUE = 1024; /* BIG_SIZE */
static uint32_t SIZE_LESSER_THAN_SIZE_VALUE01 = sizeof(VALUE01) - 1;

/* "SMART-CSLT-TA-ER" */
static TEEC_UUID UUID_TTA_answerErrorTo_Invoke = {
	0x534D4152, 0x542D, 0x4353,
	{ 0x4C, 0x54, 0x2D, 0x54, 0x41, 0x2D, 0x45, 0x52 }
};

/* "SMART-CSLT-TA-ST" */
/* Used in GP Tests */
static TEEC_UUID UUID_TTA_testingClientAPI = {
	0x534D4152, 0x542D, 0x4353,
	{ 0x4C, 0x54, 0x2D, 0x54, 0x41, 0x2D, 0x53, 0x54 }
};

static void *cancellation_thread(void *arg)
{
	TEEC_RequestCancellation((TEEC_Operation *)arg);
	return NULL;
}

/* Assigns parent, offset and size to the memref parameter */
static void TEEC_prepare_OperationEachParameter_memref(TEEC_Operation *op,
	size_t n,
	TEEC_SharedMemory *parent, unsigned offset,
	unsigned size)
{
	op->params[n].memref.parent = parent;
	op->params[n].memref.offset = offset;
	op->params[n].memref.size = size;
}

/* Assigns buffer and size to the tmpref parameter */
static void TEEC_prepare_OperationEachParameter_tmpref(TEEC_Operation *op,
						       size_t n,
						       uint8_t *buffer,
						       unsigned size)
{
	op->params[n].tmpref.buffer = buffer;
	op->params[n].tmpref.size = size;
}
#endif

#endif /* XML_CLIENT_API_H_ */
