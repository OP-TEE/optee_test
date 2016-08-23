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

#define OFFSET0 0

#define PARAM_0 0
#define PARAM_1 1
#define PARAM_2 2
#define PARAM_3 3

struct xtest_session {
	ADBG_Case_t *c;
	TEEC_Session session;
	TEEC_Context context;
};

/* Compares two memories and checks if their length and content is the same */
#define EXPECT_SHARED_MEM_BUFFER(c, exp_buf, exp_blen, op, param_num, shrm) \
	do { \
		if ((exp_buf) == NULL) { \
			ADBG_EXPECT((c), exp_blen, \
				    (op)->params[(param_num)].memref.size); \
		} else { \
			ADBG_EXPECT_COMPARE_POINTER((c), (shrm), ==, \
			    (op)->params[(param_num)].memref.parent); \
			ADBG_EXPECT_BUFFER((c), (exp_buf), (exp_blen), \
			   (shrm)->buffer, \
			   (op)->params[(param_num)].memref.size); \
		} \
	} while (0)

/*
 * Compares the content of the memory cells in OP with the expected value
 * contained.
 */
#define EXPECT_OP_TMP_MEM_BUFFER(c, exp_buf, exp_blen, op, param_num, buf) \
	do { \
		if ((exp_buf) == NULL) { \
			ADBG_EXPECT((c), exp_blen, \
			    (op)->params[(param_num)].tmpref.size); \
		} else { \
			ADBG_EXPECT_COMPARE_POINTER((c), (buf), ==, \
			    (op)->params[(param_num)].tmpref.buffer); \
			ADBG_EXPECT_BUFFER((c), (exp_buf), (exp_blen), \
			   (buf), \
			   (op)->params[(param_num)].memref.size); \
		} \
	} while (0)

/* Initiates the memory and allocates size uint32_t. */

/* Registers the TEEC_SharedMemory to the TEE. */
static TEEC_Result RegisterSharedMemory(TEEC_Context *ctx,
					TEEC_SharedMemory *shm, uint32_t size,
					uint32_t flags)
{
	shm->flags = flags;
	shm->size = size;
	return TEEC_RegisterSharedMemory(ctx, shm);
}

/* Allocates shared memory inside of the TEE. */
static TEEC_Result AllocateSharedMemory(TEEC_Context *ctx,
					TEEC_SharedMemory *shm, uint32_t size,
					uint32_t flags)
{
	shm->flags = flags;
	shm->size = size;
	return TEEC_AllocateSharedMemory(ctx, shm);
}

static void CloseSession_null(struct xtest_session *cs)
{
	Do_ADBG_BeginSubCase(cs->c, "CloseSession_null");
	{
		/* In reality doesn't test anything. */
		TEEC_CloseSession(NULL);
	}
	Do_ADBG_EndSubCase(cs->c, "CloseSession_null");
}

static void Allocate_In(struct xtest_session *cs)
{
	Do_ADBG_BeginSubCase(cs->c, "Allocate_In");
	{
		TEEC_SharedMemory shm;
		uint32_t size = 1024;

		ADBG_EXPECT(cs->c, TEEC_SUCCESS,
			TEEC_InitializeContext(_device, &cs->context));
		ADBG_EXPECT_TEEC_SUCCESS(cs->c,
			AllocateSharedMemory(&cs->context, &shm, size,
					     TEEC_MEM_INPUT));
		TEEC_ReleaseSharedMemory(&shm);
		TEEC_FinalizeContext(&cs->context);
	}
	Do_ADBG_EndSubCase(cs->c, "Allocate_In");
}

static void Allocate_out_of_memory(struct xtest_session *cs)
{
	Do_ADBG_BeginSubCase(cs->c, "Allocate_out_of_memory");
	{
		TEEC_SharedMemory shm;
		uint32_t SIZE_OVER_MEMORY_CAPACITY = INT32_MAX;

		ADBG_EXPECT(cs->c, TEEC_SUCCESS,
			    TEEC_InitializeContext(_device, &cs->context));
		ADBG_EXPECT_TEEC_RESULT(cs->c, TEEC_ERROR_OUT_OF_MEMORY,
			AllocateSharedMemory(&cs->context, &shm,
					     SIZE_OVER_MEMORY_CAPACITY,
					     TEEC_MEM_INPUT));
		ADBG_EXPECT_POINTER(cs->c, NULL, shm.buffer);
		TEEC_FinalizeContext(&cs->context);
	}
	Do_ADBG_EndSubCase(cs->c, "Allocate_out_of_memory");
}

static void OpenSession_error_notExistingTA(struct xtest_session *cs)
{
	Do_ADBG_BeginSubCase(cs->c, "OpenSession_error_notExistingTA");
	{
		TEEC_UUID NONEXISTING_TA_UUID = { 0x534D1192, 0x6143, 0x234C,
						  { 0x47, 0x55, 0x53, 0x52,
						    0x54, 0x4F, 0x4F, 0x59 } };
		uint32_t ret_orig;

		ADBG_EXPECT(cs->c, TEEC_SUCCESS,
			TEEC_InitializeContext(_device, &cs->context));

		ADBG_EXPECT_COMPARE_UNSIGNED(cs->c, TEEC_SUCCESS, !=,
			TEEC_OpenSession(&cs->context, &cs->session,
					 &NONEXISTING_TA_UUID,
					 TEEC_LOGIN_PUBLIC, NULL, NULL,
					 &ret_orig));
		ADBG_EXPECT_COMPARE_UNSIGNED(cs->c, TEEC_ORIGIN_TRUSTED_APP, !=,
					     ret_orig);
		TEEC_FinalizeContext(&cs->context);
	}
	Do_ADBG_EndSubCase(cs->c, "OpenSession_error_notExistingTA");
}

static void Allocate_InOut(struct xtest_session *cs)
{
	Do_ADBG_BeginSubCase(cs->c, "Allocate_InOut");
	{
		TEEC_SharedMemory shm;
		uint8_t val[] = { 54, 76, 98, 32 };

		ADBG_EXPECT(cs->c, TEEC_SUCCESS,
			TEEC_InitializeContext(_device, &cs->context));

		ADBG_EXPECT_TEEC_SUCCESS(cs->c,
			AllocateSharedMemory(&cs->context, &shm, sizeof(val),
					     TEEC_MEM_INPUT | TEEC_MEM_OUTPUT));

		TEEC_ReleaseSharedMemory(&shm);
		TEEC_FinalizeContext(&cs->context);
	}
	Do_ADBG_EndSubCase(cs->c, "Allocate_InOut");
}

static void Register_In(struct xtest_session *cs)
{
	Do_ADBG_BeginSubCase(cs->c, "Register_In");
	{
		TEEC_SharedMemory shm;
		uint8_t val[] = { 32, 65, 43, 21, 98 };

		ADBG_EXPECT(cs->c, TEEC_SUCCESS,
			TEEC_InitializeContext(_device, &cs->context));

		shm.buffer = val;

		ADBG_EXPECT_TEEC_SUCCESS(cs->c,
			RegisterSharedMemory(&cs->context, &shm, sizeof(val),
					     TEEC_MEM_INPUT));
		TEEC_ReleaseSharedMemory(&shm);
		TEEC_FinalizeContext(&cs->context);
	}
	Do_ADBG_EndSubCase(cs->c, "Register_In");
}

static void Register_notZeroLength_Out(struct xtest_session *cs)
{
	Do_ADBG_BeginSubCase(cs->c, "Register_notZeroLength_Out");
	{
		TEEC_SharedMemory shm;
		uint8_t val[] = { 56, 67, 78, 99 };

		ADBG_EXPECT(cs->c, TEEC_SUCCESS,
			    TEEC_InitializeContext(_device, &cs->context));

		shm.buffer = val;

		ADBG_EXPECT_TEEC_SUCCESS(cs->c, RegisterSharedMemory(
						 &cs->context, &shm,
						 sizeof(val), TEEC_MEM_OUTPUT));
		TEEC_ReleaseSharedMemory(&shm);
		TEEC_FinalizeContext(&cs->context);
	}
	Do_ADBG_EndSubCase(cs->c, "Register_notZeroLength_Out");
}

static void Register_InOut(struct xtest_session *cs)
{
	Do_ADBG_BeginSubCase(cs->c, "Register_InOut");
	{
		TEEC_SharedMemory shm;
		uint8_t val[] = { 54, 76, 23, 98, 255, 23, 86 };

		ADBG_EXPECT(cs->c, TEEC_SUCCESS,
			    TEEC_InitializeContext(_device, &cs->context));

		shm.buffer = val;
		ADBG_EXPECT_TEEC_SUCCESS(cs->c,
			RegisterSharedMemory(&cs->context, &shm, sizeof(val),
					     TEEC_MEM_INPUT | TEEC_MEM_OUTPUT));

		TEEC_ReleaseSharedMemory(&shm);
		TEEC_FinalizeContext(&cs->context);
	}
	Do_ADBG_EndSubCase(cs->c, "Register_InOut");
}

static void Register_zeroLength_Out(struct xtest_session *cs)
{
	Do_ADBG_BeginSubCase(cs->c, "Register_zeroLength_Out");
	{
		uint8_t val[] = { 65, 76, 98, 32 };
		TEEC_SharedMemory shm;

		ADBG_EXPECT(cs->c, TEEC_SUCCESS,
			    TEEC_InitializeContext(_device, &cs->context));

		shm.buffer = val;
		ADBG_EXPECT_TEEC_SUCCESS(cs->c, RegisterSharedMemory(
						 &cs->context, &shm, 0,
						 TEEC_MEM_OUTPUT));

		TEEC_ReleaseSharedMemory(&shm);
		TEEC_FinalizeContext(&cs->context);
	}
	Do_ADBG_EndSubCase(cs->c, "Register_zeroLength_Out");
}

static void Allocate_Out(struct xtest_session *cs)
{
	Do_ADBG_BeginSubCase(cs->c, "Allocate_Out");
	{
		TEEC_SharedMemory shm;

		ADBG_EXPECT(cs->c, TEEC_SUCCESS,
			    TEEC_InitializeContext(_device, &cs->context));

		ADBG_EXPECT_TEEC_SUCCESS(cs->c,
			AllocateSharedMemory(&cs->context, &shm, 0,
					     TEEC_MEM_OUTPUT));

		TEEC_ReleaseSharedMemory(&shm);
		TEEC_FinalizeContext(&cs->context);
	}
	Do_ADBG_EndSubCase(cs->c, "Allocate_Out");
}

static void FinalizeContext_null(struct xtest_session *cs)
{
	Do_ADBG_BeginSubCase(cs->c, "FinalizeContext_null");
	{
		TEEC_FinalizeContext(NULL);
	}
	Do_ADBG_EndSubCase(cs->c, "FinalizeContext_null");
}

static void InitializeContext_NotExistingTEE(struct xtest_session *cs)
{
	Do_ADBG_BeginSubCase(cs->c, "InitializeContext_NotExistingTEE");
	{
		ADBG_EXPECT_COMPARE_UNSIGNED(cs->c, TEEC_SUCCESS, !=,
			TEEC_InitializeContext("Invalid TEE name",
					       &cs->context));
	}
	Do_ADBG_EndSubCase(cs->c, "InitializeContext_NotExistingTEE");
}

static void AllocateThenRegister_SameMemory(struct xtest_session *cs)
{
	Do_ADBG_BeginSubCase(cs->c, "AllocateThenRegister_SameMemory");
	{
		TEEC_SharedMemory shm;
		uint32_t size_allocation = 32;

		ADBG_EXPECT(cs->c, TEEC_SUCCESS,
			TEEC_InitializeContext(_device, &cs->context));

		ADBG_EXPECT_TEEC_SUCCESS(cs->c,
			AllocateSharedMemory(&cs->context, &shm,
					     size_allocation, TEEC_MEM_INPUT));

		ADBG_EXPECT_TEEC_SUCCESS(cs->c,
			RegisterSharedMemory(&cs->context, &shm,
					     size_allocation, TEEC_MEM_INPUT));
	}
	Do_ADBG_EndSubCase(cs->c, "AllocateThenRegister_SameMemory");
}

static void AllocateSameMemory_twice(struct xtest_session *cs)
{
	Do_ADBG_BeginSubCase(cs->c, "AllocateSameMemory_twice");
	{
		TEEC_SharedMemory shm;
		uint32_t size_allocation = 32;

		ADBG_EXPECT(cs->c, TEEC_SUCCESS,
			TEEC_InitializeContext(_device, &cs->context));

		ADBG_EXPECT_TEEC_SUCCESS(cs->c,
			AllocateSharedMemory(&cs->context, &shm,
					     size_allocation, TEEC_MEM_INPUT));

		ADBG_EXPECT_TEEC_SUCCESS(cs->c,
			AllocateSharedMemory(&cs->context, &shm,
					     size_allocation, TEEC_MEM_INPUT));

		TEEC_ReleaseSharedMemory(&shm);
		TEEC_FinalizeContext(&cs->context);
	}
	Do_ADBG_EndSubCase(cs->c, "AllocateSameMemory_twice");
}

static void RegisterSameMemory_twice(struct xtest_session *cs)
{
	Do_ADBG_BeginSubCase(cs->c, "RegisterSameMemory_twice");
	{
		uint8_t val[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0 };
		TEEC_SharedMemory shm;

		ADBG_EXPECT(cs->c, TEEC_SUCCESS,
			TEEC_InitializeContext(_device, &cs->context));

		shm.buffer = val;
		ADBG_EXPECT_TEEC_SUCCESS(cs->c,
			RegisterSharedMemory(&cs->context, &shm, sizeof(val),
					     TEEC_MEM_INPUT));

		ADBG_EXPECT_TEEC_SUCCESS(cs->c,
			RegisterSharedMemory(&cs->context, &shm, sizeof(val),
					     TEEC_MEM_INPUT));

		TEEC_ReleaseSharedMemory(&shm);
		TEEC_FinalizeContext(&cs->context);
	}
	Do_ADBG_EndSubCase(cs->c, "RegisterSameMemory_twice");
}

static void Allocate_sharedMemory_maxSize(struct xtest_session *cs)
{
	Do_ADBG_BeginSubCase(cs->c,
			     "Allocate_sharedMemory_MaxSize_Above_and_Below, allocate max size");
	{
		uint32_t size_max = TEEC_CONFIG_SHAREDMEM_MAX_SIZE;
		TEEC_SharedMemory shm;

		ADBG_EXPECT(cs->c, TEEC_SUCCESS,
			TEEC_InitializeContext(_device, &cs->context));

		ADBG_EXPECT_TEEC_SUCCESS(cs->c,
			AllocateSharedMemory(&cs->context, &shm, size_max,
					     TEEC_MEM_INPUT));

		TEEC_ReleaseSharedMemory(&shm);
	}
	Do_ADBG_EndSubCase(cs->c,
			   "Allocate_sharedMemory_MaxSize_Above_and_Below, allocate max size");
}

static void Allocate_sharedMemory_belowMaxSize(struct xtest_session *cs)
{
	Do_ADBG_BeginSubCase(cs->c,
			     "Allocate_sharedMemory_MaxSize_Above_and_Below, "
			     "allocate just below max size");
	{
		TEEC_SharedMemory shm;
		uint32_t size_below = TEEC_CONFIG_SHAREDMEM_MAX_SIZE - 1;

		ADBG_EXPECT(cs->c, TEEC_SUCCESS,
			TEEC_InitializeContext(_device, &cs->context));

		ADBG_EXPECT_TEEC_SUCCESS(cs->c,
			AllocateSharedMemory(&cs->context, &shm, size_below,
					     TEEC_MEM_INPUT));

		TEEC_ReleaseSharedMemory(&shm);
		TEEC_FinalizeContext(&cs->context);
	}
	Do_ADBG_EndSubCase(cs->c,
			   "Allocate_sharedMemory_MaxSize_Above_and_Below, "
			   "allocate just below max size");
}

static void Allocate_sharedMemory_aboveMaxSize(struct xtest_session *cs)
{
	Do_ADBG_BeginSubCase(cs->c,
			     "Allocate_sharedMemory_MaxSize_Above_and_Below, "
			     "allocate just above max size");
	{
		TEEC_Result res;
		TEEC_SharedMemory shm;
		uint32_t size_above = TEEC_CONFIG_SHAREDMEM_MAX_SIZE + 1;

		ADBG_EXPECT(cs->c, TEEC_SUCCESS,
			TEEC_InitializeContext(_device, &cs->context));

		res = AllocateSharedMemory(&cs->context, &shm, size_above,
					   TEEC_MEM_INPUT);

		ADBG_EXPECT_TRUE(cs->c, res == TEEC_ERROR_OUT_OF_MEMORY ||
				 res == TEEC_SUCCESS);

		TEEC_ReleaseSharedMemory(&shm);
		TEEC_FinalizeContext(&cs->context);
	}
	Do_ADBG_EndSubCase(cs->c,
			   "Allocate_sharedMemory_MaxSize_Above_and_Below, "
			   "allocate just above max size");
}

static void Register_sharedMemory_maxSize(struct xtest_session *cs)
{
	Do_ADBG_BeginSubCase(cs->c, "Register_sharedMemory_maxSize");
	{
		uint32_t size_max = TEEC_CONFIG_SHAREDMEM_MAX_SIZE;
		uint8_t val[size_max];
		TEEC_SharedMemory shm;

		ADBG_EXPECT(cs->c, TEEC_SUCCESS,
			TEEC_InitializeContext(_device, &cs->context));

		shm.buffer = val;
		ADBG_EXPECT_TEEC_SUCCESS(cs->c,
			RegisterSharedMemory(&cs->context, &shm, size_max,
					     TEEC_MEM_INPUT));

		TEEC_ReleaseSharedMemory(&shm);
		TEEC_FinalizeContext(&cs->context);
	}
	Do_ADBG_EndSubCase(cs->c, "Register_sharedMemory_maxSize");
}

static void Register_sharedMemory_aboveMaxSize(struct xtest_session *cs)
{
	Do_ADBG_BeginSubCase(cs->c, "Register_sharedMemory_aboveMaxSize");
	{
		TEEC_Result res;
		uint32_t size_aboveMax = 0xffffffff;
		uint8_t val[1];
		TEEC_SharedMemory shm;

		ADBG_EXPECT(cs->c, TEEC_SUCCESS,
			TEEC_InitializeContext(_device, &cs->context));

		shm.buffer = val;
		res = RegisterSharedMemory(&cs->context, &shm, size_aboveMax,
					   TEEC_MEM_INPUT);

		ADBG_EXPECT_TRUE(cs->c, res == TEEC_ERROR_OUT_OF_MEMORY ||
				 res == TEEC_SUCCESS);

		TEEC_ReleaseSharedMemory(&shm);
	}
	Do_ADBG_EndSubCase(cs->c, "Register_sharedMemory_aboveMaxSize");
}

static void Register_sharedMemory_belowMaxSize(struct xtest_session *cs)
{
	Do_ADBG_BeginSubCase(cs->c, "Register_sharedMemory_belowMaxSize");
	{
		uint32_t size_belowMax = TEEC_CONFIG_SHAREDMEM_MAX_SIZE - 1;
		uint8_t val[size_belowMax];
		TEEC_SharedMemory shm;

		ADBG_EXPECT(cs->c, TEEC_SUCCESS,
			    TEEC_InitializeContext(_device, &cs->context));

		shm.buffer = val;
		ADBG_EXPECT_TEEC_SUCCESS(cs->c,
			RegisterSharedMemory(&cs->context, &shm, size_belowMax,
					     TEEC_MEM_INPUT));

		TEEC_ReleaseSharedMemory(&shm);
	}
	Do_ADBG_EndSubCase(cs->c, "Register_sharedMemory_belowMaxSize");
}

static void xtest_teec_TEE(ADBG_Case_t *c)
{
	struct xtest_session connection = { c };

	CloseSession_null(&connection);

	Allocate_In(&connection);

	Allocate_out_of_memory(&connection);

	OpenSession_error_notExistingTA(&connection);

	Allocate_InOut(&connection);

	Register_In(&connection);

	Register_notZeroLength_Out(&connection);

	Register_InOut(&connection);

	Register_zeroLength_Out(&connection);

	Allocate_Out(&connection);

	FinalizeContext_null(&connection);

	InitializeContext_NotExistingTEE(&connection);

	AllocateThenRegister_SameMemory(&connection);

	AllocateSameMemory_twice(&connection);

	RegisterSameMemory_twice(&connection);

	Allocate_sharedMemory_maxSize(&connection);

	Allocate_sharedMemory_belowMaxSize(&connection);

	Allocate_sharedMemory_aboveMaxSize(&connection);

	Register_sharedMemory_maxSize(&connection);

	Register_sharedMemory_aboveMaxSize(&connection);

	Register_sharedMemory_belowMaxSize(&connection);
}

ADBG_CASE_DEFINE(XTEST_TEE_5006, xtest_teec_TEE,
		/* Title */
		"Tests for Global platform TEEC",
		/* Short description */
		"Invocation of all tests for TEE Client API",
		/* Requirement IDs */
		"TEE-??",
		/* How to implement */
		"Description of how to implement ...");
