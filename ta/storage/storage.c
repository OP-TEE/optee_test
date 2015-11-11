/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "storage.h"

#include <tee_api.h>

#define ASSERT_PARAM_TYPE(pt) \
do { \
	if ((pt) != param_types) \
		return TEE_ERROR_BAD_PARAMETERS; \
} while (0)

#define VAL2HANDLE(v) (void *)(uintptr_t)(v)

TEE_Result ta_storage_cmd_open(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result res;
	TEE_ObjectHandle o;

	ASSERT_PARAM_TYPE(TEE_PARAM_TYPES
			  (TEE_PARAM_TYPE_MEMREF_INPUT,
			   TEE_PARAM_TYPE_VALUE_INOUT, TEE_PARAM_TYPE_NONE,
			   TEE_PARAM_TYPE_NONE));

	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
					params[0].memref.buffer,
					params[0].memref.size,
					params[1].value.a, &o);

	params[1].value.b = (uintptr_t)o;
	return res;
}

TEE_Result ta_storage_cmd_create(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result res;
	TEE_ObjectHandle o;

	ASSERT_PARAM_TYPE(TEE_PARAM_TYPES
			  (TEE_PARAM_TYPE_MEMREF_INPUT,
			   TEE_PARAM_TYPE_VALUE_INOUT,
			   TEE_PARAM_TYPE_VALUE_INPUT,
			   TEE_PARAM_TYPE_MEMREF_INPUT));

	res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
		 params[0].memref.buffer, params[0].memref.size,
		 params[1].value.a,
		 (TEE_ObjectHandle)(uintptr_t)params[2].value.a,
		 params[3].memref.buffer, params[3].memref.size, &o);
	params[1].value.b = (uintptr_t)o;
	return res;
}

TEE_Result ta_storage_cmd_close(uint32_t param_types, TEE_Param params[4])
{
	ASSERT_PARAM_TYPE(TEE_PARAM_TYPES
			  (TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_NONE,
			   TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE));

	TEE_CloseObject((TEE_ObjectHandle)(uintptr_t)params[0].value.a);

	return TEE_SUCCESS;
}

TEE_Result ta_storage_cmd_read(uint32_t param_types, TEE_Param params[4])
{
	TEE_ObjectHandle o = VAL2HANDLE(params[1].value.a);

	ASSERT_PARAM_TYPE(TEE_PARAM_TYPES
			  (TEE_PARAM_TYPE_MEMREF_OUTPUT,
			   TEE_PARAM_TYPE_VALUE_INOUT, TEE_PARAM_TYPE_NONE,
			   TEE_PARAM_TYPE_NONE));

	return TEE_ReadObjectData(o, params[0].memref.buffer,
				  params[0].memref.size, &params[1].value.b);
}

TEE_Result ta_storage_cmd_write(uint32_t param_types, TEE_Param params[4])
{
	TEE_ObjectHandle o = VAL2HANDLE(params[1].value.a);

	ASSERT_PARAM_TYPE(TEE_PARAM_TYPES
			  (TEE_PARAM_TYPE_MEMREF_INPUT,
			   TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_NONE,
			   TEE_PARAM_TYPE_NONE));

	return TEE_WriteObjectData(o, params[0].memref.buffer,
				   params[0].memref.size);
}

TEE_Result ta_storage_cmd_seek(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result res;
	TEE_ObjectInfo info;
	TEE_ObjectHandle o = VAL2HANDLE(params[0].value.a);

	ASSERT_PARAM_TYPE(TEE_PARAM_TYPES
			  (TEE_PARAM_TYPE_VALUE_INPUT,
			   TEE_PARAM_TYPE_VALUE_INOUT, TEE_PARAM_TYPE_NONE,
			   TEE_PARAM_TYPE_NONE));

	res = TEE_SeekObjectData(o, params[0].value.b, params[1].value.a);
	if (res != TEE_SUCCESS)
		return res;
	res = TEE_GetObjectInfo1(o, &info);

	params[1].value.b = info.dataPosition;

	return res;
}

TEE_Result ta_storage_cmd_unlink(uint32_t param_types, TEE_Param params[4])
{
	TEE_ObjectHandle o = VAL2HANDLE(params[0].value.a);

	ASSERT_PARAM_TYPE(TEE_PARAM_TYPES
			  (TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_NONE,
			   TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE));

	TEE_CloseAndDeletePersistentObject1(o);

	return TEE_SUCCESS;
}

TEE_Result ta_storage_cmd_rename(uint32_t param_types, TEE_Param params[4])
{
	TEE_ObjectHandle o = VAL2HANDLE(params[0].value.a);

	ASSERT_PARAM_TYPE(TEE_PARAM_TYPES
			  (TEE_PARAM_TYPE_VALUE_INPUT,
			   TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_NONE,
			   TEE_PARAM_TYPE_NONE));

	return TEE_RenamePersistentObject(o, params[1].memref.buffer,
					  params[1].memref.size);
}

TEE_Result ta_storage_cmd_trunc(uint32_t param_types, TEE_Param params[4])
{
	TEE_ObjectHandle o = VAL2HANDLE(params[0].value.a);

	ASSERT_PARAM_TYPE(TEE_PARAM_TYPES
			  (TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_NONE,
			   TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE));

	return TEE_TruncateObjectData(o, params[0].value.b);
}

TEE_Result ta_storage_cmd_alloc_enum(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result res;
	TEE_ObjectEnumHandle oe;

	ASSERT_PARAM_TYPE(TEE_PARAM_TYPES
			  (TEE_PARAM_TYPE_VALUE_OUTPUT, TEE_PARAM_TYPE_NONE,
			   TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE));

	res = TEE_AllocatePersistentObjectEnumerator(&oe);
	params[0].value.a = (uintptr_t)oe;
	return res;
}

TEE_Result ta_storage_cmd_free_enum(uint32_t param_types, TEE_Param params[4])
{
	TEE_ObjectEnumHandle oe = VAL2HANDLE(params[0].value.a);

	ASSERT_PARAM_TYPE(TEE_PARAM_TYPES
			  (TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_NONE,
			   TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE));

	TEE_FreePersistentObjectEnumerator(oe);
	return TEE_SUCCESS;
}

TEE_Result ta_storage_cmd_reset_enum(uint32_t param_types, TEE_Param params[4])
{
	TEE_ObjectEnumHandle oe = VAL2HANDLE(params[0].value.a);

	ASSERT_PARAM_TYPE(TEE_PARAM_TYPES
			  (TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_NONE,
			   TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE));

	TEE_ResetPersistentObjectEnumerator(oe);
	return TEE_SUCCESS;
}

TEE_Result ta_storage_cmd_start_enum(uint32_t param_types, TEE_Param params[4])
{
	TEE_ObjectEnumHandle oe = VAL2HANDLE(params[0].value.a);

	ASSERT_PARAM_TYPE(TEE_PARAM_TYPES
			  (TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_NONE,
			   TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE));

	return TEE_StartPersistentObjectEnumerator(oe, TEE_STORAGE_PRIVATE);
}

TEE_Result ta_storage_cmd_next_enum(uint32_t param_types, TEE_Param params[4])
{
	TEE_ObjectEnumHandle oe = VAL2HANDLE(params[0].value.a);

	ASSERT_PARAM_TYPE(TEE_PARAM_TYPES
			  (TEE_PARAM_TYPE_VALUE_INPUT,
			   TEE_PARAM_TYPE_MEMREF_OUTPUT,
			   TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE));

	if (params[1].memref.size < sizeof(TEE_ObjectInfo))
		return TEE_ERROR_SHORT_BUFFER;

	if (params[2].memref.size < TEE_OBJECT_ID_MAX_LEN)
		return TEE_ERROR_SHORT_BUFFER;

	params[1].memref.size = sizeof(TEE_ObjectInfo);

	return TEE_GetNextPersistentObject(oe,
			(TEE_ObjectInfo *)params[1].memref.buffer,
			params[2].memref.buffer, &params[2].memref.size);
}
