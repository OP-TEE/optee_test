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
#include "ta_storage.h"

#include <tee_api.h>
#include <trace.h>

#define ASSERT_PARAM_TYPE(pt) \
do { \
	if ((pt) != param_types) \
		return TEE_ERROR_BAD_PARAMETERS; \
} while (0)

#define VAL2HANDLE(v) (void *)(uintptr_t)(v)

TEE_Result ta_storage_cmd_open(uint32_t command,
				uint32_t param_types, TEE_Param params[4])
{
	TEE_Result res;
	TEE_ObjectHandle o;
	void *object_id;

	ASSERT_PARAM_TYPE(TEE_PARAM_TYPES
			  (TEE_PARAM_TYPE_MEMREF_INPUT,
			   TEE_PARAM_TYPE_VALUE_INOUT,
			   TEE_PARAM_TYPE_VALUE_INPUT,
			   TEE_PARAM_TYPE_NONE));

	switch (command) {
	case TA_STORAGE_CMD_OPEN:
		object_id = TEE_Malloc(params[0].memref.size, 0);
		if (!object_id)
			return TEE_ERROR_OUT_OF_MEMORY;

		TEE_MemMove(object_id, params[0].memref.buffer,
			    params[0].memref.size);
		break;
	case TA_STORAGE_CMD_OPEN_ID_IN_SHM:
		object_id = params[0].memref.buffer;
		break;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	res = TEE_OpenPersistentObject(params[2].value.a,
					object_id, params[0].memref.size,
					params[1].value.a, &o);

	params[1].value.b = (uintptr_t)o;

	if (command == TA_STORAGE_CMD_OPEN)
		TEE_Free(object_id);

	return res;
}

TEE_Result ta_storage_cmd_create(uint32_t command,
				 uint32_t param_types, TEE_Param params[4])
{
	TEE_Result res;
	TEE_ObjectHandle o;
	void *object_id;
	TEE_ObjectHandle ref_handle;

	ASSERT_PARAM_TYPE(TEE_PARAM_TYPES
			  (TEE_PARAM_TYPE_MEMREF_INPUT,
			   TEE_PARAM_TYPE_VALUE_INOUT,
			   TEE_PARAM_TYPE_VALUE_INPUT,
			   TEE_PARAM_TYPE_MEMREF_INPUT));

	switch (command) {
	case TA_STORAGE_CMD_CREATE:
		object_id = TEE_Malloc(params[0].memref.size, 0);
		if (!object_id)
			return TEE_ERROR_OUT_OF_MEMORY;

		TEE_MemMove(object_id, params[0].memref.buffer,
			    params[0].memref.size);
		break;
	case TA_STORAGE_CMD_CREATE_ID_IN_SHM:
		object_id = params[0].memref.buffer;
		break;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	ref_handle = (TEE_ObjectHandle)(uintptr_t)params[2].value.a;

	res = TEE_CreatePersistentObject(params[2].value.b,
					 object_id, params[0].memref.size,
					 params[1].value.a, ref_handle,
					 params[3].memref.buffer,
					 params[3].memref.size, &o);

	if (command == TA_STORAGE_CMD_CREATE)
		TEE_Free(object_id);

	params[1].value.b = (uintptr_t)o;

	return res;
}

TEE_Result ta_storage_cmd_create_overwrite(uint32_t command,
					   uint32_t param_types,
					   TEE_Param params[4])
{
	TEE_Result res;
	void *object_id;

	ASSERT_PARAM_TYPE(TEE_PARAM_TYPES
			  (TEE_PARAM_TYPE_MEMREF_INPUT,
			   TEE_PARAM_TYPE_VALUE_INPUT,
			   TEE_PARAM_TYPE_NONE,
			   TEE_PARAM_TYPE_NONE));

	switch (command) {
	case TA_STORAGE_CMD_CREATE_OVERWRITE:
		object_id = TEE_Malloc(params[0].memref.size, 0);
		if (!object_id)
			return TEE_ERROR_OUT_OF_MEMORY;

		TEE_MemMove(object_id, params[0].memref.buffer,
			    params[0].memref.size);
		break;
	case TA_STORAGE_CMD_CREATEOVER_ID_IN_SHM:
		object_id = params[0].memref.buffer;
		break;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	res = TEE_CreatePersistentObject(params[1].value.a,
					 object_id, params[0].memref.size,
					 TEE_DATA_FLAG_OVERWRITE,
					 NULL, NULL, 0, NULL);

	if (command == TA_STORAGE_CMD_CREATE_OVERWRITE)
		TEE_Free(object_id);

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
	int32_t offs;

	ASSERT_PARAM_TYPE(TEE_PARAM_TYPES
			  (TEE_PARAM_TYPE_VALUE_INPUT,
			   TEE_PARAM_TYPE_VALUE_INOUT, TEE_PARAM_TYPE_NONE,
			   TEE_PARAM_TYPE_NONE));

	offs = *(int32_t *)&params[0].value.b;
	res = TEE_SeekObjectData(o, offs, params[1].value.a);
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

TEE_Result ta_storage_cmd_rename(uint32_t command, uint32_t param_types,
				 TEE_Param params[4])
{
	TEE_ObjectHandle o = VAL2HANDLE(params[0].value.a);
	void *object_id;
	TEE_Result res;

	ASSERT_PARAM_TYPE(TEE_PARAM_TYPES
			  (TEE_PARAM_TYPE_VALUE_INPUT,
			   TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_NONE,
			   TEE_PARAM_TYPE_NONE));

	switch (command) {
	case TA_STORAGE_CMD_RENAME:
		object_id = TEE_Malloc(params[1].memref.size, 0);
		if (!object_id)
			return TEE_ERROR_OUT_OF_MEMORY;

		TEE_MemMove(object_id, params[1].memref.buffer,
			    params[1].memref.size);
		break;
	case TA_STORAGE_CMD_RENAME_ID_IN_SHM:
		object_id = params[1].memref.buffer;
		break;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	res = TEE_RenamePersistentObject(o, object_id, params[1].memref.size);

	if (command == TA_STORAGE_CMD_RENAME)
		TEE_Free(object_id);

	return res;
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

	return TEE_StartPersistentObjectEnumerator(oe, params[0].value.b);
}

TEE_Result ta_storage_cmd_next_enum(uint32_t param_types, TEE_Param params[4])
{
	TEE_ObjectEnumHandle oe = VAL2HANDLE(params[0].value.a);
	TEE_ObjectInfo *obj;

	if (TEE_PARAM_TYPE_GET(param_types, 0) != TEE_PARAM_TYPE_VALUE_INPUT)
		return TEE_ERROR_BAD_PARAMETERS;
	if (TEE_PARAM_TYPE_GET(param_types, 2) != TEE_PARAM_TYPE_MEMREF_OUTPUT)
		return TEE_ERROR_BAD_PARAMETERS;
	if (TEE_PARAM_TYPE_GET(param_types, 3) != TEE_PARAM_TYPE_NONE)
		return TEE_ERROR_BAD_PARAMETERS;

	if (TEE_PARAM_TYPE_GET(param_types, 1) == TEE_PARAM_TYPE_NONE)
		obj = NULL;
	else if (TEE_PARAM_TYPE_GET(param_types, 1) ==
		 TEE_PARAM_TYPE_MEMREF_OUTPUT) {
		if (params[1].memref.size < sizeof(TEE_ObjectInfo)) {
			params[1].memref.size = sizeof(TEE_ObjectInfo);
			return TEE_ERROR_SHORT_BUFFER;
		}
		params[1].memref.size = sizeof(TEE_ObjectInfo);
		obj = (TEE_ObjectInfo *)params[1].memref.buffer;
	} else
		return TEE_ERROR_BAD_PARAMETERS;

	if (params[2].memref.size < TEE_OBJECT_ID_MAX_LEN)
		return TEE_ERROR_SHORT_BUFFER;

	return TEE_GetNextPersistentObject(oe, obj,
					   params[2].memref.buffer,
					   &params[2].memref.size);
}

static TEE_Result check_obj(TEE_ObjectInfo *o1, TEE_ObjectInfo *o2)
{
	if ((o1->objectType != o2->objectType) ||
	    (o1->keySize != o2->keySize) ||
	    (o1->maxKeySize != o2->maxKeySize) ||
	    (o1->objectUsage != o2->objectUsage))
		return TEE_ERROR_GENERIC;
	return TEE_SUCCESS;
}

TEE_Result ta_storage_cmd_key_in_persistent(uint32_t param_types,
					    TEE_Param params[4])
{
	TEE_Result result = TEE_SUCCESS;
	TEE_ObjectHandle transient_key = (TEE_ObjectHandle)NULL;
	TEE_ObjectHandle persistent_key = (TEE_ObjectHandle)NULL;
	TEE_ObjectHandle key = (TEE_ObjectHandle)NULL;
	TEE_OperationHandle encrypt_op = (TEE_OperationHandle)NULL;
	TEE_ObjectInfo keyInfo;
	TEE_ObjectInfo keyInfo2;
	TEE_ObjectInfo keyInfo3;
	uint32_t alg = TEE_ALG_AES_CBC_NOPAD;
	void *IV = NULL;
	size_t IVlen = 16;
	size_t key_size = 256;
	uint32_t objectID = 1;
	uint32_t flags = TEE_DATA_FLAG_ACCESS_READ |
			 TEE_DATA_FLAG_ACCESS_WRITE |
			 TEE_DATA_FLAG_ACCESS_WRITE_META |
			 TEE_DATA_FLAG_SHARE_READ |
			 TEE_DATA_FLAG_SHARE_WRITE;

	ASSERT_PARAM_TYPE(TEE_PARAM_TYPES
			  (TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_NONE,
			   TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE));

	result = TEE_AllocateTransientObject(TEE_TYPE_AES, key_size,
					     &transient_key);
	if (result != TEE_SUCCESS) {
		EMSG("Failed to Allocate transient object handle : 0x%x",
		     result);
		goto cleanup1;
	}

	result = TEE_GenerateKey(transient_key, key_size, NULL, 0);
	if (result != TEE_SUCCESS) {
		EMSG("Failed to generate a transient key: 0x%x", result);
		goto cleanup2;
	}

	TEE_GetObjectInfo1(transient_key, &keyInfo);
	result = TEE_CreatePersistentObject(params[0].value.a,
					    &objectID, sizeof(objectID),
					    flags, transient_key, NULL, 0,
					    &persistent_key);
	if (result != TEE_SUCCESS) {
		EMSG("Failed to create a persistent key: 0x%x", result);
		goto cleanup2;
	}

	TEE_GetObjectInfo1(persistent_key, &keyInfo2);
	result = check_obj(&keyInfo, &keyInfo2);
	if (result != TEE_SUCCESS) {
		EMSG("keyInfo and keyInfo2 are different");
		goto cleanup2;
	}

	TEE_CloseObject(persistent_key);

	result = TEE_OpenPersistentObject(params[0].value.a,
					  &objectID, sizeof(objectID),
					  flags, &key);
	if (result != TEE_SUCCESS) {
		EMSG("Failed to open persistent key: 0x%x", result);
		goto cleanup2;
	}

	TEE_GetObjectInfo(key, &keyInfo3);
	result = check_obj(&keyInfo3, &keyInfo2);
	if (result != TEE_SUCCESS) {
		EMSG("keyInfo2 and keyInfo3 are different");
		goto cleanup2;
	}

	result = TEE_AllocateOperation(&encrypt_op, alg, TEE_MODE_ENCRYPT,
				       keyInfo3.maxObjectSize);
	if (result != TEE_SUCCESS) {
		EMSG("Failed to allocate an operation: 0x%x", result);
		goto cleanup3;
	}

	result = TEE_SetOperationKey(encrypt_op, key);
	if (result != TEE_SUCCESS) {
		EMSG("Failed to set operation key: 0x%x", result);
		goto cleanup4;
	}

	IV = TEE_Malloc(IVlen, 0);
	if (!IV) {
		EMSG("Out of memory for IV.");
		result = TEE_ERROR_OUT_OF_MEMORY;
		goto cleanup4;
	}

	TEE_CipherInit(encrypt_op, IV, IVlen);
	TEE_Free(IV);

cleanup4:
	TEE_FreeOperation(encrypt_op);
cleanup3:
	TEE_CloseAndDeletePersistentObject1(key);
cleanup2:
	TEE_FreeTransientObject(transient_key);
cleanup1:
	return result;
}

TEE_Result ta_storage_cmd_loop(uint32_t param_types, TEE_Param params[4])
{
	TEE_ObjectHandle object = TEE_HANDLE_NULL;
	TEE_Result res;
	int object_id = 0;
	uint32_t flags =  TEE_DATA_FLAG_OVERWRITE |
			  TEE_DATA_FLAG_ACCESS_WRITE_META;
	int i = 0;

	(void)params;
	ASSERT_PARAM_TYPE(TEE_PARAM_TYPES
			  (TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_NONE,
			   TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE));

	for (i = 0; i < 20; i++) {
		DMSG("\n\nLOOP : %d", i);
		object = TEE_HANDLE_NULL;
		object_id = i;
		res = TEE_CreatePersistentObject(params[0].value.a,
						 &object_id, sizeof(int), flags,
						 TEE_HANDLE_NULL, NULL, 0,
						 &object);

		if (res != TEE_SUCCESS) {
			EMSG("FAIL");
			return res;
		}

		res = TEE_CloseAndDeletePersistentObject1(object);
		if (res != TEE_SUCCESS) {
			EMSG("FAIL");
			return res;
		}
	}

	return TEE_SUCCESS;
}

TEE_Result ta_storage_cmd_restrict_usage(uint32_t param_types,
					 TEE_Param params[4])
{
	TEE_ObjectHandle o;

	ASSERT_PARAM_TYPE(TEE_PARAM_TYPES
			  (TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_NONE,
			   TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE));

	o = (TEE_ObjectHandle)(uintptr_t)params[0].value.a;
	TEE_RestrictObjectUsage1(o, params[0].value.b);
	return TEE_SUCCESS;
}

TEE_Result ta_storage_cmd_alloc_obj(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result res;
	TEE_ObjectHandle o;

	ASSERT_PARAM_TYPE(TEE_PARAM_TYPES
			  (TEE_PARAM_TYPE_VALUE_INPUT,
			   TEE_PARAM_TYPE_VALUE_OUTPUT,
			   TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE));

	res = TEE_AllocateTransientObject(params[0].value.a, params[0].value.b,
					  &o);
	params[1].value.a = (uint32_t)(uintptr_t)o;
	return res;
}

TEE_Result ta_storage_cmd_free_obj(uint32_t param_types, TEE_Param params[4])
{
	TEE_ObjectHandle o;

	ASSERT_PARAM_TYPE(TEE_PARAM_TYPES
			  (TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_NONE,
			   TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE));

	o = (TEE_ObjectHandle)(uintptr_t)params[0].value.a;
	TEE_FreeTransientObject(o);
	return TEE_SUCCESS;
}

TEE_Result ta_storage_cmd_reset_obj(uint32_t param_types, TEE_Param params[4])
{
	TEE_ObjectHandle o;

	ASSERT_PARAM_TYPE(TEE_PARAM_TYPES
			  (TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_NONE,
			   TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE));

	o = (TEE_ObjectHandle)(uintptr_t)params[0].value.a;
	TEE_ResetTransientObject(o);
	return TEE_SUCCESS;
}

TEE_Result ta_storage_cmd_get_obj_info(uint32_t param_types,
					    TEE_Param params[4])
{
	TEE_Result res;
	TEE_ObjectInfo *info;
	TEE_ObjectHandle o = VAL2HANDLE(params[0].value.a);

	ASSERT_PARAM_TYPE(TEE_PARAM_TYPES
			  (TEE_PARAM_TYPE_VALUE_INPUT,
			   TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE,
			   TEE_PARAM_TYPE_NONE));

	info = (TEE_ObjectInfo *)params[1].memref.buffer;
	res = TEE_GetObjectInfo1(o, info);

	return res;
}
