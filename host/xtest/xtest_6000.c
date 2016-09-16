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

#include <string.h>
#include <stdio.h>
#include <pthread.h>

#include <adbg.h>
#include <xtest_test.h>
#include <xtest_helpers.h>

#include <tee_client_api.h>
#include <ta_storage.h>
#include <tee_api_defines.h>
#include <tee_api_defines_extensions.h>
#include <tee_api_types.h>
#ifdef WITH_GP_TESTS
#include <TTA_DS_protocol.h>
#endif
#include <util.h>

static uint32_t storage_ids[] = {
	TEE_STORAGE_PRIVATE,
#ifdef CFG_REE_FS
	TEE_STORAGE_PRIVATE_REE,
#endif
#ifdef CFG_RPMB_FS
	TEE_STORAGE_PRIVATE_RPMB,
#endif
#ifdef CFG_SQL_FS
	TEE_STORAGE_PRIVATE_SQL,
#endif
};

static uint8_t file_00[] = {
	0x00, 0x6E, 0x04, 0x57, 0x08, 0xFB, 0x71, 0x96,
	0xF0, 0x2E, 0x55, 0x3D, 0x02, 0xC3, 0xA6, 0x92,
	0xE9, 0xC3, 0xEF, 0x8A, 0xB2, 0x34, 0x53, 0xE6,
	0xF0, 0x74, 0x9C, 0xD6, 0x36, 0xE7, 0xA8, 0x8E
};

static uint8_t file_01[] = {
	0x01, 0x00
};

static uint8_t file_02[] = {
	0x02, 0x11, 0x02
};

static uint8_t file_03[] = {
	0x03, 0x13, 0x03
};

static uint8_t file_04[] = {
	0x00, 0x01, 0x02
};

static uint8_t data_00[] = {
	0x00, 0x6E, 0x04, 0x57, 0x08, 0xFB, 0x71, 0x96,
	0x00, 0x2E, 0x55, 0x3D, 0x02, 0xC3, 0xA6, 0x92,
	0x00, 0xC3, 0xEF, 0x8A, 0xB2, 0x34, 0x53, 0xE6,
	0x00, 0x74, 0x9C, 0xD6, 0x36, 0xE7, 0xA8, 0x00
};

static uint8_t data_01[] = {
	0x01, 0x6E, 0x04, 0x57, 0x08, 0xFB, 0x71, 0x96,
	0x01, 0x2E, 0x55, 0x3D, 0x02, 0xC3, 0xA6, 0x92,
	0x01, 0xC3, 0xEF, 0x8A, 0xB2, 0x34, 0x53, 0xE6,
	0x01, 0x74, 0x9C, 0xD6, 0x36, 0xE7, 0xA8, 0x01
};

static TEEC_Result fs_open(TEEC_Session *sess, void *id, uint32_t id_size,
			   uint32_t flags, uint32_t *obj, uint32_t storage_id)
{
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	TEEC_Result res;
	uint32_t org;

	op.params[0].tmpref.buffer = id;
	op.params[0].tmpref.size = id_size;
	op.params[1].value.a = flags;
	op.params[1].value.b = 0;
	op.params[2].value.a = storage_id;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_VALUE_INOUT, TEEC_VALUE_INPUT,
					 TEEC_NONE);

	res = TEEC_InvokeCommand(sess, TA_STORAGE_CMD_OPEN, &op, &org);

	if (res == TEEC_SUCCESS)
		*obj = op.params[1].value.b;

	return res;
}

static TEEC_Result fs_create(TEEC_Session *sess, void *id, uint32_t id_size,
			     uint32_t flags, uint32_t attr, void *data,
			     uint32_t data_size, uint32_t *obj,
			     uint32_t storage_id)
{
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	TEEC_Result res;
	uint32_t org;

	op.params[0].tmpref.buffer = id;
	op.params[0].tmpref.size = id_size;
	op.params[1].value.a = flags;
	op.params[1].value.b = 0;
	op.params[2].value.a = attr;
	op.params[2].value.b = storage_id;
	op.params[3].tmpref.buffer = data;
	op.params[3].tmpref.size = data_size;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_VALUE_INOUT, TEEC_VALUE_INPUT,
					 TEEC_MEMREF_TEMP_INPUT);

	res = TEEC_InvokeCommand(sess, TA_STORAGE_CMD_CREATE, &op, &org);

	if (res == TEEC_SUCCESS)
		*obj = op.params[1].value.b;

	return res;
}

static TEEC_Result fs_create_overwrite(TEEC_Session *sess, void *id,
				       uint32_t id_size, uint32_t storage_id)
{
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	TEEC_Result res;
	uint32_t org;

	op.params[0].tmpref.buffer = id;
	op.params[0].tmpref.size = id_size;
	op.params[1].value.a = storage_id;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_VALUE_INPUT, TEEC_NONE,
					 TEEC_NONE);

	res = TEEC_InvokeCommand(sess, TA_STORAGE_CMD_CREATE_OVERWRITE, &op, &org);

	return res;
}

static TEEC_Result fs_close(TEEC_Session *sess, uint32_t obj)
{
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;

	op.params[0].value.a = obj;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	return TEEC_InvokeCommand(sess, TA_STORAGE_CMD_CLOSE, &op, &org);
}

static TEEC_Result fs_read(TEEC_Session *sess, uint32_t obj, void *data,
			   uint32_t data_size, uint32_t *count)
{
	TEEC_Result res;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;

	op.params[0].tmpref.buffer = data;
	op.params[0].tmpref.size = data_size;
	op.params[1].value.a = obj;
	op.params[1].value.b = 0;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_VALUE_INOUT, TEEC_NONE,
					 TEEC_NONE);

	res = TEEC_InvokeCommand(sess, TA_STORAGE_CMD_READ, &op, &org);

	if (res == TEEC_SUCCESS)
		*count = op.params[1].value.b;

	return res;
}

static TEEC_Result fs_write(TEEC_Session *sess, uint32_t obj, void *data,
			    uint32_t data_size)
{
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;

	op.params[0].tmpref.buffer = data;
	op.params[0].tmpref.size = data_size;
	op.params[1].value.a = obj;
	op.params[1].value.b = 0;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_VALUE_INPUT, TEEC_NONE,
					 TEEC_NONE);

	return TEEC_InvokeCommand(sess, TA_STORAGE_CMD_WRITE, &op, &org);
}

static TEEC_Result fs_seek(TEEC_Session *sess, uint32_t obj, int32_t offset,
			   int32_t whence)
{
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;

	op.params[0].value.a = obj;
	op.params[0].value.b = *(uint32_t *)&offset;
	op.params[1].value.a = whence;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_VALUE_INOUT,
					 TEEC_NONE, TEEC_NONE);

	return TEEC_InvokeCommand(sess, TA_STORAGE_CMD_SEEK, &op, &org);
}

static TEEC_Result fs_unlink(TEEC_Session *sess, uint32_t obj)
{
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;

	op.params[0].value.a = obj;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	return TEEC_InvokeCommand(sess, TA_STORAGE_CMD_UNLINK, &op, &org);
}

static TEEC_Result fs_trunc(TEEC_Session *sess, uint32_t obj, uint32_t len)
{
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;

	op.params[0].value.a = obj;
	op.params[0].value.b = len;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	return TEEC_InvokeCommand(sess, TA_STORAGE_CMD_TRUNC, &op, &org);
}

static TEEC_Result fs_rename(TEEC_Session *sess, uint32_t obj, void *id,
			     uint32_t id_size)
{
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;

	op.params[0].value.a = obj;
	op.params[1].tmpref.buffer = id;
	op.params[1].tmpref.size = id_size;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_TEMP_INPUT, TEEC_NONE,
					 TEEC_NONE);

	return TEEC_InvokeCommand(sess, TA_STORAGE_CMD_RENAME, &op, &org);
}

static TEEC_Result fs_alloc_enum(TEEC_Session *sess, uint32_t *e)
{
	TEEC_Result res;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(sess, TA_STORAGE_CMD_ALLOC_ENUM, &op, &org);

	if (res == TEEC_SUCCESS)
		*e = op.params[0].value.a;

	return res;
}

static TEEC_Result fs_free_enum(TEEC_Session *sess, uint32_t e)
{
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE,
					 TEEC_NONE);

	op.params[0].value.a = e;

	return TEEC_InvokeCommand(sess, TA_STORAGE_CMD_FREE_ENUM, &op, &org);
}

static TEEC_Result fs_start_enum(TEEC_Session *sess, uint32_t e,
				 uint32_t storage_id)
{
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	op.params[0].value.a = e;
	op.params[0].value.b = storage_id;

	return TEEC_InvokeCommand(sess, TA_STORAGE_CMD_START_ENUM, &op, &org);
}

static TEEC_Result fs_next_enum(TEEC_Session *sess, uint32_t e, void *obj_info,
				size_t info_size, void *id, uint32_t id_size)
{
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
					 TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE);
	if (obj_info && info_size)
		op.paramTypes |= (TEEC_MEMREF_TEMP_OUTPUT << 4);

	op.params[0].value.a = e;
	op.params[1].tmpref.buffer = obj_info;
	op.params[1].tmpref.size = info_size;
	op.params[2].tmpref.buffer = id;
	op.params[2].tmpref.size = id_size;

	return TEEC_InvokeCommand(sess, TA_STORAGE_CMD_NEXT_ENUM, &op, &org);
}

static TEEC_Result fs_restrict_usage(TEEC_Session *sess, uint32_t obj,
				     uint32_t obj_usage)
{
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;

	op.params[0].value.a = obj;
	op.params[0].value.b = obj_usage;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	return TEEC_InvokeCommand(sess, TA_STORAGE_CMD_RESTRICT_USAGE,
				  &op, &org);
}

static TEEC_Result fs_alloc_obj(TEEC_Session *sess, uint32_t obj_type,
				     uint32_t max_key_size, uint32_t *obj)
{
	TEEC_Result res;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;

	op.params[0].value.a = obj_type;
	op.params[0].value.b = max_key_size;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_VALUE_OUTPUT,
					 TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(sess, TA_STORAGE_CMD_ALLOC_OBJ, &op, &org);
	*obj = op.params[1].value.a;
	return res;
}

static TEEC_Result fs_free_obj(TEEC_Session *sess, uint32_t obj)
{
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;

	op.params[0].value.a = obj;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	return TEEC_InvokeCommand(sess, TA_STORAGE_CMD_FREE_OBJ, &op, &org);
}

static TEEC_Result fs_reset_obj(TEEC_Session *sess, uint32_t obj)
{
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;

	op.params[0].value.a = obj;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	return TEEC_InvokeCommand(sess, TA_STORAGE_CMD_RESET_OBJ, &op, &org);
}

/* trunc */
static void test_truncate_file_length(ADBG_Case_t *c, uint32_t storage_id)
{
	TEEC_Session sess;
	uint32_t obj;
	uint8_t out[10] = { 0 };
	uint32_t count;
	uint32_t orig;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		xtest_teec_open_session(&sess, &storage_ta_uuid, NULL, &orig)))
		return;

	/* create */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		fs_create(&sess, file_01, sizeof(file_01),
			  TEE_DATA_FLAG_ACCESS_WRITE |
			  TEE_DATA_FLAG_ACCESS_READ |
			  TEE_DATA_FLAG_ACCESS_WRITE_META, 0, data_00,
			  sizeof(data_00), &obj, storage_id)))
		goto exit;

	/* trunc */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, fs_trunc(&sess, obj, 10)))
		goto exit;

	/* seek */
	if (!ADBG_EXPECT_TEEC_SUCCESS(
		    c, fs_seek(&sess, obj, 5, TEE_DATA_SEEK_SET)))
		goto exit;

	/* verify */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, fs_read(&sess, obj, out, 10, &count)))
		goto exit;

	/* check buffer */
	(void)ADBG_EXPECT_BUFFER(c, &data_00[5], 5, out, count);

	/* clean */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, fs_unlink(&sess, obj)))
		goto exit;

exit:
	TEEC_CloseSession(&sess);
}

/* extend */
static void test_extend_file_length(ADBG_Case_t *c, uint32_t storage_id)
{
	TEEC_Session sess;
	uint32_t obj;
	uint8_t out[10] = { 0 };
	uint8_t expect[10] = { 0 };
	uint32_t count;
	uint32_t orig;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		xtest_teec_open_session(&sess, &storage_ta_uuid, NULL, &orig)))
		return;

	/* create */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		fs_create(&sess, file_01, sizeof(file_01),
			  TEE_DATA_FLAG_ACCESS_WRITE |
			  TEE_DATA_FLAG_ACCESS_READ |
			  TEE_DATA_FLAG_ACCESS_WRITE_META, 0, data_00,
			  sizeof(data_00), &obj, storage_id)))
		goto exit;

	/* extend */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, fs_trunc(&sess, obj, 40)))
		goto exit;

	/* seek */
	if (!ADBG_EXPECT_TEEC_SUCCESS(
		    c, fs_seek(&sess, obj, 30, TEE_DATA_SEEK_SET)))
		goto exit;

	/* verify */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, fs_read(&sess, obj, out, 10, &count)))
		goto exit;

	/* check buffer */
	expect[0] = data_00[30];
	expect[1] = data_00[31];
	(void)ADBG_EXPECT_BUFFER(c, &expect[0], 10, out, count);

	/* clean */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, fs_unlink(&sess, obj)))
		goto exit;

exit:
	TEEC_CloseSession(&sess);
}

/* file hole */
static void test_file_hole(ADBG_Case_t *c, uint32_t storage_id)
{
	TEEC_Session sess;
	uint32_t obj;
	uint8_t out[10] = { 0 };
	uint8_t expect[10] = { 0 };
	uint32_t count;
	uint32_t orig;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		xtest_teec_open_session(&sess, &storage_ta_uuid, NULL, &orig)))
		return;

	/* create */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		fs_create(&sess, file_01, sizeof(file_01),
			  TEE_DATA_FLAG_ACCESS_WRITE |
			  TEE_DATA_FLAG_ACCESS_READ |
			  TEE_DATA_FLAG_ACCESS_WRITE_META, 0, data_00,
			  sizeof(data_00), &obj, storage_id)))
		goto exit;

	/* seek */
	if (!ADBG_EXPECT_TEEC_SUCCESS(
		    c, fs_seek(&sess, obj, 80, TEE_DATA_SEEK_SET)))
		goto exit;

	/* write */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, fs_write(&sess, obj, data_00,
			sizeof(data_00))))
		goto exit;

	/* seek */
	if (!ADBG_EXPECT_TEEC_SUCCESS(
		    c, fs_seek(&sess, obj, 74, TEE_DATA_SEEK_SET)))
		goto exit;

	/* verify */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, fs_read(&sess, obj, out, 10, &count)))
		goto exit;

	/* check buffer */
	expect[6] = data_00[0];
	expect[7] = data_00[1];
	expect[8] = data_00[2];
	expect[9] = data_00[3];
	(void)ADBG_EXPECT_BUFFER(c, &expect[0], 10, out, count);

	/* clean */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, fs_unlink(&sess, obj)))
		goto exit;

exit:
	TEEC_CloseSession(&sess);
}

#ifdef WITH_GP_TESTS
static TEEC_Result ds_seek_obj_inv_handle(TEEC_Session *sess)
{
    TEEC_Operation op;
    uint32_t org;

    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);

    op.params[0].value.a = CASE_DATA_OBJECT_NOT_PERSISTENT;

    return TEEC_InvokeCommand(
        sess, CMD_SeekObjectData_panic, &op, &org);
}

static TEEC_Result ds_seek_gp(
    TEEC_Session *sess, TEE_Whence wh, uint32_t wh_off, uint32_t set_off,
    void *in, size_t in_size, void *out, size_t out_size)
{
    TEEC_Operation op;
    uint32_t org;

    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_VALUE_INPUT, TEEC_VALUE_INPUT, TEEC_MEMREF_TEMP_INPUT,
        TEEC_MEMREF_TEMP_OUTPUT);

    op.params[0].value.a = wh;
    op.params[0].value.b = wh_off;
    op.params[1].value.a = set_off;
    op.params[2].tmpref.buffer = in;
    op.params[2].tmpref.size = in_size;
    op.params[3].tmpref.buffer = out;
    op.params[3].tmpref.size = out_size;

    return TEEC_InvokeCommand(sess, CMD_SeekWriteReadObjectData, &op, &org);
}

static TEEC_Result ds_init_object_and_attributes(TEEC_Session *sess,
            uint32_t obj_type, uint32_t obj_size, const void *attr_meta,
            size_t attr_meta_len, const void *attr_data, size_t attr_data_len,
            uint32_t option)
{
    TEEC_Operation op;
    uint32_t org;

    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_VALUE_INPUT, TEEC_MEMREF_TEMP_INPUT,
        TEEC_MEMREF_TEMP_INPUT, TEEC_VALUE_INPUT);

    op.params[0].value.a = obj_type;
    op.params[0].value.b = obj_size;
    op.params[1].tmpref.buffer = (void *)attr_meta;
    op.params[1].tmpref.size = attr_meta_len;
    op.params[2].tmpref.buffer = (void *)attr_data;
    op.params[2].tmpref.size = attr_data_len;
    op.params[3].value.a = option;

    return TEEC_InvokeCommand(sess, CMD_InitObjectAndAttributes, &op, &org);
}

static TEEC_Result ds_rename_access_conflict(TEEC_Session *sess)
{
    TEEC_Operation op;
    uint32_t org;

    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);

    return TEEC_InvokeCommand(
        sess, CMD_RenamePersistentObject_AccessConflict, &op, &org);
}

static TEEC_Result ds_start_enum_no_item(TEEC_Session *sess)
{
    TEEC_Operation op;
    uint32_t org;
    TEEC_Result res;

    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_VALUE_OUTPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);

    res = TEEC_InvokeCommand(
        sess, CMD_StartNGetPersistentObjectEnumerator_itemNotFound, &op, &org);

    if (res != TEEC_SUCCESS)
        return res;

    if (op.params[0].value.a != 0 || op.params[0].value.b != 0)
        return TEEC_ERROR_GENERIC;

    return res;
}

static TEEC_Result ds_rename_success(TEEC_Session *sess)
{
    TEEC_Operation op;
    uint32_t org;

    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);

    return TEEC_InvokeCommand(
        sess, CMD_RenamePersistentObject_Success, &op, &org);
}

static TEEC_Result ds_null_close_free_reset(TEEC_Session *sess)
{
    TEEC_Operation op;
    uint32_t org;

    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);

    return TEEC_InvokeCommand(
        sess, CMD_CloseFreeAndResetObjectSuccessHandleNull, &op, &org);
}
#endif

/* create */
static void xtest_tee_test_6001_single(ADBG_Case_t *c, uint32_t storage_id)
{
	TEEC_Session sess;
	uint32_t obj;
	uint32_t orig;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		xtest_teec_open_session(&sess, &storage_ta_uuid, NULL, &orig)))
		return;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		fs_create(&sess, file_00, sizeof(file_00),
			  TEE_DATA_FLAG_ACCESS_WRITE |
			  TEE_DATA_FLAG_ACCESS_WRITE_META, 0, data_00,
			  sizeof(data_00), &obj, storage_id)))
		goto exit;

	/* clean */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, fs_unlink(&sess, obj)))
		goto exit;

exit:
	TEEC_CloseSession(&sess);
}

#define DEFINE_TEST_MULTIPLE_STORAGE_IDS(test_name)			     \
static void test_name(ADBG_Case_t *c)					     \
{									     \
	size_t i;							     \
									     \
	for (i = 0; i < ARRAY_SIZE(storage_ids); i++) {			     \
		Do_ADBG_BeginSubCase(c, "Storage id: %08x", storage_ids[i]); \
		test_name##_single(c, storage_ids[i]);			     \
		Do_ADBG_EndSubCase(c, "Storage id: %08x", storage_ids[i]);   \
	}								     \
}

DEFINE_TEST_MULTIPLE_STORAGE_IDS(xtest_tee_test_6001)

/* open */
static void xtest_tee_test_6002_single(ADBG_Case_t *c, uint32_t storage_id)
{
	TEEC_Session sess;
	uint32_t obj;
	uint32_t orig;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		xtest_teec_open_session(&sess, &storage_ta_uuid, NULL, &orig)))
		return;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		fs_create(&sess, file_01, sizeof(file_01),
			  TEE_DATA_FLAG_ACCESS_WRITE, 0, data_00,
			  sizeof(data_00), &obj, storage_id)))
		goto exit;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, fs_close(&sess, obj)))
		goto exit;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		fs_open(&sess, file_01, sizeof(file_01),
			TEE_DATA_FLAG_ACCESS_WRITE_META, &obj, storage_id)))
		goto exit;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, fs_close(&sess, obj)))
		goto exit;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		fs_open(&sess, file_01, sizeof(file_01),
			TEE_DATA_FLAG_ACCESS_WRITE_META, &obj, storage_id)))
		goto exit;

	/* clean */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, fs_unlink(&sess, obj)))
		goto exit;

exit:
	TEEC_CloseSession(&sess);
}

DEFINE_TEST_MULTIPLE_STORAGE_IDS(xtest_tee_test_6002)

/* read */
static void xtest_tee_test_6003_single(ADBG_Case_t *c, uint32_t storage_id)
{
	TEEC_Session sess;
	uint32_t obj;
	uint8_t out[10] = { 0 };
	uint32_t count;
	uint32_t orig;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		xtest_teec_open_session(&sess, &storage_ta_uuid, NULL, &orig)))
		return;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		fs_create(&sess, file_02, sizeof(file_02),
			  TEE_DATA_FLAG_ACCESS_WRITE, 0, data_01,
			  sizeof(data_01), &obj, storage_id)))
		goto exit;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, fs_close(&sess, obj)))
		goto exit;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		fs_open(&sess, file_02, sizeof(file_02),
			TEE_DATA_FLAG_ACCESS_READ |
			TEE_DATA_FLAG_ACCESS_WRITE_META, &obj, storage_id)))
		goto exit;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, fs_read(&sess, obj, out, 10, &count)))
		goto exit;

	(void)ADBG_EXPECT_BUFFER(c, data_01, 10, out, count);

	/* clean */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, fs_unlink(&sess, obj)))
		goto exit;

exit:
	TEEC_CloseSession(&sess);
}

DEFINE_TEST_MULTIPLE_STORAGE_IDS(xtest_tee_test_6003)

/* write */
static void xtest_tee_test_6004_single(ADBG_Case_t *c, uint32_t storage_id)
{
	TEEC_Session sess;
	uint32_t obj;
	uint8_t out[10] = { 0 };
	uint32_t count;
	uint32_t orig;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		xtest_teec_open_session(&sess, &storage_ta_uuid, NULL, &orig)))
		return;

	/* create */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		fs_create(&sess, file_02, sizeof(file_02),
			  TEE_DATA_FLAG_ACCESS_WRITE, 0, data_01,
			  sizeof(data_01), &obj, storage_id)))
		goto exit;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, fs_close(&sess, obj)))
		goto exit;

	/* write new data */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		fs_open(&sess, file_02, sizeof(file_02),
			TEE_DATA_FLAG_ACCESS_WRITE, &obj, storage_id)))
		goto exit;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		fs_write(&sess, obj, data_00, sizeof(data_00))))
		goto exit;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, fs_close(&sess, obj)))
		goto exit;

	/* verify */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		fs_open(&sess, file_02, sizeof(file_02),
			TEE_DATA_FLAG_ACCESS_READ |
			TEE_DATA_FLAG_ACCESS_WRITE_META, &obj, storage_id)))
		goto exit;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, fs_read(&sess, obj, out, 10, &count)))
		goto exit;

	(void)ADBG_EXPECT_BUFFER(c, data_00, 10, out, count);

	/* clean */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, fs_unlink(&sess, obj)))
		goto exit;

exit:
	TEEC_CloseSession(&sess);
}

DEFINE_TEST_MULTIPLE_STORAGE_IDS(xtest_tee_test_6004)

/* seek */
static void xtest_tee_test_6005_single(ADBG_Case_t *c, uint32_t storage_id)
{
	TEEC_Session sess;
	uint32_t obj;
	uint8_t out[10] = { 0 };
	uint32_t count;
	uint32_t orig;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		xtest_teec_open_session(&sess, &storage_ta_uuid, NULL, &orig)))
		return;

	/* create */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		fs_create(&sess, file_01, sizeof(file_01),
			  TEE_DATA_FLAG_ACCESS_WRITE |
			  TEE_DATA_FLAG_ACCESS_READ |
			  TEE_DATA_FLAG_ACCESS_WRITE_META, 0, data_00,
			  sizeof(data_00), &obj, storage_id)))
		goto exit;

	/* seek */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		fs_seek(&sess, obj, 10, TEE_DATA_SEEK_SET)))
		goto exit;

	/* verify */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, fs_read(&sess, obj, out, 10, &count)))
		goto exit;

	(void)ADBG_EXPECT_BUFFER(c, &data_00[10], 10, out, count);

	/* clean */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, fs_unlink(&sess, obj)))
		goto exit;

exit:
	TEEC_CloseSession(&sess);
}

DEFINE_TEST_MULTIPLE_STORAGE_IDS(xtest_tee_test_6005)

/* unlink */
static void xtest_tee_test_6006_single(ADBG_Case_t *c, uint32_t storage_id)
{
	TEEC_Session sess;
	uint32_t obj;
	uint32_t orig;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		xtest_teec_open_session(&sess, &storage_ta_uuid, NULL, &orig)))
		return;

	/* create */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		fs_create(&sess, file_01, sizeof(file_01),
			  TEE_DATA_FLAG_ACCESS_WRITE_META, 0, data_00,
			  sizeof(data_00), &obj, storage_id)))
		goto exit;

	/* del & close */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, fs_unlink(&sess, obj)))
		goto exit;

	/* check result */
	if (!ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_ITEM_NOT_FOUND,
		fs_open(&sess, file_01, sizeof(file_01),
			TEE_DATA_FLAG_ACCESS_READ, &obj, storage_id)))
		goto exit;

exit:
	TEEC_CloseSession(&sess);
}

DEFINE_TEST_MULTIPLE_STORAGE_IDS(xtest_tee_test_6006)

static void xtest_tee_test_6007_single(ADBG_Case_t *c, uint32_t storage_id)
{
	Do_ADBG_BeginSubCase(c, "Test truncate file length");
	test_truncate_file_length(c, storage_id);
	Do_ADBG_EndSubCase(c, "Test truncate file length");

	Do_ADBG_BeginSubCase(c, "Test extend file length");
	test_extend_file_length(c, storage_id);
	Do_ADBG_EndSubCase(c, "Test extend file length");

	Do_ADBG_BeginSubCase(c, "Test file hole");
	test_file_hole(c, storage_id);
	Do_ADBG_EndSubCase(c, "Test file hole");
}

DEFINE_TEST_MULTIPLE_STORAGE_IDS(xtest_tee_test_6007)

static void xtest_tee_test_6008_single(ADBG_Case_t *c, uint32_t storage_id)
{
	TEEC_Session sess;
	uint32_t obj;
	uint8_t out[10] = { 0 };
	uint32_t count;
	uint32_t orig;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		xtest_teec_open_session(&sess, &storage_ta_uuid, NULL, &orig)))
		return;

	/* create */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		fs_create(&sess, file_02, sizeof(file_02),
			  TEE_DATA_FLAG_ACCESS_WRITE, 0, data_01,
			  sizeof(data_01), &obj, storage_id)))
		goto exit;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, fs_close(&sess, obj)))
		goto exit;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		fs_open(&sess, file_02, sizeof(file_02),
			TEE_DATA_FLAG_ACCESS_WRITE |
			TEE_DATA_FLAG_ACCESS_WRITE_META, &obj, storage_id)))
		goto exit;

	/* write new data */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		fs_write(&sess, obj, data_00, sizeof(data_00))))
		goto exit;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		fs_rename(&sess, obj, file_03, sizeof(file_03))))
		goto exit;

	/* close */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, fs_close(&sess, obj)))
		goto exit;

	/* verify */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		fs_open(&sess, file_03, sizeof(file_03),
			TEE_DATA_FLAG_ACCESS_READ |
			TEE_DATA_FLAG_ACCESS_WRITE_META, &obj, storage_id)))
		goto exit;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, fs_read(&sess, obj, out, 10, &count)))
		goto exit;

	/* check buffer */
	(void)ADBG_EXPECT_BUFFER(c, data_00, 10, out, count);

	/* clean */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, fs_unlink(&sess, obj)))
		goto exit;

exit:
	TEEC_CloseSession(&sess);
}

DEFINE_TEST_MULTIPLE_STORAGE_IDS(xtest_tee_test_6008)

static void xtest_tee_test_6009_single(ADBG_Case_t *c, uint32_t storage_id)
{
	TEEC_Session sess;
	uint32_t obj0;
	uint32_t obj1;
	uint32_t obj2;
	uint32_t e = 0;
	uint8_t info[200];
	uint8_t id[200];
	uint32_t orig;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		xtest_teec_open_session(&sess, &storage_ta_uuid, NULL, &orig)))
		return;

	/* create file 00 */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		fs_create(&sess, file_00, sizeof(file_00),
			  TEE_DATA_FLAG_ACCESS_WRITE, 0, data_01,
			  sizeof(data_01), &obj0, storage_id)))
		goto exit;

	/* create file 01 */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		fs_create(&sess, file_01, sizeof(file_01),
			  TEE_DATA_FLAG_ACCESS_WRITE, 0, data_01,
			  sizeof(data_01), &obj1, storage_id)))
		goto exit;

	/* create file 02 */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		fs_create(&sess, file_02, sizeof(file_02),
			  TEE_DATA_FLAG_ACCESS_WRITE, 0, data_01,
			  sizeof(data_01), &obj2, storage_id)))
		goto exit;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, fs_close(&sess, obj0)))
		goto exit;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, fs_close(&sess, obj1)))
		goto exit;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, fs_close(&sess, obj2)))
		goto exit;

	/* iterate */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, fs_alloc_enum(&sess, &e)))
		goto exit;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, fs_start_enum(&sess, e, storage_id)))
		goto exit;

	/* get 00 */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		fs_next_enum(&sess, e, info, sizeof(info), id, sizeof(id))))
		goto exit;

	/* get 01 */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		fs_next_enum(&sess, e, NULL, 0, id, sizeof(id))))
		goto exit;

	/* get 02 */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		fs_next_enum(&sess, e, info, sizeof(info), id, sizeof(id))))
		goto exit;

	/* we should not have more files */
	if (!ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_ITEM_NOT_FOUND,
		fs_next_enum(&sess, e, info, sizeof(info), id, sizeof(id))))
		goto exit;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, fs_free_enum(&sess, e)))
		goto exit;

	/* clean */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		fs_open(&sess, file_00, sizeof(file_00),
			TEE_DATA_FLAG_ACCESS_WRITE_META, &obj0, storage_id)))
		goto exit;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, fs_unlink(&sess, obj0)))
		goto exit;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		fs_open(&sess, file_01, sizeof(file_01),
			TEE_DATA_FLAG_ACCESS_WRITE_META, &obj1, storage_id)))
		goto exit;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, fs_unlink(&sess, obj1)))
		goto exit;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		fs_open(&sess, file_02, sizeof(file_02),
			TEE_DATA_FLAG_ACCESS_WRITE_META, &obj2, storage_id)))
		goto exit;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, fs_unlink(&sess, obj2)))
		goto exit;

exit:
	TEEC_CloseSession(&sess);
}

DEFINE_TEST_MULTIPLE_STORAGE_IDS(xtest_tee_test_6009)

static void xtest_tee_test_6010_single(ADBG_Case_t *c, uint32_t storage_id)
{
	TEEC_Session sess;
	uint32_t orig;
	uint32_t o1;
	uint32_t o2;
	uint32_t e;
	uint32_t f;
	uint8_t data[1024];
	uint8_t out[1024];
	uint32_t n;

	for (n = 0; n < ARRAY_SIZE(data); n++)
		data[n] = n;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		xtest_teec_open_session(&sess, &storage_ta_uuid, NULL, &orig)))
		return;

	Do_ADBG_BeginSubCase(c, "CreatePersistentObject AccessConflict");

	o1 = TEE_HANDLE_NULL;
	o2 = TEE_HANDLE_NULL;
	f = TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE |
	    TEE_DATA_FLAG_ACCESS_WRITE_META | TEE_DATA_FLAG_SHARE_READ |
	    TEE_DATA_FLAG_SHARE_WRITE | TEE_DATA_FLAG_OVERWRITE;

	ADBG_EXPECT_TEEC_SUCCESS(c,
		fs_create(&sess, file_00, sizeof(file_00), f, 0, data,
			  sizeof(data), &o1, storage_id));

	f = TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE;
	ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_ACCESS_CONFLICT,
		fs_create(&sess, file_00, sizeof(file_00), f, 0, data,
			  sizeof(data), &o2, storage_id));

	ADBG_EXPECT_TEEC_SUCCESS(c, fs_unlink(&sess, o1));
	if (o2)
		ADBG_EXPECT_TEEC_SUCCESS(c, fs_unlink(&sess, o2));

	Do_ADBG_EndSubCase(c, "CreatePersistentObject AccessConflict");



	Do_ADBG_BeginSubCase(c, "RestrictObjectUsage Panic");
	ADBG_EXPECT_TEEC_RESULT(c, TEE_ERROR_TARGET_DEAD,
		fs_restrict_usage(&sess, 0xffffbad0, 0xffffffff));
	Do_ADBG_EndSubCase(c, "RestrictObjectUsage Panic");

	TEEC_CloseSession(&sess);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		xtest_teec_open_session(&sess, &storage_ta_uuid, NULL, &orig)))
		return;

	Do_ADBG_BeginSubCase(c, "SeekObjectData BadHandle");
	ADBG_EXPECT_TEEC_RESULT(c, TEE_ERROR_TARGET_DEAD,
		fs_seek(&sess, 0xffffbad0, 5, TEE_DATA_SEEK_SET));
	Do_ADBG_EndSubCase(c, "SeekObjectData BadHandle");

	TEEC_CloseSession(&sess);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		xtest_teec_open_session(&sess, &storage_ta_uuid, NULL, &orig)))
		return;

	Do_ADBG_BeginSubCase(c, "SeekObjectData NotPersist");
	o1 = 0;
	ADBG_EXPECT_TEEC_SUCCESS(c,
		fs_alloc_obj(&sess, TEE_TYPE_AES, 256, &o1));
	ADBG_EXPECT_TEEC_RESULT(c, TEE_ERROR_TARGET_DEAD,
		fs_seek(&sess, o1, 5, TEE_DATA_SEEK_SET));
	Do_ADBG_EndSubCase(c, "SeekObjectData NotPersist");

	TEEC_CloseSession(&sess);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		xtest_teec_open_session(&sess, &storage_ta_uuid, NULL, &orig)))
		return;

	Do_ADBG_BeginSubCase(c, "SeekWriteRead");
	o1 = 0;
	f = TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE |
	    TEE_DATA_FLAG_ACCESS_WRITE_META | TEE_DATA_FLAG_SHARE_READ |
	    TEE_DATA_FLAG_SHARE_WRITE | TEE_DATA_FLAG_OVERWRITE;
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		fs_create(&sess, file_00, sizeof(file_00), f, 0, data,
			  sizeof(data), &o1, storage_id)))
		goto seek_write_read_out;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		fs_seek(&sess, o1, 2, TEE_DATA_SEEK_SET)))
		goto seek_write_read_out;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		fs_seek(&sess, o1, 0, TEE_DATA_SEEK_END)))
		goto seek_write_read_out;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		fs_write(&sess, o1, data, sizeof(data))))
		goto seek_write_read_out;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		fs_seek(&sess, o1, sizeof(data), TEE_DATA_SEEK_SET)))
		goto seek_write_read_out;

	memset(out, 0xab, sizeof(out));
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		fs_read(&sess, o1, out, sizeof(out), &n)))
		goto seek_write_read_out;

	ADBG_EXPECT_BUFFER(c, data, sizeof(data), out, n);

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		fs_seek(&sess, o1, 10, TEE_DATA_SEEK_END)))
		goto seek_write_read_out;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		fs_read(&sess, o1, out, sizeof(out), &n)))
		goto seek_write_read_out;
	ADBG_EXPECT_COMPARE_UNSIGNED(c, n, ==, 0);

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		fs_seek(&sess, o1, -(int32_t)sizeof(data) / 2,
			TEE_DATA_SEEK_END)))
		goto seek_write_read_out;

	memset(out, 0xab, sizeof(out) / 2);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		fs_read(&sess, o1, out, sizeof(out) / 2, &n)))
		goto seek_write_read_out;

	ADBG_EXPECT_BUFFER(c,
		data + sizeof(data) / 2, sizeof(data) / 2,
		out + sizeof(data) / 2, n);

seek_write_read_out:
	ADBG_EXPECT_TEEC_SUCCESS(c, fs_unlink(&sess, o1));
	Do_ADBG_EndSubCase(c, "SeekWriteRead");

	Do_ADBG_BeginSubCase(c, "Rename Access Conflict");

	o1 = TEE_HANDLE_NULL;
	o2 = TEE_HANDLE_NULL;
	f = TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE |
	    TEE_DATA_FLAG_ACCESS_WRITE_META | TEE_DATA_FLAG_SHARE_READ |
	    TEE_DATA_FLAG_SHARE_WRITE | TEE_DATA_FLAG_OVERWRITE;
	ADBG_EXPECT_TEEC_SUCCESS(c,
		fs_create(&sess, file_00, sizeof(file_00), f, 0, data,
			  sizeof(data), &o1, storage_id));
	ADBG_EXPECT_TEEC_SUCCESS(c,
		fs_create(&sess, file_01, sizeof(file_01), f, 0, data,
			  sizeof(data) / 2, &o2, storage_id));

	ADBG_EXPECT_TEEC_RESULT(c, TEE_ERROR_ACCESS_CONFLICT,
		fs_rename(&sess, o2, file_00, sizeof(file_00)));

	ADBG_EXPECT_TEEC_SUCCESS(c, fs_unlink(&sess, o1));
	ADBG_EXPECT_TEEC_SUCCESS(c, fs_unlink(&sess, o2));

	Do_ADBG_EndSubCase(c, "Rename Access Conflict");

	Do_ADBG_BeginSubCase(c, "StartPersistentObjectEnumerator ItemNotFound");
	e = TEE_HANDLE_NULL;
	ADBG_EXPECT_TEEC_SUCCESS(c, fs_alloc_enum(&sess, &e));
	ADBG_EXPECT_TEEC_RESULT(c, TEE_ERROR_ITEM_NOT_FOUND,
		fs_next_enum(&sess, e, NULL, 0, out, sizeof(out)));
	ADBG_EXPECT_TEEC_RESULT(c, TEE_ERROR_ITEM_NOT_FOUND,
		fs_start_enum(&sess, e, storage_id));
	ADBG_EXPECT_TEEC_SUCCESS(c, fs_free_enum(&sess, e));
	Do_ADBG_EndSubCase(c, "StartPersistentObjectEnumerator ItemNotFound");

	Do_ADBG_BeginSubCase(c, "RenamePersistent ReadWrite");
	o1 = TEE_HANDLE_NULL;
	f = TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE |
	    TEE_DATA_FLAG_ACCESS_WRITE_META | TEE_DATA_FLAG_SHARE_READ |
	    TEE_DATA_FLAG_SHARE_WRITE | TEE_DATA_FLAG_OVERWRITE;
	ADBG_EXPECT_TEEC_SUCCESS(c,
		fs_create(&sess, file_00, sizeof(file_00), f, 0, data,
			  sizeof(data), &o1, storage_id));
	ADBG_EXPECT_TEEC_SUCCESS(c,
		fs_rename(&sess, o1, file_01, sizeof(file_01)));
	ADBG_EXPECT_TEEC_SUCCESS(c, fs_unlink(&sess, o1));
	Do_ADBG_EndSubCase(c, "RenamePersistent ReadWrite");

	Do_ADBG_BeginSubCase(c, "Close Free Reset Null");
	ADBG_EXPECT_TEEC_SUCCESS(c, fs_close(&sess, TEE_HANDLE_NULL));
	ADBG_EXPECT_TEEC_SUCCESS(c, fs_free_obj(&sess, TEE_HANDLE_NULL));
	ADBG_EXPECT_TEEC_SUCCESS(c, fs_reset_obj(&sess, TEE_HANDLE_NULL));
	Do_ADBG_EndSubCase(c, "Close Free Reset Null");

	TEEC_CloseSession(&sess);
}

DEFINE_TEST_MULTIPLE_STORAGE_IDS(xtest_tee_test_6010)

#ifdef WITH_GP_TESTS
static void xtest_tee_test_6011(ADBG_Case_t *c)
{
    TEEC_Session sess;
    uint32_t orig;
    /*
     * Test data from
     * Invoke_InitObjectAndAttributes_TEE_TYPE_AES_success_attribute_
     * TEE_ATTR_SECRET_VALUE_correct_size (9d-9a-91)
     */
    static const uint8_t attr_meta[] = {
0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x20,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    };
    static const uint8_t attr_data[] = {
0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,
0x81,0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,
0xdf,0xf4,
    };

    if (!ADBG_EXPECT_TEEC_SUCCESS(
            c, xtest_teec_open_session(
                &sess, &gp_tta_ds_uuid, NULL, &orig)))
        return;

    if (!ADBG_EXPECT_TEEC_SUCCESS(c, ds_init_object_and_attributes(&sess,
            0xa0000010, 0x100, attr_meta, sizeof(attr_meta), attr_data,
            sizeof(attr_data), 0)))
        goto exit;

exit:
    TEEC_CloseSession(&sess);
}
#endif /*WITH_GP_TESTS*/

static void xtest_tee_test_6012_single(ADBG_Case_t *c, uint32_t storage_id)
{
	TEEC_Session sess;
	uint32_t orig;
	uint32_t obj;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		xtest_teec_open_session(&sess, &storage_ta_uuid, NULL, &orig)))
		return;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		fs_create_overwrite(&sess, file_04, sizeof(file_04), storage_id)))
		goto exit;

	TEEC_CloseSession(&sess);

	/* re-create the same */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		xtest_teec_open_session(&sess, &storage_ta_uuid, NULL, &orig)))
		return;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		fs_create_overwrite(&sess, file_04, sizeof(file_04),
				    storage_id)))
		goto exit;

	/*
	 * recreate it with an object, and remove it so that xtest 6009
	 * can be replayed
	 */
	 if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		fs_create(&sess, file_04, sizeof(file_04),
			  TEE_DATA_FLAG_ACCESS_WRITE |
			  TEE_DATA_FLAG_ACCESS_WRITE_META |
			  TEE_DATA_FLAG_OVERWRITE, 0, NULL, 0, &obj,
			  storage_id)))
			goto exit;

	/* clean */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, fs_unlink(&sess, obj)))
		goto exit;

exit:
	TEEC_CloseSession(&sess);
}

DEFINE_TEST_MULTIPLE_STORAGE_IDS(xtest_tee_test_6012)

static void xtest_tee_test_6013_single(ADBG_Case_t *c, uint32_t storage_id)
{
	TEEC_Session sess;
	uint32_t orig;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		xtest_teec_open_session(&sess, &storage_ta_uuid, NULL, &orig)))
		return;

	op.params[0].value.a = storage_id;
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	ADBG_EXPECT_TEEC_SUCCESS(c,
		TEEC_InvokeCommand(&sess, TA_STORAGE_CMD_KEY_IN_PERSISTENT,
				   &op, &orig));

	TEEC_CloseSession(&sess);
}

DEFINE_TEST_MULTIPLE_STORAGE_IDS(xtest_tee_test_6013)

static void xtest_tee_test_6014_single(ADBG_Case_t *c, uint32_t storage_id)
{
	TEEC_Session sess;
	uint32_t orig;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		xtest_teec_open_session(&sess, &storage_ta_uuid, NULL, &orig)))
		return;

	op.params[0].value.a = storage_id;
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	ADBG_EXPECT_TEEC_SUCCESS(c,
		TEEC_InvokeCommand(&sess, TA_STORAGE_CMD_LOOP, &op, &orig));

	TEEC_CloseSession(&sess);
}

DEFINE_TEST_MULTIPLE_STORAGE_IDS(xtest_tee_test_6014)

static int get_ta_storage_path(TEEC_UUID *p_uuid, char *buffer, uint32_t len)
{
	int s;

	if (!p_uuid || !buffer)
		return -1;

	s = snprintf(buffer, len, "/data/tee/");
	if (s < 0 || s >= (int)len)
		return -1;

	len -= s;
	buffer += s;

	s = ree_fs_get_ta_dirname(p_uuid, buffer, len);
	return s;
}

static int rename_data_dir(TEEC_UUID *old, TEEC_UUID *nw)
{
	char opath[150];
	char npath[150];
	int s;

	s = get_ta_storage_path(old, opath, sizeof(opath));
	if (s < 0 || s >= (int)sizeof(opath)) {
		s = -1;
		goto exit;
	}
	s = get_ta_storage_path(nw, npath, sizeof(npath));
	if (s < 0 || s >= (int)sizeof(opath)) {
		s = -1;
		goto exit;
	}
	s = rename(opath, npath);
exit:
	if (s < 0)
		fprintf(stderr, "Warning: could not rename %s -> %s\n", opath,
			npath);
	return s;
}

static void xtest_tee_test_6015_single(ADBG_Case_t *c, uint32_t storage_id)
{
	TEEC_Session sess;
	TEEC_Session sess2;
	uint32_t orig;
	uint32_t obj;
	uint32_t obj2;
	TEEC_UUID uuid = TA_STORAGE_UUID;
	TEEC_UUID uuid2 = TA_STORAGE2_UUID;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		xtest_teec_open_session(&sess, &storage_ta_uuid, NULL, &orig)))
		return;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		xtest_teec_open_session(&sess2, &storage2_ta_uuid, NULL,
					&orig)))
		goto exit2;

	/* TA #1 creates a persistent object  */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		fs_create(&sess, file_01, sizeof(file_01),
			  TEE_DATA_FLAG_ACCESS_WRITE |
			  TEE_DATA_FLAG_ACCESS_READ |
			  TEE_DATA_FLAG_ACCESS_WRITE_META, 0, data_00,
			  sizeof(data_00), &obj, storage_id)))
		goto exit;

	/* TA #2 tries to open the object created by TA #1 */
	if (!ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_ITEM_NOT_FOUND,
		fs_open(&sess2, file_01, sizeof(file_01),
			TEE_DATA_FLAG_ACCESS_READ, &obj2, storage_id)))
		goto clean;

	if (storage_id == TEE_STORAGE_PRIVATE_REE) {
		/*
		 * When the storage backend is the REE filesystem, we can
		 * simulate a hack attempt by renaming the TA storage. Should
		 * be detected by the TEE.
		 */
		if (rename_data_dir(&uuid, &uuid2) < 0)
			goto clean;

		/* TA #2 tries to open the object created by TA #1 */
		ADBG_EXPECT_TEEC_RESULT(c, TEE_ERROR_CORRUPT_OBJECT,
			fs_open(&sess2, file_01, sizeof(file_01),
				TEE_DATA_FLAG_ACCESS_READ, &obj2, storage_id));
		/*
		 * At this point, the TEE is expected to have removed the
		 * corrupt object, so there is no need to try and restore the
		 * directory name.
		 */
		goto exit;
	}

clean:
	ADBG_EXPECT_TEEC_SUCCESS(c, fs_unlink(&sess, obj));
exit:
	TEEC_CloseSession(&sess2);
exit2:
	TEEC_CloseSession(&sess);
}

DEFINE_TEST_MULTIPLE_STORAGE_IDS(xtest_tee_test_6015)


struct test_6016_thread_arg {
	ADBG_Case_t *case_t;
	uint32_t storage_id;
	char file_name[8];
	TEEC_Session session;
};

static void *test_6016_thread(void *arg)
{
	struct test_6016_thread_arg *a = arg;
	TEEC_Session sess = a->session;
	uint32_t obj;
	uint8_t out[10] = { 0 };
	uint32_t count;

	/* create */
	if (!ADBG_EXPECT_TEEC_SUCCESS(a->case_t,
		fs_create(&sess, a->file_name, sizeof(a->file_name),
			  TEE_DATA_FLAG_ACCESS_WRITE, 0, data_01,
			  sizeof(data_01), &obj, a->storage_id)))
		goto exit;

	if (!ADBG_EXPECT_TEEC_SUCCESS(a->case_t, fs_close(&sess, obj)))
		goto exit;

	/* write new data */
	if (!ADBG_EXPECT_TEEC_SUCCESS(a->case_t,
		fs_open(&sess, a->file_name, sizeof(a->file_name),
			TEE_DATA_FLAG_ACCESS_WRITE, &obj, a->storage_id)))
		goto exit;

	if (!ADBG_EXPECT_TEEC_SUCCESS(a->case_t,
		fs_write(&sess, obj, data_00, sizeof(data_00))))
		goto exit;

	if (!ADBG_EXPECT_TEEC_SUCCESS(a->case_t, fs_close(&sess, obj)))
		goto exit;

	/* verify */
	if (!ADBG_EXPECT_TEEC_SUCCESS(a->case_t,
		fs_open(&sess, a->file_name, sizeof(a->file_name),
			TEE_DATA_FLAG_ACCESS_READ |
			TEE_DATA_FLAG_ACCESS_WRITE_META, &obj, a->storage_id)))
		goto exit;

	if (!ADBG_EXPECT_TEEC_SUCCESS(a->case_t,
			fs_read(&sess, obj, out, 10, &count)))
		goto exit;

	(void)ADBG_EXPECT_BUFFER(a->case_t, data_00, 10, out, count);

	/* clean */
	if (!ADBG_EXPECT_TEEC_SUCCESS(a->case_t, fs_unlink(&sess, obj)))
		goto exit;

exit:
	return NULL;
}


#define NUM_THREADS 4
static void xtest_tee_test_6016_loop(ADBG_Case_t *c, uint32_t storage_id)
{
	size_t num_threads = NUM_THREADS;
	struct test_6016_thread_arg arg[num_threads];
	pthread_t thr[num_threads];
	uint32_t orig;
	size_t i;
	size_t n = 0;
	size_t m;

	memset(arg, 0, sizeof(arg));

	for (m = 0; m < num_threads; m++)
		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			xtest_teec_open_session(&arg[m].session,
				&storage_ta_uuid, NULL, &orig)))
			goto out;

	for (n = 0; n < num_threads; n++) {
		arg[n].case_t = c;
		arg[n].storage_id = storage_id;
		snprintf(arg[n].file_name, sizeof(arg[n].file_name),
			"file_%zu", n);
		if (!ADBG_EXPECT(c, 0, pthread_create(thr + n, NULL,
						test_6016_thread, arg + n)))
			goto out;
	}

out:
	for (i = 0; i < n; i++)
		ADBG_EXPECT(c, 0, pthread_join(thr[i], NULL));
	for (i = 0; i < m; i++)
		TEEC_CloseSession(&arg[i].session);
}

/* concurency */
static void xtest_tee_test_6016_single(ADBG_Case_t *c, uint32_t storage_id)
{
	int i;
	int loops = 8;

	Do_ADBG_Log("    threads: %d, loops: %d", NUM_THREADS, loops);
	for (i = 0; i < loops; i++)
		xtest_tee_test_6016_loop(c, storage_id);
}

DEFINE_TEST_MULTIPLE_STORAGE_IDS(xtest_tee_test_6016)


ADBG_CASE_DEFINE(
	XTEST_TEE_6001, xtest_tee_test_6001,
	/* Title */
	"Test TEE_CreatePersistentObject",
	/* Short description */
	"Short description ...",
	/* Requirement IDs */
	"TEE-??",
	/* How to implement */
	"Description of how to implement ..."
	);

ADBG_CASE_DEFINE(
	XTEST_TEE_6002, xtest_tee_test_6002,
	/* Title */
	"Test TEE_OpenPersistentObject",
	/* Short description */
	"Short description ...",
	/* Requirement IDs */
	"TEE-??",
	/* How to implement */
	"Description of how to implement ..."
	);

ADBG_CASE_DEFINE(
	XTEST_TEE_6003, xtest_tee_test_6003,
	/* Title */
	"Test TEE_ReadObjectData",
	/* Short description */
	"Short description ...",
	/* Requirement IDs */
	"TEE-??",
	/* How to implement */
	"Description of how to implement ..."
	);

ADBG_CASE_DEFINE(
	XTEST_TEE_6004, xtest_tee_test_6004,
	/* Title */
	"Test TEE_WriteObjectData",
	/* Short description */
	"Short description ...",
	/* Requirement IDs */
	"TEE-??",
	/* How to implement */
	"Description of how to implement ..."
	);

ADBG_CASE_DEFINE(
	XTEST_TEE_6005, xtest_tee_test_6005,
	/* Title */
	"Test TEE_SeekObjectData",
	/* Short description */
	"Short description ...",
	/* Requirement IDs */
	"TEE-??",
	/* How to implement */
	"Description of how to implement ..."
	);

ADBG_CASE_DEFINE(
	XTEST_TEE_6006, xtest_tee_test_6006,
	/* Title */
	"Test TEE_CloseAndDeletePersistentObject",
	/* Short description */
	"Short description ...",
	/* Requirement IDs */
	"TEE-??",
	/* How to implement */
	"Description of how to implement ..."
	);

ADBG_CASE_DEFINE(
	XTEST_TEE_6007, xtest_tee_test_6007,
	/* Title */
	"Test TEE_TruncateObjectData",
	/* Short description */
	"Short description ...",
	/* Requirement IDs */
	"TEE-??",
	/* How to implement */
	"Description of how to implement ..."
	);

ADBG_CASE_DEFINE(
	XTEST_TEE_6008, xtest_tee_test_6008,
	/* Title */
	"Test TEE_RenamePersistentObject",
	/* Short description */
	"Short description ...",
	/* Requirement IDs */
	"TEE-??",
	/* How to implement */
	"Description of how to implement ..."
	);

ADBG_CASE_DEFINE(
	XTEST_TEE_6009, xtest_tee_test_6009,
	/* Title */
	"Test TEE Internal API Persistent Object Enumeration Functions",
	/* Short description */
	"Short description ...",
	/* Requirement IDs */
	"TEE-??",
	/* How to implement */
	"Description of how to implement ..."
	);

ADBG_CASE_DEFINE(
	XTEST_TEE_6010, xtest_tee_test_6010,
	/* Title */
	"Test Storage",
	/* Short description */
	"Short description ...",
	/* Requirement IDs */
	"TEE-??",
	/* How to implement */
	"Description of how to implement ..."
);

#ifdef WITH_GP_TESTS
ADBG_CASE_DEFINE(
    XTEST_TEE_6011, xtest_tee_test_6011,
    /* Title */
    "Test TEE GP TTA DS init objects",
    /* Short description */
    "Short description ...",
    /* Requirement IDs */
    "TEE-??",
    /* How to implement */
    "Description of how to implement ..."
);
#endif

ADBG_CASE_DEFINE(
    XTEST_TEE_6012, xtest_tee_test_6012,
    /* Title */
    "Test TEE GP TTA DS init objects",
    /* Short description */
    "Short description ...",
    /* Requirement IDs */
    "TEE-??",
    /* How to implement */
    "Description of how to implement ..."
);

ADBG_CASE_DEFINE(
    XTEST_TEE_6013, xtest_tee_test_6013,
    /* Title */
    "Key usage in Persistent objects",
    /* Short description */
    "Short description ...",
    /* Requirement IDs */
    "TEE-??",
    /* How to implement */
    "Description of how to implement ..."
);

ADBG_CASE_DEFINE(
    XTEST_TEE_6014, xtest_tee_test_6014,
    /* Title */
    "Loop on Persistent objects",
    /* Short description */
    "Short description ...",
    /* Requirement IDs */
    "TEE-??",
    /* How to implement */
    "Description of how to implement ..."
);

ADBG_CASE_DEFINE(
    XTEST_TEE_6015, xtest_tee_test_6015,
    /* Title */
    "Storage isolation",
    /* Short description */
    "TA #2 tries to open object created by TA #1, should fail",
    /* Requirement IDs */
    "",
    /* How to implement */
    ""
);

ADBG_CASE_DEFINE(
	XTEST_TEE_6016, xtest_tee_test_6016,
	/* Title */
	"Storage concurency",
	/* Short description */
	"Multiple thread operate secure storage",
	/* Requirement IDs */
	"",
	/* How to implement */
	""
);
