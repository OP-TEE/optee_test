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

#include <adbg.h>
#include <xtest_test.h>
#include <xtest_helpers.h>

#include <tee_client_api.h>
#include <ta_storage.h>
#include <tee_api_defines.h>
#include <tee_api_types.h>
#ifdef WITH_GP_TESTS
#include <TTA_DS_protocol.h>
#endif

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
			   uint32_t flags, uint32_t *obj)
{
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	TEEC_Result res;
	uint32_t org;

	op.params[0].tmpref.buffer = id;
	op.params[0].tmpref.size = id_size;
	op.params[1].value.a = flags;
	op.params[1].value.b = 0;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_VALUE_INOUT, TEEC_NONE,
					 TEEC_NONE);

	res = TEEC_InvokeCommand(sess, TA_STORAGE_CMD_OPEN, &op, &org);

	if (res == TEEC_SUCCESS)
		*obj = op.params[1].value.b;

	return res;
}

static TEEC_Result fs_create(TEEC_Session *sess, void *id, uint32_t id_size,
			     uint32_t flags, uint32_t attr, void *data,
			     uint32_t data_size, uint32_t *obj)
{
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	TEEC_Result res;
	uint32_t org;

	op.params[0].tmpref.buffer = id;
	op.params[0].tmpref.size = id_size;
	op.params[1].value.a = flags;
	op.params[1].value.b = 0;
	op.params[2].value.a = attr;
	op.params[2].value.b = 0;
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
				       uint32_t id_size)
{
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	TEEC_Result res;
	uint32_t org;

	op.params[0].tmpref.buffer = id;
	op.params[0].tmpref.size = id_size;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_NONE, TEEC_NONE,
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
	op.params[0].value.b = offset;
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

static TEEC_Result fs_start_enum(TEEC_Session *sess, uint32_t e)
{
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	op.params[0].value.a = e;

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

/* trunc */
static void test_truncate_file_length(ADBG_Case_t *c)
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
			  sizeof(data_00), &obj)))
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
static void test_extend_file_length(ADBG_Case_t *c)
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
			  sizeof(data_00), &obj)))
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
static void test_file_hole(ADBG_Case_t *c)
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
			  sizeof(data_00), &obj)))
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
static TEEC_Result ds_open_access_conf(TEEC_Session *sess)
{
    TEEC_Operation op;
    uint32_t org;

    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);

    return TEEC_InvokeCommand(
        sess, CMD_CreatePersistentObject_AccessConflict, &op, &org);
}

static TEEC_Result ds_res_obj_panic(TEEC_Session *sess)
{
    TEEC_Operation op;
    uint32_t org;

    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);

    return TEEC_InvokeCommand(
        sess, CMD_RestrictObjectUsagePanic, &op, &org);
}

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

static TEEC_Result ds_seek_obj_bad_handle(TEEC_Session *sess)
{
    TEEC_Operation op;
    uint32_t org;

    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);

    op.params[0].value.a = CASE_DATA_BAD_HANDLE;

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
static void xtest_tee_test_6001(ADBG_Case_t *c)
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
			  sizeof(data_00), &obj)))
		goto exit;

	/* clean */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, fs_unlink(&sess, obj)))
		goto exit;

exit:
	TEEC_CloseSession(&sess);
}

/* open */
static void xtest_tee_test_6002(ADBG_Case_t *c)
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
			  sizeof(data_00), &obj)))
		goto exit;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, fs_close(&sess, obj)))
		goto exit;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		fs_open(&sess, file_01, sizeof(file_01),
			TEE_DATA_FLAG_ACCESS_WRITE_META, &obj)))
		goto exit;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, fs_close(&sess, obj)))
		goto exit;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		fs_open(&sess, file_01, sizeof(file_01),
			TEE_DATA_FLAG_ACCESS_WRITE_META, &obj)))
		goto exit;

	/* clean */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, fs_unlink(&sess, obj)))
		goto exit;

exit:
	TEEC_CloseSession(&sess);
}

/* read */
static void xtest_tee_test_6003(ADBG_Case_t *c)
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
			  sizeof(data_01), &obj)))
		goto exit;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, fs_close(&sess, obj)))
		goto exit;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		fs_open(&sess, file_02, sizeof(file_02),
			TEE_DATA_FLAG_ACCESS_READ |
			TEE_DATA_FLAG_ACCESS_WRITE_META, &obj)))
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

/* write */
static void xtest_tee_test_6004(ADBG_Case_t *c)
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
			  sizeof(data_01), &obj)))
		goto exit;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, fs_close(&sess, obj)))
		goto exit;

	/* write new data */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		fs_open(&sess, file_02, sizeof(file_02),
			TEE_DATA_FLAG_ACCESS_WRITE, &obj)))
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
			TEE_DATA_FLAG_ACCESS_WRITE_META, &obj)))
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

/* seek */
static void xtest_tee_test_6005(ADBG_Case_t *c)
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
			  sizeof(data_00), &obj)))
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

/* unlink */
static void xtest_tee_test_6006(ADBG_Case_t *c)
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
			  sizeof(data_00), &obj)))
		goto exit;

	/* del & close */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, fs_unlink(&sess, obj)))
		goto exit;

	/* check result */
	if (!ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_ITEM_NOT_FOUND,
		fs_open(&sess, file_01, sizeof(file_01),
			TEE_DATA_FLAG_ACCESS_READ, &obj)))
		goto exit;

exit:
	TEEC_CloseSession(&sess);
}

static void xtest_tee_test_6007(ADBG_Case_t *c)
{
	Do_ADBG_BeginSubCase(c, "Test truncate file length");
	test_truncate_file_length(c);
	Do_ADBG_EndSubCase(c, "Test truncate file length");

	Do_ADBG_BeginSubCase(c, "Test extend file length");
	test_extend_file_length(c);
	Do_ADBG_EndSubCase(c, "Test extend file length");

	Do_ADBG_BeginSubCase(c, "Test file hole");
	test_file_hole(c);
	Do_ADBG_EndSubCase(c, "Test file hole");
}

static void xtest_tee_test_6008(ADBG_Case_t *c)
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
			  sizeof(data_01), &obj)))
		goto exit;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, fs_close(&sess, obj)))
		goto exit;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		fs_open(&sess, file_02, sizeof(file_02),
			TEE_DATA_FLAG_ACCESS_WRITE |
			TEE_DATA_FLAG_ACCESS_WRITE_META, &obj)))
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
			TEE_DATA_FLAG_ACCESS_WRITE_META, &obj)))
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

static void xtest_tee_test_6009(ADBG_Case_t *c)
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
			  sizeof(data_01), &obj0)))
		goto exit;

	/* create file 01 */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		fs_create(&sess, file_01, sizeof(file_01),
			  TEE_DATA_FLAG_ACCESS_WRITE, 0, data_01,
			  sizeof(data_01), &obj1)))
		goto exit;

	/* create file 02 */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		fs_create(&sess, file_02, sizeof(file_02),
			  TEE_DATA_FLAG_ACCESS_WRITE, 0, data_01,
			  sizeof(data_01), &obj2)))
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

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, fs_start_enum(&sess, e)))
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
			TEE_DATA_FLAG_ACCESS_WRITE_META, &obj0)))
		goto exit;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, fs_unlink(&sess, obj0)))
		goto exit;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		fs_open(&sess, file_01, sizeof(file_01),
			TEE_DATA_FLAG_ACCESS_WRITE_META, &obj1)))
		goto exit;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, fs_unlink(&sess, obj1)))
		goto exit;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		fs_open(&sess, file_02, sizeof(file_02),
			TEE_DATA_FLAG_ACCESS_WRITE_META, &obj2)))
		goto exit;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, fs_unlink(&sess, obj2)))
		goto exit;

exit:
	TEEC_CloseSession(&sess);
}

#ifdef WITH_GP_TESTS
static void xtest_tee_test_6010(ADBG_Case_t *c)
{
    TEEC_Session sess;
    uint32_t orig;
    uint8_t out[4000] = {0};
    uint8_t in[0x12c] = {'b'};
    int i;

    for (i=0; i<sizeof(in); i++)
	    in[i] = i;

    if (!ADBG_EXPECT_TEEC_SUCCESS(
            c, xtest_teec_open_session(
                &sess, &gp_tta_ds_uuid, NULL, &orig)))
        return;

    Do_ADBG_BeginSubCase(
        c, "GP DS CreatePersistentObject AccessConflict (9d-1d-62)");

    if (!ADBG_EXPECT_TEEC_RESULT(
            c, TEEC_ERROR_ACCESS_CONFLICT, ds_open_access_conf(&sess)))
        goto exit;

    Do_ADBG_EndSubCase(
        c, "GP DS CreatePersistentObject AccessConflict (9d-1d-62)");
    Do_ADBG_BeginSubCase(
        c, "GP DS RestrictObjectUsagePanic (9d-5d-46)");

    if (!ADBG_EXPECT_TEEC_RESULT(
            c, TEE_ERROR_TARGET_DEAD, ds_res_obj_panic(&sess)))
        goto exit;

    TEEC_CloseSession(&sess);

    Do_ADBG_EndSubCase(
        c, "GP DS RestrictObjectUsagePanic (9d-5d-46)");
    Do_ADBG_BeginSubCase(
        c, "GP DS SeekObjectData BadHandle (9d-c3-c8)");

    if (!ADBG_EXPECT_TEEC_SUCCESS(
            c, xtest_teec_open_session(
                &sess, &gp_tta_ds_uuid, NULL, &orig)))
        return;

    if (!ADBG_EXPECT_TEEC_RESULT(
            c, TEE_ERROR_TARGET_DEAD, ds_seek_obj_bad_handle(&sess)))
        goto exit;

    TEEC_CloseSession(&sess);

    Do_ADBG_EndSubCase(
        c, "GP DS SeekObjectData BadHandle (9d-c3-c8)");
    Do_ADBG_BeginSubCase(
        c, "GP DS SeekObjectData NotPersist (9d-db-4a)");

    if (!ADBG_EXPECT_TEEC_SUCCESS(
            c, xtest_teec_open_session(
                &sess, &gp_tta_ds_uuid, NULL, &orig)))
        return;

    if (!ADBG_EXPECT_TEEC_RESULT(
            c, TEE_ERROR_TARGET_DEAD, ds_seek_obj_inv_handle(&sess)))
        goto exit;

    TEEC_CloseSession(&sess);

    Do_ADBG_EndSubCase(
        c, "GP DS SeekObjectData NotPersist (9d-db-4a)");
    Do_ADBG_BeginSubCase(c, "GP DS SeekWriteRead SEEK_END (9d-e4-58)");

    if (!ADBG_EXPECT_TEEC_SUCCESS(
            c, xtest_teec_open_session(
                &sess, &gp_tta_ds_uuid, NULL, &orig)))
        return;

    if (!ADBG_EXPECT_TEEC_SUCCESS(
            c, ds_seek_gp(
                &sess, TEE_DATA_SEEK_END, 0, 2, data_00, sizeof(data_00), out,
                sizeof(out))))
        goto exit;

    /* check buffer */
    (void)ADBG_EXPECT_BUFFER(
        c, data_00, sizeof(data_00), out, sizeof(data_00));
    memset(out, 0xab, sizeof(out));

    if (!ADBG_EXPECT_TEEC_SUCCESS(
            c, ds_seek_gp(
                &sess, TEE_DATA_SEEK_END, sizeof(in)/2, 0, in, sizeof(in), out,
                sizeof(out))))
        goto exit;

    (void)ADBG_EXPECT_BUFFER(c, in, sizeof(in) / 2,
		             out + (sizeof(in) / 2), sizeof(in) / 2);
    memset(in, 0, sizeof(in));
    (void)ADBG_EXPECT_BUFFER(c, in, sizeof(in) / 2,
		             out, sizeof(in)/2);
    memset(out, 0xab, sizeof(out));

    Do_ADBG_EndSubCase(c, "GP DS SeekWriteRead SEEK_END (9d-e4-58)");
    Do_ADBG_BeginSubCase(c, "GP DS Rename Access Conflict (9d-29-d1)");

    if (!ADBG_EXPECT_TEEC_RESULT(
            c, TEE_ERROR_ACCESS_CONFLICT, ds_rename_access_conflict(&sess)))
        goto exit;

    Do_ADBG_EndSubCase(c, "GP DS Rename Access Conflict (9d-29-d1)");
    Do_ADBG_BeginSubCase(
        c, "GP DS StartPersistentObjectEnumerator ItemNotFound (9d-52-ec)");

    if (!ADBG_EXPECT_TEEC_SUCCESS(c, ds_start_enum_no_item(&sess)))
        goto exit;

    Do_ADBG_EndSubCase(
        c, "GP DS StartPersistentObjectEnumerator ItemNotFound (9d-52-ec)");
    Do_ADBG_BeginSubCase(
        c, "GP DS RenamePersistent ReadWrite (9d-19-88)");

    if (!ADBG_EXPECT_TEEC_SUCCESS(c, ds_rename_success(&sess)))
        goto exit;

    Do_ADBG_EndSubCase(
        c, "GP DS RenamePersistent ReadWrite (9d-19-88)");
    Do_ADBG_BeginSubCase(
        c, "GP DS Close Free Reset Null (9d-6d-87)");

    if (!ADBG_EXPECT_TEEC_SUCCESS(c, ds_null_close_free_reset(&sess)))
        goto exit;

    Do_ADBG_EndSubCase(
        c, "GP DS Close Free Reset Null (9d-6d-87)");

exit:
    TEEC_CloseSession(&sess);
}

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
#endif

static void xtest_tee_test_6012(ADBG_Case_t *c)
{
	TEEC_Session sess;
	uint32_t orig;
	uint32_t obj;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		xtest_teec_open_session(&sess, &storage_ta_uuid, NULL, &orig)))
		return;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		fs_create_overwrite(&sess, file_04, sizeof(file_04))))
		goto exit;

	TEEC_CloseSession(&sess);

	/* re-create the same */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		xtest_teec_open_session(&sess, &storage_ta_uuid, NULL, &orig)))
		return;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		fs_create_overwrite(&sess, file_04, sizeof(file_04))))
		goto exit;

	/*
	 * recreate it with an object, and remove it so that xtest 6009
	 * can be replayed
	 */
	 if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		fs_create(&sess, file_04, sizeof(file_04),
			  TEE_DATA_FLAG_ACCESS_WRITE |
			  TEE_DATA_FLAG_ACCESS_WRITE_META | TEE_DATA_FLAG_OVERWRITE, 0, NULL, 0, &obj)))
			goto exit;

	/* clean */
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, fs_unlink(&sess, obj)))
		goto exit;

exit:
	TEEC_CloseSession(&sess);
}

static void xtest_tee_test_6013(ADBG_Case_t *c)
{
	TEEC_Session sess;
	uint32_t orig;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		xtest_teec_open_session(&sess, &storage_ta_uuid, NULL, &orig)))
		return;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	ADBG_EXPECT_TEEC_SUCCESS(c,
		TEEC_InvokeCommand(&sess, TA_STORAGE_CMD_KEY_IN_PERSISTENT,
				   &op, &orig));

	TEEC_CloseSession(&sess);
}

static void xtest_tee_test_6014(ADBG_Case_t *c)
{
	TEEC_Session sess;
	uint32_t orig;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		xtest_teec_open_session(&sess, &storage_ta_uuid, NULL, &orig)))
		return;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	ADBG_EXPECT_TEEC_SUCCESS(c,
		TEEC_InvokeCommand(&sess, TA_STORAGE_CMD_LOOP, &op, &orig));

	TEEC_CloseSession(&sess);
}

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

#ifdef WITH_GP_TESTS
ADBG_CASE_DEFINE(
    XTEST_TEE_6010, xtest_tee_test_6010,
    /* Title */
    "Test TEE GP TTA DS storage",
    /* Short description */
    "Short description ...",
    /* Requirement IDs */
    "TEE-??",
    /* How to implement */
    "Description of how to implement ..."
);

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
