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
	TEEC_Operation op;
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
	TEEC_Operation op;
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

static TEEC_Result fs_close(TEEC_Session *sess, uint32_t obj)
{
	TEEC_Operation op;
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
	TEEC_Operation op;
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
	TEEC_Operation op;
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
	TEEC_Operation op;
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
	TEEC_Operation op;
	uint32_t org;

	op.params[0].value.a = obj;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	return TEEC_InvokeCommand(sess, TA_STORAGE_CMD_UNLINK, &op, &org);
}

static TEEC_Result fs_trunc(TEEC_Session *sess, uint32_t obj, uint32_t len)
{
	TEEC_Operation op;
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
	TEEC_Operation op;
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
	TEEC_Operation op;
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
	TEEC_Operation op;
	uint32_t org;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE,
					 TEEC_NONE);

	op.params[0].value.a = e;

	return TEEC_InvokeCommand(sess, TA_STORAGE_CMD_FREE_ENUM, &op, &org);
}

static TEEC_Result fs_start_enum(TEEC_Session *sess, uint32_t e)
{
	TEEC_Operation op;
	uint32_t org;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	op.params[0].value.a = e;

	return TEEC_InvokeCommand(sess, TA_STORAGE_CMD_START_ENUM, &op, &org);
}

static TEEC_Result fs_next_enum(TEEC_Session *sess, uint32_t e, void *obj_info,
				size_t info_size, void *id, uint32_t id_size)
{
	TEEC_Operation op;
	uint32_t org;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE);

	op.params[0].value.a = e;
	op.params[1].tmpref.buffer = obj_info;
	op.params[1].tmpref.size = info_size;
	op.params[2].tmpref.buffer = id;
	op.params[2].tmpref.size = id_size;

	return TEEC_InvokeCommand(sess, TA_STORAGE_CMD_NEXT_ENUM, &op, &org);
}

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

/* trunc */
static void xtest_tee_test_6007(ADBG_Case_t *c)
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
		fs_next_enum(&sess, e, info, sizeof(info), id, sizeof(id))))
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
