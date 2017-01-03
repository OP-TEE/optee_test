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

#if defined(CFG_REE_FS)

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#include <adbg.h>
#include <xtest_test.h>
#include <xtest_helpers.h>

#include <tee_fs_key_manager.h>
#include <tee_client_api.h>
#include <tee_api_defines_extensions.h>

#include <ta_storage.h>
#include <tee_api_defines.h>
#include <tee_api_types.h>
#include <util.h>

#define SIZE		1
#define NUMELEM		1
#define DUMPFILE 	0
#define DUMPLIMIT 	128

#define CORRUPT_META_KEY_OFFSET       offsetof(struct meta_header, encrypted_key)
#define CORRUPT_META_IV_OFFSET        (offsetof(struct meta_header, common) + \
				       offsetof(struct common_header, iv))
#define CORRUPT_META_TAG_OFFSET       (offsetof(struct meta_header, common) + \
				       offsetof(struct common_header, tag))
#define CORRUPT_META_DATA_OFFSET      sizeof(struct meta_header)

#define CORRUPT_BLOCK_IV_OFFSET       offsetof(struct common_header, iv)
#define CORRUPT_BLOCK_TAG_OFFSET      offsetof(struct common_header, tag)
#define CORRUPT_BLOCK_DATA_OFFSET     sizeof(struct block_header)

#define CORRUPT_FILE_RAND_BYTE		1024*4096+2
#define CORRUPT_FILE_FIRST_BYTE		1024*4096+1
#define CORRUPT_FILE_LAST_BYTE		1024*4096

#ifndef MIN
#define MIN(a,b) ((a)<(b) ? (a) : (b))
#endif

#define XTEST_ENC_FS(level, data_len, meta, block_num, version) \
	{ \
	  level, \
	  data_len, \
	  meta, block_num, version \
	}

enum meta {
	META0,
	META1
};

enum version {
	VERSION0,
	VERSION1
};

enum block_num {
	BLOCK0,
	BLOCK1,
	BLOCK2,
	BLOCK3,
	BLOCK4,
	BLOCK5
};

struct xtest_enc_fs_case {
	uint8_t level;
	uint32_t data_len;
	uint8_t meta;
	uint8_t block_num;
	uint8_t version;
};

static const struct xtest_enc_fs_case xtest_enc_fs_cases[] = {
	XTEST_ENC_FS(1, 1, META0, BLOCK0, VERSION1),
	XTEST_ENC_FS(1, 2, META0, BLOCK0, VERSION1),
	XTEST_ENC_FS(1, 3, META0, BLOCK0, VERSION1),
	XTEST_ENC_FS(1, 4, META0, BLOCK0, VERSION1),
	XTEST_ENC_FS(1, 8, META0, BLOCK0, VERSION1),
	XTEST_ENC_FS(1, 16, META0, BLOCK0, VERSION1),
	XTEST_ENC_FS(1, 32, META0, BLOCK0, VERSION1),
	XTEST_ENC_FS(1, 64, META0, BLOCK0, VERSION1),
	XTEST_ENC_FS(1, 128, META0, BLOCK0, VERSION1),
	XTEST_ENC_FS(1, 256, META0, BLOCK0, VERSION1),
	XTEST_ENC_FS(1, 512, META0, BLOCK0, VERSION1),
	XTEST_ENC_FS(1, 1024, META0, BLOCK0, VERSION1),
	XTEST_ENC_FS(1, 2048, META0, BLOCK0, VERSION1),
	XTEST_ENC_FS(1, 3072, META0, BLOCK0, VERSION1),
	XTEST_ENC_FS(1, 4094, META0, BLOCK0, VERSION1),
	XTEST_ENC_FS(1, 4095, META0, BLOCK0, VERSION1),
	XTEST_ENC_FS(0, 4097, META0, BLOCK0, VERSION1),
	XTEST_ENC_FS(0, 4097, META0, BLOCK1, VERSION0),
	XTEST_ENC_FS(1, 4098, META0, BLOCK0, VERSION1),
	XTEST_ENC_FS(1, 4098, META0, BLOCK1, VERSION0),
	XTEST_ENC_FS(1, 1*4096, META0, BLOCK1, VERSION0),
	XTEST_ENC_FS(1, 2*4096, META0, BLOCK2, VERSION0),
	XTEST_ENC_FS(1, 3*4096, META0, BLOCK3, VERSION0),
	XTEST_ENC_FS(1, 4*4096, META0, BLOCK3, VERSION0),
	XTEST_ENC_FS(1, 4*4096, META0, BLOCK4, VERSION0),
};

static TEEC_Result obj_open(TEEC_Session *sess, void *id, uint32_t id_size,
			    uint32_t flags, uint32_t *obj)
{
	TEEC_Operation op;
	TEEC_Result res;
	uint32_t org;

	memset(&op, 0, sizeof(op));
	op.params[0].tmpref.buffer = id;
	op.params[0].tmpref.size = id_size;
	op.params[1].value.a = flags;
	op.params[1].value.b = 0;
	op.params[2].value.a = TEE_STORAGE_PRIVATE_REE;

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_MEMREF_TEMP_INPUT, TEEC_VALUE_INOUT, TEEC_VALUE_INPUT,
		TEEC_NONE);

	res = TEEC_InvokeCommand(sess, TA_STORAGE_CMD_OPEN, &op, &org);

	if (res == TEEC_SUCCESS)
		*obj = op.params[1].value.b;

	return res;
}

static TEEC_Result obj_create(TEEC_Session *sess, void *id, uint32_t id_size,
			      uint32_t flags, uint32_t attr, void *data,
			      uint32_t data_size, uint32_t *obj)
{
	TEEC_Operation op;
	TEEC_Result res;
	uint32_t org;

	memset(&op, 0, sizeof(op));
	op.params[0].tmpref.buffer = id;
	op.params[0].tmpref.size = id_size;
	op.params[1].value.a = flags;
	op.params[1].value.b = 0;
	op.params[2].value.a = attr;
	op.params[2].value.b = TEE_STORAGE_PRIVATE_REE;
	op.params[3].tmpref.buffer = data;
	op.params[3].tmpref.size = data_size;

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_MEMREF_TEMP_INPUT, TEEC_VALUE_INOUT, TEEC_VALUE_INPUT,
		TEEC_MEMREF_TEMP_INPUT);

	res = TEEC_InvokeCommand(sess, TA_STORAGE_CMD_CREATE, &op, &org);

	if (res == TEEC_SUCCESS)
		*obj = op.params[1].value.b;

	return res;
}

static TEEC_Result obj_read(TEEC_Session *sess, uint32_t obj, void *data,
			    uint32_t data_size, uint32_t *count)
{
	TEEC_Result res;
	TEEC_Operation op;
	uint32_t org;

	memset(&op, 0, sizeof(op));
	op.params[0].tmpref.buffer = data;
	op.params[0].tmpref.size = data_size;
	op.params[1].value.a = obj;
	op.params[1].value.b = 0;

	op.paramTypes = TEEC_PARAM_TYPES(
	    TEEC_MEMREF_TEMP_OUTPUT, TEEC_VALUE_INOUT, TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(sess, TA_STORAGE_CMD_READ, &op, &org);

	if (res == TEEC_SUCCESS)
	    *count = op.params[1].value.b;

	return res;
}

static TEEC_Result obj_close(TEEC_Session *sess, uint32_t obj)
{
	TEEC_Operation op;
	uint32_t org;

	memset(&op, 0, sizeof(op));
	op.params[0].value.a = obj;

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);

	return TEEC_InvokeCommand(sess, TA_STORAGE_CMD_CLOSE, &op, &org);
}

static int get_obj_filename(void *file_id, uint32_t file_id_length,
			    char *buffer, uint32_t len)
{
	char *p = buffer;
	uint32_t i;

	if (file_id == NULL || buffer == NULL)
		return 0;

	for (i=0; i<file_id_length; i++)
		p += snprintf(p, len, "%02X", ((uint8_t *)file_id)[i]);

	return p-buffer;
}

static void dump_file(FILE * fd __attribute__ ((unused)))
{
#if DUMPFILE == 1
	uint16_t format = 16;
	uint16_t size;
	char buffer[DUMPLIMIT];

	if (!fd) {
		fprintf(stderr, "fd == NULL\n");
		return;
	}

	printf("o Dump data (limit %d bytes)\n", DUMPLIMIT);
	if (0 != fseek(fd, 0, SEEK_SET)) {
		fprintf(stderr, "fseek(%d): %s",
				0, strerror(errno));
		return;
	}

	memset(buffer, 0, sizeof(buffer));
	size = fread(buffer, 1, sizeof(buffer), fd);
	Do_ADBG_HexLog(buffer, size, format);
#endif
}

static int is_obj_present(TEEC_UUID *p_uuid, void *file_id,
                          uint32_t file_id_length)
{
        char ta_dirname[32 + 1];
        char obj_filename[2*file_id_length + 1];
        char path[PATH_MAX];
        struct stat sb;

        if (ree_fs_get_ta_dirname(p_uuid, ta_dirname, sizeof(ta_dirname)) &&
            get_obj_filename(file_id, file_id_length, obj_filename,
			     sizeof(obj_filename))) {
		snprintf(path, sizeof(path), "/data/tee/%s/%s",
			ta_dirname, obj_filename);

                return !stat(path, &sb);
        }
        return 0;
}

static TEEC_Result obj_corrupt(TEEC_UUID *p_uuid, void *file_id,
		       uint32_t file_id_length,
		       uint32_t offset, enum tee_fs_file_type file_type,
		       uint8_t block_num, uint8_t version)
{
	char ta_dirname[32 + 1];
	char obj_filename[2*file_id_length + 1];
	char name[PATH_MAX];
	FILE *fd = NULL;
	uint8_t bytes[SIZE * NUMELEM];
	int res;
	TEEC_Result tee_res = TEE_SUCCESS;
	int i;
	int num_corrupt_bytes = SIZE * NUMELEM;
	size_t real_offset;
	const size_t meta_block_size = sizeof(struct meta_header) +
				       sizeof(struct tee_fs_file_meta);
	const size_t meta_info_size = sizeof(struct meta_header) +
				      sizeof(struct tee_fs_file_info);
	const size_t block_size = sizeof(struct block_header) +
				  BLOCK_FILE_SIZE;

	memset(name, 0, sizeof(name));

	if (ree_fs_get_ta_dirname(p_uuid, ta_dirname, sizeof(ta_dirname)) &&
	    get_obj_filename(file_id, file_id_length, obj_filename,
			     sizeof(obj_filename))) {

		/*
		 * read the byte at the given offset,
		 * do a bitwise negation,
		 * and rewrite this value at the same offset
		 */

		snprintf(name, sizeof(name), "/data/tee/%s/%s",
			 ta_dirname, obj_filename);

		real_offset = sizeof(uint32_t); /* meta counter */
		if (file_type == META_FILE) {
			real_offset += version * meta_block_size;
		} else if (file_type == BLOCK_FILE) {
			real_offset += meta_block_size * 2;
			real_offset += (block_num * 2 + version) * block_size;
		}

		if (offset == CORRUPT_FILE_LAST_BYTE) {
			if (file_type == META_FILE)
				real_offset += meta_info_size;
			else
				real_offset += block_size;
			real_offset -= num_corrupt_bytes;
		} else if (offset == CORRUPT_FILE_RAND_BYTE) {
			srand(time(NULL));
			if (file_type == META_FILE)
				real_offset += rand() % (meta_info_size - 1);
			else
				real_offset += rand() % (block_size - 1);
			num_corrupt_bytes = 1;
		} else if (offset != CORRUPT_FILE_FIRST_BYTE) {
			real_offset += offset;
		}

		fd = fopen(name, "r+");
		if (!fd) {
			fprintf(stderr, "fopen(\"%s\"): %s",
					name, strerror(errno));
			tee_res = TEEC_ERROR_ACCESS_DENIED;
			goto exit;
		}

		dump_file(fd);

		if (0 != fseek(fd, real_offset, SEEK_SET)) {
			fprintf(stderr, "fseek(%zu): %s",
					real_offset, strerror(errno));
			tee_res = TEEC_ERROR_BAD_PARAMETERS;
			goto exit;
		}

		res = fread(bytes, 1, num_corrupt_bytes, fd);
		if (res != num_corrupt_bytes) {
			fprintf(stderr, "fread(%d): res=%d\n",
					num_corrupt_bytes, res);
			tee_res = TEEC_ERROR_SHORT_BUFFER;
			goto exit;
		}

		printf("o Corrupt %s\n", name);
		printf("o Byte offset: %zu (0x%04zX)\n", real_offset, real_offset);
		printf("Old value:");
		for (i = 0; i < num_corrupt_bytes; i++) {
			printf(" 0x%02x", bytes[i]);
			bytes[i] += 1;
		}
		printf("\n");

		printf("New value:");
		for (i = 0; i < num_corrupt_bytes; i++)
			printf(" 0x%02x", bytes[i]);
		printf("\n");

		if (0 != fseek(fd, real_offset, SEEK_SET)) {
			fprintf(stderr, "fseek(%zu): %s",
					real_offset, strerror(errno));
			tee_res = TEEC_ERROR_BAD_PARAMETERS;
			goto exit;
		}

		res = fwrite(bytes, 1, num_corrupt_bytes, fd);
		if (res != num_corrupt_bytes) {
			fprintf(stderr, "fwrite(%d): res=%d\n",
					num_corrupt_bytes, res);
			tee_res = TEEC_ERROR_SHORT_BUFFER;
			goto exit;
		}

		dump_file(fd);
	}

exit:
	if (fd)
		fclose(fd);

	return tee_res;
}

static void storage_corrupt(ADBG_Case_t *c,
			    enum tee_fs_file_type file_type,
			    uint32_t offset
			   )
{
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_UUID uuid = TA_STORAGE_UUID;
	unsigned int error;
	uint32_t obj_id;
	uint32_t nb;
	size_t n;
	char *filedata = NULL;


	if (!ADBG_EXPECT(c, TEE_SUCCESS,
	            TEEC_InitializeContext(_device, &ctx)))
		return;

	if (!ADBG_EXPECT(c, TEE_SUCCESS,
		    TEEC_OpenSession(&ctx, &sess, &uuid,
		        TEEC_LOGIN_PUBLIC, NULL, NULL, &error)))
		return;

	for (n = 0; n < ARRAY_SIZE(xtest_enc_fs_cases); n++) {

		const struct xtest_enc_fs_case *tv = xtest_enc_fs_cases + n;

		if (tv->level > level)
			continue;

		char buffer[tv->data_len];
		char filename[20];
		size_t p;
		uint8_t data_byte = 0;

		memset(filename, 0, sizeof(filename));

		snprintf(filename, sizeof(filename), "file_%dB", tv->data_len);
		filedata = malloc(tv->data_len * sizeof(*filedata));
		if (!filedata)
			goto exit;

		for (p = 0; p < tv->data_len; p++) {
    			filedata[p] = data_byte;
			data_byte++;
		};

		Do_ADBG_BeginSubCase(c, "| filename: %s , data size: %d byte(s)",
				     filename, tv->data_len);

		if (ADBG_EXPECT(c, TEE_SUCCESS,
			    obj_create(&sess, filename, ARRAY_SIZE(filename),
				TEE_DATA_FLAG_ACCESS_WRITE, 0, filedata,
			        tv->data_len, &obj_id)))

			ADBG_EXPECT(c, TEE_SUCCESS,
			            obj_close(&sess, obj_id));
		else
			goto exit;

		if (file_type == META_FILE)
			ADBG_EXPECT_COMPARE_UNSIGNED(c, 0, !=,
					     is_obj_present(&uuid, filename,
					     ARRAY_SIZE(filename)));

		if (file_type == BLOCK_FILE)
			ADBG_EXPECT_COMPARE_UNSIGNED(c, 0, !=,
					     is_obj_present(&uuid, filename,
					     ARRAY_SIZE(filename)));

		ADBG_EXPECT(c, TEE_SUCCESS,
			    obj_open(&sess, filename, ARRAY_SIZE(filename),
			    TEE_DATA_FLAG_ACCESS_READ |
			    TEE_DATA_FLAG_ACCESS_WRITE_META, &obj_id));

		ADBG_EXPECT(c, TEE_SUCCESS,
			    obj_read(&sess, obj_id, buffer, tv->data_len, &nb));

		ADBG_EXPECT(c, TEE_SUCCESS,
			    obj_close(&sess, obj_id));

		switch (file_type) {
		case META_FILE:
		/* corrupt object */
		if (!ADBG_EXPECT(c, TEE_SUCCESS,
				obj_corrupt(&uuid, filename,
					ARRAY_SIZE(filename), offset,
					file_type, tv->meta, tv->meta)))
			goto exit;	

		ADBG_EXPECT_TEEC_RESULT(c, TEE_ERROR_CORRUPT_OBJECT,
				obj_open(&sess, filename,
					ARRAY_SIZE(filename),
					TEE_DATA_FLAG_ACCESS_READ |
					TEE_DATA_FLAG_ACCESS_WRITE_META,
					&obj_id));

		ADBG_EXPECT_TEEC_RESULT(c, TEE_ERROR_ITEM_NOT_FOUND,
				obj_open(&sess, filename,
					ARRAY_SIZE(filename),
					TEE_DATA_FLAG_ACCESS_READ |
					TEE_DATA_FLAG_ACCESS_WRITE_META,
					&obj_id));

		ADBG_EXPECT_COMPARE_UNSIGNED(c, 0, ==,
				is_obj_present(&uuid, filename,
					       ARRAY_SIZE(filename)));
			break;

		case BLOCK_FILE:
		/* corrupt object */
		if (!ADBG_EXPECT(c, TEE_SUCCESS,
					obj_corrupt(&uuid, filename,
						ARRAY_SIZE(filename),
						offset, file_type,
						tv->block_num, tv->version)))
			goto exit;

		if ( tv->block_num == BLOCK0 ) {
			ADBG_EXPECT(c, TEE_ERROR_CORRUPT_OBJECT,
					obj_open(&sess, filename,
						ARRAY_SIZE(filename),
						TEE_DATA_FLAG_ACCESS_READ |
						TEE_DATA_FLAG_ACCESS_WRITE_META,
						&obj_id));
		} else {
			ADBG_EXPECT(c, TEE_SUCCESS,
					obj_open(&sess, filename,
						ARRAY_SIZE(filename),
						TEE_DATA_FLAG_ACCESS_READ |
						TEE_DATA_FLAG_ACCESS_WRITE_META,
						&obj_id));

			ADBG_EXPECT_TEEC_RESULT(c, TEE_ERROR_CORRUPT_OBJECT,
					obj_read(&sess, obj_id, buffer,
						tv->data_len, &nb));
		}

		ADBG_EXPECT_TEEC_RESULT(c, TEE_ERROR_ITEM_NOT_FOUND,
				obj_open(&sess, filename, ARRAY_SIZE(filename),
					TEE_DATA_FLAG_ACCESS_READ |
					TEE_DATA_FLAG_ACCESS_WRITE_META,
					&obj_id));

		ADBG_EXPECT_COMPARE_UNSIGNED(c, 0, ==,
				is_obj_present(&uuid, filename,
					       ARRAY_SIZE(filename)));
			break;

		default:
			printf("ERROR : Wrong file type\n");

		}

		free(filedata);
		filedata = NULL;
		Do_ADBG_EndSubCase(c, NULL);
	};

exit:
	free(filedata);
	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);
}

/* Corrupt Meta Encrypted Key */
static void xtest_tee_test_20001(ADBG_Case_t *c)
{
	storage_corrupt(c, META_FILE, CORRUPT_META_KEY_OFFSET
			);
}

/* Corrupt Meta IV */
static void xtest_tee_test_20002(ADBG_Case_t *c)
{
	storage_corrupt(c, META_FILE, CORRUPT_META_IV_OFFSET
			);
}

/* Corrupt Meta Tag */
static void xtest_tee_test_20003(ADBG_Case_t *c)
{
	storage_corrupt(c, META_FILE, CORRUPT_META_TAG_OFFSET
			);
}

/* Corrupt Meta Data */
static void xtest_tee_test_20004(ADBG_Case_t *c)
{
	storage_corrupt(c,
			META_FILE, CORRUPT_META_DATA_OFFSET
			);
}

/* Corrupt Meta File : first byte */
static void xtest_tee_test_20021(ADBG_Case_t *c)
{
	storage_corrupt(c, META_FILE, CORRUPT_FILE_FIRST_BYTE
			);

}

/* Corrupt Meta File : last byte */
static void xtest_tee_test_20022(ADBG_Case_t *c)
{
	storage_corrupt(c, META_FILE, CORRUPT_FILE_LAST_BYTE
			);

}

/* Corrupt Meta File : random byte */
static void xtest_tee_test_20023(ADBG_Case_t *c)
{
	storage_corrupt(c, META_FILE, CORRUPT_FILE_RAND_BYTE
			);

}

/* Corrupt Block IV */
static void xtest_tee_test_20501(ADBG_Case_t *c)
{
	storage_corrupt(c, BLOCK_FILE, CORRUPT_BLOCK_IV_OFFSET
			);

}

/* Corrupt Block Tag */
static void xtest_tee_test_20502(ADBG_Case_t *c)
{
	storage_corrupt(c, BLOCK_FILE, CORRUPT_BLOCK_TAG_OFFSET
			);
}

/* Corrupt Block Data */
static void xtest_tee_test_20503(ADBG_Case_t *c)
{

	storage_corrupt(c, BLOCK_FILE, CORRUPT_BLOCK_DATA_OFFSET
			);
}

/* Corrupt Block File : first byte */
static void xtest_tee_test_20521(ADBG_Case_t *c)
{
	storage_corrupt(c, BLOCK_FILE, CORRUPT_FILE_FIRST_BYTE
			);

}

/* Corrupt Block File : last byte */
static void xtest_tee_test_20522(ADBG_Case_t *c)
{
	storage_corrupt(c, BLOCK_FILE, CORRUPT_FILE_LAST_BYTE
			);

}

/* Corrupt Block File : random byte */
static void xtest_tee_test_20523(ADBG_Case_t *c)
{
	storage_corrupt(c, BLOCK_FILE, CORRUPT_FILE_RAND_BYTE
			);

}

ADBG_CASE_DEFINE(regression, 20001, xtest_tee_test_20001,
	"Sanity Test Corrupt Meta Encrypted Key");
ADBG_CASE_DEFINE(regression, 20002, xtest_tee_test_20002,
	"Sanity Test Corrupt Meta IV");
ADBG_CASE_DEFINE(regression, 20003, xtest_tee_test_20003,
	"Sanity Test Corrupt Meta Tag");
ADBG_CASE_DEFINE(regression, 20004, xtest_tee_test_20004,
	"Sanity Test Corrupt Meta Data");
ADBG_CASE_DEFINE(regression, 20021, xtest_tee_test_20021,
	"Sanity Test Corrupt Meta File : first byte");
ADBG_CASE_DEFINE(regression, 20022, xtest_tee_test_20022,
	"Sanity Test Corrupt Meta File : last byte");
ADBG_CASE_DEFINE(regression, 20023, xtest_tee_test_20023,
	"Sanity Test Corrupt Meta File : random byte");
ADBG_CASE_DEFINE(regression, 20501, xtest_tee_test_20501,
	"Sanity Test Corrupt Block IV");
ADBG_CASE_DEFINE(regression, 20502, xtest_tee_test_20502,
	"Sanity Test Corrupt Block Tag");
ADBG_CASE_DEFINE(regression, 20503, xtest_tee_test_20503,
	"Sanity Test Corrupt Block Data");
ADBG_CASE_DEFINE(regression, 20521, xtest_tee_test_20521,
	"Sanity Test Corrupt Block File : first byte");
ADBG_CASE_DEFINE(regression, 20522, xtest_tee_test_20522,
	"Sanity Test Corrupt Block File : last byte");
ADBG_CASE_DEFINE(regression, 20523, xtest_tee_test_20523,
	"Sanity Test Corrupt Block File : random byte");

#endif /* defined(CFG_REE_FS) */
