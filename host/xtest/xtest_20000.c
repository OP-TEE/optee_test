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

#ifdef CFG_ENC_FS

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <time.h>

#include <adbg.h>
#include <xtest_test.h>
#include <xtest_helpers.h>

#include <tee_fs_key_manager.h>
#include <tee_client_api.h>
#include <ta_storage.h>
#include <tee_api_defines.h>
#include <tee_api_types.h>

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

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

#ifndef MIN
#define MIN(a,b) ((a)<(b) ? (a) : (b))
#endif

#define SWAP_BYTES_16(w16) ((((w16) & 0xFF00) >> 8) | (((w16) & 0xFF) << 8))
#define SWAP_BYTES_32(w32) ((((w32) & 0xFF000000) >> 24) |\
			    (((w32) & 0xFF0000) >> 8) |\
			    (((w32) & 0xFF00) << 8) |\
			    (((w32) & 0xFF) << 24))

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

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_MEMREF_TEMP_INPUT, TEEC_VALUE_INOUT, TEEC_NONE, TEEC_NONE);

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
	op.params[2].value.b = 0;
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

static int get_ta_dirname(TEEC_UUID *p_uuid, char *buffer, uint32_t len)
{

	if (p_uuid == NULL || buffer == NULL)
		return 0;
	
	return snprintf(buffer, len,
		        "%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X",
		        SWAP_BYTES_32(p_uuid->timeLow),
		        SWAP_BYTES_16(p_uuid->timeMid),
		        SWAP_BYTES_16(p_uuid->timeHiAndVersion),
		        p_uuid->clockSeqAndNode[0],
	                p_uuid->clockSeqAndNode[1],
		        p_uuid->clockSeqAndNode[2],
		        p_uuid->clockSeqAndNode[3],
		        p_uuid->clockSeqAndNode[4],
		        p_uuid->clockSeqAndNode[5],
		        p_uuid->clockSeqAndNode[6],
		        p_uuid->clockSeqAndNode[7]);
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

static int dump_file(FILE *fd, char *buffer, uint32_t len)
{

	uint16_t format = 16;
	uint16_t size;
	int res=-1;

	printf("o Dump data (limit %d bytes)\n", DUMPLIMIT);
	if ( 0 != fseek(fd, 0, SEEK_SET))
		goto exit;
	fread(buffer, 1, len, fd);
	size = ( len < DUMPLIMIT ) ? len : DUMPLIMIT;
	Do_ADBG_HexLog(buffer, size, format);
	res=0;
exit:
	return res;
}

static int is_obj_present(TEEC_UUID *p_uuid, void *file_id,
                          uint32_t file_id_length,
                          enum tee_fs_file_type file_type,
                          uint8_t block_num, uint8_t version)
{
        char ta_dirname[32 + 1];
        char obj_filename[2*file_id_length + 1];
        char path[150];
        struct stat sb;

        if (get_ta_dirname(p_uuid, ta_dirname, sizeof(ta_dirname)) &&
            get_obj_filename(file_id, file_id_length, obj_filename,
			     sizeof(obj_filename))) {
                if (file_type == META_FILE) {
                        snprintf(path, sizeof(path), "/data/tee/%s/%s/meta.%d",
                                ta_dirname, obj_filename, version);
                } else if (file_type == BLOCK_FILE) {
                        snprintf(path, sizeof(path),
                                "/data/tee/%s/%s/block%d.%d", ta_dirname,
                                obj_filename, block_num, version);
                } else
                        goto err;

                return !stat(path, &sb);
        }
err:
        return 0;
}

static int obj_corrupt(TEEC_UUID *p_uuid, void *file_id,
		       uint32_t file_id_length,
		       uint32_t offset, enum tee_fs_file_type file_type,
		       uint8_t block_num, uint8_t version, uint32_t data_len)
{
	char ta_dirname[32 + 1];
	char obj_filename[2*file_id_length + 1];
	char name[500];
	FILE *fd;
	uint8_t byte;
	int res=-1;
	char buffer[data_len];
	struct stat st;

	if (get_ta_dirname(p_uuid, ta_dirname, sizeof(ta_dirname)) &&
	    get_obj_filename(file_id, file_id_length, obj_filename,
			     sizeof(obj_filename))) {

		/*
		 * read the byte at the given offset,
		 * do a bitwise negation,
		 * and rewrite this value at the same offset
		 */

		if (file_type == META_FILE) {
			snprintf(name, sizeof(name),
				 "/data/tee/%s/%s/meta.%d",
				 ta_dirname, obj_filename, version);
		}

		if (file_type == BLOCK_FILE) {
			snprintf(name, sizeof(name),
				 "/data/tee/%s/%s/block%d.%d",
				 ta_dirname, obj_filename, block_num, version);
		}

		res = stat(name, &st);
		if (res < 0)
			goto exit;

		if (offset == CORRUPT_FILE_FIRST_BYTE) {
			offset = 0;

		} else if (offset == CORRUPT_FILE_LAST_BYTE) {
			offset = st.st_size-1;

		} else if (offset == CORRUPT_FILE_RAND_BYTE) {
			srand(time(NULL));
			offset = rand() % (st.st_size-1);
		}

		fd = fopen(name, "r+");
		if (!fd)
			goto exit;

		if (DUMPFILE)
			dump_file(fd, buffer, sizeof(buffer));

		if (0 != fseek(fd, offset, SEEK_SET))
			goto exit;

		if (SIZE*NUMELEM != fread(&byte, SIZE, NUMELEM,fd))
			goto exit;

		printf("o Corrupt %s\n", name);
		printf("o Size: %ld byte(s)\n", st.st_size);
		printf("o Byte offset: %u (0x%04X), ", offset, offset);
		printf("Old value: 0x%x, ", byte);
		byte += 1;
		printf("New value: 0x%x\n", byte);

		if ( 0 != fseek(fd, offset, SEEK_SET))
			goto exit;

		if (SIZE*NUMELEM != fwrite(&byte, SIZE, NUMELEM,fd))
			goto exit;

		if (DUMPFILE)
			dump_file(fd, buffer, sizeof(buffer));

		fclose(fd);

		res = 0;
		goto exit;
	}

exit:
	return res;
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


	ADBG_EXPECT(c, TEE_SUCCESS,
		    TEEC_InitializeContext(_device, &ctx));

	ADBG_EXPECT(c, TEE_SUCCESS,
		    TEEC_OpenSession(&ctx, &sess, &uuid,
			TEEC_LOGIN_PUBLIC, NULL, NULL, &error));

	for (n = 0; n < ARRAY_SIZE(xtest_enc_fs_cases); n++) {

		const struct xtest_enc_fs_case *tv = xtest_enc_fs_cases + n;

		if (tv->level > level)
			continue;

		char buffer[tv->data_len];
		char filename[20];
		char *filedata = NULL;
		size_t p;
		uint8_t data_byte = 0;
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

		ADBG_EXPECT(c, TEE_SUCCESS,
			    obj_create(&sess, filename, ARRAY_SIZE(filename),
				TEE_DATA_FLAG_ACCESS_WRITE, 0, filedata,
				tv->data_len, &obj_id));

		ADBG_EXPECT(c, TEE_SUCCESS,
			    obj_close(&sess, obj_id));

		if (file_type == META_FILE)
			ADBG_EXPECT_COMPARE_UNSIGNED(c, 0, !=,
					     is_obj_present(&uuid, filename,
					     ARRAY_SIZE(filename), file_type,
					     tv->meta, tv->meta));

		if (file_type == BLOCK_FILE)
			ADBG_EXPECT_COMPARE_UNSIGNED(c, 0, !=,
					     is_obj_present(&uuid, filename,
					     ARRAY_SIZE(filename), file_type,
					     tv->block_num, tv->version));

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
			         file_type, tv->meta, tv->meta,
				 tv->data_len)))
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
					     is_obj_present(&uuid,
					     filename,
					     ARRAY_SIZE(filename), file_type,
					     tv->meta, tv->meta));
			break;

		case BLOCK_FILE:
		/* corrupt object */
		if (!ADBG_EXPECT(c, TEE_SUCCESS,
			         obj_corrupt(&uuid, filename,
				 ARRAY_SIZE(filename), offset,
			         file_type, tv->block_num, tv->version,
				 tv->data_len)))
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
			    TEE_DATA_FLAG_ACCESS_WRITE_META, &obj_id));

		ADBG_EXPECT_COMPARE_UNSIGNED(c, 0, ==,
					     is_obj_present(&uuid,
					     filename,
					     ARRAY_SIZE(filename),
					     file_type, tv->block_num,
					     tv->version));
			break;

		default:
			printf("ERROR : Wrong file type\n");

		}

		free(filedata);
		Do_ADBG_EndSubCase(c, NULL);
	};

exit:
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

ADBG_CASE_DEFINE(
	XTEST_TEE_20001, xtest_tee_test_20001,
	/* Title */
	"Sanity Test Corrupt Meta Encrypted Key",
	/* Short description */
	"Short description ...",
	/* Requirement IDs */
	"TEE-??",
	/* How to implement */
	"Description of how to implement ..."
	);

ADBG_CASE_DEFINE(
	XTEST_TEE_20002, xtest_tee_test_20002,
	/* Title */
	"Sanity Test Corrupt Meta IV",
	/* Short description */
	"Short description ...",
	/* Requirement IDs */
	"TEE-??",
	/* How to implement */
	"Description of how to implement ..."
	);

ADBG_CASE_DEFINE(
	XTEST_TEE_20003, xtest_tee_test_20003,
	/* Title */
	"Sanity Test Corrupt Meta Tag",
	/* Short description */
	"Short description ...",
	/* Requirement IDs */
	"TEE-??",
	/* How to implement */
	"Description of how to implement ..."
	);

ADBG_CASE_DEFINE(
	XTEST_TEE_20004, xtest_tee_test_20004,
	/* Title */
	"Sanity Test Corrupt Meta Data",
	/* Short description */
	"Short description ...",
	/* Requirement IDs */
	"TEE-??",
	/* How to implement */
	"Description of how to implement ..."
	);

ADBG_CASE_DEFINE(
	XTEST_TEE_20021, xtest_tee_test_20021,
	/* Title */
	"Sanity Test Corrupt Meta File : first byte",
	/* Short description */
	"Short description ...",
	/* Requirement IDs */
	"TEE-??",
	/* How to implement */
	"Description of how to implement ..."
	);

ADBG_CASE_DEFINE(
	XTEST_TEE_20022, xtest_tee_test_20022,
	/* Title */
	"Sanity Test Corrupt Meta File : last byte",
	/* Short description */
	"Short description ...",
	/* Requirement IDs */
	"TEE-??",
	/* How to implement */
	"Description of how to implement ..."
	);

ADBG_CASE_DEFINE(
	XTEST_TEE_20023, xtest_tee_test_20023,
	/* Title */
	"Sanity Test Corrupt Meta File : random byte",
	/* Short description */
	"Short description ...",
	/* Requirement IDs */
	"TEE-??",
	/* How to implement */
	"Description of how to implement ..."
	);

ADBG_CASE_DEFINE(
	XTEST_TEE_20501, xtest_tee_test_20501,
	/* Title */
	"Sanity Test Corrupt Block IV",
	/* Short description */
	"Short description ...",
	/* Requirement IDs */
	"TEE-??",
	/* How to implement */
	"Description of how to implement ..."
	);

ADBG_CASE_DEFINE(
	XTEST_TEE_20502, xtest_tee_test_20502,
	/* Title */
	"Sanity Test Corrupt Block Tag",
	/* Short description */
	"Short description ...",
	/* Requirement IDs */
	"TEE-??",
	/* How to implement */
	"Description of how to implement ..."
	);

ADBG_CASE_DEFINE(
	XTEST_TEE_20503, xtest_tee_test_20503,
	/* Title */
	"Sanity Test Corrupt Block Data",
	/* Short description */
	"Short description ...",
	/* Requirement IDs */
	"TEE-??",
	/* How to implement */
	"Description of how to implement ..."
	);

ADBG_CASE_DEFINE(
	XTEST_TEE_20521, xtest_tee_test_20521,
	/* Title */
	"Sanity Test Corrupt Block File : first byte",
	/* Short description */
	"Short description ...",
	/* Requirement IDs */
	"TEE-??",
	/* How to implement */
	"Description of how to implement ..."
	);

ADBG_CASE_DEFINE(
	XTEST_TEE_20522, xtest_tee_test_20522,
	/* Title */
	"Sanity Test Corrupt Block File : last byte",
	/* Short description */
	"Short description ...",
	/* Requirement IDs */
	"TEE-??",
	/* How to implement */
	"Description of how to implement ..."
	);

ADBG_CASE_DEFINE(
	XTEST_TEE_20523, xtest_tee_test_20523,
	/* Title */
	"Sanity Test Corrupt Block File : random byte",
	/* Short description */
	"Short description ...",
	/* Requirement IDs */
	"TEE-??",
	/* How to implement */
	"Description of how to implement ..."
	);

#endif /* CFG_ENC_FS */
