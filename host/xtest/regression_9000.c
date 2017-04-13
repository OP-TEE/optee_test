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
#include <fs_htree.h>
#include <tee_client_api.h>
#include <tee_api_defines_extensions.h>

#include <ta_storage.h>
#include <tee_api_defines.h>
#include <tee_api_types.h>
#include <util.h>

#define BLOCK_SIZE	(4 * 1024)

#define SIZE		1
#define NUMELEM		1
#define DUMPFILE 	0
#define DUMPLIMIT 	128

#define CORRUPT_META_KEY_OFFSET       offsetof(struct tee_fs_htree_image, enc_fek)
#define CORRUPT_META_IV_OFFSET        offsetof(struct tee_fs_htree_image, iv)
#define CORRUPT_META_TAG_OFFSET       offsetof(struct tee_fs_htree_image, tag)
#define CORRUPT_META_DATA_OFFSET      offsetof(struct tee_fs_htree_image, imeta)

#define CORRUPT_BLOCK_IV_OFFSET       offsetof(struct tee_fs_htree_node_image, iv)
#define CORRUPT_BLOCK_TAG_OFFSET      offsetof(struct tee_fs_htree_node_image, tag)
#define CORRUPT_BLOCK_DATA_OFFSET     0

#define CORRUPT_FILE_RAND_BYTE		1024*4096+2
#define CORRUPT_FILE_FIRST_BYTE		1024*4096+1
#define CORRUPT_FILE_LAST_BYTE		1024*4096

#ifndef MIN
#define MIN(a,b) ((a)<(b) ? (a) : (b))
#endif

#define XTEST_ENC_FS(level, data_len, meta, block_num, block_vers, node_vers) \
	{ \
	  level, \
	  data_len, \
	  meta, block_num, block_vers, node_vers \
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
	uint8_t block_version;
	uint8_t node_version;
};

static const struct xtest_enc_fs_case xtest_enc_fs_cases[] = {
	XTEST_ENC_FS(1, 1, META0, BLOCK0, VERSION1, VERSION0),
	XTEST_ENC_FS(1, 2, META0, BLOCK0, VERSION1, VERSION0),
	XTEST_ENC_FS(1, 3, META0, BLOCK0, VERSION1, VERSION0),
	XTEST_ENC_FS(1, 4, META0, BLOCK0, VERSION1, VERSION0),
	XTEST_ENC_FS(1, 8, META0, BLOCK0, VERSION1, VERSION0),
	XTEST_ENC_FS(1, 16, META0, BLOCK0, VERSION1, VERSION0),
	XTEST_ENC_FS(1, 32, META0, BLOCK0, VERSION1, VERSION0),
	XTEST_ENC_FS(1, 64, META0, BLOCK0, VERSION1, VERSION0),
	XTEST_ENC_FS(1, 128, META0, BLOCK0, VERSION1, VERSION0),
	XTEST_ENC_FS(1, 256, META0, BLOCK0, VERSION1, VERSION0),
	XTEST_ENC_FS(1, 512, META0, BLOCK0, VERSION1, VERSION0),
	XTEST_ENC_FS(1, 1024, META0, BLOCK0, VERSION1, VERSION0),
	XTEST_ENC_FS(1, 2048, META0, BLOCK0, VERSION1, VERSION0),
	XTEST_ENC_FS(1, 3072, META0, BLOCK0, VERSION1, VERSION0),
	XTEST_ENC_FS(1, 4094, META0, BLOCK0, VERSION1, VERSION0),
	XTEST_ENC_FS(1, 4095, META0, BLOCK0, VERSION1, VERSION0),
	XTEST_ENC_FS(0, 4097, META0, BLOCK0, VERSION1, VERSION0),
	XTEST_ENC_FS(0, 4097, META0, BLOCK1, VERSION1, VERSION1),
	XTEST_ENC_FS(1, 4098, META0, BLOCK0, VERSION1, VERSION0),
	XTEST_ENC_FS(1, 4098, META0, BLOCK1, VERSION1, VERSION1),
	XTEST_ENC_FS(1, 1*4096, META0, BLOCK1, VERSION1, VERSION1),
	XTEST_ENC_FS(1, 2*4096, META0, BLOCK2, VERSION1, VERSION1),
	XTEST_ENC_FS(1, 3*4096, META0, BLOCK3, VERSION1, VERSION1),
	XTEST_ENC_FS(1, 4*4096, META0, BLOCK3, VERSION1, VERSION1),
	XTEST_ENC_FS(1, 4*4096, META0, BLOCK4, VERSION1, VERSION1),
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

static int is_obj_present(uint32_t file_id)
{
        char path[PATH_MAX];
        struct stat sb;

	snprintf(path, sizeof(path), "/data/tee/%" PRIu32, file_id);

	return !stat(path, &sb);
}

static bool obj_unlink(uint32_t file_id)
{
        char path[PATH_MAX];

	snprintf(path, sizeof(path), "/data/tee/%" PRIu32, file_id);
	if (unlink(path)) {
		fprintf(stderr, "unlink(\"%s\"): %s", path, strerror(errno));
		return false;
	}
	return true;
}

static TEEC_Result get_offs_size(enum tee_fs_htree_type type, size_t idx,
				 uint8_t vers, size_t *offs, size_t *size)
{
	const size_t node_size = sizeof(struct tee_fs_htree_node_image);
	const size_t block_nodes = BLOCK_SIZE / (node_size * 2);
	size_t pbn;
	size_t bidx;
	size_t sz;

	/*
	 * File layout
	 *
	 * phys block 0:
	 * tee_fs_htree_image vers 0 @ offs = 0
	 * tee_fs_htree_image vers 1 @ offs = sizeof(tee_fs_htree_image)
	 *
	 * phys block 1:
	 * tee_fs_htree_node_image 0  vers 0 @ offs = 0
	 * tee_fs_htree_node_image 0  vers 1 @ offs = node_size
	 * tee_fs_htree_node_image 1  vers 0 @ offs = node_size * 2
	 * tee_fs_htree_node_image 1  vers 1 @ offs = node_size * 3
	 * ...
	 * tee_fs_htree_node_image 61 vers 0 @ offs = node_size * 122
	 * tee_fs_htree_node_image 61 vers 1 @ offs = node_size * 123
	 *
	 * phys block 2:
	 * data block 0 vers 0
	 *
	 * phys block 3:
	 * data block 0 vers 1
	 *
	 * ...
	 * phys block 63:
	 * data block 61 vers 0
	 *
	 * phys block 64:
	 * data block 61 vers 1
	 *
	 * phys block 65:
	 * tee_fs_htree_node_image 62  vers 0 @ offs = 0
	 * tee_fs_htree_node_image 62  vers 1 @ offs = node_size
	 * tee_fs_htree_node_image 63  vers 0 @ offs = node_size * 2
	 * tee_fs_htree_node_image 63  vers 1 @ offs = node_size * 3
	 * ...
	 * tee_fs_htree_node_image 121 vers 0 @ offs = node_size * 122
	 * tee_fs_htree_node_image 121 vers 1 @ offs = node_size * 123
	 *
	 * ...
	 */

	switch (type) {
	case TEE_FS_HTREE_TYPE_HEAD:
		*offs = sizeof(struct tee_fs_htree_image) * vers;
		sz = sizeof(struct tee_fs_htree_image);
		break;
	case TEE_FS_HTREE_TYPE_NODE:
		pbn = 1 + ((idx / block_nodes) * block_nodes * 2);
		*offs = pbn * BLOCK_SIZE +
			2 * node_size * (idx % block_nodes) +
			node_size * vers;
		sz = node_size;
		break;
	case TEE_FS_HTREE_TYPE_BLOCK:
		bidx = 2 * idx + vers;
		pbn = 2 + bidx + bidx / (block_nodes * 2 - 1);
		*offs = pbn * BLOCK_SIZE;
		sz = BLOCK_SIZE;
		break;
	default:
		return TEEC_ERROR_BAD_PARAMETERS;
		break;
	}

	if (size)
		*size = sz;

	return TEEC_SUCCESS;
}

static TEEC_Result obj_corrupt(uint32_t file_id, uint32_t offset,
			       enum tee_fs_htree_type type, uint8_t block_num,
			       uint8_t version)
{
	char name[PATH_MAX];
	FILE *fd = NULL;
	uint8_t bytes[SIZE * NUMELEM];
	int res;
	TEEC_Result tee_res = TEE_SUCCESS;
	int i;
	int num_corrupt_bytes = SIZE * NUMELEM;
	size_t real_offset;
	size_t node_size = sizeof(struct tee_fs_htree_node_image);

	memset(name, 0, sizeof(name));

	/*
	 * read the byte at the given offset,
	 * do a bitwise negation,
	 * and rewrite this value at the same offset
	 */

	snprintf(name, sizeof(name), "/data/tee/%" PRIu32, file_id);

	tee_res = get_offs_size(type, block_num, version, &real_offset, NULL);
	if (tee_res != TEEC_SUCCESS) {
		fprintf(stderr, "invalid type\n");
		goto exit;
	}

	if (offset == CORRUPT_FILE_LAST_BYTE) {
		if (type == TEE_FS_HTREE_TYPE_HEAD)
			real_offset += node_size;
		else
			real_offset += BLOCK_SIZE;
		real_offset -= num_corrupt_bytes;
	} else if (offset == CORRUPT_FILE_RAND_BYTE) {
		srand(time(NULL));
		if (type == TEE_FS_HTREE_TYPE_HEAD)
			real_offset += rand() % (node_size - 1);
		else
			real_offset += rand() % (BLOCK_SIZE - 1);
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

exit:
	if (fd)
		fclose(fd);

	return tee_res;
}

static void storage_corrupt(ADBG_Case_t *c,
			    enum tee_fs_htree_type file_type,
			    uint32_t offset
			   )
{
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_UUID uuid = TA_STORAGE_UUID;
	unsigned int error;
	uint32_t obj_id;
	uint32_t nb;
	uint32_t f;
	size_t n;
	uint8_t vers;
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
		uint32_t file_id = 0;
		size_t p;
		uint8_t data_byte = 0;

		if (!ADBG_EXPECT_BOOLEAN(c, false, is_obj_present(file_id)))
			goto exit;

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

		f = TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE_META;

		if (file_type == TEE_FS_HTREE_TYPE_HEAD)
			ADBG_EXPECT_COMPARE_UNSIGNED(c, 0, !=,
					     is_obj_present(file_id));

		if (file_type == TEE_FS_HTREE_TYPE_BLOCK)
			ADBG_EXPECT_COMPARE_UNSIGNED(c, 0, !=,
					     is_obj_present(file_id));

		ADBG_EXPECT(c, TEE_SUCCESS,
			    obj_open(&sess, filename, ARRAY_SIZE(filename),
				     f, &obj_id));

		ADBG_EXPECT(c, TEE_SUCCESS,
			    obj_read(&sess, obj_id, buffer, tv->data_len, &nb));

		ADBG_EXPECT(c, TEE_SUCCESS,
			    obj_close(&sess, obj_id));


		switch (file_type) {
		case TEE_FS_HTREE_TYPE_HEAD:
			/* corrupt object */
			if (!ADBG_EXPECT(c, TEE_SUCCESS,
					 obj_corrupt(file_id, offset, file_type,
						     tv->meta, tv->meta)))
				goto exit;

			ADBG_EXPECT_TEEC_RESULT(c, TEE_ERROR_CORRUPT_OBJECT,
						obj_open(&sess, filename,
							 ARRAY_SIZE(filename),
							 f, &obj_id));

			ADBG_EXPECT_TEEC_RESULT(c, TEE_ERROR_ITEM_NOT_FOUND,
						obj_open(&sess, filename,
						ARRAY_SIZE(filename),
						f, &obj_id));

			ADBG_EXPECT_COMPARE_UNSIGNED(c, 0, ==,
					is_obj_present(file_id));
			break;

		case TEE_FS_HTREE_TYPE_NODE:
		case TEE_FS_HTREE_TYPE_BLOCK:
			if (file_type == TEE_FS_HTREE_TYPE_NODE)
				vers = tv->node_version;
			else
				vers = tv->block_version;

			/* corrupt object */
			if (!ADBG_EXPECT(c, TEE_SUCCESS,
				obj_corrupt(file_id, offset, file_type,
					    tv->block_num, vers)))
				goto exit;

			/*
			 * All nodes are currently verified when opening so
			 * any corrupt node will be detected. This will
			 * change if lazy loading of nodes is implemented.
			 */
			if (tv->block_num == BLOCK0 ||
			    (file_type == TEE_FS_HTREE_TYPE_NODE &&
			     tv->block_num <= BLOCK5)) {
				ADBG_EXPECT(c, TEE_ERROR_CORRUPT_OBJECT,
					    obj_open(&sess, filename,
						     ARRAY_SIZE(filename),
						     f, &obj_id));
			} else {
				ADBG_EXPECT(c, TEE_SUCCESS,
					    obj_open(&sess, filename,
						     ARRAY_SIZE(filename),
						     f, &obj_id));

				ADBG_EXPECT_TEEC_RESULT(c,
					TEE_ERROR_CORRUPT_OBJECT,
					obj_read(&sess, obj_id, buffer,
						 tv->data_len, &nb));
			}

			ADBG_EXPECT_TEEC_RESULT(c, TEE_ERROR_ITEM_NOT_FOUND,
				obj_open(&sess, filename, ARRAY_SIZE(filename),
					 f, &obj_id));

			ADBG_EXPECT_COMPARE_UNSIGNED(c, 0, ==,
					is_obj_present(file_id));
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
static void xtest_tee_test_9001(ADBG_Case_t *c)
{
	storage_corrupt(c, TEE_FS_HTREE_TYPE_HEAD, CORRUPT_META_KEY_OFFSET
			);
}

/* Corrupt Meta IV */
static void xtest_tee_test_9002(ADBG_Case_t *c)
{
	storage_corrupt(c, TEE_FS_HTREE_TYPE_HEAD, CORRUPT_META_IV_OFFSET
			);
}

/* Corrupt Meta Tag */
static void xtest_tee_test_9003(ADBG_Case_t *c)
{
	storage_corrupt(c, TEE_FS_HTREE_TYPE_HEAD, CORRUPT_META_TAG_OFFSET
			);
}

/* Corrupt Meta Data */
static void xtest_tee_test_9004(ADBG_Case_t *c)
{
	storage_corrupt(c,
			TEE_FS_HTREE_TYPE_HEAD, CORRUPT_META_DATA_OFFSET
			);
}

/* Corrupt Meta File : first byte */
static void xtest_tee_test_9021(ADBG_Case_t *c)
{
	storage_corrupt(c, TEE_FS_HTREE_TYPE_HEAD, CORRUPT_FILE_FIRST_BYTE
			);

}

/* Corrupt Meta File : last byte */
static void xtest_tee_test_9022(ADBG_Case_t *c)
{
	storage_corrupt(c, TEE_FS_HTREE_TYPE_HEAD, CORRUPT_FILE_LAST_BYTE
			);

}

/* Corrupt Meta File : random byte */
static void xtest_tee_test_9023(ADBG_Case_t *c)
{
	storage_corrupt(c, TEE_FS_HTREE_TYPE_HEAD, CORRUPT_FILE_RAND_BYTE
			);

}

/* Corrupt Block IV */
static void xtest_tee_test_9501(ADBG_Case_t *c)
{
	storage_corrupt(c, TEE_FS_HTREE_TYPE_NODE, CORRUPT_BLOCK_IV_OFFSET
			);

}

/* Corrupt Block Tag */
static void xtest_tee_test_9502(ADBG_Case_t *c)
{
	storage_corrupt(c, TEE_FS_HTREE_TYPE_NODE, CORRUPT_BLOCK_TAG_OFFSET
			);
}

/* Corrupt Block Data */
static void xtest_tee_test_9503(ADBG_Case_t *c)
{

	storage_corrupt(c, TEE_FS_HTREE_TYPE_BLOCK, CORRUPT_BLOCK_DATA_OFFSET
			);
}

/* Corrupt Block File : first byte */
static void xtest_tee_test_9521(ADBG_Case_t *c)
{
	storage_corrupt(c, TEE_FS_HTREE_TYPE_BLOCK, CORRUPT_FILE_FIRST_BYTE
			);

}

/* Corrupt Block File : last byte */
static void xtest_tee_test_9522(ADBG_Case_t *c)
{
	storage_corrupt(c, TEE_FS_HTREE_TYPE_BLOCK, CORRUPT_FILE_LAST_BYTE
			);

}

/* Corrupt Block File : random byte */
static void xtest_tee_test_9523(ADBG_Case_t *c)
{
	storage_corrupt(c, TEE_FS_HTREE_TYPE_BLOCK, CORRUPT_FILE_RAND_BYTE
			);

}

static void xtest_tee_test_9524(ADBG_Case_t *c)
{
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_UUID uuid = TA_STORAGE_UUID;
	uint32_t error;
	char filename[] = "file";
	uint32_t file_id = 0;
	uint32_t obj_id;
	char filedata[] = "data";

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, TEEC_InitializeContext(_device, &ctx)))
		return;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		TEEC_OpenSession(&ctx, &sess, &uuid,
				 TEEC_LOGIN_PUBLIC, NULL, NULL, &error)))
		goto final_ctx;


	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, 0, ==, is_obj_present(file_id)))
		goto close_sess;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		    obj_create(&sess, filename, ARRAY_SIZE(filename),
			TEE_DATA_FLAG_ACCESS_WRITE, 0, filedata,
			sizeof(filedata), &obj_id)))
		goto close_sess;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c, obj_close(&sess, obj_id)))
		goto close_sess;

	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, 0, !=, is_obj_present(file_id)))
		goto close_sess;

	if (!ADBG_EXPECT_TRUE(c, obj_unlink(file_id)))
		goto close_sess;

	if (!ADBG_EXPECT_TEEC_RESULT(c, TEE_ERROR_CORRUPT_OBJECT,
		obj_open(&sess, filename, ARRAY_SIZE(filename),
			 TEE_DATA_FLAG_ACCESS_READ, &obj_id)))
		goto close_sess;

	ADBG_EXPECT_TEEC_RESULT(c, TEE_ERROR_ITEM_NOT_FOUND,
		obj_open(&sess, filename, ARRAY_SIZE(filename),
			 TEE_DATA_FLAG_ACCESS_READ, &obj_id));

close_sess:
	TEEC_CloseSession(&sess);
final_ctx:
	TEEC_FinalizeContext(&ctx);
}

ADBG_CASE_DEFINE(regression, 9001, xtest_tee_test_9001,
	"Sanity Test Corrupt Meta Encrypted Key");
ADBG_CASE_DEFINE(regression, 9002, xtest_tee_test_9002,
	"Sanity Test Corrupt Meta IV");
ADBG_CASE_DEFINE(regression, 9003, xtest_tee_test_9003,
	"Sanity Test Corrupt Meta Tag");
ADBG_CASE_DEFINE(regression, 9004, xtest_tee_test_9004,
	"Sanity Test Corrupt Meta Data");
ADBG_CASE_DEFINE(regression, 9021, xtest_tee_test_9021,
	"Sanity Test Corrupt Meta File : first byte");
ADBG_CASE_DEFINE(regression, 9022, xtest_tee_test_9022,
	"Sanity Test Corrupt Meta File : last byte");
ADBG_CASE_DEFINE(regression, 9023, xtest_tee_test_9023,
	"Sanity Test Corrupt Meta File : random byte");
ADBG_CASE_DEFINE(regression, 9501, xtest_tee_test_9501,
	"Sanity Test Corrupt Block IV");
ADBG_CASE_DEFINE(regression, 9502, xtest_tee_test_9502,
	"Sanity Test Corrupt Block Tag");
ADBG_CASE_DEFINE(regression, 9503, xtest_tee_test_9503,
	"Sanity Test Corrupt Block Data");
ADBG_CASE_DEFINE(regression, 9521, xtest_tee_test_9521,
	"Sanity Test Corrupt Block File : first byte");
ADBG_CASE_DEFINE(regression, 9522, xtest_tee_test_9522,
	"Sanity Test Corrupt Block File : last byte");
ADBG_CASE_DEFINE(regression, 9523, xtest_tee_test_9523,
	"Sanity Test Corrupt Block File : random byte");
ADBG_CASE_DEFINE(regression, 9524, xtest_tee_test_9524,
	"Sanity Test Remove file");

#endif /* defined(CFG_REE_FS) */
