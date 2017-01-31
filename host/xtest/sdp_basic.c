/*
 * Copyright (c) 2016, Linaro Limited
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

#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <tee_client_api.h>
#include <tee_client_api_extensions.h>
#include <unistd.h>

#include "include/uapi/linux/ion.h"
#include "ta_sdp_basic.h"
#include "crypto_common.h"

/*
 * SDP basic test setup overview.
 *
 * - A dedicated trusted application (SDP basic TA) supports 3 commands:
 *   - 'inject' data from a nonsecure buffer into a secure buffer
 *   - 'transform' data inside a secure buffer (bitwise invert + unsigned incr)
 *   - 'dump' data from a secure buffer into a nonsecure buffer

 * - This test client application (CA) invokes the TA for these 3 operations,
 *   inject random value, trasforming them then dump them.
 *
 * To do so, CA allocates a 'SDP secure buffer' and invoke the TA for these 3
 * operations (inject then transform then dump) over the allocate buffer.
 *
 * The secure buffer is currently allocation through ION support adn
 * registered to OP-TEE and as shared memory.
 *
 * To enhance test coverage against buffer alignement usecase, the CA invokes
 * the TA with a variable offset inside the buffer. As CA injects random data
 * into the buffer, the CA uses one of the random bytes to set the value of the
 * offset in the accessed secure buffer.
 *
 * For debugging support, the CA may map (in nonsecure world) the secure
 * buffer to read its content. As this is unsafe on a hardened platform, this
 * operation is default disable. When enable, error only print out a warning
 * trace but does not actually fail the test. This also give an easy way to
 * check that some HW complains on access violation when nonsecure accesses
 * secure data.
 */

static int verbosity = 1;

struct tee_ctx {
	TEEC_Context ctx;
	TEEC_Session sess;
};

/* exported to xtest */
int allocate_ion_buffer(size_t size, int heap_id);

/* non zero value forces buffer to be mappeable from nonsecure */
#define BUF_MUST_MAP	0

#define DEFAULT_ION_HEAP_TYPE	ION_HEAP_TYPE_UNMAPPED

/*
 * Warm when nonsecure maps SDP buffer and found unexpected content.
 * Since mapping SDP buffers from nonsecure is unsafe, such accesses
 * from nonsecure shall not trigger errors, only warnings.
 */
static int warm_ns_access = 1;

int allocate_ion_buffer(size_t size, int heap_id)
{
	struct ion_allocation_data alloc_data;
	struct ion_handle_data hdl_data;
	struct ion_fd_data fd_data;
	int ion;
	int fd = -1;

	ion = open("/dev/ion", O_RDWR);
	if (ion < 0) {
		fprintf(stderr, "Error; failed to open /dev/ion\n");
		verbose("Seems no ION heap is available.\n");
		verbose("To test ION allocation you can enable\n");
		verbose("CONFIG_ION and CONFIG_ION_DUMMY in your\n");
		verbose("linux kernel configuration.\n");
		return fd;
	}

	if (heap_id < 0)
		heap_id = DEFAULT_ION_HEAP_TYPE;

	verbose("Allocate in ION heap '%s'\n",
		heap_id == ION_HEAP_TYPE_SYSTEM ? "system" :
		heap_id == ION_HEAP_TYPE_SYSTEM_CONTIG ? "system contig" :
		heap_id == ION_HEAP_TYPE_CARVEOUT ? "carveout" :
		heap_id == ION_HEAP_TYPE_CHUNK ? "chunk" :
		heap_id == ION_HEAP_TYPE_DMA ? "dma" :
		heap_id == ION_HEAP_TYPE_UNMAPPED ? "unmapped" :
		"custom");

	alloc_data.len = size;
	alloc_data.align = 0;
	alloc_data.flags = 0;
	alloc_data.heap_id_mask = 1 << heap_id;
	if (ioctl(ion, ION_IOC_ALLOC, &alloc_data) == -1)
		goto out;

	fd_data.handle = alloc_data.handle;
	if (ioctl(ion, ION_IOC_SHARE, &fd_data) != -1)
		fd = fd_data.fd;

	hdl_data.handle = alloc_data.handle;
	(void)ioctl(ion, ION_IOC_FREE, &hdl_data);
out:
	close(ion);
	return fd;
}

static void finalize_tee_ctx(struct tee_ctx *ctx)
{
	if (!ctx)
		return;

	TEEC_CloseSession(&ctx->sess);
	TEEC_FinalizeContext(&ctx->ctx);
}

static int create_tee_ctx(struct tee_ctx *ctx)
{
	TEEC_Result teerc;
	TEEC_UUID uuid = TA_SDP_BASIC_UUID;
	uint32_t err_origin;

	teerc = TEEC_InitializeContext(NULL, &ctx->ctx);
	if (teerc != TEEC_SUCCESS)
		return -1;

	teerc = TEEC_OpenSession(&ctx->ctx, &ctx->sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (teerc != TEEC_SUCCESS)
		fprintf(stderr, "Error: open session to SDP test TA failed %x %d\n",
			teerc, err_origin);

	return (teerc == TEEC_SUCCESS) ? 0 : -1;
}

static int tee_register_buffer(struct tee_ctx *ctx, void **shm_ref, int fd)
{
	TEEC_Result teerc;
	TEEC_SharedMemory *shm;

	shm = malloc(sizeof(*shm));
	if (!shm)
		return 1;

	shm->flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
	teerc = TEEC_RegisterSharedMemoryFileDescriptor(&ctx->ctx, shm, fd);
	if (teerc != TEEC_SUCCESS) {
		fprintf(stderr, "Error: TEEC_RegisterMemoryFileDescriptor() failed %x\n",
			teerc);
		return 1;
	}

	*shm_ref = shm;
	return 0;
}

static void tee_deregister_buffer(struct tee_ctx *ctx, void *shm_ref)
{
	(void)ctx;

	if (!shm_ref)
		return;

	TEEC_ReleaseSharedMemory((TEEC_SharedMemory *)shm_ref);
	free(shm_ref);
}

static int inject_sdp_data(struct tee_ctx *ctx,
		    void *in, size_t offset, size_t len, void *shm_ref, int ind)
{
	TEEC_SharedMemory *shm = (TEEC_SharedMemory *)shm_ref;
	TEEC_Result teerc;
	TEEC_Operation op;
	uint32_t err_origin;
	unsigned cmd = ind ? TA_SDP_BASIC_CMD_INVOKE_INJECT :
				TA_SDP_BASIC_CMD_INJECT;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_PARTIAL_OUTPUT,
					 TEEC_NONE, TEEC_NONE);

	op.params[0].tmpref.buffer = in;
	op.params[0].tmpref.size = len;

	op.params[1].memref.parent = shm;
	op.params[1].memref.size = len;
	op.params[1].memref.offset = offset;

	teerc = TEEC_InvokeCommand(&ctx->sess, cmd, &op, &err_origin);
	if (teerc != TEEC_SUCCESS)
		fprintf(stderr, "Error: invoke SDP test TA (inject) failed %x %d\n",
			teerc, err_origin);

	return (teerc == TEEC_SUCCESS) ? 0 : -1;
}

static int transform_sdp_data(struct tee_ctx *ctx,
			size_t offset, size_t len, void *shm_ref, int ind)
{
	TEEC_SharedMemory *shm = (TEEC_SharedMemory *)shm_ref;
	TEEC_Result teerc;
	TEEC_Operation op;
	uint32_t err_origin;
	unsigned cmd = ind ? TA_SDP_BASIC_CMD_INVOKE_TRANSFORM :
				TA_SDP_BASIC_CMD_TRANSFORM;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INOUT,
					 TEEC_NONE, TEEC_NONE, TEEC_NONE);
	op.params[0].memref.parent = shm;
	op.params[0].memref.size = len;
	op.params[0].memref.offset = offset;

	teerc = TEEC_InvokeCommand(&ctx->sess, cmd, &op, &err_origin);
	if (teerc != TEEC_SUCCESS)
		fprintf(stderr, "Error: invoke SDP test TA (transform) failed %x %d\n",
			teerc, err_origin);

	return (teerc == TEEC_SUCCESS) ? 0 : -1;
}

static int dump_sdp_data(struct tee_ctx *ctx,
		  void *out, size_t offset, size_t len, void *shm_ref, int ind)
{
	TEEC_SharedMemory *shm = (TEEC_SharedMemory *)shm_ref;
	TEEC_Result teerc;
	TEEC_Operation op;
	uint32_t err_origin;
	unsigned cmd = ind ? TA_SDP_BASIC_CMD_INVOKE_DUMP :
				TA_SDP_BASIC_CMD_DUMP;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].memref.parent = shm;
	op.params[0].memref.size = len;
	op.params[0].memref.offset = offset;

	op.params[1].tmpref.buffer = out;
	op.params[1].tmpref.size = len;

	teerc = TEEC_InvokeCommand(&ctx->sess, cmd, &op, &err_origin);
	if (teerc != TEEC_SUCCESS)
		fprintf(stderr, "Error: invoke SDP test TA (dump) failed %x %d\n",
			teerc, err_origin);

	return (teerc == TEEC_SUCCESS) ? 0 : -1;
}

static int check_sdp_dumped(struct tee_ctx *ctx, void *ref, size_t len,
								void *out)
{
	char *bref = (char *)ref;
	char *data = (char *)out;
	int err = 0;

	(void)ctx;

	while(len--)
		if (*data++ != (unsigned char)(~(*bref++) + 1))
			err++;

	return err;
}

/*
 * Consider 32kByte + 1 of random data is sufficient for an accurate test
 * whatever the test buffer size is. Random buffer is read as a ring buffer.
 */
#define RANDOM_BUFFER_SIZE	(32 * 1024 + 1)
static int get_random_bytes(char *out, size_t len)
{
	static char *rand_buf = NULL;
	static size_t rand_idx = 0;
	int rc;

	if (!rand_buf) {
		const char rand_dev[] = "/dev/urandom";
		int fd;

		rand_buf = malloc(RANDOM_BUFFER_SIZE);
		if (!rand_buf) {
			fprintf(stderr, "failed to random buffer memory (%d bytes)\n",
				RANDOM_BUFFER_SIZE);
			return -1;
		}

		fd = open(rand_dev, O_RDONLY);
		if (fd < 0) {
			fprintf(stderr, "failed to open %s\n", rand_dev);
			return -1;
		}

		rc = read(fd, rand_buf, RANDOM_BUFFER_SIZE);
		if (rc != RANDOM_BUFFER_SIZE) {
			fprintf(stderr, "failed to read %d bytes from %s\n",
				RANDOM_BUFFER_SIZE, rand_dev);
			return -1;
		}
		close(fd);
	}

	while (len) {
		size_t t_len = (RANDOM_BUFFER_SIZE < len) ? RANDOM_BUFFER_SIZE : len;

		if ((rand_idx + t_len) > RANDOM_BUFFER_SIZE) {
			int sz_end = RANDOM_BUFFER_SIZE - rand_idx;
			int sz_beg = t_len - sz_end;

			memcpy(out, rand_buf + rand_idx, sz_end);
			memcpy(out + sz_end, rand_buf , sz_beg);
			rand_idx = sz_beg;
		} else {
			memcpy(out, rand_buf + rand_idx, t_len);
			rand_idx += t_len;
		}
		len -= t_len;
	}
	return 0;
}


static int sdp_basic_test(size_t size, size_t loop, int ion_heap, int rnd_offset)
{
	struct tee_ctx *ctx = NULL;
	unsigned char *test_buf = NULL;
	unsigned char *ref_buf = NULL;
	void *shm_ref = NULL;
	unsigned int err = 1;
	int fd = -1;
	size_t sdp_size = size;
	size_t offset;
	size_t loop_cnt;

	if (!loop) {
		fprintf(stderr, "Error: null loop value\n");
		return 1;
	}

	/* reduce size to enable offset tests (max offset is 255 bytes) */
	if (rnd_offset)
		size -= 255;

	test_buf = malloc(size);
	ref_buf = malloc(size);
	if (!test_buf || !ref_buf) {
		verbose("failed to allocate memory\n");
		goto out;
	}

	fd = allocate_ion_buffer(sdp_size, ion_heap);
	if (fd < 0) {
		verbose("Failed to allocate SDP buffer (%lu bytes) in ION heap %d: %d\n",
				sdp_size, ion_heap, fd);
		goto out;
	}

	/* register secure buffer to TEE */
	ctx = malloc(sizeof(*ctx));
	if (!ctx)
		goto out;
	if (create_tee_ctx(ctx))
		goto out;
	if (tee_register_buffer(ctx, &shm_ref, fd))
		goto out;

	/* release registered fd: tee should still hold refcount on resource */
	close(fd);
	fd = -1;

	/* invoke trusted application with secure buffer as memref parameter */
	for (loop_cnt = loop; loop_cnt; loop_cnt--) {
		/* get an buffer of random-like values */
		if (get_random_bytes((char *)ref_buf, size))
			goto out;
		memcpy(test_buf, ref_buf, size);
		/* random offset [0 255] */
		offset = (unsigned int)*ref_buf;

		/* TA writes into SDP buffer */
		if (inject_sdp_data(ctx, test_buf, offset, size, shm_ref, 0))
			goto out;

		/* TA reads/writes into SDP buffer */
		if (transform_sdp_data(ctx, offset, size, shm_ref, 0))
			goto out;

		/* TA reads into SDP buffer */
		if (dump_sdp_data(ctx, test_buf, offset, size, shm_ref, 0))
			goto out;

		/* check dumped data are the expected ones */
		if (check_sdp_dumped(ctx, ref_buf, size, test_buf)) {
			fprintf(stderr, "check SDP data: %d errors\n", err);
			goto out;
		}
	}

	/* invoke trusted application with secure buffer as memref parameter */
	for (loop_cnt = loop; loop_cnt; loop_cnt--) {
		/* get an buffer of random-like values */
		if (get_random_bytes((char *)ref_buf, size))
			goto out;
		memcpy(test_buf, ref_buf, size);
		/* random offset [0 255] */
		offset = (unsigned int)*ref_buf;

		/* TA writes into SDP buffer */
		if (inject_sdp_data(ctx, test_buf, offset, size, shm_ref, 1))
			goto out;

		/* TA reads/writes into SDP buffer */
		if (transform_sdp_data(ctx, offset, size, shm_ref, 1))
			goto out;

		/* TA reads into SDP buffer */
		if (dump_sdp_data(ctx, test_buf, offset, size, shm_ref, 1))
			goto out;

		/* check dumped data are the expected ones */
		if (check_sdp_dumped(ctx, ref_buf, size, test_buf)) {
			fprintf(stderr, "check SDP data: %d errors\n", err);
			goto out;
		}
	}

	err = 0;
	verbose("%s: successed\n", __func__);
out:
	if (err)
		verbose("test failed\n");
	if (fd >= 0)
		close(fd);
	if (shm_ref)
		tee_deregister_buffer(ctx, shm_ref);
	finalize_tee_ctx(ctx);
	free(ctx);
	free(ref_buf);
	free(test_buf);
	return err;
}

#define _TO_STR(x) #x
#define TO_STR(x) _TO_STR(x)

static void usage(const char *progname, size_t size, int loop, int ion_heap)
{
	fprintf(stderr, "Usage: %s [OPTION]\n", progname);
	fprintf(stderr,
		"Testing basic accesses to secure buffer (SDP) on OP-TEE.\n"
		"Allocates a secure buffer and invoke a TA to access it.\n"
		"TA is used to init/transform/dump the secure buffer.\n"
		"CA check dumped content.\n\n");

	fprintf(stderr, "Options:\n");
	fprintf(stderr, " -h|--help      Print this help and exit\n");
	fprintf(stderr, " -v             Be verbose\n");
	fprintf(stderr, " -s SIZE        SDP buffer byte size [%zu]\n", size);
	fprintf(stderr, " -n LOOP        Test loop iterations [%u]\n", loop);
	fprintf(stderr, " --ion-heap ID  Target ION heap ID [%d]\n", ion_heap);
	fprintf(stderr, " --no-offset    No random offset [0 255] in buffer\n");
}

#define NEXT_ARG(i) \
	do { \
		if (++i == argc) { \
			fprintf(stderr, "%s: %s: missing argument\n", \
				argv[0], argv[i-1]); \
			return 1; \
		} \
	} while (0);

int sdp_basic_runner_cmd_parser(int argc, char *argv[])
{
	size_t test_size = 5000;
	size_t test_loop = 1000;
	int ion_heap = DEFAULT_ION_HEAP_TYPE;
	int rnd_offset = 1;
	int i;

	/* Parse command line */
	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
			usage(argv[0], test_size, test_loop, ion_heap);
			return 0;
		}
	}
	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-v")) {
			verbosity++;
		} else if (!strcmp(argv[i], "-s")) {
			NEXT_ARG(i);
			test_size = atoi(argv[i]);
		} else if (!strcmp(argv[i], "-n")) {
			NEXT_ARG(i);
			test_loop = atoi(argv[i]);
		} else if (!strcmp(argv[i], "--ion-heap")) {
			NEXT_ARG(i);
			ion_heap = atoi(argv[i]);
		} else if (!strcmp(argv[i], "--no-offset")) {
			rnd_offset = 0;
		} else {
			fprintf(stderr, "%s: invalid argument: %s\n",
				argv[0], argv[i]);
			usage(argv[0], test_size, test_loop, ion_heap);
			return 1;
		}
	}

	verbose("Secure Data Path basic accesses from trusted applications\n");

	warm_ns_access = 1;
	if (sdp_basic_test(test_size, test_loop, ion_heap, rnd_offset))
		return 1;

	return 0;
}
