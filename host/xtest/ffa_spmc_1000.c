// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2022-2023, Arm Limited and Contributors. All rights reserved.
 */
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include "include/uapi/linux/arm_ffa_user.h"
#include "xtest_helpers.h"
#include "xtest_test.h"

#define FFA_DRIVER_FS_PATH	"/sys/kernel/debug/arm_ffa_user"
#define SPMC_TEST_OK 0xaa
#define INCORRECT_ENDPOINT_ID 0xffff
#define NORMAL_WORLD_ENDPOINT_ID	0

#define FFA_USER_REQ_VER_MAJOR 5
#define FFA_USER_REQ_VER_MINOR 0
#define FFA_USER_REQ_VER_PATCH 1

/* Get the 32 least significant bits of a handle.*/
#define MEM_SHARE_HANDLE_LOW(x) ((x) & 0xffffffff)
/* Get the 32 most significant bits of a handle.*/
#define MEM_SHARE_HANDLE_HIGH(x) (((x) >> 32) & 0xffffffff)

#define MEM_SHARE_HANDLE_LOW_INDEX	1
#define MEM_SHARE_HANDLE_HIGH_INDEX	2
#define MEM_SHARE_HANDLE_ENDPOINT_INDEX	3

enum sp_tests {
	EP_TEST_SP,
	EP_TEST_SP_COMMUNICATION,
	EP_TEST_SP_INCREASE,
	EP_TRY_R_ACCESS,
	EP_TRY_W_ACCESS,
	EP_RETRIEVE,
	EP_RELINQUISH,
	EP_SP_MEM_SHARING,
	EP_SP_MEM_SHARING_MULTI,
	EP_SP_MEM_SHARING_EXC,
	EP_SP_MEM_INCORRECT_ACCESS,
	EP_SP_NOP
};

static int ffa_fd = -1;

static const char test_endpoint1_uuid[] =
	"5c9edbc3-7b3a-4367-9f83-7c191ae86a37";
static const char test_endpoint2_uuid[] =
	"7817164c-c40c-4d1a-867a-9bb2278cf41a";
static const char test_endpoint3_uuid[] =
	"23eb0100-e32a-4497-9052-2f11e584afa6";
static const char test_lsp_endpoint_uuid[] =
	"54b5440e-a3d2-48d1-872a-7b6cbfc34855";

static struct ffa_ioctl_ep_desc test_endpoint1 = {
	.uuid_ptr = (uint64_t)test_endpoint1_uuid,
};

static struct ffa_ioctl_ep_desc test_endpoint2 = {
	.uuid_ptr = (uint64_t)test_endpoint2_uuid,
};

static struct ffa_ioctl_ep_desc test_endpoint3 = {
	.uuid_ptr = (uint64_t)test_endpoint3_uuid,
};

static struct ffa_ioctl_ep_desc test_lsp_endpoint = {
	.uuid_ptr = (uint64_t)test_lsp_endpoint_uuid,
};

static bool check_ffa_user_version(void)
{
	FILE *f = NULL;
	int ver_major = -1;
	int ver_minor = -1;
	int ver_patch = -1;
	int scan_cnt = 0;

	f = fopen("/sys/module/arm_ffa_user/version", "r");
	if (f) {
		scan_cnt = fscanf(f, "%d.%d.%d",
				  &ver_major, &ver_minor, &ver_patch);
		fclose(f);
		if (scan_cnt != 3) {
			printf("error: failed to parse arm_ffa_user version\n");
			return false;
		}
	} else {
		printf("error: failed to read arm_ffa_user module info - %s\n",
		       strerror(errno));
		return false;
	}

	if (ver_major != FFA_USER_REQ_VER_MAJOR)
		goto err;

	if (ver_minor < FFA_USER_REQ_VER_MINOR)
		goto err;

	if (ver_minor == FFA_USER_REQ_VER_MINOR)
		if (ver_patch < FFA_USER_REQ_VER_PATCH)
			goto err;

	return true;

err:
	printf("error: Incompatible arm_ffa_user driver detected.");
	printf("Found v%d.%d.%d wanted >= v%d.%d.%d)\n",
	       ver_major, ver_minor, ver_patch, FFA_USER_REQ_VER_MAJOR,
		   FFA_USER_REQ_VER_MINOR, FFA_USER_REQ_VER_PATCH);

	return false;
}

static void close_debugfs(void)
{
	int err = 0;

	if (ffa_fd >= 0) {
		err = close(ffa_fd);
		if (err < 0)
			Do_ADBG_Log("Error: Could not close the FF-A driver");
	}
	ffa_fd = -1;
}

static bool init_sp_xtest(ADBG_Case_t *c)
{
	if (!check_ffa_user_version())
		return false;

	if (ffa_fd < 0) {
		ffa_fd = open(FFA_DRIVER_FS_PATH, O_RDWR);
		if (ffa_fd < 0) {
			Do_ADBG_Log("Error: Could not open the FF-A driver");
			return false;
		}
	}

	return true;
}

static int start_sp_test(uint16_t endpoint, enum sp_tests test,
			 struct ffa_ioctl_msg_args *args)
{
	args->dst_id = endpoint;
	args->args[0] = test;
	return ioctl(ffa_fd, FFA_IOC_MSG_SEND, args);
}

static uint16_t get_endpoint_id(uint64_t endp)
{
	struct ffa_ioctl_ep_desc sid = { .uuid_ptr = endp };

	/* Get ID of destination SP based on UUID */
	if (ioctl(ffa_fd, FFA_IOC_GET_PART_ID, &sid))
		return INCORRECT_ENDPOINT_ID;

	return sid.id;
}

static void xtest_ffa_spmc_test_1001(ADBG_Case_t *c)
{
	struct ffa_ioctl_msg_args args = { 0 };
	uint16_t endpoint1_id = 0;
	uint16_t endpoint2_id = 0;
	int rc = 0;

	Do_ADBG_BeginSubCase(c, "SP1 comms check");
	if (!init_sp_xtest(c)) {
		Do_ADBG_Log("Failed to initialise test, skipping SP test");
		goto out;
	}

	endpoint1_id = get_endpoint_id(test_endpoint1.uuid_ptr);
	if (endpoint1_id == INCORRECT_ENDPOINT_ID) {
		Do_ADBG_Log("Could not contact xtest_1 sp, skipping SP test");
		Do_ADBG_Log("Add xtest_1 sp to the image to enable tests");
		goto out;
	}

	memset(&args, 0, sizeof(args));
	rc = start_sp_test(endpoint1_id, EP_TEST_SP, &args);
	if (!ADBG_EXPECT_COMPARE_SIGNED(c, rc, ==, 0))
		goto out;

	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, args.args[0], ==, SPMC_TEST_OK))
		goto out;
	Do_ADBG_EndSubCase(c, "SP1 comms check");

	Do_ADBG_BeginSubCase(c, "Sp2 comms check");
	endpoint2_id = get_endpoint_id(test_endpoint2.uuid_ptr);
	if (endpoint2_id == INCORRECT_ENDPOINT_ID) {
		Do_ADBG_Log("Could not contact xtest_2 sp, skipping SP test");
		Do_ADBG_Log("Add xtest_2 sp to the image to enable tests");
		goto out;
	}

	memset(&args, 0, sizeof(args));
	rc = start_sp_test(endpoint2_id, EP_TEST_SP, &args);
	if (!ADBG_EXPECT_COMPARE_SIGNED(c, rc, ==, 0))
		goto out;

	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, args.args[0], ==, SPMC_TEST_OK))
		goto out;
	Do_ADBG_EndSubCase(c, "Sp2 comms check");

	/* Test SP to SP messaging. */
	Do_ADBG_BeginSubCase(c, "SP to SP messaging check");
	memset(&args, 0, sizeof(args));
	args.args[1] = endpoint2_id;

	rc = start_sp_test(endpoint1_id, EP_TEST_SP_COMMUNICATION, &args);
	ADBG_EXPECT_COMPARE_SIGNED(c, rc, ==, 0);
	ADBG_EXPECT_COMPARE_UNSIGNED(c, args.args[0], ==, SPMC_TEST_OK);

	memset(&args, 0, sizeof(args));
	args.args[1] = endpoint1_id;

	rc = start_sp_test(endpoint2_id, EP_TEST_SP_COMMUNICATION, &args);
	ADBG_EXPECT_COMPARE_SIGNED(c, rc, ==, 0);
	ADBG_EXPECT_COMPARE_UNSIGNED(c, args.args[0], ==, SPMC_TEST_OK);

out:
	Do_ADBG_EndSubCase(c, NULL);
	close_debugfs();
}

ADBG_CASE_DEFINE(ffa_spmc, 1001, xtest_ffa_spmc_test_1001,
		 "Test FF-A communication");

static void check_alive(ADBG_Case_t *c, uint16_t endpoint)
{
	struct ffa_ioctl_msg_args args = {};
	int rc = 0;

	args.dst_id = endpoint;
	rc = start_sp_test(endpoint, EP_SP_NOP, &args);
	ADBG_EXPECT_COMPARE_SIGNED(c, rc, ==, 0);
	ADBG_EXPECT_COMPARE_UNSIGNED(c, args.args[0], ==, SPMC_TEST_OK);
}

static int share_mem(uint16_t endpoint, uint64_t *handle)
{
	int status = false;
	struct ffa_ioctl_shm_desc shm_desc = { .dst_id = endpoint,
					      .size = 0x1000 };

	status = ioctl(ffa_fd, FFA_IOC_SHM_INIT, &shm_desc);

	if (!status)
		*handle = shm_desc.handle;

	return status;
}

static int set_up_mem(struct ffa_ioctl_ep_desc *endp,
		      struct ffa_ioctl_msg_args *args,
		      uint64_t *handle, ADBG_Case_t *c)
{
	uint16_t endpoint = 0;
	int rc = 0;

	endpoint = get_endpoint_id(endp->uuid_ptr);
	*handle = 0;
	/* Share memory with SP*/
	rc = share_mem(endpoint, handle);
	ADBG_EXPECT_COMPARE_SIGNED(c, rc, ==, 0);

	if (!ADBG_EXPECT_NOT_NULL(c, handle))
		return TEEC_ERROR_GENERIC;

	/* SP will retrieve the memory region. */
	memset(args, 0, sizeof(*args));
	args->dst_id = endpoint;
	args->args[MEM_SHARE_HANDLE_LOW_INDEX] = MEM_SHARE_HANDLE_LOW(*handle);
	args->args[MEM_SHARE_HANDLE_HIGH_INDEX] =
		MEM_SHARE_HANDLE_HIGH(*handle);
	args->args[MEM_SHARE_HANDLE_ENDPOINT_INDEX] = NORMAL_WORLD_ENDPOINT_ID;

	rc = start_sp_test(endpoint, EP_RETRIEVE, args);
	ADBG_EXPECT_COMPARE_SIGNED(c, rc, ==, 0);
	ADBG_EXPECT_COMPARE_UNSIGNED(c, args->args[0], ==, SPMC_TEST_OK);

	return TEEC_SUCCESS;
}

static void xtest_ffa_spmc_test_1002(ADBG_Case_t *c)
{
	struct ffa_ioctl_msg_args args = { 0 };
	uint64_t handle = 0;
	uint16_t endpoint1_id = 0;
	int rc = 0;
	struct ffa_ioctl_shm_desc shm_desc = { 0 };

	if (!init_sp_xtest(c)) {
		Do_ADBG_Log("Failed to initialise test, skipping SP test");
		goto out;
	}

	endpoint1_id = get_endpoint_id(test_endpoint1.uuid_ptr);
	if (endpoint1_id == INCORRECT_ENDPOINT_ID) {
		Do_ADBG_Log("Could not contact xtest_1 sp, skipping SP test");
		Do_ADBG_Log("Add xtest_1 sp to the image to enable tests");
		goto out;
	}

	memset(&args, 0, sizeof(args));
	rc = start_sp_test(endpoint1_id, EP_TEST_SP, &args);
	ADBG_EXPECT_COMPARE_SIGNED(c, rc, ==, 0);
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(c, args.args[0], ==, SPMC_TEST_OK))
		goto out;

	/* Set up memory and have the SP retrieve it. */
	Do_ADBG_BeginSubCase(c, "Test memory set-up");
	memset(&args, 0, sizeof(args));
	if (set_up_mem(&test_endpoint1, &args, &handle, c)) {
		Do_ADBG_EndSubCase(c, "Test memory set-up");
		goto out;
	}
	Do_ADBG_EndSubCase(c, "Test memory set-up");

	/* Retrieve it again. */
	Do_ADBG_BeginSubCase(c, "Test retrieve memory second time");
	memset(&args, 0, sizeof(args));
	args.dst_id = endpoint1_id;
	args.args[MEM_SHARE_HANDLE_LOW_INDEX] = MEM_SHARE_HANDLE_LOW(handle);
	args.args[MEM_SHARE_HANDLE_HIGH_INDEX] = MEM_SHARE_HANDLE_HIGH(handle);
	args.args[MEM_SHARE_HANDLE_ENDPOINT_INDEX] = NORMAL_WORLD_ENDPOINT_ID;
	rc = start_sp_test(endpoint1_id, EP_RETRIEVE, &args);
	ADBG_EXPECT_COMPARE_SIGNED(c, rc, ==, 0);
	Do_ADBG_EndSubCase(c, "Test retrieve memory second time");

	/*Access it. */
	Do_ADBG_BeginSubCase(c, "Test accessing memory");
	memset(&args, 0, sizeof(args));
	rc = start_sp_test(endpoint1_id, EP_TRY_R_ACCESS, &args);
	ADBG_EXPECT_COMPARE_SIGNED(c, rc, ==, 0);
	ADBG_EXPECT_COMPARE_UNSIGNED(c, args.args[0], ==, SPMC_TEST_OK);
	Do_ADBG_EndSubCase(c, "Test accessing memory");

	/*RELINQUISH the memory area.*/
	Do_ADBG_BeginSubCase(c, "Test relinquish memory");
	memset(&args, 0, sizeof(args));
	args.args[MEM_SHARE_HANDLE_LOW_INDEX] = MEM_SHARE_HANDLE_LOW(handle);
	args.args[MEM_SHARE_HANDLE_HIGH_INDEX] = MEM_SHARE_HANDLE_HIGH(handle);
	rc = start_sp_test(endpoint1_id, EP_RELINQUISH, &args);
	ADBG_EXPECT_COMPARE_SIGNED(c, rc, ==, 0);
	ADBG_EXPECT_COMPARE_UNSIGNED(c, args.args[0], ==, SPMC_TEST_OK);
	check_alive(c, endpoint1_id);
	Do_ADBG_EndSubCase(c, "Test relinquish memory");

	/* Try to reclaim the mem with the SP still having access to it. */
	Do_ADBG_BeginSubCase(c, "Test incorrect reclaim");
	shm_desc.handle = handle;
	shm_desc.dst_id = endpoint1_id;
	rc = ioctl(ffa_fd, FFA_IOC_SHM_DEINIT, &shm_desc);
	ADBG_EXPECT_COMPARE_SIGNED(c, rc, <, 0);
	Do_ADBG_EndSubCase(c, "Test incorrect reclaim");

	/*RELINQUISH the memory area.*/
	Do_ADBG_BeginSubCase(c, "Test relinquish memory second time");
	memset(&args, 0, sizeof(args));
	args.args[MEM_SHARE_HANDLE_LOW_INDEX] = MEM_SHARE_HANDLE_LOW(handle);
	args.args[MEM_SHARE_HANDLE_HIGH_INDEX] = MEM_SHARE_HANDLE_HIGH(handle);
	rc = start_sp_test(endpoint1_id, EP_RELINQUISH, &args);
	ADBG_EXPECT_COMPARE_SIGNED(c, rc, ==, 0);
	ADBG_EXPECT_COMPARE_UNSIGNED(c, args.args[0], ==, SPMC_TEST_OK);
	check_alive(c, endpoint1_id);
	Do_ADBG_EndSubCase(c, "Test relinquish memory second time");

	/* Try to reclaim again this time it should work. */
	Do_ADBG_BeginSubCase(c, "Test correct reclaim");
	shm_desc.handle = handle;
	shm_desc.dst_id = endpoint1_id;
	rc = ioctl(ffa_fd, FFA_IOC_SHM_DEINIT, &shm_desc);
	ADBG_EXPECT_COMPARE_SIGNED(c, rc, >=, 0);
	check_alive(c, endpoint1_id);
	Do_ADBG_EndSubCase(c, "Test correct reclaim");

	/* SP will try to retrieve invalid memory region. */
	Do_ADBG_BeginSubCase(c, "Test retrieve invalid memory region");
	memset(&args, 0, sizeof(args));
	args.args[MEM_SHARE_HANDLE_LOW_INDEX] = MEM_SHARE_HANDLE_LOW(handle);
	args.args[MEM_SHARE_HANDLE_HIGH_INDEX] = MEM_SHARE_HANDLE_HIGH(handle);
	args.args[MEM_SHARE_HANDLE_ENDPOINT_INDEX] = NORMAL_WORLD_ENDPOINT_ID;
	rc = start_sp_test(endpoint1_id, EP_RETRIEVE, &args);
	ADBG_EXPECT_COMPARE_SIGNED(c, rc, ==, 0);
	ADBG_EXPECT_COMPARE_UNSIGNED(c, args.args[0], !=, SPMC_TEST_OK);
	check_alive(c, endpoint1_id);

	Do_ADBG_EndSubCase(c, "Test retrieve invalid memory region");
out:
	close_debugfs();
}

ADBG_CASE_DEFINE(ffa_spmc, 1002, xtest_ffa_spmc_test_1002,
		 "Test FF-A memory: share memory from Normal World to SP");

static void xtest_ffa_spmc_test_1003(ADBG_Case_t *c)
{
	struct ffa_ioctl_msg_args args = { 0 };
	uint16_t endpoint1 = 0;
	uint16_t endpoint2 = 0;
	int rc = 0;

	if (!init_sp_xtest(c)) {
		Do_ADBG_Log("Failed to initialise test, skipping SP test");
		goto out;
	}

	endpoint1 = get_endpoint_id(test_endpoint1.uuid_ptr);
	if (endpoint1 == INCORRECT_ENDPOINT_ID) {
		Do_ADBG_Log("Could not contact xtest_1 sp, skipping SP test");
		Do_ADBG_Log("Add xtest_1 sp to the image to enable tests");
		goto out;
	}

	/* Test SP to SP memory sharing. */
	endpoint2 = get_endpoint_id(test_endpoint2.uuid_ptr);
	if (endpoint2 == INCORRECT_ENDPOINT_ID) {
		Do_ADBG_Log("Could not contact xtest_2 sp, skipping SP test");
		Do_ADBG_Log("Add xtest_2 sp to the image to enable tests");
		goto out;
	}

	memset(&args, 0, sizeof(args));
	args.args[1] = endpoint2;
	rc = start_sp_test(endpoint1, EP_SP_MEM_SHARING, &args);
	ADBG_EXPECT_COMPARE_SIGNED(c, rc, ==, 0);
	ADBG_EXPECT_COMPARE_UNSIGNED(c, args.args[0], ==, SPMC_TEST_OK);

out:
	close_debugfs();
}

ADBG_CASE_DEFINE(ffa_spmc, 1003, xtest_ffa_spmc_test_1003,
		 "Test FF-A memory: SP to SP");

static void xtest_ffa_spmc_test_1004(ADBG_Case_t *c)
{
	struct ffa_ioctl_msg_args args = { 0 };
	uint16_t endpoint1 = 0;
	uint16_t endpoint2 = 0;
	int rc = 0;

	if (!init_sp_xtest(c)) {
		Do_ADBG_Log("Failed to initialise test, skipping SP test");
		goto out;
	}

	endpoint1 = get_endpoint_id(test_endpoint1.uuid_ptr);
	if (endpoint1 == INCORRECT_ENDPOINT_ID) {
		Do_ADBG_Log("Could not contact xtest_1 sp, skipping SP test");
		Do_ADBG_Log("Add xtest_1 sp to the image to enable tests");
		goto out;
	}

	/* Test SP to SP memory sharing. */
	endpoint2 = get_endpoint_id(test_endpoint2.uuid_ptr);
	if (endpoint2 == INCORRECT_ENDPOINT_ID) {
		Do_ADBG_Log("Could not contact xtest_2 sp, skipping SP test");
		Do_ADBG_Log("Add xtest_2 sp to the image to enable tests");
		goto out;
	}

	Do_ADBG_BeginSubCase(c, "Test sharing with exc access");
	memset(&args, 0, sizeof(args));
	args.args[1] = endpoint2;
	rc = start_sp_test(endpoint1, EP_SP_MEM_SHARING_EXC, &args);
	ADBG_EXPECT_COMPARE_SIGNED(c, rc, ==, 0);
	ADBG_EXPECT_COMPARE_UNSIGNED(c, args.args[0], ==, SPMC_TEST_OK);
	Do_ADBG_EndSubCase(c, "Test sharing with exc access");

	Do_ADBG_BeginSubCase(c, "Test sharing with incorrect access");
	memset(&args, 0, sizeof(args));
	args.args[1] = endpoint2;
	rc = start_sp_test(endpoint1, EP_SP_MEM_INCORRECT_ACCESS, &args);
	ADBG_EXPECT_COMPARE_SIGNED(c, rc, ==, 0);
	ADBG_EXPECT_COMPARE_UNSIGNED(c, args.args[0], ==, SPMC_TEST_OK);
	Do_ADBG_EndSubCase(c, "Test sharing with incorrect access");

out:
	close_debugfs();
}

ADBG_CASE_DEFINE(ffa_spmc, 1004, xtest_ffa_spmc_test_1004,
		 "Test FF-A memory: Access and flags");

static void xtest_ffa_spmc_test_1005(ADBG_Case_t *c)
{
	struct ffa_ioctl_msg_args args = { 0 };
	uint16_t endpoint1 = 0;
	uint16_t endpoint2 = 0;
	uint16_t endpoint3 = 0;
	int rc = 0;

	if (!init_sp_xtest(c)) {
		Do_ADBG_Log("Failed to initialise test, skipping SP test");
		goto out;
	}

	endpoint1 = get_endpoint_id(test_endpoint1.uuid_ptr);
	if (endpoint1 == INCORRECT_ENDPOINT_ID) {
		Do_ADBG_Log("Could not contact xtest_1 sp, skipping SP test");
		Do_ADBG_Log("Add xtest_1 sp to the image to enable tests");
		goto out;
	}

	endpoint2 = get_endpoint_id(test_endpoint2.uuid_ptr);
	if (endpoint2 == INCORRECT_ENDPOINT_ID) {
		Do_ADBG_Log("Could not contact xtest_2 sp, skipping SP test");
		Do_ADBG_Log("Add xtest_2 sp to the image to enable tests");
		goto out;
	}

	endpoint3 = get_endpoint_id(test_endpoint3.uuid_ptr);
	if (endpoint3 == INCORRECT_ENDPOINT_ID) {
		Do_ADBG_Log("Could not contact xtest_3 sp, skipping SP test");
		Do_ADBG_Log("Add xtest_3 sp to the image to enable tests");
		goto out;
	}

	memset(&args, 0, sizeof(args));
	args.args[1] = endpoint2;
	args.args[2] = endpoint3;
	rc = start_sp_test(endpoint1, EP_SP_MEM_SHARING_MULTI, &args);
	ADBG_EXPECT_COMPARE_SIGNED(c, rc, ==, 0);
	ADBG_EXPECT_COMPARE_UNSIGNED(c, args.args[0], ==, SPMC_TEST_OK);

out:
	close_debugfs();
}

ADBG_CASE_DEFINE(ffa_spmc, 1005, xtest_ffa_spmc_test_1005,
		 "Test FF-A memory: multiple receiver");

static void xtest_ffa_spmc_test_1006(ADBG_Case_t *c)
{
	struct ffa_ioctl_msg_args args = { .args = {0, 1, 2, 3, 4 }};
	uint16_t ep = 0;
	int rc = 0;

	if (!init_sp_xtest(c)) {
		Do_ADBG_Log("Failed to initialise test, skipping SP test");
		goto out;
	}

	ep = get_endpoint_id(test_lsp_endpoint.uuid_ptr);
	if (ep == INCORRECT_ENDPOINT_ID) {
		Do_ADBG_Log("Could not contact LSP, skipping LSP test");
		goto out;
	}

	Do_ADBG_BeginSubCase(c, "LSP direct request/response");
	args.dst_id = ep;
	rc = ioctl(ffa_fd, FFA_IOC_MSG_SEND, &args);
	if (ADBG_EXPECT_COMPARE_SIGNED(c, rc, ==, 0))
		ADBG_EXPECT_COMPARE_UNSIGNED(c, args.args[0], ==, 10);

	Do_ADBG_EndSubCase(c, "LSP direct request/response");
out:
	close_debugfs();
}
ADBG_CASE_DEFINE(ffa_spmc, 1006, xtest_ffa_spmc_test_1006, "Test FF-A LSP")
