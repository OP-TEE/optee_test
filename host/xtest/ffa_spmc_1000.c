// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2022, Arm Limited and Contributors. All rights reserved.
 */
#include <fcntl.h>
#include <ffa.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include "include/uapi/linux/arm_ffa_user.h"
#include "xtest_helpers.h"
#include "xtest_test.h"

#define FFA_DRIVER_FS_PATH	"/sys/kernel/debug/arm_ffa_user"
#define SPMC_TEST_OK 0xaa

enum sp_tests {
	EP_TEST_SP,
	EP_TEST_SP_COMMUNICATION,
};

static int ffa_fd = -1;

static const char test_endpoint1_uuid[] =
	"5c9edbc3-7b3a-4367-9f83-7c191ae86a37";
static const char test_endpoint2_uuid[] =
	"7817164c-c40c-4d1a-867a-9bb2278cf41a";
static const char test_endpoint3_uuid[] =
	"23eb0100-e32a-4497-9052-2f11e584afa6";

static struct ffa_ioctl_ep_desc test_endpoint1 = {
	.uuid_ptr = (uint64_t) test_endpoint1_uuid,
};

static struct ffa_ioctl_ep_desc test_endpoint2 = {
	.uuid_ptr = (uint64_t) test_endpoint2_uuid,
};

static struct ffa_ioctl_ep_desc test_endpoint3 = {
	.uuid_ptr = (uint64_t) test_endpoint3_uuid,
};

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
	args->args[0] = (uint32_t)test;
	return ioctl(ffa_fd, FFA_IOC_MSG_SEND, args);
}

static uint16_t get_endpoint_id(uint64_t endp)
{
	struct ffa_ioctl_ep_desc sid = { .uuid_ptr = endp };

	/* Get ID of destination SP based on UUID */
	if(ioctl(ffa_fd, FFA_IOC_GET_PART_ID, &sid))
		return 0xffff;

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
	if (endpoint1_id == 0xffff) {
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
	if (endpoint2_id == 0xffff) {
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
