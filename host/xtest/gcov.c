// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2020 NXP
 */
#include <string.h>

#include <adbg.h>
#include <pta_gcov.h>
#include <ta_gcov.h>
#include <tee_client_api.h>
#include <xtest_helpers.h>
#include <xtest_test.h>

struct gcov_dump_conf {
	const char *desc;
	TEEC_UUID *uuid;
	unsigned int cmd;
};


static void do_get_version_command(ADBG_Case_t *c, TEEC_UUID *uuid,
				   unsigned int cmd)
{
	TEEC_Session session = { };
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig = 0;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		xtest_teec_open_session(&session, uuid, NULL, &ret_orig)))
		return;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	(void)ADBG_EXPECT_TEEC_SUCCESS(c,
		TEEC_InvokeCommand(&session, cmd, &op, &ret_orig));

	ADBG_EXPECT_TRUE(c, (op.params[0].value.a != 0));

	TEEC_CloseSession(&session);
}

static void xtest_tee_test_31001(ADBG_Case_t *c)
{
	TEEC_UUID pta_uuid = PTA_GCOV_UUID;

	do_get_version_command(c, &pta_uuid, PTA_CMD_GCOV_GET_VERSION);
}

static void xtest_tee_test_31002(ADBG_Case_t *c)
{
	TEEC_UUID ta_uuid = TA_GCOV_UUID;

	do_get_version_command(c, &ta_uuid, TA_GCOV_CMD_GET_VERSION);
}

static void do_dump_command(ADBG_Case_t *c, const struct gcov_dump_conf *conf)
{
	TEEC_Session session = { };
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig = 0;

	ADBG_EXPECT_NOT_NULL(c, conf);

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		xtest_teec_open_session(&session, conf->uuid, NULL,
					&ret_orig)))
		return;

	op.params[0].tmpref.buffer = (char *)conf->desc;
	op.params[0].tmpref.size = strlen(conf->desc) + 1;
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	(void)ADBG_EXPECT_TEEC_SUCCESS(c,
		TEEC_InvokeCommand(&session, conf->cmd, &op, &ret_orig));

	TEEC_CloseSession(&session);
}

static void xtest_tee_test_31003(ADBG_Case_t *c)
{
	TEEC_UUID pta_uuid = PTA_GCOV_UUID;

	struct gcov_dump_conf conf = {"boot", &pta_uuid,
				      PTA_CMD_GCOV_CORE_DUMP_ALL};

	do_dump_command(c, &conf);
}

static void do_core_reset_command(ADBG_Case_t *c)
{
	TEEC_Session session = { };
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	TEEC_UUID pta_uuid = PTA_GCOV_UUID;
	uint32_t ret_orig = 0;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		xtest_teec_open_session(&session, &pta_uuid, NULL, &ret_orig)))
		return;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE,
					 TEEC_NONE);

	(void)ADBG_EXPECT_TEEC_SUCCESS(c,
		TEEC_InvokeCommand(&session, PTA_CMD_GCOV_CORE_RESET, &op,
				   &ret_orig));

	TEEC_CloseSession(&session);
}

static void xtest_tee_test_31004(ADBG_Case_t *c)
{
	do_core_reset_command(c);
}

/*
 * Add the test at the front of the test suite to capture the code coverage
 * of the test suite
 */
ADBG_CASE_DEFINE_FRONT(regression, 31004, xtest_tee_test_31004,
		       "Reset core code coverage data");

ADBG_CASE_DEFINE_FRONT(regression, 31003, xtest_tee_test_31003,
		       "Dump boot code coverage data of core");

ADBG_CASE_DEFINE_FRONT(regression, 31002, xtest_tee_test_31002,
		       "Get version of code coverage data for TA");

ADBG_CASE_DEFINE_FRONT(regression, 31001, xtest_tee_test_31001,
		       "Get version of code coverage data for the core");

static void xtest_tee_test_31005(ADBG_Case_t *c)
{
	long unsigned int i = 0;
	TEEC_UUID ta_uuid = TA_GCOV_UUID;
	TEEC_UUID pta_uuid = PTA_GCOV_UUID;

	struct gcov_dump_conf list_conf[] = {
		{"xtest_core_from_ca", &pta_uuid, PTA_CMD_GCOV_CORE_DUMP_ALL},
		{"xtest_core_from_ta", &ta_uuid, TA_GCOV_CMD_DUMP_CORE},
		{"xtest_ta_from_ta", &ta_uuid, TA_GCOV_CMD_DUMP_TA},
	};

	for (i = 0; i < sizeof(list_conf) / sizeof(list_conf[0]); i++) {
		struct gcov_dump_conf *conf = &list_conf[i];

		Do_ADBG_BeginSubCase(c, "Dump %s", conf->desc);

		/* TODO delete the folder in FS */

		do_dump_command(c, conf);

		/* TODO check the folder is created in FS with files */

		Do_ADBG_EndSubCase(c, "Dump %s", conf->desc);
	}
}
ADBG_CASE_DEFINE(regression, 31005, xtest_tee_test_31005,
		 "Dump code coverage data of xtest");
