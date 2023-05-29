// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2023, Linaro Limited
 */

#include <err.h>
#include <ta_storage.h>
#include <tee_client_api.h>
#include <stdlib.h>
#include <util.h>

#include "clear_storage.h"

static int clear_storage_for_ta(TEEC_UUID *uuid)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Context ctx = { };
	TEEC_Session sess = { };
	TEEC_Operation op = { };
	uint32_t eo = 0;

	res = TEEC_InitializeContext(NULL, &ctx);
	if (res)
		errx(EXIT_FAILURE, "TEEC_InitializeContext: %#"PRIx32, res);

	res = TEEC_OpenSession(&ctx, &sess, uuid, TEEC_LOGIN_PUBLIC, NULL,
			       NULL, &eo);
	if (res)
		errx(EXIT_FAILURE,
		     "TEEC_OpenSession: res %#"PRIx32" err_orig %#"PRIx32,
			res, eo);

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE,
					 TEEC_NONE);
	res = TEEC_InvokeCommand(&sess, TA_STORAGE_CMD_CLEAR_STORAGE, &op, &eo);
	if (res)
		errx(EXIT_FAILURE,
		     "TEEC_InvokeCommand: res %#"PRIx32" err_orig %#"PRIx32,
		     res, eo);

	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);
	return 0;
}

int clear_storage(void)
{
	TEEC_UUID uuid[] = { TA_STORAGE_UUID, TA_STORAGE2_UUID };
	size_t i = 0;
	int res = 0;

	for (i = 0; i < ARRAY_SIZE(uuid); i++) {
		res = clear_storage_for_ta(uuid + i);
		if (res)
			break;
	}
	return res;
}
