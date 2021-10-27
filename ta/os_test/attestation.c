// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021, Huawei Technologies Co., Ltd
 */
#include <pta_attestation.h>
#include <ta_os_test.h>
#include <tee_internal_api.h>

#include "os_test.h"

TEE_Result ta_entry_attestation(uint32_t param_types, TEE_Param params[4])
{
	TEE_TASessionHandle sess = TEE_HANDLE_NULL;
	TEE_UUID att_uuid = PTA_ATTESTATION_UUID;
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t ret_orig = 0;

	res = TEE_OpenTASession(&att_uuid, TEE_TIMEOUT_INFINITE, 0, NULL, &sess,
				&ret_orig);
	if (res)
		goto out;
	res = TEE_InvokeTACommand(sess, TEE_TIMEOUT_INFINITE,
				  PTA_ATTESTATION_HASH_TA_MEMORY, param_types,
				  params, &ret_orig);
out:
	TEE_CloseTASession(sess);
	return res;
}
