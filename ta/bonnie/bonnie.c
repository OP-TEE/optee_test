/*
 * Copyright (c) 2015, Linaro Limited
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

#include <tee_api.h>
#include "include/bonnie.h"

#define ASSERT_PARAM_TYPE(pt_in, pt_expect) \
do { \
	if ((pt_in) != (pt_expect)) \
		return TEE_ERROR_BAD_PARAMETERS; \
} while (0)


TEE_Result ta_bonnie_cmd_test_putc(__unused uint32_t param_types,
		__unused TEE_Param params[4])
{
	//TODO: implement it
	return TEE_SUCCESS;
}

TEE_Result ta_bonnie_cmd_test_rewrite(__unused uint32_t param_types,
		__unused TEE_Param params[4])
{
	//TODO: implement it
	return TEE_SUCCESS;
}

TEE_Result ta_bonnie_cmd_test_fastwrite(__unused uint32_t param_types,
		__unused TEE_Param params[4])
{
	//TODO: implement it
	return TEE_SUCCESS;
}

TEE_Result ta_bonnie_cmd_test_getc(__unused uint32_t param_types,
		__unused TEE_Param params[4])
{
	//TODO: implement it
	return TEE_SUCCESS;
}

TEE_Result ta_bonnie_cmd_test_fastread(__unused uint32_t param_types,
		__unused TEE_Param params[4])
{
	//TODO: implement it
	return TEE_SUCCESS;
}

TEE_Result ta_bonnie_cmd_test_lseek(__unused uint32_t param_types,
		__unused TEE_Param params[4])
{
	//TODO: implement it
	return TEE_SUCCESS;
}

