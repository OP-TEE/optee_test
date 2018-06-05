/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
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

#ifndef OS_TEST_H
#define OS_TEST_H

#include <tee_api.h>

TEE_Result ta_entry_basic(uint32_t param_types, TEE_Param params[4]);
TEE_Result ta_entry_client_with_timeout(uint32_t param_types,
					TEE_Param params[4]);
TEE_Result ta_entry_panic(uint32_t param_types, TEE_Param params[4]);
TEE_Result ta_entry_client(uint32_t param_types, TEE_Param params[4]);
TEE_Result ta_entry_params_access_rights(uint32_t p_types, TEE_Param params[4]);
TEE_Result ta_entry_wait(uint32_t param_types, TEE_Param params[4]);
TEE_Result ta_entry_bad_mem_access(uint32_t param_types, TEE_Param params[4]);
TEE_Result ta_entry_ta2ta_memref(uint32_t param_types, TEE_Param params[4]);
TEE_Result ta_entry_ta2ta_memref_mix(uint32_t param_types,
				     TEE_Param params[4]);
TEE_Result ta_entry_params(uint32_t param_types, TEE_Param params[4]);
TEE_Result ta_entry_call_lib(uint32_t param_types, TEE_Param params[4]);
TEE_Result ta_entry_call_lib_panic(uint32_t param_types, TEE_Param params[4]);

#endif /*OS_TEST_H */
