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

#ifndef STORAGE_H
#define STORAGE_H

#include <tee_api.h>

TEE_Result ta_storage_cmd_open(uint32_t command, uint32_t param_types,
						 TEE_Param params[4]);
TEE_Result ta_storage_cmd_create(uint32_t command, uint32_t param_types,
						   TEE_Param params[4]);
TEE_Result ta_storage_cmd_create_overwrite(uint32_t command,
					   uint32_t param_types,
					   TEE_Param params[4]);
TEE_Result ta_storage_cmd_close(uint32_t param_types, TEE_Param params[4]);
TEE_Result ta_storage_cmd_read(uint32_t param_types, TEE_Param params[4]);
TEE_Result ta_storage_cmd_write(uint32_t param_types, TEE_Param params[4]);
TEE_Result ta_storage_cmd_seek(uint32_t param_types, TEE_Param params[4]);
TEE_Result ta_storage_cmd_unlink(uint32_t param_types, TEE_Param params[4]);
TEE_Result ta_storage_cmd_rename(uint32_t command, uint32_t param_types,
						   TEE_Param params[4]);
TEE_Result ta_storage_cmd_trunc(uint32_t param_types, TEE_Param params[4]);
TEE_Result ta_storage_cmd_alloc_enum(uint32_t param_types, TEE_Param params[4]);
TEE_Result ta_storage_cmd_free_enum(uint32_t param_types, TEE_Param params[4]);
TEE_Result ta_storage_cmd_reset_enum(uint32_t param_types, TEE_Param params[4]);
TEE_Result ta_storage_cmd_start_enum(uint32_t param_types, TEE_Param params[4]);
TEE_Result ta_storage_cmd_next_enum(uint32_t param_types, TEE_Param params[4]);
TEE_Result ta_storage_cmd_key_in_persistent(uint32_t param_types,
					    TEE_Param params[4]);
TEE_Result ta_storage_cmd_loop(uint32_t param_types, TEE_Param params[4]);
TEE_Result ta_storage_cmd_restrict_usage(uint32_t param_types,
					 TEE_Param params[4]);
TEE_Result ta_storage_cmd_alloc_obj(uint32_t param_types, TEE_Param params[4]);
TEE_Result ta_storage_cmd_free_obj(uint32_t param_types, TEE_Param params[4]);
TEE_Result ta_storage_cmd_reset_obj(uint32_t param_types, TEE_Param params[4]);
TEE_Result ta_storage_cmd_get_obj_info(uint32_t param_types,
					    TEE_Param params[4]);

#endif /*STORAGE_H */
