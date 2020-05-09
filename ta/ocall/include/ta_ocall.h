// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2020, Microsoft Corporation
 */

#ifndef TA_OCALL_H
#define TA_OCALL_H

#include <tee_api.h>

extern bool g_close_session_entry_point_called;
extern bool g_test_premature_context_finalize_during_session_open_ocall_ok;

TEE_Result test_no_ecall_params_no_ocall_params(uint32_t param_types);
TEE_Result test_no_ecall_params_ocall_value_params(uint32_t param_types);
TEE_Result test_no_ecall_params_ocall_memref_params(uint32_t param_types);
TEE_Result test_null_memref_params(uint32_t param_types);
TEE_Result test_null_memref_params_mixed(uint32_t param_types);
TEE_Result test_null_memref_params_invalid(uint32_t param_types);
TEE_Result test_premature_session_close(uint32_t param_types);
TEE_Result get_premature_session_close_status(uint32_t param_types);
TEE_Result test_premature_context_finalize(uint32_t param_types);
TEE_Result get_premature_context_finalize_status(uint32_t param_types);
TEE_Result get_premature_context_finalize_during_session_open_ocall_status(uint32_t param_types);

#endif /* TA_OCALL_H */
