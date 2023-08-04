/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 */

#ifndef TA_ASYM_CIPHER_PERF_PRIV_H
#define TA_ASYM_CIPHER_PERF_PRIV_H

#include <tee_api.h>

TEE_Result cmd_process_keypair(uint32_t param_types, TEE_Param params[4]);
TEE_Result cmd_process_rsa_ecc(uint32_t param_types, TEE_Param params[4]);

TEE_Result cmd_prepare_obj(uint32_t param_types, TEE_Param params[4]);
TEE_Result cmd_prepare_keypair(uint32_t param_types, TEE_Param params[4]);
TEE_Result cmd_prepare_hash(uint32_t param_types, TEE_Param params[4]);
TEE_Result cmd_prepare_enc_sign(uint32_t param_types, TEE_Param params[4]);
void cmd_clean_op(void);
void cmd_clean_obj(void);
#endif /* TA_ASYM_CIPHER_PERF_PRIV_H*/
