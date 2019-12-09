/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2019 Huawei Technologies Co., Ltd
 */

#ifndef SM4_TAF_H
#define SM4_TAF_H

#include <tee_api.h>

TEE_Result ta_entry_sm4(uint32_t param_type, TEE_Param params[4]);

#endif /* SM4_TAF_H */
