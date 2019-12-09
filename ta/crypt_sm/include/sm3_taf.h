/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2019 Huawei Technologies Co., Ltd
 */

#ifndef SM3_TAF_H
#define SM3_TAF_H

#include <tee_api.h>

TEE_Result ta_entry_sm3(uint32_t param_type, TEE_Param params[4]);

#endif /* SM3_TAF_H */
