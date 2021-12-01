/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2021, Linaro Limited
 * All rights reserved.
 */

#ifndef TA_ARM_BTI_PRIVATE_H
#define TA_ARM_BTI_PRIVATE_H

#include <tee_api.h>

TEE_Result test_bti(uint32_t nCommandID, uint32_t nParamTypes,
		    TEE_Param pParams[4]);

#endif /* TA_ARM_BTI_PRIVATE_H */
