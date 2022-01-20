/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2022, Linaro Limited
 * All rights reserved.
 */

#ifndef TA_ARM_PAUTH_PRIVATE_H
#define TA_ARM_PAUTH_PRIVATE_H

#include <tee_api.h>

void corrupt_pac(void);
TEE_Result test_nop(void);

#endif /* TA_ARM_PAUTH_PRIVATE_H */
