/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 */

#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

#include <ta_concurrent.h>
#include <user_ta_header.h>

#define TA_UUID TA_CONCURRENT_UUID

#define TA_FLAGS ( TA_FLAG_EXEC_DDR | TA_FLAG_MULTI_SESSION)
#define TA_STACK_SIZE (2 * 1024)
#define TA_DATA_SIZE (32 * 1024)

#endif /*USER_TA_HEADER_DEFINES_H*/
