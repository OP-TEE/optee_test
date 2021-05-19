/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2021, Linaro Limited
 */

#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

#include <ta_large.h>
#include <user_ta_header.h>

#define TA_UUID TA_LARGE_UUID

#define TA_FLAGS	(TA_FLAG_MULTI_SESSION)
#define TA_STACK_SIZE	(2 * 1024)
#define TA_DATA_SIZE	(2 * 1024)

#endif /*USER_TA_HEADER_DEFINES_H*/
