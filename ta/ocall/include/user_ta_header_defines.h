// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2020, Microsoft Corporation
 */

#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

#include <ta_ocall_test.h>
#include <user_ta_header.h>

#define TA_UUID		TA_OCALL_UUID

#define TA_FLAGS	(TA_FLAG_SINGLE_INSTANCE | \
			 TA_FLAG_MULTI_SESSION | \
			 TA_FLAG_INSTANCE_KEEP_ALIVE)

#define TA_STACK_SIZE	(4 * 1024)
#define TA_DATA_SIZE	(64 * 1024)

#endif /* USER_TA_HEADER_DEFINES_H */
