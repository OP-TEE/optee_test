/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026, Jaehun Lee */
#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

#include <core_fuzz_ta.h>

#define TA_UUID CORE_FUZZ_TA_UUID
#define TA_FLAGS 0
#define TA_STACK_SIZE (16 * 1024)
#define TA_DATA_SIZE (32 * 1024)
#define TA_VERSION "0.1"
#define TA_DESCRIPTION "Core crypto coverage demo TA"

#endif /* USER_TA_HEADER_DEFINES_H */
