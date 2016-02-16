/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

#include <stdint.h>
#include <ta_os_test.h>
#include <user_ta_header.h>

#define TA_UUID TA_OS_TEST_UUID

#define TA_FLAGS (TA_FLAG_USER_MODE | TA_FLAG_EXEC_DDR | \
		  TA_FLAG_UNSAFE_NW_PARAMS | \
		  TA_FLAG_MULTI_SESSION)
#define TA_STACK_SIZE (8 * 1024)
#define TA_DATA_SIZE (900 * 1024)

#define TA_CURRENT_TA_EXT_PROPERTIES \
	{ "myprop.true", USER_TA_PROP_TYPE_BOOL, &(const bool){ true } }, \
	{ "myprop.42",   USER_TA_PROP_TYPE_U32,  &(const uint32_t){ 42 } }, \
	{ "myprop.123",  USER_TA_PROP_TYPE_UUID, \
		&(const TEE_UUID) {1, 2, 3 } }, \
	{ "myprop.1234", USER_TA_PROP_TYPE_IDENTITY, \
		&(const TEE_Identity) { 1, { 2, 3, 4 } } }, \
	{ "myprop.hello", USER_TA_PROP_TYPE_STRING, \
		"hello property, larger than 80 characters, so that it checks that it is not truncated by anything in the source code which may be wrong" }, \
	{ "myprop.binaryblock", USER_TA_PROP_TYPE_BINARY_BLOCK, \
	   "SGVsbG8gd29ybGQh" },
#endif
