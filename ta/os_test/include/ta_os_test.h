/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * All rights reserved.
 */

#ifndef TA_OS_TEST_H
#define TA_OS_TEST_H

/* This UUID is generated with the ITU-T UUID generator at
   http://www.itu.int/ITU-T/asn1/uuid.html */
#define TA_OS_TEST_UUID { 0x5b9e0e40, 0x2636, 0x11e1, \
	{ 0xad, 0x9e, 0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b } }

#define TA_OS_TEST_CMD_INIT                 0
#define TA_OS_TEST_CMD_CLIENT_WITH_TIMEOUT  1
#define TA_OS_TEST_CMD_BASIC                5
#define TA_OS_TEST_CMD_PANIC                6
#define TA_OS_TEST_CMD_CLIENT               7
#define TA_OS_TEST_CMD_PARAMS_ACCESS        8
#define TA_OS_TEST_CMD_WAIT                 9
#define TA_OS_TEST_CMD_BAD_MEM_ACCESS       10
#define TA_OS_TEST_CMD_TA2TA_MEMREF         11
#define TA_OS_TEST_CMD_TA2TA_MEMREF_MIX     12
#define TA_OS_TEST_CMD_PARAMS               13
#define TA_OS_TEST_CMD_CALL_LIB             14
#define TA_OS_TEST_CMD_CALL_LIB_PANIC       15
#define TA_OS_TEST_CMD_CALL_LIB_DL          16
#define TA_OS_TEST_CMD_CALL_LIB_DL_PANIC    17
#define TA_OS_TEST_CMD_GET_GLOBAL_VAR       18
#define TA_OS_TEST_CMD_NULL_MEMREF_PARAMS   19
#define TA_OS_TEST_CMD_CLIENT_IDENTITY      20
#define TA_OS_TEST_CMD_TLS_TEST_MAIN        21
#define TA_OS_TEST_CMD_TLS_TEST_SHLIB       22
#define TA_OS_TEST_CMD_DL_PHDR              23
#define TA_OS_TEST_CMD_DL_PHDR_DL           24
#define TA_OS_TEST_CMD_CXX_CTOR_MAIN        25
#define TA_OS_TEST_CMD_CXX_CTOR_SHLIB       26
#define TA_OS_TEST_CMD_CXX_CTOR_SHLIB_DL    27
#define TA_OS_TEST_CMD_CXX_EXC_MAIN         28
#define TA_OS_TEST_CMD_CXX_EXC_MIXED        29
#define TA_OS_TEST_CMD_PAUTH_NOP            30
#define TA_OS_TEST_CMD_PAUTH_CORRUPT_PAC    31
#define TA_OS_TEST_CMD_ATTESTATION          32
#define TA_OS_TEST_CMD_MEMTAG_USE_AFTER_FREE 33
#define TA_OS_TEST_CMD_MEMTAG_INVALID_TAG   34
#define TA_OS_TEST_CMD_MEMTAG_DOUBLE_FREE   35
#define TA_OS_TEST_CMD_MEMTAG_BUFFER_OVERRUN 36
#define TA_OS_TEST_CMD_TA2TA_MEMREF_SIZE0   37
#define TA_OS_TEST_CMD_ASAN_STACK           38
#define TA_OS_TEST_CMD_ASAN_GLOBAL          39
#define TA_OS_TEST_CMD_ASAN_MALLOC          40
#define TA_OS_TEST_CMD_ASAN_UAF             41
#define TA_OS_TEST_CMD_ASAN_MEMFUNC         42
#define TA_OS_TEST_CMD_RISCV_FP_CONTEXT     43

/*
 * Sub-tests of TA_OS_TEST_CMD_RISCV_FP_CONTEXT, selected with
 * params[0].value.a. params[0].value.b carries a seed which picks the
 * register pattern, so that one invocation can be told apart from another.
 * On failure params[1].value.a holds the index of the first field that did
 * not survive, 0..11 for fs0..fs11 and 12 for fcsr.
 */

/* Return immediately without touching the floating-point unit */
#define TA_RISCV_FP_SUBTEST_NO_FP	0
/* Check the context survives a syscall that stays inside the TEE */
#define TA_RISCV_FP_SUBTEST_SYSCALL	1
/* Check the context survives an RPC out to the normal world */
#define TA_RISCV_FP_SUBTEST_RPC		2
/* Check the context survives a crypto operation carried out by the TEE */
#define TA_RISCV_FP_SUBTEST_CRYPTO	3
/* Leave the pattern in the registers and return */
#define TA_RISCV_FP_SUBTEST_TAINT	4
/* Fail if the registers still hold the pattern left by an earlier TA */
#define TA_RISCV_FP_SUBTEST_CHECK_TAINT	5

#endif /*TA_OS_TEST_H */
