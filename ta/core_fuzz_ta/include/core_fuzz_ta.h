/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026, Jaehun Lee */
#ifndef CORE_FUZZ_TA_H
#define CORE_FUZZ_TA_H

/* Input: "CFZ1", count, then count [opcode, slot, length LE16, data]. */
/* AES_ALLOC data is a 16-byte key; AES_INIT data is a 16-byte IV. */
/* RUN returns core coverage in param 1 and step counts/status in param 2. */
#define CORE_FUZZ_TA_UUID { 0x92ea581c, 0xd6ec, 0x449e, \
	{ 0x9a, 0xa6, 0xcf, 0x93, 0xaa, 0x2b, 0x44, 0xdd } }
#define CORE_FUZZ_TA_CMD_RUN 0
#define CORE_FUZZ_TA_MAGIC "CFZ1"
#define CORE_FUZZ_TA_MAGIC_SIZE 4
#define CORE_FUZZ_TA_HEADER_SIZE 5
#define CORE_FUZZ_TA_RECORD_HEADER_SIZE 4
#define CORE_FUZZ_TA_MAX_INPUT 1024
#define CORE_FUZZ_TA_MAX_RECORDS 16
#define CORE_FUZZ_TA_MAX_PAYLOAD 256
#define CORE_FUZZ_TA_SLOTS 4
#define CORE_FUZZ_TA_COVERAGE_SIZE (16 * 1024)

#define CORE_FUZZ_OP_DIGEST_ALLOC 0
#define CORE_FUZZ_OP_DIGEST_UPDATE 1
#define CORE_FUZZ_OP_DIGEST_FINAL 2
#define CORE_FUZZ_OP_AES_ALLOC 3
#define CORE_FUZZ_OP_AES_INIT 4
#define CORE_FUZZ_OP_AES_UPDATE 5
#define CORE_FUZZ_OP_FREE 6

#endif /* CORE_FUZZ_TA_H */
