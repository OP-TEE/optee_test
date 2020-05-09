// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2020, Microsoft Corporation
 */

#ifndef TA_OCALL_DATA_H
#define TA_OCALL_DATA_H

/*
 * Test values (in/out specified from the TA's point of view)
 */

static const uint32_t ocall_test_val1_in_a = 0;
static const uint32_t ocall_test_val1_in_b = 0xffffffff;

static const uint32_t ocall_test_val2_in_a = 0xacd0281f;
static const uint32_t ocall_test_val2_in_b = 104826;

static const uint32_t ocall_test_val2_out_a = 9;
static const uint32_t ocall_test_val2_out_b = 0x98f5d1ce;

static const uint32_t ocall_test_val3_out_a = 0x71fae3db;
static const uint32_t ocall_test_val3_out_b = 10394;

static const uint32_t ocall_test_val4_in_a = 0xfffffffe;
static const uint32_t ocall_test_val4_in_b = 1;

static const uint32_t ocall_test_val5_out_a = 0xfd185;
static const uint32_t ocall_test_val5_out_b = 0;

/*
 * Test buffers (in/out specified from the TA's point of view)
 */

/* 1 byte */
static const char ocall_test_buf1_in[] = { 0xe3 };

/* 8 bytes */
static const char ocall_test_buf2_in[] = {
	0x5a, 0xc9, 0x5f, 0x4a, 0x79, 0x39, 0x88, 0xb8
};
static const char ocall_test_buf2_out[] = {
	0x37, 0x52, 0x26, 0xab, 0x57, 0x9f, 0xc9, 0xd1
};

/* 16 bytes */
static const char ocall_test_buf3_out[] = {
	0x03, 0x63, 0x23, 0xc2, 0x80, 0x5c, 0x5b, 0xd6,
	0xcf, 0xaf, 0xfd, 0x7c, 0x2f, 0x4d, 0xcf, 0x47,
};

/* 32 bytes */
static const char ocall_test_buf4_in[] = {
	0xc8, 0x62, 0x93, 0x9b, 0x37, 0xd5, 0x3a, 0xd9,
	0x65, 0xb1, 0xea, 0x36, 0x97, 0x7d, 0x36, 0x30,
	0xff, 0x94, 0x00, 0xa3, 0xc1, 0x59, 0x7f, 0x34,
	0x47, 0x5d, 0x8e, 0x77, 0xe8, 0x2a, 0x83, 0x06,
};

#endif /* TA_OCALL_DATA_H */
