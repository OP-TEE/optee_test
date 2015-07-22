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

#include "testframework.h"

#define ADD(s, t, r)                          \
do {                                          \
	TEE_BigIntConvertFromString(a, (s));  \
	TEE_BigIntConvertFromString(b, (t));  \
	TEE_BigIntAdd(c, a, b);               \
	TB_ASSERT_HEX_PRINT_VALUE(c, (r));    \
	TEE_BigIntAdd(a, a, b);               \
	TB_ASSERT_HEX_PRINT_VALUE(a, (r));    \
	TEE_BigIntSub(a, a, b);               \
	TEE_BigIntAdd(b, a, b);               \
	TB_ASSERT_HEX_PRINT_VALUE(b, (r));    \
} while (0)

#define ADDWORD(s, t, r)                                \
do {                                                    \
	TEE_BigIntConvertFromString(a, (s));            \
	mpa_add_word((mpanum)b, (mpanum)a, t, mempool); \
	TB_ASSERT_HEX_PRINT_VALUE(b, (r));              \
} while (0)

#define SUB(r, t, s)                          \
do {                                          \
	TEE_BigIntConvertFromString(a, (s));  \
	TEE_BigIntConvertFromString(b, (t));  \
	TEE_BigIntSub(c, a, b);               \
	TB_ASSERT_HEX_PRINT_VALUE(c, (r));    \
	TEE_BigIntSub(a, a, b);               \
	TB_ASSERT_HEX_PRINT_VALUE(a, (r));    \
	TEE_BigIntAdd(a, a, b);               \
	TEE_BigIntSub(b, a, b);               \
	TB_ASSERT_HEX_PRINT_VALUE(b, (r));    \
} while (0)

#define SUBWORD(r, t, s)                                \
do {                                                    \
	TEE_BigIntConvertFromString(a, (s));            \
	mpa_sub_word((mpanum)b, (mpanum)a, t, mempool); \
	TB_ASSERT_HEX_PRINT_VALUE(b, (r));              \
} while (0)

#define NEG(s, r)                              \
do {                                           \
	TEE_BigIntConvertFromString(a, (s));   \
	TEE_BigIntNeg(b, a);                   \
	TB_ASSERT_HEX_PRINT_VALUE(b, (r));     \
	TEE_BigIntConvertFromString(c, (r));   \
	TEE_BigIntNeg(c, c);                   \
	TB_ASSERT_HEX_PRINT_VALUE(c, (s));     \
} while (0)

void tb_addsub(void)
{
	const char *TEST_NAME = "Addition and Subtraction";

	TB_HEADER(TEST_NAME);
	DEF_BIGINT(a, 1024);
	DEF_BIGINT(b, 1024);
	DEF_BIGINT(c, 1024);

	TB_INFO("Testing basic cases");
	ADD("1", "1", "2");
	SUB("1", "1", "2");
	ADD("-1", "1", "0");
	SUB("-1", "1", "0");
	ADD("0", "0", "0");
	SUB("0", "0", "0");
	ADD("0", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
	    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
	SUB("0", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
	    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");

	TB_INFO("Both ops positive");

	/* single word, no carry */
	ADD("FF", "FF", "1FE");
	SUB("FF", "FF", "1FE");

	/* single word, with carry */
	ADD("FFFFFFFF", "FFFFFFFF", "1FFFFFFFE");
	SUB("FFFFFFFF", "FFFFFFFF", "1FFFFFFFE");

	/* mult word with partial carry */
	ADD("FFFFFFFF", "100000000FFFFFFFFFFFFFFFF",
	    "10000000100000000FFFFFFFE");
	SUB("FFFFFFFF", "100000000FFFFFFFFFFFFFFFF",
	    "10000000100000000FFFFFFFE");

	/* mult word with carry all the way */
	ADD("FFFFFFFFFFFFFFFF", "FFFFFFFFFFFFFFFF", "1FFFFFFFFFFFFFFFE");
	SUB("FFFFFFFFFFFFFFFF", "FFFFFFFFFFFFFFFF", "1FFFFFFFFFFFFFFFE");

	TB_INFO("Both ops negative");
	/* single word, no carry */
	ADD("-FF", "-FF", "-1FE");
	SUB("-FF", "-FF", "-1FE");

	/* single word, with carry */
	ADD("-FFFFFFFF", "-FFFFFFFF", "-1FFFFFFFE");
	SUB("-FFFFFFFF", "-FFFFFFFF", "-1FFFFFFFE");

	/* mult word with partial carry */
	ADD("-FFFFFFFF", "-100000000FFFFFFFFFFFFFFFF",
	    "-10000000100000000FFFFFFFE");
	SUB("-FFFFFFFF", "-100000000FFFFFFFFFFFFFFFF",
	    "-10000000100000000FFFFFFFE");

	/* mult word with carry */
	ADD("-FFFFFFFFFFFFFFFF", "-FFFFFFFFFFFFFFFF", "-1FFFFFFFFFFFFFFFE");
	SUB("-FFFFFFFFFFFFFFFF", "-FFFFFFFFFFFFFFFF", "-1FFFFFFFFFFFFFFFE");

	TB_INFO("Op1 positive, op2 negative, |op1| > |op2|");
	/* single word, no carry */
	ADD("FFFF", "-FF", "FF00");
	SUB("FFFF", "-FF", "FF00");

	/* single word, with carry */
	ADD("F00000000", "-00000FFFF", "EFFFF0001");
	SUB("F00000000", "-00000FFFF", "EFFFF0001");

	/* multi words with carry */
	ADD("FFFFFFFF00000000", "-FFFFFFFF", "FFFFFFFE00000001");
	SUB("FFFFFFFF00000000", "-FFFFFFFF", "FFFFFFFE00000001");
	ADD("10000000FFFFFFFF00000000", "-FFFFFFFF",
	    "10000000FFFFFFFE00000001");
	SUB("10000000FFFFFFFF00000000", "-FFFFFFFF",
	    "10000000FFFFFFFE00000001");
	ADD("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
	    "-FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE", "1");
	SUB("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
	    "-FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE", "1");

	TB_INFO("Op1 positive, op2 negative, |op1| < |op2|");
	ADD("FF", "-FFFF", "-FF00");
	SUB("FF", "-FFFF", "-FF00");
	ADD("FFFFFFFF", "-1FFFFFFFF", "-100000000");
	SUB("FFFFFFFF", "-1FFFFFFFF", "-100000000");

	TB_INFO("Op1 negative, op2 positive, |op1| > |op2|");
	/* single word, no carry */
	ADD("-FFFF", "FF", "-FF00");
	SUB("-FFFF", "FF", "-FF00");

	/* single word, with carry */
	ADD("-F00000000", "00000FFFF", "-EFFFF0001");
	SUB("-F00000000", "00000FFFF", "-EFFFF0001");

	/* multi words with carry */
	ADD("-FFFFFFFF00000000", "FFFFFFFF", "-FFFFFFFE00000001");
	SUB("-FFFFFFFF00000000", "FFFFFFFF", "-FFFFFFFE00000001");
	ADD("-10000000FFFFFFFF00000000", "FFFFFFFF",
	    "-10000000FFFFFFFE00000001");
	SUB("-10000000FFFFFFFF00000000", "FFFFFFFF",
	    "-10000000FFFFFFFE00000001");
	ADD("-FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
	    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE", "-1");
	SUB("-FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
	    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE", "-1");

	TB_INFO("Op1 negative, op2 positive, |op1| < |op2|");
	ADD("-FF", "FFFF", "FF00");
	SUB("-FF", "FFFF", "FF00");
	ADD("-FFFFFFFF", "1FFFFFFFF", "100000000");
	SUB("-FFFFFFFF", "1FFFFFFFF", "100000000");

	TB_INFO("Testing AddWord and SubWord ");
	ADDWORD("0", 0, "0");
	SUBWORD("0", 0, "0");
	ADDWORD("-1", 1, "0");
	SUBWORD("-1", 1, "0");
	ADDWORD("0", 0xffffffff, "FFFFFFFF");
	SUBWORD("0", 0xffffffff, "FFFFFFFF");
	ADDWORD("FFFFFFFFFFFFFFFF", 1, "10000000000000000");
	SUBWORD("FFFFFFFFFFFFFFFF", 1, "10000000000000000");
	ADDWORD("100000000FFFFFFFF", 1, "10000000100000000");
	SUBWORD("100000000FFFFFFFF", 1, "10000000100000000");
	ADDWORD("-FFFFFFFFFFFFFFFF", 1, "-FFFFFFFFFFFFFFFE");
	SUBWORD("-FFFFFFFFFFFFFFFF", 1, "-FFFFFFFFFFFFFFFE");
	ADDWORD("-100000000FFFFFFFF", 1, "-100000000FFFFFFFE");
	SUBWORD("-100000000FFFFFFFF", 1, "-100000000FFFFFFFE");
	ADDWORD("1", 0xffffffff, "100000000");
	SUBWORD("1", 0xffffffff, "100000000");
	ADDWORD("-1", 0xffffffff, "FFFFFFFE");
	SUBWORD("-1", 0xffffffff, "FFFFFFFE");
	ADDWORD("100", 0x10, "110");
	SUBWORD("100", 0x10, "110");

	TB_INFO("Testing Neg");
	NEG("0", "0");
	NEG("1", "-1");
	NEG("123", "-123");
	NEG("123456789123456789", "-123456789123456789");

	DEL_BIGINT(a);
	DEL_BIGINT(b);
	DEL_BIGINT(c);

	TB_FOOTER(TEST_NAME);
}
