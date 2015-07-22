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

#define DIV(s, t, out)                               \
do {                                                 \
	TEE_BigIntConvertFromString(n, (s));         \
	TEE_BigIntConvertFromString(d, (t));         \
	TEE_BigIntDiv(q, r, n, d);                   \
	TB_ASSERT_HEX_PRINT_VALUE(q, (out));         \
	if (TEE_BigIntCmpS32(d, 0) > 0)              \
			TB_ASSERT_BIGINT_LESS(r, d); \
} while (0)

#define SELF_VERIFY_DIV(s, t)                        \
do {                                                 \
	TEE_BigIntConvertFromString(n, (s));         \
	TEE_BigIntConvertFromString(d, (t));         \
	TEE_BigIntDiv(q, r, n, d);                   \
	if (TEE_BigIntCmpS32(d, 0) > 0)              \
			TB_ASSERT_BIGINT_LESS(r, d); \
	TEE_BigIntMul(v, q, d);                      \
	TEE_BigIntAdd(v, v, r);                      \
	TB_ASSERT_BIGINT_EQ(n, v);                   \
} while (0)

static void test_div_basic(void)
{
	TB_INFO("   Testing basic cases");

	DEF_BIGINT(n, 2048);
	DEF_BIGINT(d, 2048);
	DEF_BIGINT(q, 2048);
	DEF_BIGINT(r, 2048);
	DEF_BIGINT(v, 2048);

	SELF_VERIFY_DIV("8111_1110_0000_0001_12345678", "8000000012345678");

	DIV("0", "1", "0");
	DIV("1", "1", "1");
	DIV("b7fb", "5", "24CB");
	DIV("124378912734891273894712890347102358129034789120374",
	    "1984086C15FA011154C86FA68", "B73D14EC7205D3311F6E78411D");
	SELF_VERIFY_DIV("124378912734891273894712890347102358129034789120374",
			"1984086C15FA011154C86FA68");
	SELF_VERIFY_DIV("-124378912734891273894712890347102358129034789120374",
			"1984086C15FA011154C86FA68");
	SELF_VERIFY_DIV("124378912734891273894712890347102358129034789120374",
			"-1984086C15FA011154C86FA68");
	SELF_VERIFY_DIV("-124378912734891273894712890347102358129034789120374",
			"-1984086C15FA011154C86FA68");
	SELF_VERIFY_DIV("12345678", "10");
	SELF_VERIFY_DIV("-12345678", "10");
	SELF_VERIFY_DIV("12345678", "-10");
	SELF_VERIFY_DIV("-12345678", "-10");
	SELF_VERIFY_DIV("12345678901234567890123456789012345678901", "10");
	SELF_VERIFY_DIV("1234567890123456789012345678901234567890", "10");
	SELF_VERIFY_DIV("123456789012345678901234567890123456789", "10");

	DEL_BIGINT(n);
	DEL_BIGINT(d);
	DEL_BIGINT(q);
	DEL_BIGINT(r);
	DEL_BIGINT(v);
}

static void test_div_random(void)
{
	int i;
	char str[MAX_RAND_STRING_SIZE];

	TB_INFO("   Testing random divisions");

	DEF_BIGINT(n, 2048);
	DEF_BIGINT(d, 2048);
	DEF_BIGINT(q, 2048);
	DEF_BIGINT(r, 2048);
	DEF_BIGINT(v, 2048);

	for (i = 0; i < 10000; i++) {
		tb_set_random_value(n, str, 1);
		/* don't divide by zero */
		do {
			tb_set_random_value(d, str, 1);
		} while (TEE_BigIntCmpS32(d, 0) == 0);
		TEE_BigIntDiv(q, r, n, d);
		TEE_BigIntMul(v, q, d);
		TEE_BigIntAdd(v, v, r);
		TB_ASSERT_BIGINT_EQ(n, v);
		if (TEE_BigIntCmpS32(d, 0) > 0)
			TB_ASSERT_BIGINT_LESS(r, d);

	}

	DEL_BIGINT(n);
	DEL_BIGINT(d);
	DEL_BIGINT(q);
	DEL_BIGINT(r);
	DEL_BIGINT(v);
}

#define CMP_EQUAL    ==
#define CMP_LARGER   >
#define CMP_SMALLER  <
#define DIV_CHECK_SIGN(sn, sd, cmpq, cmpr) \
do {\
	SELF_VERIFY_DIV(sn, sd); \
	TEE_BigIntConvertFromString(n, (sn)); \
	TEE_BigIntConvertFromString(d, (sd)); \
	TEE_BigIntDiv(q, r, n, d); \
	TB_ASSERT_MSG(TEE_BigIntCmpS32(q, 0) cmpq 0, "q has wrong sign."); \
	TB_ASSERT_MSG(TEE_BigIntCmpS32(r, 0) cmpr 0, "r has wrong sign."); \
} while (0)

static void test_div_signs(void)
{
	TB_INFO("   Testing signs of q and r");

	DEF_BIGINT(n, 2048);
	DEF_BIGINT(d, 2048);
	DEF_BIGINT(q, 2048);
	DEF_BIGINT(r, 2048);
	DEF_BIGINT(v, 2048);

	DIV_CHECK_SIGN("53", "7", CMP_LARGER, CMP_LARGER);
	DIV_CHECK_SIGN("-53", "7", CMP_SMALLER, CMP_SMALLER);
	DIV_CHECK_SIGN("53", "-7", CMP_SMALLER, CMP_LARGER);
	DIV_CHECK_SIGN("-53", "-7", CMP_LARGER, CMP_SMALLER);

	DIV_CHECK_SIGN("123456789abcdef123456789abcdef", "fedcba98765432100",
		       CMP_LARGER, CMP_LARGER);
	DIV_CHECK_SIGN("-123456789abcdef123456789abcdef", "fedcba98765432100",
		       CMP_SMALLER, CMP_SMALLER);
	DIV_CHECK_SIGN("123456789abcdef123456789abcdef", "-fedcba98765432100",
		       CMP_SMALLER, CMP_LARGER);
	DIV_CHECK_SIGN("-123456789abcdef123456789abcdef", "-fedcba98765432100",
		       CMP_LARGER, CMP_SMALLER);

	DEL_BIGINT(n);
	DEL_BIGINT(d);
	DEL_BIGINT(q);
	DEL_BIGINT(r);
	DEL_BIGINT(v);
}

void tb_div(void)
{
	const char *TEST_NAME = "Division";

	TB_HEADER(TEST_NAME);

	test_div_basic();
	test_div_random();
	test_div_signs();

	TB_FOOTER(TEST_NAME);
}
