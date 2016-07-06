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
#include <assert.h>
#include <compiler.h>

#define TEST_GCD(stra, strb)                  \
do {                                          \
	TEE_BigIntConvertFromString(x, stra); \
	TEE_BigIntConvertFromString(y, strb); \
} while (0)

static void test_extended_gcd_basic(void)
{
	DEF_BIGINT(x, 2048);
	DEF_BIGINT(y, 2048);
	DEF_BIGINT(a, 2048);
	DEF_BIGINT(b, 2048);
	DEF_BIGINT(gcd, 2048);

	TB_INFO("   Testing extended GCD");

	TEST_GCD("0", "0");
	TEST_GCD("0", "123");
	TEST_GCD("1", "1");
	TEST_GCD("1", "-1");
	TEST_GCD("2", "2");
	TEST_GCD("-2", "2");
	TEST_GCD("2", "4");
	TEST_GCD("-2", "-4");
	TEST_GCD("0x400", "0x800");

	TEST_GCD("0x261", "0x2B5");
	TEST_GCD("F", "A");
	TEST_GCD("C", "13");
	TEST_GCD("0x165D662", "0x1664FEA");

	TEST_GCD("0xAB59CDFD83CE2B24",
		 "0x4961BF04008953A7F9567AAFBA94D4AF55F473F14FD68AA022982F0FE");

	/* two large primes */
	TEST_GCD("0x5D0A380DC40EDE5E036FA051FC6D7F93",
		 "0x3277FD425328576569AFB2EAC6B1430578099CA8ADA4BC73");

	/* two large powers of 2 */
	TEST_GCD
	    ("0x2000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	     "0x40000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");

	DEL_BIGINT(x);
	DEL_BIGINT(y);
	DEL_BIGINT(b);
	DEL_BIGINT(a);
	DEL_BIGINT(gcd);
}

static void test_extended_gcd_special(void)
{
	DEF_BIGINT(x, 2048);
	DEF_BIGINT(y, 2048);
	DEF_BIGINT(a, 2048);
	DEF_BIGINT(b, 2048);
	DEF_BIGINT(gcd, 2048);
	DEF_BIGINT(tmp1, 2048);
	DEF_BIGINT(tmp2, 2048);

	TB_INFO("   Testing special cases of extended GCD");

	/* both a and b are zero */
	TEE_BigIntConvertFromString(x, "0x7B");
	TEE_BigIntConvertFromString(y, "0x57677928C");
	TEE_BigIntComputeExtendedGcd(gcd, 0, 0, x, y);
	TB_ASSERT_BIGINT_EQ(tmp1, gcd);

	/* only a is zero */
	TEE_BigIntConvertFromString(x, "0xAB05C2E2A7870B12");
	TEE_BigIntConvertFromString(y, "0x943B1377291233F7928C");
	TEE_BigIntComputeExtendedGcd(gcd, 0, b, x, y);
	TB_ASSERT_BIGINT_EQ(tmp1, gcd);

	/* only b is zero */
	TEE_BigIntConvertFromString(x, "0x13EF245EE37410377D5432D96");
	TEE_BigIntConvertFromString(y, "0xAB621806355B60955F1C89BC2CF365");
	TEE_BigIntComputeExtendedGcd(gcd, a, 0, x, y);

	TB_ASSERT_BIGINT_EQ(tmp1, gcd);

	DEL_BIGINT(x);
	DEL_BIGINT(y);
	DEL_BIGINT(b);
	DEL_BIGINT(a);
	DEL_BIGINT(gcd);
	DEL_BIGINT(tmp1);
	DEL_BIGINT(tmp2);
}

static void test_relative_prime(void)
{
	bool res __maybe_unused;

	DEF_BIGINT(x, 2048);
	DEF_BIGINT(y, 2048);

	TB_INFO("   Testing relative prime function");

	TEE_BigIntConvertFromString(x, "0x7B");
	TEE_BigIntConvertFromString(y, "0x57677928C");
	res = TEE_BigIntRelativePrime(x, y);
	assert(res == false);

	TEE_BigIntConvertFromString(x, "0x157");
	TEE_BigIntConvertFromString(y, "0x5F5E1");
	res = TEE_BigIntRelativePrime(x, y);
	assert(res == true);

	TEE_BigIntConvertFromString(x, "0x2FD4ABD35311DC9884CFCBDC1");
	TEE_BigIntConvertFromString(y, "0x12E0B94A7ED49AA36A982ADCBDE813");
	res = TEE_BigIntRelativePrime(x, y);
	assert(res == true);

	DEL_BIGINT(x);
	DEL_BIGINT(y);
}

void tb_gcd(void)
{
	const char *TEST_NAME = "GCD and Extended GCD";

	TB_HEADER(TEST_NAME);

	test_extended_gcd_basic();
	test_extended_gcd_special();
	test_relative_prime();

	TB_FOOTER(TEST_NAME);
}
