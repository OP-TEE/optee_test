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

#include <trace.h>

#define CMP_EQUAL ==
#define CMP_LARGER >
#define CMP_SMALLER <
#define COMPARE(s, t, cmpf) \
do {\
	int __i__;\
	TEE_BigIntConvertFromString(a, (s));\
	TEE_BigIntConvertFromString(b, (t));\
	__i__ = TEE_BigIntCmp(a, b);\
	if (!(__i__  cmpf 0)) {\
		EMSG("Assertion failed Str_Cmp == %d\n", __i__);\
		HALT\
	} \
} while (0)

#define NR_RAND_RUNS 1000

static void test_compare(void)
{
	char str[MAX_RAND_STRING_SIZE];
	char str2[MAX_RAND_STRING_SIZE];
	int i;

	TB_INFO("Testing TEE_BigIntCompare");

	DEF_BIGINT(a, 2048);
	DEF_BIGINT(b, 2048);

	TB_INFO("   Testing various cases");
	COMPARE("0", "1", CMP_SMALLER);
	COMPARE("1", "0", CMP_LARGER);
	COMPARE("1", "2", CMP_SMALLER);
	COMPARE("2", "1", CMP_LARGER);
	COMPARE("-1", "FFFFFFFFFF", CMP_SMALLER);
	COMPARE("FFFFFFFFFF", "-1", CMP_LARGER);
	COMPARE("1", "-FFFFFFFFFF", CMP_LARGER);
	COMPARE("-FFFFFFFFFF", "1", CMP_SMALLER);
	COMPARE("1", "100000000", CMP_SMALLER);

	TB_INFO("   Testing equality");
	COMPARE("0", "0", CMP_EQUAL);
	COMPARE("1", "1", CMP_EQUAL);
	COMPARE("-1", "-1", CMP_EQUAL);
	for (i = 0; i < NR_RAND_RUNS; i++) {
		tb_get_random_str(str, 1);
		COMPARE(str, str, CMP_EQUAL);
	}

	TB_INFO("   Testing equal magnitude, but different signs");
	for (i = 0; i < NR_RAND_RUNS; i++) {
		tb_get_random_str(str, 0);
		if (my_strlen(str) > 2) {
			my_strlcpy(str2, str, MAX_RAND_STRING_SIZE);
			str[0] = '0';
			str2[0] = '-';
			COMPARE(str, str2, CMP_LARGER);
			COMPARE(str2, str, CMP_SMALLER);
		}
	}

	DEL_BIGINT(a);
	DEL_BIGINT(b);
}

#define COMPARE_SHORT(s, t, cmpf) \
do {\
	int __i__;\
	TEE_BigIntConvertFromString(a, (s));\
	__i__ = TEE_BigIntCmpS32(a, t);\
	if (!(__i__  cmpf 0)) {\
		EMSG("Assertion failed Str_Cmp == %d\n", __i__);\
		HALT\
	} \
} while (0)

static void test_compare_short(void)
{

	TB_INFO("Testing TEE_BigIntCmpS32");

	DEF_BIGINT(a, 2048);

	TB_INFO("   Testing various cases");
	COMPARE_SHORT("0", 0, CMP_EQUAL);
	COMPARE_SHORT("0", 1, CMP_SMALLER);
	COMPARE_SHORT("1", 0, CMP_LARGER);
	COMPARE_SHORT("0", -1, CMP_LARGER);
	COMPARE_SHORT("-1", 0, CMP_SMALLER);
	COMPARE_SHORT("1", 1, CMP_EQUAL);
	COMPARE_SHORT("-1", -1, CMP_EQUAL);
	COMPARE_SHORT("-1", 1, CMP_SMALLER);
	COMPARE_SHORT("1", -1, CMP_LARGER);
	COMPARE_SHORT("123", 0x123, CMP_EQUAL);
	COMPARE_SHORT("-123", -0x123, CMP_EQUAL);

	/* testing corner case */
	COMPARE_SHORT("7FFFFFFF", INT32_MAX, CMP_EQUAL);
	COMPARE_SHORT("-7FFFFFFF", INT32_MIN, CMP_LARGER);
	COMPARE_SHORT("7FFFFFFF", 0, CMP_LARGER);
	COMPARE_SHORT("-7FFFFFFF", 0, CMP_SMALLER);
	COMPARE_SHORT("-80000000", INT32_MIN, CMP_EQUAL);
	COMPARE_SHORT("80000000", INT32_MAX, CMP_LARGER);
	COMPARE_SHORT("-80000001", INT32_MIN, CMP_SMALLER);
	COMPARE_SHORT("-7FFFFFFF", INT32_MIN, CMP_LARGER);

	TB_INFO("   Testing large BigInt");
	COMPARE_SHORT("1FFFFFFFF", 1, CMP_LARGER);
	COMPARE_SHORT("-1FFFFFFFF", 1, CMP_SMALLER);

	DEL_BIGINT(a);

}

void tb_cmp(void)
{
	const char *TEST_NAME = "Comparison functions";

	TB_HEADER(TEST_NAME);

	test_compare();
	test_compare_short();

	TB_FOOTER(TEST_NAME);
}
