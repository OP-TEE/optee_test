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
#include <stdint.h>
#include "testframework.h"

#define getsettest(bigint, _short)                                      \
do {                                                                    \
	int32_t bi = 0;                                                 \
	TEE_Result result;                                              \
	TEE_BigIntConvertFromS32((bigint), (_short));                   \
	TB_ASSERT_EQ_SHORT((bigint), (_short));                         \
	result = TEE_BigIntConvertToS32(&bi, (bigint));                 \
	TB_ASSERT_MSG(result == TEE_SUCCESS, "Failed getting short\n"); \
	TB_ASSERT_INT_EQ(bi, (_short));                                 \
} while (0)

static void test_BigInt_getsetShort(void)
{
	int32_t b;
	TEE_Result res;

	TB_INFO("Testing GetShort and SetShort");

	DEF_BIGINT(a, 512);

	getsettest(a, 1);
	getsettest(a, -1);
	getsettest(a, 123);
	getsettest(a, -123);
	getsettest(a, 0x7FFFFFFF);
	getsettest(a, (int)0x80000000);
	getsettest(a, (int)0xFFFFFFFF);
	getsettest(a, 0);

	/* Testing too large BigInt */
	TEE_BigIntConvertFromString(a, "0x1FFFFFFFFF");
	res = TEE_BigIntConvertToS32(&b, a);
	TB_ASSERT(res == TEE_ERROR_OVERFLOW);

	mpa_wipe((mpanum) a);

	TEE_BigIntConvertFromString(a, "-0x1FFFFFFFFF");
	res = TEE_BigIntConvertToS32(&b, a);
	TB_ASSERT(res == TEE_ERROR_OVERFLOW);

	DEL_BIGINT(a);

}

static void test_BigInt_getsetOctetString(void)
{
	uint8_t os1[] = { 1, 2, 3, 4 };
	uint8_t os2[] = { 1, 2, 3, 4, 5 };
	uint8_t os3[] = { 0, 1, 2, 3, 4 };
	uint8_t os4[] = { 0x11, 0x22, 0x44, 0x55, 0x66, 0x77, 0x88 };
	uint8_t os_res[10];
	TEE_Result res;
	uint32_t os_len;

	DEF_BIGINT(a, 512);
	DEF_BIGINT(b, 512);

	TB_INFO("Testing Convert to and from OctetString");

	/* Test with 0x0102030405 */
	TEE_BigIntConvertFromString(a, "0x0102030405");
	os_len = sizeof(os_res);
	res = TEE_BigIntConvertToOctetString(os_res, &os_len, a);
	TB_ASSERT(res == TEE_SUCCESS);
	TB_ASSERT(sizeof(os2) == os_len
		  && TEE_MemCompare(os2, os_res, sizeof(os2)) == 0);

	res = TEE_BigIntConvertFromOctetString(b, os_res, os_len, 1);
	TB_ASSERT(res == TEE_SUCCESS);
	TB_ASSERT(TEE_BigIntCmp(a, b) == 0);

	/* Test with 0x11224455667788 */
	TEE_BigIntConvertFromString(a, "0x11224455667788");
	os_len = sizeof(os_res);
	res = TEE_BigIntConvertToOctetString(os_res, &os_len, a);
	TB_ASSERT(res == TEE_SUCCESS);
	TB_ASSERT(sizeof(os4) == os_len
		  && TEE_MemCompare(os4, os_res, sizeof(os4)) == 0);

	res = TEE_BigIntConvertFromOctetString(b, os_res, os_len, 1);
	TB_ASSERT(res == TEE_SUCCESS);
	TB_ASSERT(TEE_BigIntCmp(a, b) == 0);

	/* Test with static octet strings */
	res = TEE_BigIntConvertFromOctetString(a, (uint8_t *)os1, sizeof(os1), 1);
	TB_ASSERT(res == TEE_SUCCESS);

	os_len = sizeof(os_res);
	res = TEE_BigIntConvertToOctetString(os_res, &os_len, a);
	TB_ASSERT(res == TEE_SUCCESS);
	TB_ASSERT(sizeof(os1) == os_len
		  && TEE_MemCompare(os1, os_res, sizeof(os1)) == 0);

	res = TEE_BigIntConvertFromOctetString(b, (uint8_t *)os3, sizeof(os3), 1);
	TB_ASSERT(res == TEE_SUCCESS);
	TB_ASSERT(TEE_BigIntCmp(a, b) == 0);

	DEL_BIGINT(a);
	DEL_BIGINT(b);
}

void tb_conv(void)
{
	const char *TEST_NAME = "Conversion functions";

	TB_HEADER(TEST_NAME);

	test_BigInt_getsetShort();
	test_BigInt_getsetOctetString();

	TB_FOOTER(TEST_NAME);

}
