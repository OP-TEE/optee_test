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

#define MAX_RAND_RUNS 10000

#define SHIFT_LEFT(in, s, out)                          \
{                                                       \
	{                                               \
		TEE_BigIntConvertFromString(a, (in));   \
		TB_ASSERT_HEX_PRINT_VALUE(b, (out));    \
	} while (0);                                    \
}

static void tb_shift_left_simple(void)
{

	DEF_BIGINT(a, 64);
	DEF_BIGINT(b, 64);

	TB_INFO("   Simple shift left");
	SHIFT_LEFT("0", 1, "0");
	SHIFT_LEFT("-1", 1, "-2");
	SHIFT_LEFT("1", 0, "1");
	SHIFT_LEFT("1", 1, "2");
	SHIFT_LEFT("1", 2, "4");
	SHIFT_LEFT("1", 3, "8");
	SHIFT_LEFT("1", 4, "10");
	SHIFT_LEFT("1", 5, "20");
	SHIFT_LEFT("1", 6, "40");
	SHIFT_LEFT("1", 7, "80");
	SHIFT_LEFT("1", 8, "100");
	SHIFT_LEFT("1", 9, "200");
	SHIFT_LEFT("1", 10, "400");
	SHIFT_LEFT("1", 11, "800");
	SHIFT_LEFT("1", 12, "1000");
	SHIFT_LEFT("1", 13, "2000");
	SHIFT_LEFT("1", 14, "4000");
	SHIFT_LEFT("1", 15, "8000");
	SHIFT_LEFT("1", 16, "10000");
	SHIFT_LEFT("1", 17, "20000");
	SHIFT_LEFT("1", 18, "40000");
	SHIFT_LEFT("1", 19, "80000");
	SHIFT_LEFT("1", 20, "100000");
	SHIFT_LEFT("1", 21, "200000");
	SHIFT_LEFT("1", 22, "400000");
	SHIFT_LEFT("1", 23, "800000");
	SHIFT_LEFT("1", 24, "1000000");
	SHIFT_LEFT("1", 25, "2000000");
	SHIFT_LEFT("1", 26, "4000000");
	SHIFT_LEFT("1", 27, "8000000");
	SHIFT_LEFT("1", 28, "10000000");
	SHIFT_LEFT("1", 29, "20000000");
	SHIFT_LEFT("1", 30, "40000000");
	SHIFT_LEFT("1", 31, "80000000");
	TB_ASSERT_INT_EQ(((mpanum) b)->size, 1);

	/* patterns */
	TB_INFO("Simple shift left of patterns");
	SHIFT_LEFT("05A5A5A5", 4, "5A5A5A50");

	DEL_BIGINT(a);
	DEL_BIGINT(b);
}

static void tb_shift_left_words(void)
{
	DEF_BIGINT(a, 256);
	DEF_BIGINT(b, 256);

	TB_INFO("   Shift left by multiples of word size");
	SHIFT_LEFT("1", 32, "100000000");
	SHIFT_LEFT("1", 64, "10000000000000000");
	SHIFT_LEFT("FFFFFFFF", 64, "FFFFFFFF0000000000000000");
	SHIFT_LEFT("123456789ABCDEF0", 32, "123456789ABCDEF000000000");

	DEL_BIGINT(a);
	DEL_BIGINT(b);
}

static void tb_shift_left_complex(void)
{
	DEF_BIGINT(a, 256);
	DEF_BIGINT(b, 256);

	TB_INFO("   Shift left by any value");
	SHIFT_LEFT("1", 33, "200000000");
	SHIFT_LEFT("1", 65, "20000000000000000");
	SHIFT_LEFT("FFFFFFFF", 65, "1FFFFFFFE0000000000000000");

	/* patterns */
	SHIFT_LEFT("6E740D74D7F0DB4BF23376E", 73,
		   "DCE81AE9AFE1B697E466EDC000000000000000000");

	DEL_BIGINT(a);
	DEL_BIGINT(b);
}

static void tb_shift_left(void)
{
	tb_shift_left_simple();
	tb_shift_left_words();
	tb_shift_left_complex();
}

#define SHIFT_RIGHT(out, s, in)                         \
{                                                       \
	{                                               \
		TEE_BigIntConvertFromString(a, (in));   \
		TEE_BigIntShiftRight(b, a, (s));        \
		TB_ASSERT_HEX_PRINT_VALUE(b, (out));    \
	} while (0);                                    \
}

static void tb_shift_right_simple(void)
{
	DEF_BIGINT(a, 64);
	DEF_BIGINT(b, 64);

	TB_INFO("   Simple shift right");
	SHIFT_RIGHT("0", 31, "7FFFFFFF");
	SHIFT_RIGHT("0", 65, "7FFFFFFF");
	SHIFT_RIGHT("0", 1, "0");
	SHIFT_RIGHT("-1", 1, "-2");
	SHIFT_RIGHT("1", 0, "1");
	SHIFT_RIGHT("1", 1, "2");
	SHIFT_RIGHT("1", 2, "4");
	SHIFT_RIGHT("1", 3, "8");
	SHIFT_RIGHT("1", 4, "10");
	SHIFT_RIGHT("1", 5, "20");
	SHIFT_RIGHT("1", 6, "40");
	SHIFT_RIGHT("1", 7, "80");
	SHIFT_RIGHT("1", 8, "100");
	SHIFT_RIGHT("1", 9, "200");
	SHIFT_RIGHT("1", 10, "400");
	SHIFT_RIGHT("1", 11, "800");
	SHIFT_RIGHT("1", 12, "1000");
	SHIFT_RIGHT("1", 13, "2000");
	SHIFT_RIGHT("1", 14, "4000");
	SHIFT_RIGHT("1", 15, "8000");
	SHIFT_RIGHT("1", 16, "10000");
	SHIFT_RIGHT("1", 17, "20000");
	SHIFT_RIGHT("1", 18, "40000");
	SHIFT_RIGHT("1", 19, "80000");
	SHIFT_RIGHT("1", 20, "100000");
	SHIFT_RIGHT("1", 21, "200000");
	SHIFT_RIGHT("1", 22, "400000");
	SHIFT_RIGHT("1", 23, "800000");
	SHIFT_RIGHT("1", 24, "1000000");
	SHIFT_RIGHT("1", 25, "2000000");
	SHIFT_RIGHT("1", 26, "4000000");
	SHIFT_RIGHT("1", 27, "8000000");
	SHIFT_RIGHT("1", 28, "10000000");
	SHIFT_RIGHT("1", 29, "20000000");
	SHIFT_RIGHT("1", 30, "40000000");
	SHIFT_RIGHT("1", 31, "80000000");

	/* patterns */
	TB_INFO("Simple shift right of patterns");
	SHIFT_RIGHT("5A5A5A5", 4, "5A5A5A50");

	DEL_BIGINT(a);
	DEL_BIGINT(b);
}

static void tb_shift_right_words(void)
{
	DEF_BIGINT(a, 256);
	DEF_BIGINT(b, 256);

	TB_INFO("   Shift right by multiples of word size");
	SHIFT_RIGHT("1", 32, "100000000");
	SHIFT_RIGHT("1", 64, "10000000000000000");
	SHIFT_RIGHT("FFFFFFFF", 64, "FFFFFFFF0000000000000000");
	SHIFT_RIGHT("1111FFFF0000", 64, "1111FFFF00000000000000000000");

	DEL_BIGINT(a);
	DEL_BIGINT(b);
}

static void tb_shift_right_complex(void)
{
	DEF_BIGINT(a, 256);
	DEF_BIGINT(b, 256);

	TB_INFO("   Shift right by any value");
	SHIFT_RIGHT("1", 33, "200000000");
	SHIFT_RIGHT("1", 65, "20000000000000000");
	SHIFT_RIGHT("FFFFFFFF", 65, "1FFFFFFFE0000000000000000");

	/* patterns */
	SHIFT_RIGHT("24B0D975EC8FCC8E1D54CA4BF7ACFC4534F04", 81,
	    "4961B2EBD91F991C3AA99497EF59F88A69E08AD5C340167793C3CC32F");

	DEL_BIGINT(a);
	DEL_BIGINT(b);
}

static void tb_shift_right(void)
{

	tb_shift_right_simple();
	tb_shift_right_words();
	tb_shift_right_complex();
}

void tb_shift(void)
{
	const char *TEST_NAME = "Left and Right shift";

	TB_HEADER(TEST_NAME);

	TB_INFO("Testing shift left");
	tb_shift_left();

	TB_INFO("Testing shift right");
	tb_shift_right();

	TB_FOOTER(TEST_NAME);
}
