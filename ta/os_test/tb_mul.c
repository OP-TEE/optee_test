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

#define MUL(s, t, r)                          \
do {                                          \
	TEE_BigIntConvertFromString(a, (s));  \
	TEE_BigIntConvertFromString(b, (t));  \
	TEE_BigIntMul(c, a, b);               \
	TB_ASSERT_HEX_PRINT_VALUE(c, (r));    \
	TEE_BigIntMul(a, a, b);               \
	TB_ASSERT_HEX_PRINT_VALUE(a, (r));    \
} while (0)

#define MULWORD(s, t, r)                                \
do {                                                    \
	TEE_BigIntConvertFromString(a, (s));            \
	mpa_mul_word((mpanum)b, (mpanum)a, t, mempool); \
	TB_ASSERT_HEX_PRINT_VALUE(b, (r));              \
	mpa_mul_word((mpanum)a, (mpanum)a, t, mempool); \
	TB_ASSERT_HEX_PRINT_VALUE(a, (r));              \
} while (0)

void tb_mul(void)
{
	const char *TEST_NAME = "Multiplication";

	TB_HEADER(TEST_NAME);

	DEF_BIGINT(a, 1024);
	DEF_BIGINT(b, 1024);
	DEF_BIGINT(c, 2048);

	TB_INFO("Testing basic cases");
	MUL("0", "0", "0");
	MULWORD("0", 0, "0");
	MUL("0", "FFFFFFFF", "0");
	MULWORD("0", 0xffffffff, "0");
	MUL("1", "1", "1");
	MULWORD("1", 1, "1");
	MUL("-1", "1", "-1");
	MULWORD("-1", 1, "-1");
	MUL("-1", "-1", "1");
	MUL("FF", "1", "FF");
	MULWORD("1", 0xff, "FF");
	MULWORD("FF", 1, "FF");
	MUL("2", "2", "4");
	MUL("3", "3", "9");
	MUL("100", "100", "10000");
	MUL("FFFFFFFF", "FFFFFFFF", "FFFFFFFE00000001");
	MULWORD("FFFFFFFF", 0xffffffff, "FFFFFFFE00000001");
	MUL("4F239BBAE89A447149CDB0B50A103C69591DD9E0C91A57955A6C266C7ED42A5ED5F4",
	    "44FF5A67036657E041D55AE42AE25517A1",
	    "155465C8221717FFC135C87ABF6D34184DF5E6906D2EBA7C364879AA0BE840FD06F1E0A7036BC3B7B1844FF95F07A39CE17A74");
	MUL("4F239BBAE89A447149CDB0B50A103C69591DD9E0C91A57955A6C266C7ED42A5ED5F4",
	    "-44FF5A67036657E041D55AE42AE25517A1",
	    "-155465C8221717FFC135C87ABF6D34184DF5E6906D2EBA7C364879AA0BE840FD06F1E0A7036BC3B7B1844FF95F07A39CE17A74");
	MUL("-4F239BBAE89A447149CDB0B50A103C69591DD9E0C91A57955A6C266C7ED42A5ED5F4",
	    "-44FF5A67036657E041D55AE42AE25517A1",
	    "155465C8221717FFC135C87ABF6D34184DF5E6906D2EBA7C364879AA0BE840FD06F1E0A7036BC3B7B1844FF95F07A39CE17A74");

	DEL_BIGINT(a);
	DEL_BIGINT(b);
	DEL_BIGINT(c);

	TB_FOOTER(TEST_NAME);
}
