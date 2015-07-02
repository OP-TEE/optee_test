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

/*------------------------------------------------------------
 *
 *  test_BigIntInit
 *
 */
static void test_BigIntInit(void)
{

	TEE_BigInt *a;
	size_t aLen;

	TB_INFO("Testing BigIntInit");

	/* Testing normal allocation and initialization */
	aLen = TEE_BigIntSizeInU32(512);
	a = (TEE_BigInt *) TEE_Malloc(aLen * sizeof(TEE_BigInt), 0);
	TEE_BigIntInit(a, aLen);
	TEE_Free(a);

	/* Testing zero allocation */
	aLen = TEE_BigIntSizeInU32(0);
	a = (TEE_BigInt *) TEE_Malloc(aLen * sizeof(TEE_BigInt), 0);
	TEE_BigIntInit(a, aLen);
	TEE_Free(a);

	/* Testing too large */
	aLen = TEE_BigIntSizeInU32(4096);
	a = (TEE_BigInt *) TEE_Malloc(aLen * sizeof(TEE_BigInt), 0);
	TEE_BigIntInit(a, aLen);
	TEE_Free(a);

	/* Testing boundaries */
	aLen = TEE_BigIntSizeInU32(2048);
	a = (TEE_BigInt *) TEE_Malloc(aLen * sizeof(TEE_BigInt), 0);
	TEE_BigIntInit(a, aLen);
	TEE_Free(a);

	aLen = TEE_BigIntSizeInU32(2049);
	a = (TEE_BigInt *) TEE_Malloc(aLen * sizeof(TEE_BigInt), 0);
	TEE_BigIntInit(a, aLen);
	TEE_Free(a);

}

/*------------------------------------------------------------
 *
 *  tb_var
 *
 */
void tb_var(void)
{
	const char *TEST_NAME = "Variables";

	TB_HEADER(TEST_NAME);

	test_BigIntInit();

	TB_FOOTER(TEST_NAME);

}
