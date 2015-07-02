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
#ifndef TB_MACROS_H
#define TB_MACROS_H

#include <tee_internal_api_extensions.h>

#define TB_HEADER(str)                               \
	printf("\n*********** TESTBENCH ***********" \
	       "\n***         RUNNING: <<< %s >>>"   \
	       "\n*********************************\n\n", str)

#define TB_FOOTER(str)                               \
	printf("\n*********** TESTBENCH ***********" \
	       "\n***         PASSED:  <<< %s >>>"   \
	       "\n*********************************\n\n", str)

#define TB_INFO(str) printf("*** INFO : %s \n", (str))

#define HALT                                                             \
	{                                                                \
		printf("\n*** FAILED ***"                                \
		       "\nTestbench halted at line %d in function %s\n", \
			 __LINE__, __func__);                            \
		printf("\nWaiting for keypress to enable debugging.\n"); \
		TEE_Panic(0);                                            \
	}

#define STARTING                                       \
	printf("\n*********** TESTBENCH ***********"   \
	       "\n*** For the GlobalPlatform Math API" \
	       "\n*********************************\n\n")

#define ALL_PASSED \
	printf("\n*********** TESTBENCH ***********" \
	       "\n***     ALL TESTS PASSED      ***" \
	       "\n*********************************\n\n")

/*
 * DEF_BIGINT defines and initialize a BigInt with name and size.
 */
#define DEF_BIGINT(name, size)                                                \
	TEE_BigInt *name;                                                     \
	size_t name##_size;                                                   \
	name##_size = TEE_BigIntSizeInU32(size);                              \
	name = (TEE_BigInt *)TEE_Malloc(name##_size * sizeof(TEE_BigInt), 0); \
	TEE_BigIntInit(name, name##_size)

/*
 * DEL_BIGINT frees the BigInt.
 */
#define DEL_BIGINT(name) TEE_Free(name)

/*
 * TB_PRINT_BIGINT prints the mpanum in base 16.
 */
#define TB_PRINT_BIGINT(n)                                                     \
do {                                                                           \
	char *str;                                                             \
	str = TEE_BigIntConvertToString(NULL, TEE_STRING_MODE_HEX_UC, 0, (n)); \
	printf("%s\n", str);                                                   \
	TEE_Free(str);                                                         \
} while (0)

#endif
