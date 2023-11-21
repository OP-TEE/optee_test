/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * All rights reserved.
 */
#ifndef TB_MACROS_H
#define TB_MACROS_H

#include <tee_internal_api_extensions.h>

#define TB_HEADER(str)                            \
	MSG("\n*********** TESTBENCH ***********" \
	    "\n***         RUNNING: <<< %s >>>"   \
	    "\n*********************************", str)

#define TB_FOOTER(str)                            \
	MSG("\n*********** TESTBENCH ***********" \
	    "\n***         PASSED:  <<< %s >>>"   \
	    "\n*********************************", str)

#define TB_INFO(str) MSG("*** INFO : %s \n", (str))

#define HALT                                                           \
	{                                                              \
		EMSG("\n*** FAILED ***"                                \
		     "\nTestbench halted at line %d in function %s";   \
		MSG("\nWaiting for keypress to enable debugging.");    \
		TEE_Panic(0);                                          \
	}

#define STARTING                                    \
	MSG("\n*********** TESTBENCH ***********"   \
	    "\n*** For the GlobalPlatform Math API" \
	    "\n*********************************")

#define ALL_PASSED \
	MSG("\n*********** TESTBENCH ***********" \
	    "\n***     ALL TESTS PASSED      ***" \
	    "\n*********************************")

/*
 * DEF_BIGINT defines and initialize a BigInt with name and size.
 */
#define DEF_BIGINT(name, size)                                                \
	TEE_BigInt *name;                                                     \
	size_t name##_size;                                                   \
									      \
	name##_size = TEE_BigIntSizeInU32(size);                              \
	name = (TEE_BigInt *)TEE_Malloc(name##_size * sizeof(TEE_BigInt), 0); \
	TEE_BigIntInit(name, name##_size)

/*
 * DEL_BIGINT frees the BigInt.
 */
#define DEL_BIGINT(name) TEE_Free(name)

#endif
