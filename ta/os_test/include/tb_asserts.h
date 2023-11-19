/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * All rights reserved.
 */

#ifndef TB_ASSERTS_H
#define TB_ASSERTS_H

#include <trace.h>
#include "tb_macros.h"

/*
 * TB_ASSERT_MSG general assert function with a message.
 */
#define TB_ASSERT_MSG(cond, str)                                   \
do {                                                               \
	if (!(cond)) {                                             \
		EMSG("Assertion failed at line %d in file:\n%s",   \
			__LINE__, __FILE__);                       \
		EMSG("Message: %s", str);                          \
		HALT;                                              \
	}; \
} while (0)

/*
 * TB_ASSERT general assert function.
 */
#define TB_ASSERT(cond)                                            \
do {                                                               \
	if (!(cond)) {                                             \
		EMSG("Assertion failed at line %d in file:\n%s",   \
			__LINE__, __FILE__);                       \
		HALT;                                              \
	};                                                         \
} while (0)

/*
 * TB_ASSERT_EQ_SHORT checks that src equals the short value.
 */
#define TB_ASSERT_EQ_SHORT(src, short)                                         \
do {                                                                           \
	if (((short) == 0) && (__mpanum_size((mpanum)src) != 0)) {             \
		EMSG("Assertion failed at line %d in file:\n%s",               \
			__LINE__, __FILE__);                                   \
		EMSG("short == 0, but size != 0");                             \
		HALT;                                                          \
	} else if (__mpanum_size((mpanum)src) > 1) {                           \
		EMSG("Assertion failed at line %d in file:\n%s",               \
			__LINE__, __FILE__);                                   \
		EMSG("size > 1, cannot be equal to a short.");                 \
		HALT;                                                          \
	} else if (                                                            \
		(int)(__mpanum_lsw((mpanum)src)*__mpanum_sign((mpanum)src)) != \
			(int)(short)) {                                        \
		EMSG("Assertion failed at line %d in file:\n%s",               \
				__LINE__, __FILE__);                           \
		EMSG("short == %d, but src == %d", (short),                    \
			(int)(__mpanum_lsw((mpanum)src)                        \
			*__mpanum_sign((mpanum)src)));                         \
		HALT;                                                          \
	};                                                                     \
} while (0)

/*
 * TB_ASSERT_STR_EQ checks that the two strings a and b are equal.
 */
#define TB_ASSERT_STR_EQ(a, b)                                  \
do {                                                            \
	if (my_strcmp((a), (b)) != 0) {                         \
		EMSG("Assertion failed %s != %s", (a), (b));    \
		HALT;                                           \
	};                                                      \
} while (0)

/*
 * TB_ASSERT_POINTER_NULL(p) checks that p is null
 */
#define TB_ASSERT_POINTER_NULL(p)                                  \
do {                                                               \
	if ((p) != 0) {                                            \
		EMSG("Assertion failed, pointer was not null.");   \
		HALT;                                              \
	};                                                         \
} while (0)

/*
 * TB_ASSERT_POINTERS_EQ checks that p, q are pointing to the same element
 */
#define TB_ASSERT_POINTERS_EQ(p, q)                                  \
do {                                                                 \
	if ((p) != (q)) {                                            \
		EMSG("Assertion failed, pointers are not equal.");   \
		HALT;                                                \
	};                                                           \
} while (0)

/*
 * TB_ASSERT_POINTERS_NEQ checks that p, q are not pointing to the same element
 */
#define TB_ASSERT_POINTERS_NEQ(p, q)                             \
do {                                                             \
	if ((p) == (q)) {                                        \
		EMSG("Assertion failed, pointers are equal.");   \
		HALT;                                            \
	};                                                       \
} while (0)

/*
 * TB_ASSERT_BIGINT_EQ Checks that a and b are equal
 */
#define TB_ASSERT_BIGINT_EQ(a, b)                                   \
do {                                                                \
	if (TEE_BigIntCmp((a), (b)) != 0) {                         \
		EMSG("Assertion failed, numbers are not equal.");   \
		HALT;                                               \
	};                                                          \
} while (0)

/*
 * TB_ASSERT_BIGINT_NEQ Checks that a and b are different
 */
#define TB_ASSERT_BIGINT_NEQ(a, b)                              \
do {                                                            \
	if (TEE_BigIntCmp((a), (b)) == 0) {                     \
		EMSG("Assertion failed, numbers are equal.");   \
		HALT;                                           \
	};                                                      \
} while (0)

/*
 * TB_ASSERT_BIGINT_LESS Checks that a < b
 */
#define TB_ASSERT_BIGINT_LESS(a, b)                                         \
do {                                                                        \
	if (TEE_BigIntCmp((a), (b)) >= 0) {                                 \
		EMSG("Assertion failed, first is not less than second.");   \
		HALT;                                                       \
	}; \
} while (0)

/*
 * TB_ASSERT_INT_EQ Checks that a and be are equal
 */
#define TB_ASSERT_INT_EQ(a, b)                                      \
do {                                                                \
	if ((a) != (b)) {                                           \
		EMSG("Assertion failed, numbers are not equal.");   \
		HALT;                                               \
	};                                                          \
} while (0)

#endif
