/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2018, Linaro Limited
 */

#ifndef _OS_TEST_LIB_H_
#define _OS_TEST_LIB_H_

#if defined(CFG_TA_DYNLINK)

int os_test_shlib_add(int a, int b);
void os_test_shlib_panic(void);

#else

#include <compiler.h>
#include <tee_internal_api.h>

static inline int os_test_shlib_add(int a __unused, int b __unused)
{
	TEE_Panic(0);
	return 0;
}

static inline void os_test_shlib_panic(void)
{
}

#endif /* CFG_TA_DYNLINK */

#endif /* _OS_TEST_LIB_H_ */
