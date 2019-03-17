/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2019, Linaro Limited
 */

#ifndef _OS_TEST_LIB_DL_H_
#define _OS_TEST_LIB_DL_H_

#if defined(CFG_TA_DL)

int os_test_shlib_dl_add(int a, int b);
void os_test_shlib_dl_panic(void);

#else

#include <compiler.h>
#include <tee_internal_api.h>

static inline int os_test_shlib_dl_add(int a __unused, int b __unused)
{
	TEE_Panic(0);
	return 0;
}

static inline void os_test_shlib_dl_panic(void)
{
}

#endif /* CFG_TA_DL */

#endif /* _OS_TEST_LIB_DL_H_ */
