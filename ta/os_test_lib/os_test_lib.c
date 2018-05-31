// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018, Linaro Limited
 */

#include "os_test_lib.h"
#include <tee_internal_api.h>

int os_test_shlib_add(int a, int b)
{
	return a + b;
}

void os_test_shlib_panic(void)
{
	TEE_Panic(0);
}
