/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2022, Linaro Limited
 * All rights reserved.
 */

#ifndef TA_ARM_PAUTH_H
#define TA_ARM_PAUTH_H

#define TA_PAUTH_UUID	 { 0x999e4033, 0x3460, 0x4f67, \
	{ 0x92, 0x2e, 0x45, 0xe4, 0x15, 0x3f, 0xb2, 0x0e} }

/*
 * Commands implemented by the TA
 */
#define	TA_TEST_CORRUPT_PAC		0
#define	TA_TEST_NOP			1

#endif /* TA_ARM_PAUTH_H */
