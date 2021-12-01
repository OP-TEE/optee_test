/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2021, Linaro Limited
 * All rights reserved.
 */

#ifndef TA_ARM_BTI_H
#define TA_ARM_BTI_H

#define TA_BTI_UUID { 0x3616069b, 0x504d, 0x4044, \
	{ 0x94, 0x97, 0xfe, 0xb8, 0x4a, 0x07, 0x3a, 0x14} }

/*
 * Commands implemented by the TA
 */
#define	TA_TEST_USING_BLR		0
#define	TA_TEST_USING_BR		1
#define	TA_TEST_USING_BR_X16		2
#define	TA_FEAT_BTI_IMPLEMENTED		3

/*
 * Parameter values
 */
#define	TA_FUNC_BTI_C			0
#define	TA_FUNC_BTI_J			1
#define	TA_FUNC_BTI_JC			2
#define	TA_FUNC_BTI_NONE		3

#endif /* TA_ARM_BTI_H */
