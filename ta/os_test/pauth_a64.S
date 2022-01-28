/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2022, Linaro Limited
 */

#include <asm.S>

/*
 * void corrupt_pac(void)
 *
 * The function corrupts a single bit of the PAC to ensure that the
 * authentication will fail. paciasp calculates and adds the PAC to the
 * link register and autiasp is used to authenticate the PAC.
 */
FUNC corrupt_pac , :
	paciasp
	/* Flip a random bit in PAC field of the return address */
	eor lr, lr , 1 << 58
	autiasp
	ret
END_FUNC corrupt_pac

emit_aarch64_feature_1_and     GNU_PROPERTY_AARCH64_FEATURE_1_BTI
