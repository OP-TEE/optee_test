/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2022, Linaro Limited
 */

#include <asm.S>

FUNC corrupt_pac , :
	paciasp
	/* Flip a random bit in PAC */
	eor lr, lr , 1 << 58
	autiasp
	ret
END_FUNC corrupt_pac

emit_aarch64_feature_1_and     GNU_PROPERTY_AARCH64_FEATURE_1_BTI
