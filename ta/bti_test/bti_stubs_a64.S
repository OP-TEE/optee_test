/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2021, Linaro Limited
 */

#include <asm.S>

FUNC call_using_blr , : , , , no_bti
	bti	c
	stp     x29, x30, [sp, #-16]!
	blr     x0
	ldp     x29, x30, [sp], #16
	ret
END_FUNC call_using_blr

FUNC call_using_br , : , , , no_bti
	bti	c
	br	x0
END_FUNC call_using_br

FUNC call_using_br_x16 , : , , , no_bti
	bti	c
	mov 	x16, x0
	br	x16
END_FUNC call_using_br_x16

FUNC bti_j , : , , , no_bti
	bti	j
	ret
END_FUNC bti_j

FUNC bti_c , : , , , no_bti
	bti	c
	ret
END_FUNC bti_c

FUNC bti_jc , : , , , no_bti
	bti	jc
	ret
END_FUNC bti_jc

FUNC bti_none , : , , , no_bti
	ret
END_FUNC bti_none

emit_aarch64_feature_1_and     GNU_PROPERTY_AARCH64_FEATURE_1_BTI
