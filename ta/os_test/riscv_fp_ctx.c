// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, RISCStar Solutions Limited
 */

#include <riscv_fp_ctx.h>

#if defined(__riscv_flen) && __riscv_flen == 64

#include <util.h>

/*
 * fcsr layout: bits [7:5] hold the rounding mode (frm), bits [4:0] the
 * accrued exception flags.
 */
#define RISCV_FCSR_FRM_SHIFT	5
#define RISCV_FCSR_FRM_RDN	2	/* round down; differs from reset */
#define RISCV_FCSR_FFLAGS_ALL	0x1f	/* all five accrued flags set */

void riscv_fp_ctx_pattern(struct riscv_fp_ctx *ctx, uint32_t seed)
{
	int n = 0;

	for (n = 0; n < RISCV_FP_NUM_FS; n++)
		ctx->fs[n] = SHIFT_U64(0x3fd0 + n, 48) |
			     SHIFT_U64(seed, 16) | (n + 1);

	/*
	 * frm = 2, round down, which differs from the reset value, and all
	 * five accrued exception flags set. The flags are sticky and are
	 * only ever cleared explicitly, so starting from all ones keeps the
	 * comparison from tripping over a called function that happens to
	 * do some arithmetic of its own, while a save or restore that drops
	 * fcsr altogether still shows up.
	 */
	ctx->fcsr = SHIFT_U32(RISCV_FCSR_FRM_RDN, RISCV_FCSR_FRM_SHIFT) |
		    RISCV_FCSR_FFLAGS_ALL;
}

int riscv_fp_ctx_diff(const struct riscv_fp_ctx *a,
		      const struct riscv_fp_ctx *b)
{
	int n = 0;

	for (n = 0; n < RISCV_FP_NUM_FS; n++)
		if (a->fs[n] != b->fs[n])
			return n;

	if (a->fcsr != b->fcsr)
		return RISCV_FP_NUM_FS;

	return -1;
}

#endif /* __riscv_flen == 64 */
