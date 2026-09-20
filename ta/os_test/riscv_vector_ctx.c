// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026, RISCStar Solutions Limited
 */

#include <riscv_vector_ctx.h>

#if defined(__riscv) && defined(__riscv_v)

#include <util.h>

/*
 * vtype for SEW=8, LMUL=1, tail and mask agnostic, which is what a vsetvli of
 * e8, m1, ta, ma produces. Bit 7 is vma and bit 6 is vta, both set so that a
 * save or restore which drops vtype is caught.
 */
#define RISCV_VTYPE_VMA		BIT(7)
#define RISCV_VTYPE_VTA		BIT(6)

/* vcsr: vxrm (bits 2:1) = 3 and vxsat (bit 0) = 1, both non-reset values. */
#define RISCV_VCSR_VXRM_RDN	SHIFT_U32(3, 1)
#define RISCV_VCSR_VXSAT	BIT(0)

/* Spreads the per-register seed so each register gets a distinct pattern. */
#define RISCV_VECTOR_CTX_REG_STRIDE	7

void riscv_vector_ctx_pattern(struct riscv_vector_ctx *ctx, uint32_t seed,
			      unsigned long vlenb)
{
	size_t reg = 0;
	size_t n = 0;

	for (reg = 0; reg < RISCV_VECTOR_CTX_NUM_REGS; reg++)
		for (n = 0; n < vlenb; n++)
			ctx->vregs[reg * vlenb + n] =
				seed + reg * RISCV_VECTOR_CTX_REG_STRIDE + n;

	ctx->vtype = RISCV_VTYPE_VMA | RISCV_VTYPE_VTA;
	ctx->vl = vlenb;
	ctx->vcsr = RISCV_VCSR_VXRM_RDN | RISCV_VCSR_VXSAT;
	ctx->vstart = 0;
}

int riscv_vector_ctx_diff(const struct riscv_vector_ctx *a,
			  const struct riscv_vector_ctx *b, unsigned long vlenb)
{
	size_t reg = 0;
	size_t n = 0;

	for (reg = 0; reg < RISCV_VECTOR_CTX_NUM_REGS; reg++)
		for (n = 0; n < vlenb; n++)
			if (a->vregs[reg * vlenb + n] != b->vregs[reg * vlenb + n])
				return reg;

	if (a->vl != b->vl || a->vtype != b->vtype || a->vcsr != b->vcsr)
		return RISCV_VECTOR_CTX_NUM_REGS;

	return -1;
}

#endif /* __riscv && __riscv_v */
