/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, RISCStar Solutions Limited
 */

#include <asm.S>
#include <riscv_fp_ctx.h>

#if defined(__riscv_flen) && __riscv_flen == 64

/*
 * The whole point of these routines is to have the values actually sitting
 * in fs0..fs11 and fcsr across a call; from C the compiler would be free to
 * keep them on the stack instead, which would test nothing.
 *
 * They operate on struct riscv_fp_ctx (see riscv_fp_ctx.h) through the
 * RISCV_FP_CTX_*_OFF offsets it defines, so the layout lives in one place.
 *
 * Stack frame of riscv_fp_ctx_roundtrip():
 *	   0	ra
 *	   8	s0
 *	  16	caller's fcsr
 *	  24	caller's fs0..fs11
 */

/*
 * TEE_Result riscv_fp_ctx_roundtrip(const struct riscv_fp_ctx *in,
 *				     struct riscv_fp_ctx *out,
 *				     TEE_Result (*fn)(void *), void *arg);
 *
 * Installs *in, calls fn(arg), stores what is left of the context in *out
 * and returns what fn returned. The caller's own context is preserved.
 */
FUNC riscv_fp_ctx_roundtrip , :
	addi	sp, sp, -128
	sd	ra, 0(sp)
	sd	s0, 8(sp)
	/* Preserve the caller's own context before overwriting it */
	frcsr	t0
	sw	t0, 16(sp)
	fsd	fs0, 24(sp)
	fsd	fs1, 32(sp)
	fsd	fs2, 40(sp)
	fsd	fs3, 48(sp)
	fsd	fs4, 56(sp)
	fsd	fs5, 64(sp)
	fsd	fs6, 72(sp)
	fsd	fs7, 80(sp)
	fsd	fs8, 88(sp)
	fsd	fs9, 96(sp)
	fsd	fs10, 104(sp)
	fsd	fs11, 112(sp)
	mv	s0, a1			/* out */
	mv	t1, a2			/* fn */
	/* Install the pattern taken from *in */
	fld	fs0, (RISCV_FP_CTX_FS_OFF + 0)(a0)
	fld	fs1, (RISCV_FP_CTX_FS_OFF + 8)(a0)
	fld	fs2, (RISCV_FP_CTX_FS_OFF + 16)(a0)
	fld	fs3, (RISCV_FP_CTX_FS_OFF + 24)(a0)
	fld	fs4, (RISCV_FP_CTX_FS_OFF + 32)(a0)
	fld	fs5, (RISCV_FP_CTX_FS_OFF + 40)(a0)
	fld	fs6, (RISCV_FP_CTX_FS_OFF + 48)(a0)
	fld	fs7, (RISCV_FP_CTX_FS_OFF + 56)(a0)
	fld	fs8, (RISCV_FP_CTX_FS_OFF + 64)(a0)
	fld	fs9, (RISCV_FP_CTX_FS_OFF + 72)(a0)
	fld	fs10, (RISCV_FP_CTX_FS_OFF + 80)(a0)
	fld	fs11, (RISCV_FP_CTX_FS_OFF + 88)(a0)
	lw	t0, RISCV_FP_CTX_FCSR_OFF(a0)
	fscsr	t0
	mv	a0, a3			/* arg */
	jalr	t1
	/* Capture what survived, fn's return value stays in a0 */
	fsd	fs0, (RISCV_FP_CTX_FS_OFF + 0)(s0)
	fsd	fs1, (RISCV_FP_CTX_FS_OFF + 8)(s0)
	fsd	fs2, (RISCV_FP_CTX_FS_OFF + 16)(s0)
	fsd	fs3, (RISCV_FP_CTX_FS_OFF + 24)(s0)
	fsd	fs4, (RISCV_FP_CTX_FS_OFF + 32)(s0)
	fsd	fs5, (RISCV_FP_CTX_FS_OFF + 40)(s0)
	fsd	fs6, (RISCV_FP_CTX_FS_OFF + 48)(s0)
	fsd	fs7, (RISCV_FP_CTX_FS_OFF + 56)(s0)
	fsd	fs8, (RISCV_FP_CTX_FS_OFF + 64)(s0)
	fsd	fs9, (RISCV_FP_CTX_FS_OFF + 72)(s0)
	fsd	fs10, (RISCV_FP_CTX_FS_OFF + 80)(s0)
	fsd	fs11, (RISCV_FP_CTX_FS_OFF + 88)(s0)
	frcsr	t0
	sw	t0, RISCV_FP_CTX_FCSR_OFF(s0)
	/* Put the caller's own context back */
	fld	fs0, 24(sp)
	fld	fs1, 32(sp)
	fld	fs2, 40(sp)
	fld	fs3, 48(sp)
	fld	fs4, 56(sp)
	fld	fs5, 64(sp)
	fld	fs6, 72(sp)
	fld	fs7, 80(sp)
	fld	fs8, 88(sp)
	fld	fs9, 96(sp)
	fld	fs10, 104(sp)
	fld	fs11, 112(sp)
	lw	t0, 16(sp)
	fscsr	t0
	ld	ra, 0(sp)
	ld	s0, 8(sp)
	addi	sp, sp, 128
	ret
END_FUNC riscv_fp_ctx_roundtrip

/*
 * void riscv_fp_ctx_load(const struct riscv_fp_ctx *in);
 *
 * Installs *in and returns with it still in the registers. This breaks the
 * calling convention on purpose; the caller must have no live floating-point
 * values of its own.
 */
FUNC riscv_fp_ctx_load , :
	fld	fs0, (RISCV_FP_CTX_FS_OFF + 0)(a0)
	fld	fs1, (RISCV_FP_CTX_FS_OFF + 8)(a0)
	fld	fs2, (RISCV_FP_CTX_FS_OFF + 16)(a0)
	fld	fs3, (RISCV_FP_CTX_FS_OFF + 24)(a0)
	fld	fs4, (RISCV_FP_CTX_FS_OFF + 32)(a0)
	fld	fs5, (RISCV_FP_CTX_FS_OFF + 40)(a0)
	fld	fs6, (RISCV_FP_CTX_FS_OFF + 48)(a0)
	fld	fs7, (RISCV_FP_CTX_FS_OFF + 56)(a0)
	fld	fs8, (RISCV_FP_CTX_FS_OFF + 64)(a0)
	fld	fs9, (RISCV_FP_CTX_FS_OFF + 72)(a0)
	fld	fs10, (RISCV_FP_CTX_FS_OFF + 80)(a0)
	fld	fs11, (RISCV_FP_CTX_FS_OFF + 88)(a0)
	lw	t0, RISCV_FP_CTX_FCSR_OFF(a0)
	fscsr	t0
	ret
END_FUNC riscv_fp_ctx_load

/* void riscv_fp_ctx_store(struct riscv_fp_ctx *out); */
FUNC riscv_fp_ctx_store , :
	fsd	fs0, (RISCV_FP_CTX_FS_OFF + 0)(a0)
	fsd	fs1, (RISCV_FP_CTX_FS_OFF + 8)(a0)
	fsd	fs2, (RISCV_FP_CTX_FS_OFF + 16)(a0)
	fsd	fs3, (RISCV_FP_CTX_FS_OFF + 24)(a0)
	fsd	fs4, (RISCV_FP_CTX_FS_OFF + 32)(a0)
	fsd	fs5, (RISCV_FP_CTX_FS_OFF + 40)(a0)
	fsd	fs6, (RISCV_FP_CTX_FS_OFF + 48)(a0)
	fsd	fs7, (RISCV_FP_CTX_FS_OFF + 56)(a0)
	fsd	fs8, (RISCV_FP_CTX_FS_OFF + 64)(a0)
	fsd	fs9, (RISCV_FP_CTX_FS_OFF + 72)(a0)
	fsd	fs10, (RISCV_FP_CTX_FS_OFF + 80)(a0)
	fsd	fs11, (RISCV_FP_CTX_FS_OFF + 88)(a0)
	frcsr	t0
	sw	t0, RISCV_FP_CTX_FCSR_OFF(a0)
	ret
END_FUNC riscv_fp_ctx_store

#endif /* __riscv_flen == 64 */
