/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, RISCStar Solutions Limited
 */

#ifndef RISCV_FP_CTX_H
#define RISCV_FP_CTX_H

#if defined(__riscv) && defined(__riscv_flen) && __riscv_flen == 64
#define RISCV_FP_CTX_SUPPORTED	1

#include <stddef.h>
#include <stdint.h>

/*
 * The floating-point state the RISC-V calling convention requires a callee
 * to preserve. Everything else, ft0..ft11 and fa0..fa7, may legitimately be
 * clobbered by a call, so a caller cannot tell a context switching bug from
 * a compiler doing what the ABI allows and those registers are left out of
 * these checks.
 *
 * The layout is shared with riscv_fp_rv64.S.
 */
struct riscv_fp_ctx {
	uint64_t fs[12];	/* fs0..fs11 */
	uint32_t fcsr;
};

/*
 * Installs @in, calls fn(arg), stores what is left of the context in @out
 * and returns what fn returned. The caller's own context is preserved.
 */
unsigned long riscv_fp_ctx_roundtrip(const struct riscv_fp_ctx *in,
				     struct riscv_fp_ctx *out,
				     unsigned long (*fn)(void *), void *arg);

/*
 * Installs @in and returns with it still in the registers. This breaks the
 * calling convention on purpose, the caller must have no live
 * floating-point values of its own.
 */
void riscv_fp_ctx_load(const struct riscv_fp_ctx *in);

/* Stores the current context to @out without changing it */
void riscv_fp_ctx_store(struct riscv_fp_ctx *out);

/*
 * Fills @ctx with a value per register that is distinct, derived from
 * @seed, and a finite double rather than a NaN or an infinity so that
 * nothing traps should a value reach an arithmetic instruction. fcsr gets a
 * rounding mode and accrued exception flags that differ from the reset
 * value, so that a save or restore which forgets fcsr is caught too.
 */
static inline void riscv_fp_ctx_pattern(struct riscv_fp_ctx *ctx,
					uint32_t seed)
{
	size_t n = 0;

	for (n = 0; n < sizeof(ctx->fs) / sizeof(ctx->fs[0]); n++)
		ctx->fs[n] = ((uint64_t)(0x3fd0 + n) << 48) |
			     ((uint64_t)seed << 16) | (n + 1);

	/*
	 * frm = 2, round down, which differs from the reset value, and all
	 * five accrued exception flags set. The flags are sticky and are
	 * only ever cleared explicitly, so starting from all ones keeps the
	 * comparison from tripping over a called function that happens to
	 * do some arithmetic of its own, while a save or restore that drops
	 * fcsr altogether still shows up.
	 */
	ctx->fcsr = (2 << 5) | 0x1f;
}

/*
 * Returns the index of the first field of @a that differs from @b, 12 if
 * only fcsr differs, and -1 if the two contexts are identical.
 */
static inline int riscv_fp_ctx_diff(const struct riscv_fp_ctx *a,
				    const struct riscv_fp_ctx *b)
{
	size_t n = 0;

	for (n = 0; n < sizeof(a->fs) / sizeof(a->fs[0]); n++)
		if (a->fs[n] != b->fs[n])
			return (int)n;

	if (a->fcsr != b->fcsr)
		return 12;

	return -1;
}

/*
 * The three routines above are written in assembly because the whole point
 * is to have the values actually sitting in fs0..fs11 across a call, and
 * from C the compiler would be free to keep them on the stack instead,
 * which would test nothing.
 *
 * They are emitted here, rather than from a .S file, so that the same
 * implementation serves the TA and xtest without either build system
 * needing to grow an assembler rule. Exactly one translation unit per
 * binary must define RISCV_FP_CTX_IMPLEMENTATION before including this.
 *
 * Comments inside the block use '#' rather than C syntax: these strings do
 * not go through the preprocessor the way a .S file does, so the assembler
 * sees them verbatim, and Clang's integrated assembler rejects a comment
 * in the C form.
 *
 * Stack frame of riscv_fp_ctx_roundtrip():
 *	   0	ra
 *	   8	s0
 *	  16	caller's fcsr
 *	  24	caller's fs0..fs11
 */
#ifdef RISCV_FP_CTX_IMPLEMENTATION
_Static_assert(offsetof(struct riscv_fp_ctx, fs) == 0,
	       "riscv_fp_ctx layout out of sync with the assembly below");
_Static_assert(offsetof(struct riscv_fp_ctx, fcsr) == 96,
	       "riscv_fp_ctx layout out of sync with the assembly below");

__asm__(
"	.text\n"
"\n"
"	.globl	riscv_fp_ctx_roundtrip\n"
"	.type	riscv_fp_ctx_roundtrip, @function\n"
"riscv_fp_ctx_roundtrip:\n"
"	addi	sp, sp, -128\n"
"	sd	ra, 0(sp)\n"
"	sd	s0, 8(sp)\n"
"	# Preserve the caller's own context before overwriting it\n"
"	frcsr	t0\n"
"	sw	t0, 16(sp)\n"
"	fsd	fs0, 24(sp)\n"
"	fsd	fs1, 32(sp)\n"
"	fsd	fs2, 40(sp)\n"
"	fsd	fs3, 48(sp)\n"
"	fsd	fs4, 56(sp)\n"
"	fsd	fs5, 64(sp)\n"
"	fsd	fs6, 72(sp)\n"
"	fsd	fs7, 80(sp)\n"
"	fsd	fs8, 88(sp)\n"
"	fsd	fs9, 96(sp)\n"
"	fsd	fs10, 104(sp)\n"
"	fsd	fs11, 112(sp)\n"
"	mv	s0, a1			# out\n"
"	mv	t1, a2			# fn\n"
"	# Install the pattern taken from *in\n"
"	fld	fs0, 0(a0)\n"
"	fld	fs1, 8(a0)\n"
"	fld	fs2, 16(a0)\n"
"	fld	fs3, 24(a0)\n"
"	fld	fs4, 32(a0)\n"
"	fld	fs5, 40(a0)\n"
"	fld	fs6, 48(a0)\n"
"	fld	fs7, 56(a0)\n"
"	fld	fs8, 64(a0)\n"
"	fld	fs9, 72(a0)\n"
"	fld	fs10, 80(a0)\n"
"	fld	fs11, 88(a0)\n"
"	lw	t0, 96(a0)\n"
"	fscsr	t0\n"
"	mv	a0, a3			# arg\n"
"	jalr	t1\n"
"	# Capture what survived, fn's return value stays in a0\n"
"	fsd	fs0, 0(s0)\n"
"	fsd	fs1, 8(s0)\n"
"	fsd	fs2, 16(s0)\n"
"	fsd	fs3, 24(s0)\n"
"	fsd	fs4, 32(s0)\n"
"	fsd	fs5, 40(s0)\n"
"	fsd	fs6, 48(s0)\n"
"	fsd	fs7, 56(s0)\n"
"	fsd	fs8, 64(s0)\n"
"	fsd	fs9, 72(s0)\n"
"	fsd	fs10, 80(s0)\n"
"	fsd	fs11, 88(s0)\n"
"	frcsr	t0\n"
"	sw	t0, 96(s0)\n"
"	# Put the caller's own context back\n"
"	fld	fs0, 24(sp)\n"
"	fld	fs1, 32(sp)\n"
"	fld	fs2, 40(sp)\n"
"	fld	fs3, 48(sp)\n"
"	fld	fs4, 56(sp)\n"
"	fld	fs5, 64(sp)\n"
"	fld	fs6, 72(sp)\n"
"	fld	fs7, 80(sp)\n"
"	fld	fs8, 88(sp)\n"
"	fld	fs9, 96(sp)\n"
"	fld	fs10, 104(sp)\n"
"	fld	fs11, 112(sp)\n"
"	lw	t0, 16(sp)\n"
"	fscsr	t0\n"
"	ld	ra, 0(sp)\n"
"	ld	s0, 8(sp)\n"
"	addi	sp, sp, 128\n"
"	ret\n"
"	.size	riscv_fp_ctx_roundtrip, .-riscv_fp_ctx_roundtrip\n"
"\n"
"	.globl	riscv_fp_ctx_load\n"
"	.type	riscv_fp_ctx_load, @function\n"
"riscv_fp_ctx_load:\n"
"	fld	fs0, 0(a0)\n"
"	fld	fs1, 8(a0)\n"
"	fld	fs2, 16(a0)\n"
"	fld	fs3, 24(a0)\n"
"	fld	fs4, 32(a0)\n"
"	fld	fs5, 40(a0)\n"
"	fld	fs6, 48(a0)\n"
"	fld	fs7, 56(a0)\n"
"	fld	fs8, 64(a0)\n"
"	fld	fs9, 72(a0)\n"
"	fld	fs10, 80(a0)\n"
"	fld	fs11, 88(a0)\n"
"	lw	t0, 96(a0)\n"
"	fscsr	t0\n"
"	ret\n"
"	.size	riscv_fp_ctx_load, .-riscv_fp_ctx_load\n"
"\n"
"	.globl	riscv_fp_ctx_store\n"
"	.type	riscv_fp_ctx_store, @function\n"
"riscv_fp_ctx_store:\n"
"	fsd	fs0, 0(a0)\n"
"	fsd	fs1, 8(a0)\n"
"	fsd	fs2, 16(a0)\n"
"	fsd	fs3, 24(a0)\n"
"	fsd	fs4, 32(a0)\n"
"	fsd	fs5, 40(a0)\n"
"	fsd	fs6, 48(a0)\n"
"	fsd	fs7, 56(a0)\n"
"	fsd	fs8, 64(a0)\n"
"	fsd	fs9, 72(a0)\n"
"	fsd	fs10, 80(a0)\n"
"	fsd	fs11, 88(a0)\n"
"	frcsr	t0\n"
"	sw	t0, 96(a0)\n"
"	ret\n"
"	.size	riscv_fp_ctx_store, .-riscv_fp_ctx_store\n"
);
#endif /* RISCV_FP_CTX_IMPLEMENTATION */

#endif /* __riscv && __riscv_flen == 64 */
#endif /* RISCV_FP_CTX_H */
