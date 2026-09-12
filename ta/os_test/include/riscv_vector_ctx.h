/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, RISCStar Solutions Limited
 */

#ifndef RISCV_VECTOR_CTX_H
#define RISCV_VECTOR_CTX_H

#if defined(__riscv) && defined(__riscv_v)
#define RISCV_VECTOR_CTX_SUPPORTED	1

#include <stddef.h>
#include <stdint.h>

/*
 * Widest vector register these tests are built for. VLEN is discovered at
 * run time from vlenb, so the buffers are sized for the largest register
 * width worth carrying and only the first vlenb bytes of each register are
 * ever looked at.
 */
#define RISCV_VECTOR_CTX_VLENB_MAX	128
#define RISCV_VECTOR_CTX_NUM_REGS	32

/*
 * Unlike the floating-point calling convention, the vector one has no
 * callee-saved vector registers at all: v0..v31 and the vector CSRs may
 * legitimately be clobbered by any call. A test therefore cannot check the
 * vector context across an ordinary C call and learn anything, which is why
 * riscv_vector_ctx_syscall() below reaches the TEE through a bare ecall
 * with no compiler-generated code between installing the context and
 * reading it back.
 *
 * The layout is shared with the assembly at the bottom of this header:
 *	  0	vl
 *	  8	vtype
 *	 16	vcsr
 *	 24	vstart
 *	 32	vregs
 */
struct riscv_vector_ctx {
	unsigned long vl;
	unsigned long vtype;
	unsigned long vcsr;
	unsigned long vstart;
	uint8_t vregs[RISCV_VECTOR_CTX_NUM_REGS * RISCV_VECTOR_CTX_VLENB_MAX];
};

/* Width of one vector register in bytes. Traps if vector is disabled. */
unsigned long riscv_vector_ctx_vlenb(void);

/* Installs @in, leaving it in the registers */
void riscv_vector_ctx_load(const struct riscv_vector_ctx *in);

/* Reads the live context into @out */
void riscv_vector_ctx_store(struct riscv_vector_ctx *out);

/*
 * Installs @in, calls fn(arg), reads the result back into @out and returns
 * what fn returned. Any vector register may be clobbered by the call, so
 * this only says something when the caller knows what fn does.
 */
unsigned long riscv_vector_ctx_roundtrip(const struct riscv_vector_ctx *in,
					 struct riscv_vector_ctx *out,
					 unsigned long (*fn)(void *),
					 void *arg);

/*
 * Installs @in, issues OP-TEE syscall @scn with the single argument @arg
 * through a bare ecall, reads the result back into @out and returns what
 * the syscall returned. Nothing the compiler generated runs in between, so
 * every vector register has to come back exactly as it went in. TA only.
 */
unsigned long riscv_vector_ctx_syscall(const struct riscv_vector_ctx *in,
				       struct riscv_vector_ctx *out,
				       unsigned long scn, unsigned long arg);

/*
 * Fills @ctx with a byte pattern that is distinct per register and derived
 * from @seed, and a vl, vtype and vcsr that differ from the reset values so
 * that a save or restore which drops the CSRs is caught too.
 */
static inline void riscv_vector_ctx_pattern(struct riscv_vector_ctx *ctx,
					    uint32_t seed, unsigned long vlenb)
{
	size_t reg = 0;
	size_t n = 0;

	for (reg = 0; reg < RISCV_VECTOR_CTX_NUM_REGS; reg++)
		for (n = 0; n < vlenb; n++)
			ctx->vregs[reg * vlenb + n] =
				(uint8_t)(seed + reg * 7 + n);

	/*
	 * SEW=8, LMUL=1, tail and mask agnostic, which is what a vsetvli
	 * of e8, m1, ta, ma produces, with vl set to one register's worth
	 * of elements.
	 */
	ctx->vtype = (1UL << 7) | (1UL << 6);
	ctx->vl = vlenb;
	ctx->vcsr = 0x7;
	ctx->vstart = 0;
}

/*
 * Returns the index of the first vector register whose first @vlenb bytes
 * differ, RISCV_VECTOR_CTX_NUM_REGS for a CSR mismatch, and -1 if the two
 * contexts agree.
 */
static inline int riscv_vector_ctx_diff(const struct riscv_vector_ctx *a,
					const struct riscv_vector_ctx *b,
					unsigned long vlenb)
{
	size_t reg = 0;
	size_t n = 0;

	for (reg = 0; reg < RISCV_VECTOR_CTX_NUM_REGS; reg++)
		for (n = 0; n < vlenb; n++)
			if (a->vregs[reg * vlenb + n] !=
			    b->vregs[reg * vlenb + n])
				return (int)reg;

	if (a->vl != b->vl || a->vtype != b->vtype || a->vcsr != b->vcsr)
		return RISCV_VECTOR_CTX_NUM_REGS;

	return -1;
}

/*
 * The routines above are in assembly because the whole point is to have the
 * values actually sitting in the vector registers across the excursion, and
 * from C the compiler would be free to keep them in memory instead, which
 * would test nothing.
 *
 * They are emitted from this header rather than a .S file so that the same
 * implementation serves the TA and xtest without either build growing an
 * assembler rule. Exactly one translation unit per binary must define
 * RISCV_VECTOR_CTX_IMPLEMENTATION before including this.
 *
 * The vector ISA is enabled per block with .option arch, so no -march
 * override is needed anywhere, and comments use '#' rather than C syntax:
 * these strings do not go through the preprocessor the way a .S file does,
 * and Clang's integrated assembler rejects a comment in the C form.
 */
#ifdef RISCV_VECTOR_CTX_IMPLEMENTATION
_Static_assert(offsetof(struct riscv_vector_ctx, vl) == 0,
	       "riscv_vector_ctx layout out of sync with the assembly below");
_Static_assert(offsetof(struct riscv_vector_ctx, vregs) == 32,
	       "riscv_vector_ctx layout out of sync with the assembly below");

__asm__(
"	.text\n"
"\n"
"	.globl	riscv_vector_ctx_vlenb\n"
"	.type	riscv_vector_ctx_vlenb, @function\n"
"riscv_vector_ctx_vlenb:\n"
"	csrr	a0, 0xc22		# vlenb\n"
"	ret\n"
"	.size	riscv_vector_ctx_vlenb, .-riscv_vector_ctx_vlenb\n"
"\n"
"	.globl	riscv_vector_ctx_load\n"
"	.type	riscv_vector_ctx_load, @function\n"
"riscv_vector_ctx_load:\n"
"	.option push\n"
"	.option arch, +v\n"
"	# The whole-register loads honour vstart, so start them from zero\n"
"	csrw	0x008, zero		# vstart\n"
"	csrr	t2, 0xc22		# vlenb\n"
"	slli	t2, t2, 3		# eight registers at a time\n"
"	addi	t1, a0, 32		# ctx->vregs\n"
"	vl8r.v	v0, (t1)\n"
"	add	t1, t1, t2\n"
"	vl8r.v	v8, (t1)\n"
"	add	t1, t1, t2\n"
"	vl8r.v	v16, (t1)\n"
"	add	t1, t1, t2\n"
"	vl8r.v	v24, (t1)\n"
"	# vl and vtype are read only, put back by re-running their vsetvl\n"
"	ld	t0, 0(a0)		# ctx->vl\n"
"	ld	t3, 8(a0)		# ctx->vtype\n"
"	vsetvl	zero, t0, t3\n"
"	ld	t0, 16(a0)		# ctx->vcsr\n"
"	csrw	0x00f, t0		# vcsr\n"
"	ld	t0, 24(a0)		# ctx->vstart\n"
"	csrw	0x008, t0		# vstart\n"
"	.option pop\n"
"	ret\n"
"	.size	riscv_vector_ctx_load, .-riscv_vector_ctx_load\n"
"\n"
"	.globl	riscv_vector_ctx_store\n"
"	.type	riscv_vector_ctx_store, @function\n"
"riscv_vector_ctx_store:\n"
"	.option push\n"
"	.option arch, +v\n"
"	# Take the CSRs before vstart is cleared for the transfer\n"
"	csrr	t0, 0xc20		# vl\n"
"	sd	t0, 0(a0)\n"
"	csrr	t0, 0xc21		# vtype\n"
"	sd	t0, 8(a0)\n"
"	csrr	t0, 0x00f		# vcsr\n"
"	sd	t0, 16(a0)\n"
"	csrr	t0, 0x008		# vstart\n"
"	sd	t0, 24(a0)\n"
"	csrw	0x008, zero		# vstart\n"
"	csrr	t2, 0xc22		# vlenb\n"
"	slli	t2, t2, 3\n"
"	addi	t1, a0, 32		# ctx->vregs\n"
"	vs8r.v	v0, (t1)\n"
"	add	t1, t1, t2\n"
"	vs8r.v	v8, (t1)\n"
"	add	t1, t1, t2\n"
"	vs8r.v	v16, (t1)\n"
"	add	t1, t1, t2\n"
"	vs8r.v	v24, (t1)\n"
"	.option pop\n"
"	ret\n"
"	.size	riscv_vector_ctx_store, .-riscv_vector_ctx_store\n"
"\n"
"	.globl	riscv_vector_ctx_roundtrip\n"
"	.type	riscv_vector_ctx_roundtrip, @function\n"
"riscv_vector_ctx_roundtrip:\n"
"	addi	sp, sp, -32\n"
"	sd	ra, 0(sp)\n"
"	sd	s0, 8(sp)\n"
"	sd	s1, 16(sp)\n"
"	mv	s0, a1			# out\n"
"	mv	s1, a2			# fn\n"
"	call	riscv_vector_ctx_load\n"
"	mv	a0, a3			# arg\n"
"	jalr	s1\n"
"	mv	s1, a0			# fn return value\n"
"	mv	a0, s0\n"
"	call	riscv_vector_ctx_store\n"
"	mv	a0, s1\n"
"	ld	ra, 0(sp)\n"
"	ld	s0, 8(sp)\n"
"	ld	s1, 16(sp)\n"
"	addi	sp, sp, 32\n"
"	ret\n"
"	.size	riscv_vector_ctx_roundtrip, .-riscv_vector_ctx_roundtrip\n"
"\n"
"	.globl	riscv_vector_ctx_syscall\n"
"	.type	riscv_vector_ctx_syscall, @function\n"
"riscv_vector_ctx_syscall:\n"
"	addi	sp, sp, -32\n"
"	sd	ra, 0(sp)\n"
"	sd	s0, 8(sp)\n"
"	sd	s1, 16(sp)\n"
"	sd	s2, 24(sp)\n"
"	mv	s0, a1			# out\n"
"	mv	s1, a2			# syscall number\n"
"	mv	s2, a3			# syscall argument\n"
"	call	riscv_vector_ctx_load\n"
"	# The OP-TEE syscall ABI: t0 holds the number, t1 the argument count\n"
"	mv	a0, s2\n"
"	mv	t0, s1\n"
"	li	t1, 1\n"
"	ecall\n"
"	mv	s1, a0			# syscall return value\n"
"	mv	a0, s0\n"
"	call	riscv_vector_ctx_store\n"
"	mv	a0, s1\n"
"	ld	ra, 0(sp)\n"
"	ld	s0, 8(sp)\n"
"	ld	s1, 16(sp)\n"
"	ld	s2, 24(sp)\n"
"	addi	sp, sp, 32\n"
"	ret\n"
"	.size	riscv_vector_ctx_syscall, .-riscv_vector_ctx_syscall\n"
);
#endif /* RISCV_VECTOR_CTX_IMPLEMENTATION */

#endif /* __riscv && __riscv_v */
#endif /* RISCV_VECTOR_CTX_H */
