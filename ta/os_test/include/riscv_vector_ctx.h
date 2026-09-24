/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, RISCStar Solutions Limited
 */

#ifndef RISCV_VECTOR_CTX_H
#define RISCV_VECTOR_CTX_H

#if defined(__riscv) && defined(__riscv_v)
#define RISCV_VECTOR_CTX_SUPPORTED	1

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <util.h>

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
 * The layout is shared with the assembly in riscv_vector_ctx_rv.S:
 *	  0	vl
 *	  8	vtype
 *	 16	vcsr
 *	 24	vstart
 *	 32	vregs
 */
struct riscv_vector_ctx {
	uint64_t vl;
	uint64_t vtype;
	uint64_t vcsr;
	uint64_t vstart;
	uint8_t vregs[RISCV_VECTOR_CTX_NUM_REGS * RISCV_VECTOR_CTX_VLENB_MAX];
};

/* The offsets are hard-coded in riscv_vector_ctx_rv.S */
static_assert(offsetof(struct riscv_vector_ctx, vl) == 0, "vl offset");
static_assert(offsetof(struct riscv_vector_ctx, vtype) == 8, "vtype offset");
static_assert(offsetof(struct riscv_vector_ctx, vcsr) == 16, "vcsr offset");
static_assert(offsetof(struct riscv_vector_ctx, vstart) == 24, "vstart offset");
static_assert(offsetof(struct riscv_vector_ctx, vregs) == 32, "vregs offset");

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
			ctx->vregs[reg * vlenb + n] = seed + reg * 7 + n;

	/*
	 * SEW=8, LMUL=1, tail and mask agnostic, which is what a vsetvli
	 * of e8, m1, ta, ma produces, with vl set to one register's worth
	 * of elements. In vtype, bit 7 is vma and bit 6 is vta.
	 */
	ctx->vtype = BIT(7) | BIT(6);
	ctx->vl = vlenb;
	/* vcsr: vxrm = 3 (bits 2:1) and vxsat = 1 (bit 0), both non-reset */
	ctx->vcsr = BIT(2) | BIT(1) | BIT(0);
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
				return reg;

	if (a->vl != b->vl || a->vtype != b->vtype || a->vcsr != b->vcsr)
		return RISCV_VECTOR_CTX_NUM_REGS;

	return -1;
}

/*
 * riscv_vector_ctx_vlenb(), _load(), _store(), _roundtrip() and _syscall()
 * are implemented in assembly (riscv_vector_ctx_rv.S): the point is to keep
 * the values in the vector registers across the call, which from C the
 * compiler would be free to keep in memory instead.
 */

#endif /* __riscv && __riscv_v */
#endif /* RISCV_VECTOR_CTX_H */
