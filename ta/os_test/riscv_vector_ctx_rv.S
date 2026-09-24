/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, RISCStar Solutions Limited
 */

#include <asm.S>

/*
 * Assembly helpers for the RISC-V vector context test. The values have to
 * stay in the vector registers across the call, so these are written in
 * assembly: from C the compiler would be free to keep them in memory
 * instead, which would test nothing. The layout matches
 * struct riscv_vector_ctx in riscv_vector_ctx.h:
 *	  0	vl
 *	  8	vtype
 *	 16	vcsr
 *	 24	vstart
 *	 32	vregs
 *
 * The vector ISA is enabled per block with .option arch, so this file needs
 * no -march override.
 */

/* unsigned long riscv_vector_ctx_vlenb(void) */
FUNC riscv_vector_ctx_vlenb , :
	csrr	a0, 0xc22		/* vlenb */
	ret
END_FUNC riscv_vector_ctx_vlenb

/* void riscv_vector_ctx_load(const struct riscv_vector_ctx *in) */
FUNC riscv_vector_ctx_load , :
	.option push
	.option arch, +v
	/* The whole-register loads honour vstart, so start them from zero */
	csrw	0x008, zero		/* vstart */
	csrr	t2, 0xc22		/* vlenb */
	slli	t2, t2, 3		/* eight registers at a time */
	addi	t1, a0, 32		/* ctx->vregs */
	vl8r.v	v0, (t1)
	add	t1, t1, t2
	vl8r.v	v8, (t1)
	add	t1, t1, t2
	vl8r.v	v16, (t1)
	add	t1, t1, t2
	vl8r.v	v24, (t1)
	/* vl and vtype are read only, put back by re-running their vsetvl */
	ld	t0, 0(a0)		/* ctx->vl */
	ld	t3, 8(a0)		/* ctx->vtype */
	vsetvl	zero, t0, t3
	ld	t0, 16(a0)		/* ctx->vcsr */
	csrw	0x00f, t0		/* vcsr */
	ld	t0, 24(a0)		/* ctx->vstart */
	csrw	0x008, t0		/* vstart */
	.option pop
	ret
END_FUNC riscv_vector_ctx_load

/* void riscv_vector_ctx_store(struct riscv_vector_ctx *out) */
FUNC riscv_vector_ctx_store , :
	.option push
	.option arch, +v
	/* Take the CSRs before vstart is cleared for the transfer */
	csrr	t0, 0xc20		/* vl */
	sd	t0, 0(a0)
	csrr	t0, 0xc21		/* vtype */
	sd	t0, 8(a0)
	csrr	t0, 0x00f		/* vcsr */
	sd	t0, 16(a0)
	csrr	t0, 0x008		/* vstart */
	sd	t0, 24(a0)
	csrw	0x008, zero		/* vstart */
	csrr	t2, 0xc22		/* vlenb */
	slli	t2, t2, 3
	addi	t1, a0, 32		/* ctx->vregs */
	vs8r.v	v0, (t1)
	add	t1, t1, t2
	vs8r.v	v8, (t1)
	add	t1, t1, t2
	vs8r.v	v16, (t1)
	add	t1, t1, t2
	vs8r.v	v24, (t1)
	.option pop
	ret
END_FUNC riscv_vector_ctx_store

/*
 * unsigned long riscv_vector_ctx_roundtrip(const struct riscv_vector_ctx *in,
 *					    struct riscv_vector_ctx *out,
 *					    unsigned long (*fn)(void *),
 *					    void *arg)
 */
FUNC riscv_vector_ctx_roundtrip , :
	addi	sp, sp, -32
	sd	ra, 0(sp)
	sd	s0, 8(sp)
	sd	s1, 16(sp)
	mv	s0, a1			/* out */
	mv	s1, a2			/* fn */
	call	riscv_vector_ctx_load
	mv	a0, a3			/* arg */
	jalr	s1
	mv	s1, a0			/* fn return value */
	mv	a0, s0
	call	riscv_vector_ctx_store
	mv	a0, s1
	ld	ra, 0(sp)
	ld	s0, 8(sp)
	ld	s1, 16(sp)
	addi	sp, sp, 32
	ret
END_FUNC riscv_vector_ctx_roundtrip

/*
 * unsigned long riscv_vector_ctx_syscall(const struct riscv_vector_ctx *in,
 *					  struct riscv_vector_ctx *out,
 *					  unsigned long scn, unsigned long arg)
 */
FUNC riscv_vector_ctx_syscall , :
	addi	sp, sp, -32
	sd	ra, 0(sp)
	sd	s0, 8(sp)
	sd	s1, 16(sp)
	sd	s2, 24(sp)
	mv	s0, a1			/* out */
	mv	s1, a2			/* syscall number */
	mv	s2, a3			/* syscall argument */
	call	riscv_vector_ctx_load
	/* The OP-TEE syscall ABI: t0 holds the number, t1 the argument count */
	mv	a0, s2
	mv	t0, s1
	li	t1, 1
	ecall
	mv	s1, a0			/* syscall return value */
	mv	a0, s0
	call	riscv_vector_ctx_store
	mv	a0, s1
	ld	ra, 0(sp)
	ld	s0, 8(sp)
	ld	s1, 16(sp)
	ld	s2, 24(sp)
	addi	sp, sp, 32
	ret
END_FUNC riscv_vector_ctx_syscall
