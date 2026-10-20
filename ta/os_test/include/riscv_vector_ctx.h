/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, RISCStar Solutions Limited
 */

#ifndef RISCV_VECTOR_CTX_H
#define RISCV_VECTOR_CTX_H

#if defined(__riscv) && defined(__riscv_v)

/*
 * Widest vector register these tests are built for. VLEN is discovered at run
 * time from vlenb, so the buffers are sized for the largest register width
 * worth carrying and only the first vlenb bytes of each register are ever
 * looked at. RISCV_VECTOR_CTX_NUM_REGS is also the index riscv_vector_ctx_diff()
 * returns to mean "only the vector CSRs differ".
 */
#define RISCV_VECTOR_CTX_VLENB_MAX	128
#define RISCV_VECTOR_CTX_NUM_REGS	32

/*
 * Offsets into struct riscv_vector_ctx, shared with riscv_vector_ctx_rv64.S so
 * the assembly does not hard-code them. The static_assert()s below check that
 * the struct actually has this layout.
 */
#define RISCV_VECTOR_CTX_VL_OFF		0
#define RISCV_VECTOR_CTX_VTYPE_OFF	8
#define RISCV_VECTOR_CTX_VCSR_OFF	16
#define RISCV_VECTOR_CTX_VSTART_OFF	24
#define RISCV_VECTOR_CTX_VREGS_OFF	32

#ifndef __ASSEMBLER__

#include <assert.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Unlike the floating-point calling convention, the vector one has no
 * callee-saved vector registers at all: v0..v31 and the vector CSRs may
 * legitimately be clobbered by any call. A test therefore cannot check the
 * vector context across an ordinary C call and learn anything, which is why
 * riscv_vector_ctx_syscall() below reaches the TEE through a bare ecall with no
 * compiler-generated code between installing the context and reading it back.
 *
 * The layout is shared with riscv_vector_ctx_rv64.S.
 */
struct riscv_vector_ctx {
	uint64_t vl;
	uint64_t vtype;
	uint64_t vcsr;
	uint64_t vstart;
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
 * what fn returned. Any vector register may be clobbered by the call, so this
 * only says something when the caller knows what fn does.
 */
unsigned long riscv_vector_ctx_roundtrip(const struct riscv_vector_ctx *in,
					 struct riscv_vector_ctx *out,
					 unsigned long (*fn)(void *),
					 void *arg);

/*
 * Installs @in, issues OP-TEE syscall @scn with the single argument @arg
 * through a bare ecall, reads the result back into @out and returns what the
 * syscall returned. Nothing the compiler generated runs in between, so every
 * vector register has to come back exactly as it went in. TA only.
 */
unsigned long riscv_vector_ctx_syscall(const struct riscv_vector_ctx *in,
				       struct riscv_vector_ctx *out,
				       unsigned long scn, unsigned long arg);

/*
 * Fills @ctx with a byte pattern that is distinct per register and derived
 * from @seed, and a vl, vtype and vcsr that differ from the reset values so
 * that a save or restore which drops the CSRs is caught too.
 */
void riscv_vector_ctx_pattern(struct riscv_vector_ctx *ctx, uint32_t seed,
			      unsigned long vlenb);

/*
 * Returns the index of the first vector register whose first @vlenb bytes
 * differ, RISCV_VECTOR_CTX_NUM_REGS for a CSR mismatch, and -1 if the two
 * contexts agree.
 */
int riscv_vector_ctx_diff(const struct riscv_vector_ctx *a,
			  const struct riscv_vector_ctx *b, unsigned long vlenb);

/*
 * riscv_vector_ctx_vlenb(), _load(), _store(), _roundtrip() and _syscall() are
 * implemented in riscv_vector_ctx_rv64.S: the values have to stay in the vector
 * registers across the call, which C cannot guarantee. That file uses the
 * RISCV_VECTOR_CTX_*_OFF offsets above; these asserts keep the struct in sync.
 */
static_assert(offsetof(struct riscv_vector_ctx, vl) == RISCV_VECTOR_CTX_VL_OFF,
	      "riscv_vector_ctx layout out of sync with riscv_vector_ctx_rv64.S");
static_assert(offsetof(struct riscv_vector_ctx, vtype) ==
	      RISCV_VECTOR_CTX_VTYPE_OFF,
	      "riscv_vector_ctx layout out of sync with riscv_vector_ctx_rv64.S");
static_assert(offsetof(struct riscv_vector_ctx, vcsr) ==
	      RISCV_VECTOR_CTX_VCSR_OFF,
	      "riscv_vector_ctx layout out of sync with riscv_vector_ctx_rv64.S");
static_assert(offsetof(struct riscv_vector_ctx, vstart) ==
	      RISCV_VECTOR_CTX_VSTART_OFF,
	      "riscv_vector_ctx layout out of sync with riscv_vector_ctx_rv64.S");
static_assert(offsetof(struct riscv_vector_ctx, vregs) ==
	      RISCV_VECTOR_CTX_VREGS_OFF,
	      "riscv_vector_ctx layout out of sync with riscv_vector_ctx_rv64.S");

#endif /* !__ASSEMBLER__ */

#endif /* __riscv && __riscv_v */
#endif /* RISCV_VECTOR_CTX_H */
