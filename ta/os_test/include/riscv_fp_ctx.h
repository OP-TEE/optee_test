/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026, RISCStar Solutions Limited
 */

#ifndef RISCV_FP_CTX_H
#define RISCV_FP_CTX_H

#if defined(__riscv_flen) && __riscv_flen == 64

/*
 * Number of callee-saved f registers preserved by the RISC-V calling
 * convention: fs0..fs11. Also the index riscv_fp_ctx_diff() returns to mean
 * "only fcsr differs".
 */
#define RISCV_FP_NUM_FS		12

/*
 * Offsets into struct riscv_fp_ctx, shared with riscv_fp_ctx_rv64.S so the
 * assembly does not hard-code them. The static_assert()s below check that the
 * struct actually has this layout.
 */
#define RISCV_FP_CTX_FS_OFF	0
#define RISCV_FP_CTX_FCSR_OFF	(RISCV_FP_NUM_FS * 8)

#ifndef __ASSEMBLER__

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <tee_api_types.h>

/*
 * The floating-point state the RISC-V calling convention requires a callee
 * to preserve. Everything else, ft0..ft11 and fa0..fa7, may legitimately be
 * clobbered by a call, so a caller cannot tell a context switching bug from
 * a compiler doing what the ABI allows and those registers are left out of
 * these checks.
 *
 * The layout is shared with riscv_fp_ctx_rv64.S.
 */
struct riscv_fp_ctx {
	uint64_t fs[RISCV_FP_NUM_FS];	/* fs0..fs11 */
	uint32_t fcsr;
};

/*
 * Installs @in, calls fn(arg), stores what is left of the context in @out
 * and returns what fn returned. The caller's own context is preserved.
 */
TEE_Result riscv_fp_ctx_roundtrip(const struct riscv_fp_ctx *in,
				  struct riscv_fp_ctx *out,
				  TEE_Result (*fn)(void *), void *arg);

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
void riscv_fp_ctx_pattern(struct riscv_fp_ctx *ctx, uint32_t seed);

/*
 * Returns the index of the first field of @a that differs from @b,
 * RISCV_FP_NUM_FS if only fcsr differs, and -1 if the two contexts are
 * identical.
 */
int riscv_fp_ctx_diff(const struct riscv_fp_ctx *a,
		      const struct riscv_fp_ctx *b);

/*
 * riscv_fp_ctx_roundtrip(), riscv_fp_ctx_load() and riscv_fp_ctx_store() are
 * implemented in riscv_fp_ctx_rv64.S: the values have to be sitting in
 * fs0..fs11 across a call, which C cannot guarantee. That file uses the
 * RISCV_FP_CTX_*_OFF offsets above; these asserts keep the struct in sync.
 */
static_assert(offsetof(struct riscv_fp_ctx, fs) == RISCV_FP_CTX_FS_OFF,
	      "riscv_fp_ctx layout out of sync with riscv_fp_ctx_rv64.S");
static_assert(offsetof(struct riscv_fp_ctx, fcsr) == RISCV_FP_CTX_FCSR_OFF,
	      "riscv_fp_ctx layout out of sync with riscv_fp_ctx_rv64.S");

#endif /* !__ASSEMBLER__ */

#endif /* __riscv_flen == 64 */
#endif /* RISCV_FP_CTX_H */
