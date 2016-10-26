/*
 * Copyright (c) 2014, Linaro Limited
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#ifndef LATENCY_DEFINES_H
#define LATENCY_DEFINES_H

#include <inttypes.h>

/* max amount of timestamps */
#define TEE_BENCH_MAX_STAMPS	100
#define TEE_BENCH_RB_SIZE sizeof(struct tee_ringbuf) \
		+ sizeof(struct tee_time_st) * TEE_BENCH_MAX_STAMPS
#define TEE_BENCH_DEF_PARAM		3

/* OP-TEE susbsystems ids */
#define TEE_BENCH_CORE		0x00000001
#define TEE_BENCH_KMOD		0x00000002
#define TEE_BENCH_CLIENT	0x00000003
#define TEE_BENCH_DUMB_TA	0x10000001


/* storing timestamps */
struct tee_time_st {
	uint64_t cnt;		/* stores value from CNTPCT register */
	uint64_t addr;		/* stores value from program counter register */
	uint64_t src; 			/* OP-TEE subsystem id */
};

/* memory layout for shared memory, where timestamps will be stored */
struct tee_ringbuf {
	uint64_t tm_ind;		/* index of the last timestamp in stamps[] */
	struct tee_time_st stamps[];
};



/* Global ifdef for CFG_TEE_BENCHMARK */
#ifdef CFG_TEE_BENCHMARK
#define TEE_BENCH_PC(src) \
	asm volatile("mov %0, r15": "=r"(src));

#if defined(__GNUC__) && defined(__ARM_ARCH_7A__)
#define TEE_BENCH_TSC(src) \
	asm volatile("mrc p15, 0, %0, c9, c13, 0" : "=r"(src));
#else
#error Unsupported architecture/compiler!
#endif /* defined(__GNUC__) && defined(__ARM_ARCH_7A__) */

#define TEE_BENCH_DEFINE_RINGBUF(ringbuf_shm) \
	static TEEC_SharedMemory ringbuf_shm = { \
		.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT, \
		.buffer = NULL, \
		.size = TEE_BENCH_RB_SIZE \
	};

#define TEE_BENCH_ALLOC_RINGBUF(ringbuf_shm, ctx, exit_label) \
	do {				\
		TEEC_Result res_ring; \
		TEEC_SharedMemory *ringbuf_intr = ringbuf_shm; \
		res_ring = TEEC_AllocateSharedMemory(ctx, ringbuf_shm); \
		if (res_ring != TEEC_SUCCESS) goto exit_label; \
		memset(ringbuf_intr->buffer, 0, ringbuf_intr->size); \
	} while (0)

#define TEE_BENCH_FREE_RINGBUF(ringbuf_shm) \
	do { \
		TEEC_ReleaseSharedMemory(ringbuf_shm); \
	} while(0)

#define TEE_BENCH_ADD_TS(ringbuf_raw, source) \
	do { \
		struct tee_ringbuf *rng = (struct tee_ringbuf *)ringbuf_raw; \
		uint64_t ts_i; \
		if(rng->tm_ind >= TEE_BENCH_MAX_STAMPS) rng->tm_ind = 0; \
		ts_i = rng->tm_ind++; \
		TEE_BENCH_TSC(rng->stamps[ts_i].cnt); \
		TEE_BENCH_PC(rng->stamps[ts_i].addr); \
		rng->stamps[ts_i].src = source; \
	} while (0)

// TODO: add support of printing results if ringbuffer "overflows"
// This macro can be used only within NW app now
#define TEE_BENCH_PRINT_RES(ringbuf_raw) \
	do { \
		struct tee_ringbuf *rng = (struct tee_ringbuf *)ringbuf_raw; \
		for(uint32_t ts_i = 0; ts_i < rng->tm_ind; ts_i++) \
			printf("Cycle count = %" PRIu64 "\tSrc = %s\tPC = 0x%" PRIx64 \
			"\n", (rng->stamps[ts_i].cnt), \
			src_str(rng->stamps[ts_i].src), \
			(rng->stamps[ts_i].addr));	\
	} while(0)

#else /* CFG_TEE_BENCHMARK */
#define TEE_BENCH_ADD_TS(ringbuf_raw_, source) \
	do { \
		; \
	} while (0)
#endif /* CFG_TEE_BENCHMARK */
#endif /* LATENCY_DEFINES_H */
