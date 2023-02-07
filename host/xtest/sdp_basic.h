/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 */

#ifndef XTEST_SDP_BASIC_H
#define XTEST_SDP_BASIC_H

#include <linux/dma-buf.h>
#include <linux/version.h>
#include <linux/dma-heap.h>
#define DEFAULT_HEAP_NAME	"/dev/dma_heap/sdp"

#include "ta_sdp_basic.h"

enum test_target_ta {
	TEST_NS_TO_TA,
	TEST_NS_TO_PTA,
	TEST_TA_TO_TA,
	TEST_TA_TO_PTA,
};

int allocate_dma_buffer(size_t size, const char *heap_name, int verbosity);
static inline int allocate_buffer(size_t size, const char *heap_name,
				  int verbosity)
{
	return allocate_dma_buffer(size, heap_name, verbosity);
}
int sdp_basic_test(enum test_target_ta ta,
			  size_t size, size_t loop, const char *heap_name,
			  int rnd_offset, int verbosity);

int sdp_out_of_bounds_memref_test(size_t size, const char *heap_name,
				  int verbosity);

#endif /* XTEST_SDP_BASIC_H */
