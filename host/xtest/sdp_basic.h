/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 */

#ifndef XTEST_SDP_BASIC_H
#define XTEST_SDP_BASIC_H

#include <linux/dma-buf.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
#include <linux/dma-heap.h>
#define DEFAULT_HEAP_TYPE	0
#define DEFAULT_HEAP_NAME	"/dev/dma_heap/sdp"
#else
#include "include/uapi/linux/ion.h"
#include "include/uapi/linux/ion_old.h"
#define DEFAULT_HEAP_TYPE	ION_HEAP_TYPE_UNMAPPED
#define DEFAULT_HEAP_NAME	"unmapped"
#endif

#include "ta_sdp_basic.h"

enum test_target_ta {
	TEST_NS_TO_TA,
	TEST_NS_TO_PTA,
	TEST_TA_TO_TA,
	TEST_TA_TO_PTA,
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
int allocate_dma_buffer(size_t size, const char *heap_name, int verbosity);
static inline int allocate_buffer(size_t size, const char *heap_name, int heap_id, int verbosity)
{
	return allocate_dma_buffer(size, heap_name, verbosity);
}
#else
int allocate_ion_buffer(size_t size, const char *heap_name, int heap_id, int verbosity);
static inline int allocate_buffer(size_t size, const char *heap_name, int heap_id, int verbosity)
{
	return allocate_ion_buffer(size, heap_name, heap_id, verbosity);
}
#endif
int sdp_basic_test(enum test_target_ta ta,
			  size_t size, size_t loop, const char *heap_name, int ion_heap,
			  int rnd_offset, int verbosity);

int sdp_out_of_bounds_memref_test(size_t size, const char *heap_name, int ion_heap, int verbosity);

#endif /* XTEST_SDP_BASIC_H */
