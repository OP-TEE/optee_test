/*
 * Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef TA_CONCURRENT_H
#define TA_CONCURRENT_H

/* This UUID is generated with the ITU-T UUID generator at
   http://www.itu.int/ITU-T/asn1/uuid.html */
#define TA_CONCURRENT_UUID { 0xe13010e0, 0x2ae1, 0x11e5, \
	{ 0x89, 0x6a, 0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b } }

struct ta_concurrent_shm {
	uint32_t active_count;
};

/*
 * Busy loops and updates max concurrency.  params[0].memref should contain
 * a struct ta_concurent_shm which can be used to tell how many instances
 * of this function is running in parallel.
 *
 * in/out	params[0].memref
 * in/out	params[1].value.a	(input) number times to calcule the hash
 * in/out	params[1].value.b	(output) max concurency
 */

#define TA_CONCURRENT_CMD_BUSY_LOOP	0

/*
 * Calculates a sha-256 hash over param[2].memref and stores the result in
 * params[3].memref. params[0].memref should contain a struct
 * ta_concurent_shm which can be used to tell how many instances of this
 * function is running in parallel.
 *
 * in/out	params[0].memref
 * in/out	params[1].value.a	(input) number times to calcule the hash
 * in/out	params[1].value.b	(output) max concurency
 * in		params[2].memref
 * out		params[3].memref
 */
#define TA_CONCURRENT_CMD_SHA256	1

#endif /*TA_OS_TEST_H */
