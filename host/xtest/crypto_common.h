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

#ifndef XTEST_CRYPTO_COMMON_H
#define XTEST_CRYPTO_COMMON_H

#include "ta_aes_perf.h"
#include "ta_sha_perf.h"




#define AES_PERF_INPLACE 0

#define CRYPTO_DEF_LOOPS 1 /* Default amount of inner loops */

#define CRYPTO_USE_ZEROS  0 /* Init input data to zero */
#define CRYPTO_USE_RANDOM 1 /* Get input data from /dev/urandom */
#define CRYPTO_NOT_INITED 2 /* Input data are not initialized */

#define CRYPTO_DEF_WARMUP 2 /* Start with a 2-second busy loop  */
#define CRYPTO_DEF_COUNT 5000	/* Default number of measurements */
#define CRYPTO_DEF_VERBOSITY 0
#define CRYPTO_DEF_UNIT_SIZE 0 /* Process whole buffer */


#define _verbose(lvl, ...)			\
	do {					\
		if (verbosity >= lvl) {		\
			printf(__VA_ARGS__);	\
			fflush(stdout);		\
		}				\
	} while (0)

#define verbose(...)  _verbose(1, __VA_ARGS__)
#define vverbose(...) _verbose(2, __VA_ARGS__)


int aes_perf_runner_cmd_parser(int argc, char *argv[]);
void aes_perf_run_test(int mode, int keysize, int decrypt, size_t size,
		       size_t unit, unsigned int n, unsigned int l,
		       int random_in, int in_place, int warmup, int verbosity);

int sha_perf_runner_cmd_parser(int argc, char *argv[]);
void sha_perf_run_test(int algo, size_t size, unsigned int n,
				unsigned int l, int random_in, int offset,
				int warmup, int verbosity);

#ifdef CFG_SECURE_DATA_PATH
int sdp_basic_runner_cmd_parser(int argc, char *argv[]);
#endif

#endif /* XTEST_CRYPTO_PERF_H */
