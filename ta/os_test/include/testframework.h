/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
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

#ifndef GUARD_testframework_H
#define GUARD_testframework_H

#include "tee_internal_api.h"

#include "tee_arith_internal.h"

#include "tb_macros.h"
#include "tb_asserts.h"

/* define the max size of generated numbers */
/* this is number of hex chars in the number */
#define MAX_RAND_DIGITS         256
#define MAX_RAND_STRING_SIZE    (MAX_RAND_DIGITS + 2)

size_t my_strlen(const char *string);
int my_strcmp(const char *s1, const char *s2);
size_t my_strlcpy(char *dst, const char *src, size_t siz);

void tb_set_random_value(TEE_BigInt *a, char *str, int allow_neg);
void tb_get_random_str(char *str, int allow_neg);

void tb_main(void);

void tb_var(void);
void tb_conv(void);
void tb_cmp(void);
void tb_addsub(void);
void tb_mul(void);
void tb_shift(void);
void tb_div(void);
void tb_gcd(void);
void tb_modulus(void);
void tb_fmm(void);
void tb_prime(void);

int TEE_BigIntConvertFromString(TEE_BigInt *dest, const char *src);
char *TEE_BigIntConvertToString(char *dest, int mode, const TEE_BigInt *src);

#endif /* include guard */
