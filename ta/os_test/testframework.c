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
#include "tee_internal_api.h"
#include "testframework.h"

/*
 * TEE_BigIntConvertFromString
 *
 * !! Not part of the spec !!
 *
 * Assigns dest the value of the src, where src is a zero-terminated character
 * string. If the src starts with a valid number, the valid part will be
 * converted and the rest of the src will not be parsed further. src is assumed
 * to be in base 16. Returns -1 if the src was malformed, and the number of base
 * digits converted (not including leading zeros) if the conversion was OK. If
 * the src is a null-ptr we return -1. If the src is empty, we don't touch dest
 * and just returns 0. If the src only consists of white spaces, we set dest to
 * zero returns 0.
 */
int TEE_BigIntConvertFromString(TEE_BigInt *dest, const char *src)
{
	mpanum mpa_dest = (mpa_num_base *) dest;

	return mpa_set_str(mpa_dest, src);
}

/*
 * TEE_BigIntConvertToString
 *
 * !! Not part of the spec !!
 *
 * Prints a zero-terminated string representation of src into dest. The need
 * length of dest is the space needed to print src plus additional chars for the
 * minus sign and the terminating '\0' char.  A pointer to str is returned.
 * If something went wrong, we return 0.
 *
 * mode is one of the following:
 *     TEE_MATHAPI_PRINT_MODE_HEX_LC   : output in lower case hex
 *     TEE_MATHAPI_PRINT_MODE_DEC      : output in decimal
 */
char *TEE_BigIntConvertToString(char *dest, int mode, const TEE_BigInt *src)
{
	mpanum mpa_src = (mpa_num_base *) src;

	if (dest == 0) {
		dest = TEE_Malloc(mpa_get_str_size(), 0);
		if (dest == 0)
			return 0;
	}
	return mpa_get_str(dest, mode, mpa_src);
}

static uint8_t myrand(void)
{
	static uint32_t lcg_state = 17;
	static const uint32_t a = 1664525;
	static const uint32_t c = 1013904223;

	lcg_state = (a * lcg_state + c);
	return (uint8_t) (lcg_state >> 24);
}

static int getrand(int min, int max)
{
	return (myrand() % (max - min)) + min;
}

static char nibble_to_char(int c)
{
	if (c < 10)
		return '0' + (char)c;
	c -= 10;
	return 'A' + (char)c;
}

static char getrandchar(int base)
{
	return nibble_to_char(getrand(0, base == 16 ? 15 : 9));
}

/*
 *  Function:   tb_get_random_str
 *
 *  Sets str to a random number in base 16 of max length
 *  MAX_RAND_DIGITS. str must point to a memory arear which is
 *  at least MAX_RAND_STR_SIZE big.
 *  if allow_neg is 1 we can generate negative numbers
 */
void tb_get_random_str(char *str, int allow_neg)
{
	char *ptr;
	int r;
	int neg = 0;
	int j;
	char c;

	ptr = str;
	if (allow_neg) {
		neg = getrand(0, 1);
		if (neg)
			*ptr++ = '-';
	}
	r = getrand(0, MAX_RAND_DIGITS);
	if (r == 0 && neg) {
		*str++ = '0';
		*str = '\0';
		return;
	}

	for (j = 0; j < r; j++) {
		c = getrandchar(16);

		/* avoid leading zeros since that is difficult to test later */
		if (j == 0 && c == '0') {
			while ((c = getrandchar(16)) == '0')
				;
		}
		*ptr++ = c;
	}
	*ptr++ = '\0';
}

/*
 *  Function:   tb_set_random_value
 *
 *  Sets a to a random value and returns the representation in str (in base
 *  "base")
 */
void tb_set_random_value(TEE_BigInt *a, char *str, int allow_neg)
{
	do {
		tb_get_random_str(str, allow_neg);
	} while (*str == '\0');

	TEE_BigIntConvertFromString(a, str);
}

static uint32_t mempool_u32[mpa_scratch_mem_size_in_U32(10, 2048)];
mpa_scratch_mem mempool = (void *)&mempool_u32;

void tb_main(void)
{
	mpa_init_scratch_mem(mempool, sizeof(mempool_u32), 2048);

	tb_var();
	tb_conv();
	tb_cmp();
	tb_addsub();
	tb_mul();
	tb_div();
	tb_modulus();
	tb_prime();

	ALL_PASSED;
}
