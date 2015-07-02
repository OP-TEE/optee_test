/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

/*************************************************************************
* 1. Includes
*************************************************************************/
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include "security_utils_mem.h"

/*************************************************************************
* 2. Definition of external constants and variables
*************************************************************************/

/*************************************************************************
* 3. File scope types, constants and variables
*************************************************************************/

/*************************************************************************
* 4. Declaration of file local functions
*************************************************************************/

static uint32_t MWC_Random(void *Pointer_p);

/*************************************************************************
* 5. Definition of external functions
*************************************************************************/
char *SecUtil_Heap_StrDup(
	const char *const String_p,
	const bool Unsafe,
	const char *const File_p,
	const unsigned int Line
	)
{
	(void)&Unsafe;
	(void)&File_p;
	(void)&Line;
	return strdup(String_p);
}

void SecUtil_WipeMemory(
	void *const Buffer_p,
	const size_t BufferLength
	)
{
	uint8_t *p = Buffer_p;
	size_t n;
	uint32_t Number;

	for (n = 0; n < BufferLength; n++)
		p[n] = (uint8_t)n;

	memset(p, 0xAA, BufferLength);
	memset(p, 0x55, BufferLength);

	for (n = 0; n < BufferLength / sizeof(uint32_t); n++) {
		Number = MWC_Random(Buffer_p);
		memcpy(p + n, &Number, sizeof(uint32_t));
	}

	n = (n - 1) * sizeof(uint32_t);

/* Add the last bytes which didn't fill a complete uint32_t */
	Number = MWC_Random(Buffer_p);
	for (; n < BufferLength; n++) {
		p[n] = 0xF & (uint8_t)Number;
		Number >>= 8;
	}
}

void SecUtil_SecureHeapFree_helper(
	void **const Buffer_pp
	)
{
	if (Buffer_pp != NULL) {
		if (*Buffer_pp != NULL) {
			free(*Buffer_pp);
			*Buffer_pp = NULL;
		}
	}
}

/*************************************************************************
* 6. Definition of internal functions
*************************************************************************/

/*
 * There may be concurrent calls to this function but it doesn't matter,
 * the result will still be hard to predict.
 *
 * Inspiration for implementation of this function was collected from
 * http://www.bobwheeler.com/statistics/Password/MarsagliaPost.txt
 * It doesn't seem to have any specified license, but in any case
 * this a somewhat different implementation.
 */
static uint32_t MWC_Random(void *Pointer_p)
{
	static uint32_t static_z;
	static uint32_t static_w;
	static bool Initialized;
/*
 * In case of concurrent access, use private variables for
 * the actual calculation.
 */
	uint32_t z = static_z;
	uint32_t w = static_w;

	if (!Initialized) {
		z = 362436069 * ((uint32_t)(uintptr_t)Pointer_p >> 16);
		w = 521288629 * ((uint32_t)(uintptr_t)Pointer_p & 0xFFFF);
		Initialized = true;
	}

	z = 36969 * (z & 65535) + (z >> 16);
	w = 18000 * (w & 65535) + (w >> 16);

	static_z = z;
	static_w = w;

	return (z << 16) + (w & 65535);
}
