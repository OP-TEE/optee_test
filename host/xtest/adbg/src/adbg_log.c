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

#include "adbg_int.h"

#include <stdlib.h>

#include <ctype.h>
/*************************************************************************
 * 2. Definition of external constants and variables
 ************************************************************************/

/*************************************************************************
 * 3. File scope types, constants and variables
 ************************************************************************/

/*************************************************************************
 * 4. Declaration of file local functions
 ************************************************************************/

/*************************************************************************
 * 5. Definition of external functions
 ************************************************************************/

/******************************************************************************/
/*! @fn void Do_ADBG_Log( void* This_p, char* Format, ...)
 * @brief
 * @param [in] This_p
 * @param [in] Format
 * @param [in] ...
 * @return void
 */
/******************************************************************************/
void Do_ADBG_Log(const char *const Format, ...)
{
	va_list ap;

	va_start(ap, Format);
	vprintf(Format, ap);
	printf("\n");
	va_end(ap);
	fflush(stdout);
}

void Do_ADBG_HexLog(
	const void *const Buf_p,
	const size_t Size,
	const size_t Cols
	)
{
	const uint8_t *Data_p = Buf_p;
	size_t n;

	for (n = 0; n < Size; n += Cols) {
		char HexBuffer[ADBG_STRING_LENGTH_MAX];
		char AsciiBuffer[ADBG_STRING_LENGTH_MAX / 3];
		size_t m, NumCols;

		(void)SecUtil_BufferToHex(Data_p + n, MIN(Cols, Size - n), NULL,
					  HexBuffer, sizeof(HexBuffer));
		NumCols = MIN(MIN(Cols, Size - n), sizeof(AsciiBuffer) - 1);
		for (m = 0; m < NumCols; m++) {
			int ch = Data_p[n + m];

			if (isprint(ch))
				AsciiBuffer[m] = (char)ch;
			else
				AsciiBuffer[m] = '.';
		}
		AsciiBuffer[m] = '\0';

		Do_ADBG_Log("  %-*s %s", (int)Cols * 3, HexBuffer, AsciiBuffer);
	}
}

/*************************************************************************
 * 6. Definitions of internal functions
 ************************************************************************/
