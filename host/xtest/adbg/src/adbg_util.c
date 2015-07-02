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
 ************************************************************************/
#include "adbg_int.h"

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
bool ADBG_TestIDMatches(
	const char *const TestID_p,
	const char *const Argument_p
	)
{
	if (Argument_p == NULL)
		return false;

	return strstr(TestID_p, Argument_p) != NULL;
}

void *ADBG_ListMemAllocFunction(size_t Length)
{
	return HEAP_UNTYPED_ALLOC(Length);
}

void ADBG_ListMemFreeFunction(void *Memory_p)
{
	void *p = Memory_p;

	HEAP_FREE(&p);
}

int ADBG_snprintf(
	char *Buffer_p,
	size_t BufferSize,
	const char *Format_p,
	...
	)
{
	va_list List;
	int ReturnValue;

	/*lint -save -e718 -e746 -e530 lint doesn't seem to know of va_start */
	va_start(List, Format_p);
	/*lint -restore */
	ReturnValue = ADBG_vsnprintf(Buffer_p, BufferSize, Format_p, List);
	va_end(List);
	return ReturnValue;
}

int ADBG_vsnprintf(
	char *Buffer_p,
	size_t BufferSize,
	const char *Format_p,
	va_list List
	)
{
	int Length;

	Length = vsnprintf(Buffer_p, BufferSize, Format_p, List);

	/*
	 * The moses version of vsnprintf() doesn't seem to add
	 * a terminating zero to the string if the result is too
	 * large.
	 */
	if (Buffer_p != NULL && BufferSize > 0)
		Buffer_p[BufferSize - 1] = '\0';

	return Length;
}

/*************************************************************************
 * 6. Definitions of internal functions
 ************************************************************************/
