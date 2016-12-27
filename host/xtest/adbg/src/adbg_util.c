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

/*************************************************************************
 * 6. Definitions of internal functions
 ************************************************************************/
