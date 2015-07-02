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
#include "adbg_int.h"

/*************************************************************************
* 2. Definition of external constants and variables
*************************************************************************/


ADBG_ENUM_TABLE_DEFINE_BEGIN(Boolean)
ADBG_ENUM_TABLE_ENTRY(false),
ADBG_ENUM_TABLE_ENTRY(true)
ADBG_ENUM_TABLE_DEFINE_END(Boolean);


/*************************************************************************
* 3. File scope types, constants and variables
*************************************************************************/

/*************************************************************************
* 4. Declaration of file local functions
*************************************************************************/

/*************************************************************************
* 5. Definition of external functions
*************************************************************************/
const char *Do_ADBG_GetEnumName(
	const int Value,
	const ADBG_EnumTable_t *const EnumTable_p
	)
{
	const ADBG_EnumTable_t *Entry_p = EnumTable_p;

	for (; Entry_p->Name_p != NULL; Entry_p++) {
		if (Entry_p->Value == Value)
			return Entry_p->Name_p;
	}
	return "<unresolvable enum name>";
}


/*************************************************************************
* 6. Definition of internal functions
*************************************************************************/
