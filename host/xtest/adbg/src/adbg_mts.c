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
void Do_ADBG_MTS_Suite(
	const ADBG_Suite_Definition_t *Suite_p,
	int argc,
	char *argv[]
	)
{
	const ADBG_Case_Definition_t *CaseDefinition_p;
	char *Argument_p = NULL;
	size_t n;
	ADBG_LogTable_t LogTable[3] = {
	{ 11, NULL }, { 52, NULL }, { 13, NULL } };

	if (argc > 1)
		Argument_p = argv[1];

	/* Title of MTS */
	Do_ADBG_LogHeading(0, "%s module test specification",
			   Suite_p->SuiteID_p);

	Do_ADBG_LogHeading(1, "Description of the test cases");

	/* Horizontal line for three columns */
	Do_ADBG_LogTableLine(LogTable, 3);

	/* Description of each column */
	LogTable[0].Text_p = "Test CaseID";
	LogTable[1].Text_p = "Short Description";
	LogTable[2].Text_p = "Requirement IDs";
	Do_ADBG_LogTable(LogTable, 3);

	/* Horizontal line for three columns */
	Do_ADBG_LogTableLine(LogTable, 3);

	for (n = 0; Suite_p->SuiteEntries_p[n].CaseDefinition_p != NULL; n++) {
		CaseDefinition_p = Suite_p->SuiteEntries_p[n].CaseDefinition_p;

		if (Argument_p != NULL &&
		    !ADBG_TestIDMatches(CaseDefinition_p->TestID_p,
					Argument_p)) {
			continue;
		}

		/* Print the three columns of a test case */
		LogTable[0].Text_p = CaseDefinition_p->TestID_p;
		LogTable[1].Text_p = CaseDefinition_p->ShortDescription_p;
		LogTable[2].Text_p = CaseDefinition_p->RequirementIDs_p;
		Do_ADBG_LogTable(LogTable, 3);

		/* Horizontal line for three columns */
		Do_ADBG_LogTableLine(LogTable, 3);
	}


	Do_ADBG_Log(" ");
	Do_ADBG_LogHeading(1, "Detailed description of each test case");

	for (n = 0; Suite_p->SuiteEntries_p[n].CaseDefinition_p != NULL; n++) {
		CaseDefinition_p = Suite_p->SuiteEntries_p[n].CaseDefinition_p;

		if (Argument_p != NULL &&
		    !ADBG_TestIDMatches(CaseDefinition_p->TestID_p,
					Argument_p)) {
			continue;
		}

		Do_ADBG_LogHeading(2, "%s %s",
				   CaseDefinition_p->TestID_p,
				   CaseDefinition_p->Title_p);
		if (Suite_p->SuiteEntries_p[n].WhyDisabled_p != NULL) {
			Do_ADBG_LogText("This test was disabled because:");
			Do_ADBG_LogText(
				Suite_p->SuiteEntries_p[n].WhyDisabled_p);
			Do_ADBG_Log(" ");
		}
		Do_ADBG_LogText("Objective:");
		Do_ADBG_LogText(CaseDefinition_p->ShortDescription_p);
		Do_ADBG_Log(" ");
		Do_ADBG_LogText("Implementation:");
		Do_ADBG_LogText(CaseDefinition_p->HowToImplement_p);
		Do_ADBG_Log(" ");
	}
}

/*************************************************************************
 * 6. Definitions of internal functions
 ************************************************************************/
