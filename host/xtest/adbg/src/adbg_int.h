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

#ifndef ADBG_INT_H
#define ADBG_INT_H
#include <sys/queue.h>
#include <sys/param.h>

#include <adbg.h>

#include "security_utils_hex.h"
#include "security_utils_mem.h"

#include <sys/queue.h>

#include <string.h>

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>

#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif
#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif


/*************************************************************************
* 2. Types, constants and external variables
*************************************************************************/

typedef struct ADBG_Result {
	int NumTests;
	int NumFailedTests;
	int NumSubTests;
	int NumFailedSubTests;
	int NumSubCases;
	int NumFailedSubCases;
	int FirstFailedRow;
	char const *FirstFailedFile_p;
	bool AbortTestSuite;
	const char *WhySkipped_p;
} ADBG_Result_t;

TAILQ_HEAD(ADBG_SubCaseHead, ADBG_SubCase);
typedef struct ADBG_SubCaseHead ADBG_SubCaseHead_t;

typedef struct ADBG_SubCase ADBG_SubCase_t;
struct ADBG_SubCase {
	char *TestID_p;
	char *Title_p;
	ADBG_Result_t Result;
	ADBG_SubCase_t *Parent_p; /* The SubCase where this SubCase was added */
	ADBG_SubCaseHead_t SubCasesList; /* SubCases created in this SubCase*/
	TAILQ_ENTRY(ADBG_SubCase) Link;
};

/* Typedefed in t_adbg.h */
struct ADBG_Case {
	const ADBG_Case_SuiteEntry_t *SuiteEntry_p;

	ADBG_SubCase_t *CurrentSubCase_p;
	ADBG_SubCase_t *FirstSubCase_p;

	ADBG_SuiteData_t *SuiteData_p;
	ADBG_Result_t Result;
	TAILQ_ENTRY(ADBG_Case)          Link;
};

typedef struct {
	ADBG_Case_t *Case_p;
	ADBG_SubCase_t *CurrentSubCase_p;
} ADBG_SubCase_Iterator_t;


/*************************************************************************
* 3. Functions
*************************************************************************/
void *ADBG_ListMemAllocFunction(size_t Length);
void  ADBG_ListMemFreeFunction(void *Memory_p);

bool ADBG_Case_SubCaseIsMain(const ADBG_Case_t *const Case_p,
			     const ADBG_SubCase_t *const SubCase_p);

void ADBG_Case_IterateSubCase(ADBG_Case_t *Case_p,
			      ADBG_SubCase_Iterator_t *Iterator_p);

ADBG_SubCase_t *ADBG_Case_NextSubCase(ADBG_SubCase_Iterator_t *Iterator_p);

ADBG_Case_t *ADBG_Case_New(const ADBG_Case_SuiteEntry_t *SuiteEntry_p,
			   ADBG_SuiteData_t *SuiteData_p);

void ADBG_Case_Delete(ADBG_Case_t *Case_p);

int ADBG_snprintf(char *Buffer_p, size_t BufferSize, const char *Format_p,
		  ...) __attribute__((__format__(__printf__, 3, 4)));

int ADBG_vsnprintf(char *Buffer_p, size_t BufferSize, const char *Format_p,
		   va_list List) __attribute__((__format__(__printf__, 3, 0)));

bool ADBG_TestIDMatches(const char *const TestID_p,
			const char *const Argument_p);

#define HEAP_ALLOC(x) ((x *)malloc(sizeof(x)))
#define HEAP_UNTYPED_ALLOC(x) malloc((x))
#define HEAP_FREE(x) do { if (*(x) != NULL) { free(*(x)); *(x) = NULL; \
			  } } while (0)

#define IDENTIFIER_NOT_USED(x) { if (sizeof(&x)) {} }

#endif /* ADBG_INT_H */
