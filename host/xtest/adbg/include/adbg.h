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

#ifndef ADBG_H
#define ADBG_H
#include <stddef.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>

#define ADBG_STRING_LENGTH_MAX (1024)

/*
 * Case definitions
 */

/**
 * Defines a test case
 *
 * Used in the follwing way for readability:
 */
#if 0   /* #if 0 to avoid nested comments */
ADBG_CASE_DEFINE(TEST_1001, TEST_Test_1001,
		/* Title */
		"My test case title",
		);
#endif

#define ADBG_CASE_DEFINE(TestID, Run, Title) \
	const ADBG_Case_Definition_t TestID = {#TestID, Title, Run, }

#define ADBG_CASE_DECLARE(name) \
	extern const ADBG_Case_Definition_t name


typedef struct ADBG_Case ADBG_Case_t;


typedef struct {
	const char *TestID_p;
	const char *Title_p;
	void (*Run_fp)(ADBG_Case_t *ADBG_Case_pp);
} ADBG_Case_Definition_t;

typedef struct {
	const ADBG_Case_Definition_t *CaseDefinition_p;
} ADBG_Case_SuiteEntry_t;

typedef struct {
	const char *SuiteID_p;
	const ADBG_Case_SuiteEntry_t *SuiteEntries_p;
} ADBG_Suite_Definition_t;

/*
 * Suite definitions
 */

/**
 * Declares a suite defined in a C-file.
 */
#define ADBG_SUITE_DECLARE(Name) \
	extern const ADBG_Suite_Definition_t ADBG_Suite_ ## Name;

#define ADBG_SUITE_DEFINE_BEGIN(Name) \
	extern const ADBG_Case_SuiteEntry_t ADBG_SuiteEntries_ ## Name[]; \
	const ADBG_Suite_Definition_t ADBG_Suite_ ## Name = \
	{ #Name, ADBG_SuiteEntries_ ## Name }; \
	const ADBG_Case_SuiteEntry_t ADBG_SuiteEntries_ ## Name[] = {
/**
 * Defines a suite entry, this is the name of a case.
 */
#define ADBG_SUITE_ENTRY(name) { &name },

#define ADBG_SUITE_DEFINE_END() { NULL } };

/*************************************************************************
* 2.3 IDbg table definitions
*************************************************************************/

typedef struct {
	const char *Command_p;
	const char *Help_p;
} ADBG_HelpTable_t;

#define ADBG_IDBG_TBL_HELP(Command, Help) \
	{ Command, Help },

/*
 * Enum table definitions
 */

#define ADBG_ENUM_TABLE_DECLARE(Name) \
	extern const ADBG_EnumTable_t ADBG_EnumTable_ ## Name[]

#define ADBG_ENUM_TABLE_DEFINE_BEGIN(Name) \
	const ADBG_EnumTable_t ADBG_EnumTable_ ## Name[] = {
#define ADBG_ENUM_TABLE_ENTRY(Value) { Value, #Value }

#define ADBG_ENUM_TABLE_DEFINE_END(Name) , { 0, NULL } }

typedef struct {
	int Value;
	const char *const Name_p;
} ADBG_EnumEntry_t;

typedef ADBG_EnumEntry_t ADBG_EnumTable_t;

ADBG_ENUM_TABLE_DECLARE(Boolean);

#define ADBG_ASSERT_STRINGS_EQUAL(Case_p, Str1_p, Str2_p) \
	Do_ADBG_Assert(Case_p, __FILE__, __LINE__, \
		       Str1_p != NULL && Str2_p != NULL && \
		       strcmp(Str1_p, Str2_p) == 0, \
		       "Assertion \"%s\" == \"%s\" failed", \
		       #Str1_p, #Str2_p)

#define ADBG_ASSERT_EQUAL(Case_p, Buf1_p, Buf2_p, Length) \
	Do_ADBG_Assert(Case_p, __FILE__, __LINE__, \
		       memcmp(Buf1_p, Buf2_p, Length) == 0, \
		       "Buffer equality of %s and %s Length %d failed", \
		       #Buf1_p, #Buf2_p, Length)

#define ADBG_ASSERT(Case_p, Expression) \
	Do_ADBG_Assert(Case_p, __FILE__, __LINE__, Expression, \
		       "Assertion %s failed", #Expression)

/**
 * Explicitly add an error to the test case
 */
#define ADBG_ERROR(Case_p) \
	Do_ADBG_Assert(Case_p, __FILE__, __LINE__, False, \
		       "Excplicitly added error")


void Do_ADBG_Assert(ADBG_Case_t *const Case_p, const char *const FileName_p,
		    const int LineNumber, const bool ExpressionOK,
		    const char *const Format_p,
		    ...) __attribute__((__format__(__printf__, 5, 6)));


/*
 * Expect functions/macros
 */

#define ADBG_EXPECT(Case_p, Expected, Got) \
	ADBG_EXPECT_ENUM(Case_p, Expected, Got, NULL)

#define ADBG_EXPECT_NOT(Case_p, Expected, Got) \
	ADBG_EXPECT_NOT_ENUM(Case_p, Expected, Got, NULL)

#define ADBG_EXPECT_ENUM(Case_p, Expected, Got, EnumTable_p) \
	Do_ADBG_Expect(Case_p, __FILE__, __LINE__, Expected, Got, #Got, \
		       EnumTable_p)

#define ADBG_EXPECT_NOT_ENUM(Case_p, NotExpected, Got, EnumTable_p) \
	Do_ADBG_ExpectNot(Case_p, __FILE__, __LINE__, \
			  NotExpected, Got, #Got, EnumTable_p)

#define ADBG_EXPECT_BOOLEAN(Case_p, Expected, Got) \
	ADBG_EXPECT_ENUM(Case_p, Expected, Got, ADBG_EnumTable_Boolean)

#define ADBG_EXPECT_TRUE(Case_p, Got) \
	ADBG_EXPECT_ENUM(Case_p, true, Got, ADBG_EnumTable_Boolean)

#define ADBG_EXPECT_EQUAL(Case_p, Buf1_p, Buf2_p, Length) \
	ADBG_EXPECT(Case_p, 0, memcmp(Buf1_p, Buf2_p, Length))

#define ADBG_EXPECT_BUFFER(Case_p, ExpBuf_p, ExpBufLen, GotBuf_p, GotBufLen) \
	Do_ADBG_ExpectBuffer(Case_p, __FILE__, __LINE__, \
			     ExpBuf_p, ExpBufLen, #GotBuf_p, GotBuf_p, \
			     #GotBufLen, GotBufLen)

#define ADBG_EXPECT_POINTER(Case_p, Expected, Got) \
	Do_ADBG_ExpectPointer(Case_p, __FILE__, __LINE__, Expected, Got, #Got)

#define ADBG_EXPECT_NOT_NULL(Case_p, Got) \
	Do_ADBG_ExpectPointerNotNULL(Case_p, __FILE__, __LINE__, Got, #Got)

#define ADBG_EXPECT_COMPARE_SIGNED(Case_p, Val1, Compar, Val2) \
	Do_ADBG_ExpectCompareSigned(Case_p, __FILE__, __LINE__, \
				    Val1, Val2, (Val1)Compar( \
					    Val2), #Val1, #Compar, #Val2)

#define ADBG_EXPECT_COMPARE_UNSIGNED(Case_p, Val1, Compar, Val2) \
	Do_ADBG_ExpectCompareUnsigned(Case_p, __FILE__, __LINE__, \
				      Val1, Val2, (Val1)Compar( \
					      Val2), #Val1, #Compar, #Val2)

#define ADBG_EXPECT_COMPARE_POINTER(Case_p, Val1, Compar, Val2) \
	Do_ADBG_ExpectComparePointer(Case_p, __FILE__, __LINE__, \
				     Val1, Val2, (Val1)Compar( \
					     Val2), #Val1, #Compar, #Val2)

#define ADBG_REQUIRE(Case_p, Recovery, Expected, Got) {\
	if (!ADBG_EXPECT(Case_p, Expected, Got)) \
		Recovery }

#define ADBG_REQUIRE_ENUM(Case_p, Recovery, Expected, Got, EnumTable_p) {\
	if (!ADBG_EXPECT_ENUM(Case_p, Expected, Got, EnumTable_p)) \
		Recovery }

#define ADBG_REQUIRE_BOOLEAN(Case_p, Recovery, Expected, Got) {\
	if (!ADBG_EXPECT_BOOLEAN(Case_p, Expected, Got)) \
		Recovery }

#define ADBG_REQUIRE_TRUE(Case_p, Recovery, Got) {\
	if (!ADBG_EXPECT_TRUE(Case_p, Got)) \
		Recovery }

#define ADBG_REQUIRE_EQUAL(Case_p, Recovery, Buf1_p, Buf2_p, Length) {\
	if (!ADBG_EXPECT_EQUAL(Case_p, Buf1_p, Buf2_p, Length)) \
		Recovery }

#define ADBG_REQUIRE_BUFFER(Case_p, Recovery, ExpBuf_p, ExpBufLen, GotBuf_p, \
			    GotBufLen) {\
	if (!ADBG_EXPECT_BUFFER(Case_p, ExpBuf_p, ExpBufLen, GotBuf_p, \
				GotBufLen)) \
		Recovery }

#define ADBG_REQUIRE_POINTER(Case_p, Recovery, Expected, Got) {\
	if (!ADBG_EXPECT_POINTER(Case_p, Expected, Got)) \
		Recovery }

#define ADBG_REQUIRE_NOT_NULL(Case_p, Recovery, Got) {\
	if (!ADBG_EXPECT_NOT_NULL(Case_p, Got)) \
		Recovery }

#define ADBG_REQUIRE_COMPARE_SIGNED(Case_p, Recovery, Val1, Compar, Val2) {\
	if (!ADBG_EXPECT_COMPARE_SIGNED(Case_p, Val1, Compar, Val2)) \
		Recovery }

#define ADBG_REQUIRE_COMPARE_UNSIGNED(Case_p, Recovery, Val1, Compar, Val2) {\
	if (!ADBG_EXPECT_COMPARE_UNSIGNED(Case_p, Val1, Compar, Val2)) \
		Recovery }

#define ADBG_REQUIRE_COMPARE_POINTER(Case_p, Recovery, Val1, Compar, Val2) {\
	if (!ADBG_EXPECT_COMPARE_POINTER(Case_p, Val1, Compar, Val2)) \
		Recovery }

bool Do_ADBG_Expect(ADBG_Case_t *const Case_p, const char *const FileName_p,
		    const int LineNumber, const int Expected, const int Got,
		    const char *const GotVarName_p,
		    const ADBG_EnumTable_t *const EnumTable_p);

bool Do_ADBG_ExpectNot(ADBG_Case_t *const Case_p, const char *const FileName_p,
		       const int LineNumber, const int NotExpected,
		       const int Got, const char *const GotVarName_p,
		       const ADBG_EnumTable_t *const EnumTable_p);

bool Do_ADBG_ExpectBuffer(ADBG_Case_t *const Case_p,
			  const char *const FileName_p, const int LineNumber,
			  const void *const ExpectedBuffer_p,
			  const size_t ExpectedBufferLength,
			  const char *const GotBufferName_p,
			  const void *const GotBuffer_p,
			  const char *const GotBufferLengthName_p,
			  const size_t GotBufferLength);

bool Do_ADBG_ExpectPointer(ADBG_Case_t *const Case_p,
			   const char *const FileName_p, const int LineNumber,
			   const void *Expected_p, const void *Got_p,
			   const char *const GotVarName_p);

bool Do_ADBG_ExpectPointerNotNULL(ADBG_Case_t *const Case_p,
				  const char *const FileName_p,
				  const int LineNumber, const void *Got_p,
				  const char *const GotVarName_p);

bool Do_ADBG_ExpectCompareSigned(ADBG_Case_t *const Case_p,
				 const char *const FileName_p,
				 const int LineNumber, const long Value1,
				 const long Value2, const bool Result,
				 const char *const Value1Str_p,
				 const char *const ComparStr_p,
				 const char *const Value2Str_p);

bool Do_ADBG_ExpectCompareUnsigned(ADBG_Case_t *const Case_p,
				   const char *const FileName_p,
				   const int LineNumber,
				   const unsigned long Value1,
				   const unsigned long Value2,
				   const bool Result,
				   const char *const Value1Str_p,
				   const char *const ComparStr_p,
				   const char *const Value2Str_p);

bool Do_ADBG_ExpectComparePointer(ADBG_Case_t *const Case_p,
				  const char *const FileName_p,
				  const int LineNumber,
				  const void *const Value1_p,
				  const void *const Value2_p, const bool Result,
				  const char *const Value1Str_p,
				  const char *const ComparStr_p,
				  const char *const Value2Str_p);

const char *Do_ADBG_GetEnumName(const int Value,
				const ADBG_EnumTable_t *const EnumTable_p);

/**
 * Writes a string to output.
 * String length max is defined by ADBG_STRING_LENGTH_MAX
 *
 * @param Format_p The formatting string as in printf
 */
void Do_ADBG_Log(const char *const Format_p, ...)
__attribute__((__format__(__printf__, 1, 2)));

/**
 * Writes out the contents of buf_p formatted so that each line will
 * have cols number of columns.
 *
 * @param[in] Buf_p  Buffer to print
 * @param[in] Size   Size of buffer (in bytes)
 * @param[in] Cols   Number of columns.
 */
void Do_ADBG_HexLog(const void *const Buf_p, const size_t Size,
		    const size_t Cols);

/*
 * Suite functions
 */

int Do_ADBG_RunSuite(const ADBG_Suite_Definition_t *Suite_p, int argc,
		     char *argv[]);

/*
 * SubCase functions
 */
void Do_ADBG_BeginSubCase(ADBG_Case_t *const Case_p,
			  const char *const FormatTitle_p,
			  ...) __attribute__((__format__(__printf__, 2, 3)));

void Do_ADBG_EndSubCase(ADBG_Case_t *const Case_p,
			const char *const FormatTitle_p,
			...) __attribute__((__format__(__printf__, 2, 3)));

#endif /* ADBG_H */
